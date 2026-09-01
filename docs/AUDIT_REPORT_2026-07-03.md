# Autobahn Defender — Security & Functionality Audit Report
**Auditor:** GLM-5.2 (personal audit, no subagents)
**Date:** June 26, 2026
**Scope:** Full source tree (v1.x review working copy)

---

## EXECUTIVE SUMMARY

Overall the codebase is well-structured with good security practices already in place: subprocess calls use list arguments (not shell=True), quarantine has path validation, the database has restrictive permissions, and the environment is cleaned for subprocess calls. However, I found several security issues ranging from CRITICAL to LOW, plus a number of functionality/efficiency improvements. All findings are detailed below with specific file/line references.

---

## SECURITY AUDIT FINDINGS

### S1. HIGH — `_secure_delete` passes 1 and 2 allocate full file size in memory (OOM risk)
**File:** `quarantine.py`, lines 187-216
**Severity:** HIGH (denial of service / OOM on large files)

The third pass (random data overwrite) has a bug in the loop logic:

```python
size = filepath.stat().st_size  # e.g. 5000
# ...
for _ in range(size // 1024 + 1):  # range(5 + 1) = 6 iterations
    chunk = min(1024, size)  # first iter: min(1024, 5000) = 1024
    f.write(bytes([random.randint(0, 255) for _ in range(chunk)]))
    size -= chunk  # size = 5000 - 1024 = 3976
    if size <= 0:
        break
```

After testing: the random pass loop logic is actually CORRECT — it writes exactly the right number of bytes (verified by simulation). The decrement + `min(1024, size)` pattern works.

However, passes 1 and 2 write `b"\x00" * size` and `b"\xFF" * size` using the FULL file size, which allocates a potentially huge byte string in memory. For a large quarantined file (say 2GB), this tries to allocate 2GB of bytes in a single `f.write()` call, which could OOM the system.

**Fix:** Use chunked writing for ALL three passes (the random pass already does this correctly). Apply the same chunked pattern to passes 1 and 2.

### S2. HIGH — TOCTOU race condition in quarantine_file
**File:** `quarantine.py`, lines 60-104
**Severity:** HIGH

```python
filepath = Path(filepath).resolve()  # Resolve symlinks
if not filepath.exists():            # Check exists (TIME T1)
    return False
# ... time passes ...
shutil.move(str(filepath), str(dest))  # Move (TIME T2)
```

Between the `exists()` check and the `shutil.move()`, an attacker could replace the file with a symlink pointing to a critical system file. The `resolve()` at the top helps, but `shutil.move` follows symlinks — if the file is replaced with a symlink between the check and the move, the move would follow the symlink and move the target file.

**Fix:** Use `os.rename()` which operates on the path itself, or open the file with `O_NOFOLLOW` first to verify it's not a symlink, then move the file descriptor.

### S3. HIGH — `_parse_clamscan_output` splits on colon, misparses filenames with colons
**File:** `scanner.py`, lines 548-593
**Severity:** HIGH (false negatives — threats could be missed)

```python
elif " FOUND" in line:
    parts = line.split(":")
    if len(parts) >= 2:
        filepath = parts[0].strip()
        threat = parts[-1].replace(" FOUND", "").strip()
```

ClamAV output format is: `filepath: threatname FOUND`

If the filepath contains colons (common on Linux — e.g. `/home/user/my:file:txt`), the split produces more than 2 parts. `parts[0]` would only get the text before the first colon, not the full path. This means:
1. The filepath is wrong in the results (user can't find the file)
2. The threat name extraction is also wrong (it takes `parts[-1]` which is correct, but the filepath is truncated)

**Fix:** Use `rsplit(":", 1)` to split from the right, or better yet, use `line.rsplit(" FOUND", 1)[0].rsplit(": ", 1)` to properly separate filepath from threat name. Actually, the safest approach is to use `--infected` format with `--bell` or parse using the known format: everything before the last `: ` is the filepath, everything after is the threat + " FOUND".

### S4. MEDIUM — Silent exception swallowing in multiple locations
**File:** Multiple files
**Severity:** MEDIUM (masks bugs, can hide security issues)

Found these `except: pass` or `except Exception: pass` patterns:

1. `scanner.py:701-704` — `except Exception: pass` in YARA validation, continues even if validation fails
2. `scanner.py:758-759` — `except Exception: pass` in `_scan_single_file`, swallows all YARA scanning errors
3. `main.py:816-817` — `except Exception: self._usb_monitor = None` in USB monitor start
4. `updater.py:64-65` — `except (json.JSONDecodeError, OSError): pass` in state loading (acceptable)
5. `ui_tabs.py:2003-2004` — `except Exception:` in `_open_yara_folder` (acceptable — just shows message)

The most concerning are #1 and #2. If YARA rule validation fails, the scan continues with potentially broken rules, and if individual file scanning errors are swallowed, threats could be missed silently.

**Fix:** Log errors instead of silently passing. At minimum, collect errors and report them in scan results.

### S5. MEDIUM — No file size limit for YARA scanning (memory DoS)
**File:** `scanner.py`, lines 595-617
**Severity:** MEDIUM

`_is_scannable_file()` checks for empty files and special files, but has NO maximum file size check. YARA loads the entire file into memory for scanning. If a user scans a directory containing a very large file (e.g., a 50GB disk image, a 100GB database dump), YARA will try to load it all into memory, potentially causing OOM.

**Fix:** Add a configurable maximum file size for YARA scanning (default: 100MB or 250MB). Files larger than this should be skipped with a note in the results.

### S6. MEDIUM — `xdg-open` called without sanitization
**File:** `ui_tabs.py`, line 2002
**Severity:** LOW-MEDIUM

```python
subprocess.Popen(["xdg-open", str(RULES_DIR)])
```

This uses list form (no shell=True), which is good. But `RULES_DIR` is a fixed path (`~/.autobahn/rules`), so this is safe. However, if this pattern were copied for user-provided paths, it would be dangerous. No action needed for this specific instance, but worth noting as a pattern to maintain.

### S7. LOW — History database connections not always closed on error
**File:** `history_db.py`
**Severity:** LOW

The `_get_conn()` function returns a connection that callers are responsible for closing. Most functions do close it, but if an exception occurs between `_get_conn()` and `conn.close()`, the connection leaks. This is mitigated by the `_db_lock` and WAL mode, but could still cause issues over long sessions.

**Fix:** Use context managers (`with` blocks) or try/finally.

### S8. LOW — Autostart desktop file permissions too permissive
**File:** `main.py`, line 187
**Severity:** LOW

```python
os.chmod(str(AUTOSTART_FILE), 0o755)
```

A `.desktop` file in `~/.config/autostart/` doesn't need to be executable. It should be `0o644` (readable, not executable). Setting it to `0o755` means any process running as the user can modify it to execute arbitrary commands at login.

**Fix:** Change to `0o644`.

### S9. LOW — Version header inconsistency
**File:** `main.py`, line 2 vs line 36
**Severity:** LOW (cosmetic, but could confuse users/debugging)

```python
"""Autobahn Defender v1.1 - Main Application Entry Point"""  # Line 2
APP_VERSION = "1.2"  # Line 36
```

**Fix:** Update the header comment to say v1.2.

### S10. INFO — Subprocess calls are properly done (POSITIVE FINDING)
**File:** All files
**Severity:** N/A (good practice)

All subprocess calls use list arguments (e.g., `subprocess.run(["clamscan", "--database", defs_path, ...])`) rather than `shell=True`. This properly prevents command injection. The `_clean_env()` function correctly strips `LD_LIBRARY_PATH`, `PYTHONPATH`, and `LD_PRELOAD` from subprocess environments. Module name validation in `kernel_checker.py` uses regex `^[a-zA-Z0-9_.-]+$` before passing to `modinfo`.

### S11. INFO — Quarantine path validation is good (POSITIVE FINDING)
**File:** `quarantine.py`, lines 67-69, 118-136
**Severity:** N/A (good practice)

Critical system paths are blocked from quarantine, and `_safe_restore_path()` validates that restore destinations are within user-accessible directories (home, /tmp, /media, /mnt, /run/media). Manifest is saved atomically with tmp file + replace.

### S12. INFO — Database has restrictive permissions (POSITIVE FINDING)
**File:** `history_db.py`, lines 30-78
**Severity:** N/A (good practice)

Database file and parent directory are created with `0o600`/`0o700` permissions. WAL mode is enabled for safe concurrent reads. The previous session's fix is present in the clone.

---

## EFFICIENCY / FUNCTIONALITY AUDIT FINDINGS

### E1. HIGH — No YARA rule compilation caching
**File:** `scanner.py`, lines 643-700
**Severity:** HIGH (performance)

Every scan call to `_run_yara()` does the following every time:
1. Globs all `.yar` files from RULES_DIR
2. Reads and merges all rule files into a temp file
3. Validates by running `yara` on `/dev/null`
4. Scans files

Steps 1-3 are repeated on every single scan, even if the rules haven't changed. For 1,958 rules totaling 42,168 lines, this merge + validate step takes several seconds.

**Fix:** Cache the merged rule file. Only re-merge + validate when rule files have changed (check modification times or content hashes). Store the merged file at `~/.autobahn/rules/.merged_cache.yar` with a metadata file tracking source file hashes.

### E2. MEDIUM — File count estimation does a full directory walk
**File:** `scanner.py`, lines 456-474
**Severity:** MEDIUM (performance)

`_estimate_file_count()` does `p.rglob("*")` which is a full recursive walk — the same work that `_collect_scannable_files()` does later. For a full system scan, this means walking the filesystem TWICE.

**Fix:** Either skip the estimation and use an indeterminate progress bar, or combine the estimation with the actual collection in a single pass. Alternatively, use a streaming approach where progress is based on files actually scanned without a total.

### E3. MEDIUM — YARA scans each file with a separate subprocess
**File:** `scanner.py`, lines 727-760
**Severity:** MEDIUM (performance)

Each file gets its own `subprocess.Popen(["yara", merged_path, filepath])` call. For thousands of files, this means thousands of process spawns. YARA has to parse and compile the rules for EVERY file.

**Fix:** Use `yara-python` (the Python bindings) to compile rules once in memory and scan files directly via the API. This eliminates subprocess overhead entirely. The `yara-python` package is already a dependency of many YARA-based tools and would be much more efficient. Alternatively, batch multiple files into a single YARA invocation: `yara merged_rules file1 file2 file3 ...`.

### E4. MEDIUM — ThreadPoolExecutor doesn't handle KeyboardInterrupt gracefully
**File:** `scanner.py`, lines 763-776
**Severity:** MEDIUM (functionality)

When scanning with threads, the `ThreadPoolExecutor` context manager (`with` block) will wait for all submitted futures to complete before exiting, even if `_cancelled` is set. This means canceling a scan with many files in flight could take a while.

**Fix:** Use `pool.shutdown(wait=False, cancel_futures=True)` or break out of the `as_completed` loop and manually cancel remaining futures.

### E5. LOW — Duplicate scan path logic between DashboardTab and ScanTab
**File:** `ui_tabs.py`, lines 601-620 (DashboardTab) and 1166-1186 (ScanTab)
**Severity:** LOW (code quality)

Both `DashboardTab.start_scan()` and `ScanTab.start_scan()` have nearly identical code for the full-system root check and custom path dialog. This is duplicated logic.

**Fix:** Extract to a shared helper function.

### E6. LOW — First-run setup shows guidance dialog BEFORE definitions download completes
**File:** `main.py`, lines 913-939
**Severity:** LOW (UX)

In `_run_first_run_setup()`, the definitions download is started (line 923) but not waited on. The guidance dialog is shown immediately after (line 939), and the window is shown (line 932-934). The definitions dialog manages its own lifecycle, but the user might see the main window before definitions are downloaded, which could be confusing.

**Fix:** Show the definitions dialog as modal (`.exec()`) and wait for it to complete before showing the guidance dialog.

### E7. LOW — USB monitor polls /proc/mounts every 3 seconds
**File:** `usb_monitor.py`
**Severity:** LOW (efficiency)

The USB monitor polls `/proc/mounts` every 3 seconds. This is acceptable for a desktop app, but could be improved with inotify or udev monitoring for instant detection. Not a priority.

### E8. INFO — Previous session fixes status
**Status:** PARTIALLY PRESENT

Checking the previous session fixes:
- `settings.py`: Autostart exec path uses `sys.executable` — **NOT PRESENT** (uses `Path(__file__).resolve()`)
- `quarantine.py`: 3-pass secure delete — **PRESENT** (but has the bug in S1)
- `history_db.py`: Restrictive permissions — **PRESENT**
- `scanner.py`: CachyOS distro support — **PARTIALLY** (cachyos is in updater.py but not in scanner.py's distro list)
- `scanner.py`: `_clean_env()` — **PRESENT**
- `main.py`: CachyOS in arch distro list — **NOT PRESENT** (main.py checks for "cachyos" but the list at line 394 uses the string "cachyos" — actually it IS there)

The autostart exec path difference is intentional — `main.py`'s `_set_autostart()` uses `Path(__file__).resolve()` for source runs and `sys.executable` for frozen, which is actually correct. The `settings.py` version also does the same. So this is fine.

---

## RESEARCH FINDINGS

### Windows YARA Rules Sources (for Feature #3)

1. **YARA Forge (YARAHQ/yara-forge)** — The gold standard. Automated weekly releases. Has a "Core Set" with high accuracy / low FP rules. Curated from multiple sources. Available at github.com/YARAHQ/yara-forge. This is the BEST source for Windows malware rules.

2. **Florian Roth signature-base (Neo23x0/signature-base)** — Already used in the project for Linux rules. Also contains Windows-specific rules. High quality, minimal FPs.

3. **Elastic Security YARA Rules** — Already used. Contains Windows malware rules alongside Linux rules.

4. **ReversingLabs** — Already used for 22 rules. Has Windows-specific rules.

5. **ANY.RUN YARA (anyrun/YARA)** — Curated collection targeting malware families, phishing. Good quality.

**Recommendation:** Use YARA Forge Core Set for Windows rules. It's curated, has low FPs, and is actively maintained. We can download the Windows-specific subset from their releases. Alternatively, extract PE-targeting rules from the existing sources (Florian Roth, Elastic) that are already bundled.

### YARA False Positive Reduction (for Feature #4)

From research and the Stairwell/Nextron best practices:

1. **File-type pre-filtering with magic bytes:**
   - PE files: `uint16(0) == 0x5A4D` (MZ header)
   - ELF files: `uint32(0) == 0x464C457F` (ELF magic)
   - This is the recommended approach per Nextron Systems and Stairwell docs
   - Use `uint16(0)` instead of `pe.is_pe` for performance (avoids loading the PE module unnecessarily)

2. **Rule-level conditions:** Well-written YARA rules already include file-type conditions in their `condition:` field. The existing rules from Elastic and Florian Roth typically include `uint16(0) == 0x5A4D and ...` for PE rules and `uint32(0) == 0x464C457F and ...` for ELF rules.

3. **Safe default whitelist paths:** System directories that are managed by the package manager and are extremely unlikely to contain malware:
   - `/usr/lib` (but NOT `/usr/local/lib` — that's user-writable)
   - `/usr/share` (read-only data)
   - `/lib` and `/lib64` (system libraries)
   - DO NOT whitelist: `/tmp`, `/home`, `/var/tmp`, `/dev/shm`, `/usr/local`, downloads directories

4. **Signature age:** Consider adding a `date` metadata field check to YARA rules. Rules older than 3-5 years targeting specific malware variants tend to have higher FP rates because the patterns they match are now common in legitimate software.

### PyQt6 UI/Animation Best Practices (for Feature #2)

From research:

1. **QPropertyAnimation** — The standard way to animate widget properties in PyQt6. Can animate geometry, position, window opacity, etc.
2. **QEasingCurve** — Provides smooth transitions (e.g., `OutCubic`, `InOutQuart`).
3. **For tab switching:** Use `QStackedWidget` with a `QPropertyAnimation` on the `pos` property (slide in/out) or `windowOpacity` (fade). The existing code already uses `QStackedWidget`.
4. **For collapsible sections:** Use `QPropertyAnimation` on `maximumHeight` property (from 0 to content height).
5. **Performance:** Animations should be lightweight (100-300ms duration) to avoid lag on slower systems.

---

## IMPLEMENTATION PLAN

Based on the approved features and audit findings:

### Phase 1: Security fixes (from audit)
1. Fix `_secure_delete` chunked writing + logic bug (S1)
2. Fix clamscan output parsing with rsplit (S3)
3. Add file size limit for YARA scanning (S5)
4. Fix autostart file permissions (S8)
5. Fix version header (S9)
6. Add error logging for swallowed exceptions (S4)

### Phase 2: Start Minimized feature
1. Add `start_minimized` setting to `settings.py`
2. Add checkbox in Auto-Start card in `ui_tabs.py`
3. Modify `main.py` startup to check setting and hide window

### Phase 3: UI improvements
1. Enhanced dashboard with visual stats
2. Color-coded severity in scan results
3. Collapsible settings sections
4. Smooth tab switching animation
5. Overall polish (rounded corners, spacing, icons)

### Phase 4: Windows malware detection
1. Create `rules/windows-malware-rules.yar` with curated PE-targeting rules
2. Add `yara/scan_windows_malware` setting (default: False)
3. Add checkbox in YARA Rules card in Settings
4. Modify scanner to load Windows rules when enabled

### Phase 5: False positive reduction
1. File-type pre-filtering (PE rules only on PE files, ELF rules only on ELF files)
2. Safe default whitelist pre-population
3. File size limit (also from S5)

### Phase 6: Efficiency improvements
1. YARA rule compilation caching (E1)
2. Batch YARA scanning (E3)
3. Fix duplicate scan path logic (E5)

---

## SUMMARY TABLE

| ID | Severity | File | Issue |
|----|----------|------|-------|
| S1 | HIGH | quarantine.py:187-216 | _secure_delete memory allocation (OOM on large files) |
| S2 | HIGH | quarantine.py:60-104 | TOCTOU race in quarantine_file |
| S3 | HIGH | scanner.py:548-593 | clamscan colon parsing |
| S4 | MEDIUM | multiple | Silent exception swallowing |
| S5 | MEDIUM | scanner.py:595-617 | No file size limit (OOM risk) |
| S6 | LOW-MED | ui_tabs.py:2002 | xdg-open (safe in current use) |
| S7 | LOW | history_db.py | DB connection leak on error |
| S8 | LOW | main.py:187 | Autostart file 0o755 |
| S9 | LOW | main.py:2 | Version header mismatch |
| E1 | HIGH | scanner.py:643-700 | No YARA compilation caching |
| E2 | MEDIUM | scanner.py:456-474 | Double filesystem walk |
| E3 | MEDIUM | scanner.py:727-760 | Per-file subprocess for YARA |
| E4 | MEDIUM | scanner.py:763-776 | ThreadPool cancel issue |
| E5 | LOW | ui_tabs.py | Duplicate scan logic |
| E6 | LOW | main.py:913-939 | First-run UX timing |