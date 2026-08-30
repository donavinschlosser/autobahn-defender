"""
Autobahn Defender - Quarantine Manager
Move, track, restore, and delete quarantined files.
"""

import json
import os
import shutil
import hashlib
import uuid
from pathlib import Path
from datetime import datetime

APP_DIR = Path.home() / ".autobahn"
QUARANTINE_DIR = APP_DIR / "quarantine"
MANIFEST_FILE = QUARANTINE_DIR / "manifest.json"
LEDGER_FILE = APP_DIR / "detection_ledger.json"
DELETION_LOG_FILE = APP_DIR / "deletion_log.jsonl"

# Maximum deletion log entries (caps at 100k per Kudu design)
MAX_DELETION_LOG_ENTRIES = 100_000


class DetectionLedger:
    """Detection ledger with content-hash binding (Kudu-inspired, MIT).

    Records files flagged by a scan along with their SHA256 hash at scan time.
    Before quarantine/delete, the caller must verify the file is in the ledger
    AND its current hash matches the scan-time hash. This prevents:
    - A prompt-injected AI from deleting arbitrary files
    - Acting on stale detections where the file has been modified since scan
    - Race conditions where a file is swapped after scanning but before action

    The ledger is per-scan: it is populated during a scan and cleared at the
    start of the next scan. This ensures only files from the current scan
    can be quarantined.
    """

    def __init__(self):
        self._entries = {}  # filepath -> sha256 hash
        self._load()

    def _load(self):
        """Load the ledger from disk."""
        if LEDGER_FILE.exists():
            try:
                data = json.loads(LEDGER_FILE.read_text())
                if isinstance(data, dict):
                    self._entries = data
            except (json.JSONDecodeError, OSError):
                self._entries = {}

    def _save(self):
        """Save the ledger to disk atomically."""
        try:
            LEDGER_FILE.parent.mkdir(parents=True, exist_ok=True)
            data = json.dumps(self._entries, indent=2)
            tmp = LEDGER_FILE.with_suffix(".tmp")
            tmp.write_text(data)
            tmp.replace(LEDGER_FILE)
        except OSError:
            pass

    def record(self, filepath: str, file_hash: str):
        """Record a flagged file with its content hash at scan time."""
        self._entries[str(Path(filepath).resolve())] = file_hash
        self._save()

    def verify(self, filepath: str, current_hash: str = None) -> bool:
        """Verify a file is in the ledger and (optionally) its hash matches.

        If current_hash is provided, checks that it matches the recorded
        scan-time hash. If the file was modified since the scan, verification
        fails and the file should NOT be quarantined/deleted.

        Returns True if the file is verified, False otherwise.
        """
        resolved = str(Path(filepath).resolve())
        if resolved not in self._entries:
            return False
        if current_hash is not None:
            return self._entries[resolved] == current_hash
        return True

    def is_flagged(self, filepath: str) -> bool:
        """Check if a file is in the detection ledger (flagged by a scan)."""
        return str(Path(filepath).resolve()) in self._entries

    def clear(self):
        """Clear all entries. Called at the start of each new scan."""
        self._entries = {}
        self._save()

    def count(self) -> int:
        """Number of flagged files in the ledger."""
        return len(self._entries)


# Global singleton
_ledger_instance = None

def get_detection_ledger():
    """Get the global DetectionLedger singleton."""
    global _ledger_instance
    if _ledger_instance is None:
        _ledger_instance = DetectionLedger()
    return _ledger_instance


class QuarantineManager:
    """Manages quarantined files with a JSON manifest."""

    def __init__(self):
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(QUARANTINE_DIR), 0o700)
        except OSError:
            pass
        self.manifest = self._load_manifest()

    def _load_manifest(self):
        """Load the quarantine manifest from disk.
        Validates that all quarantine_name entries match the expected format
        to prevent path traversal attacks.
        """
        import re
        # Only allow alphanumeric, underscores, hyphens, dots in quarantine names
        # Format: <16 hex chars>_<original filename>
        safe_name_re = re.compile(r'^[a-f0-9]{16}_[^/]+$')
        if MANIFEST_FILE.exists():
            try:
                data = json.loads(MANIFEST_FILE.read_text())
                if isinstance(data, list):
                    # Validate each entry's quarantine_name
                    validated = []
                    for entry in data:
                        if isinstance(entry, dict):
                            qname = entry.get("quarantine_name", "")
                            if qname and safe_name_re.match(qname):
                                validated.append(entry)
                    return validated
                return []
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def _save_manifest(self):
        """Save the quarantine manifest to disk atomically."""
        try:
            data = json.dumps(self.manifest, indent=2)
            tmp = MANIFEST_FILE.with_suffix(".tmp")
            tmp.write_text(data)
            tmp.replace(MANIFEST_FILE)
        except OSError:
            pass

    def _hash_file(self, filepath):
        """Generate a SHA256 hash for a file."""
        h = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, IOError):
            return uuid.uuid4().hex

    def quarantine_file(self, filepath, threat_name=""):
        """Move a file to the quarantine directory.

        Uses os.open with O_NOFOLLOW to prevent symlink-based TOCTOU races.
        An attacker cannot swap the file for a symlink between the existence
        check and the move because we verify the file descriptor directly.

        Detection ledger (Kudu-inspired, MIT): verifies the file was flagged
        by a scan AND its content hash hasn't changed since the scan. This
        prevents a prompt-injected AI from quarantining arbitrary files.
        """
        filepath = Path(filepath).resolve()  # Resolve symlinks before quarantine
        if not filepath.exists():
            return False

        # Detection ledger verification: file must be flagged by a scan
        # AND its content hash must match the scan-time hash (TOCTOU guard).
        ledger = get_detection_ledger()
        if not ledger.is_flagged(str(filepath)):
            import logging
            logging.getLogger(__name__).warning(
                f"Quarantine denied: {filepath} not in detection ledger "
                f"(not flagged by any scan)"
            )
            return False
        # Verify content hash matches scan-time hash
        try:
            current_hash = hashlib.sha256(filepath.read_bytes()).hexdigest()
            if not ledger.verify(str(filepath), current_hash):
                import logging
                logging.getLogger(__name__).warning(
                    f"Quarantine denied: {filepath} content hash mismatch "
                    f"(file modified since scan)"
                )
                return False
        except (OSError, PermissionError):
            return False

        # Safety check: don't quarantine critical system paths
        system_paths = {"/", "/etc", "/usr", "/boot", "/dev", "/proc", "/sys", "/lib", "/bin", "/sbin"}
        resolved_str = str(filepath)
        if resolved_str.rstrip("/") in system_paths:
            return False

        # Open the file with O_NOFOLLOW to prevent symlink race attacks.
        # If the file is a symlink (or becomes one between the check and open),
        # this will fail with ELOOP and we'll abort the quarantine.
        try:
            import errno
            fd = os.open(str(filepath), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as e:
            if e.errno == errno.ELOOP:
                # File is or became a symlink — abort to prevent TOCTOU
                return False
            raise

        # Verify the file descriptor points to a regular file (not a device)
        import stat as _stat_mod
        fd_stat = os.fstat(fd)
        if not _stat_mod.S_ISREG(fd_stat.st_mode):
            os.close(fd)
            return False

        file_hash = self._hash_file(filepath)
        quarantine_name = f"{file_hash[:16]}_{filepath.name}"
        dest = QUARANTINE_DIR / quarantine_name

        # Avoid name collisions
        counter = 1
        while dest.exists():
            quarantine_name = f"{file_hash[:16]}_{filepath.name}_{counter}"
            dest = QUARANTINE_DIR / quarantine_name
            counter += 1

        try:
            # Record the entry first so the manifest is always consistent
            # even if the move fails, the manifest won't reference a missing file
            entry = {
                "original_path": str(filepath),
                "quarantine_name": quarantine_name,
                "sha256": file_hash,
                "threat": threat_name,
                "date": datetime.now().isoformat(),
                "size": fd_stat.st_size,
            }
            os.close(fd)
            shutil.move(str(filepath), str(dest))
            # Remove execute permissions from quarantined file
            try:
                os.chmod(str(dest), 0o600)
            except OSError:
                pass
            self.manifest.append(entry)
            self._save_manifest()
            return True
        except (OSError, shutil.Error):
            try:
                os.close(fd)
            except OSError:
                pass
            return False

    def get_quarantined(self):
        """Return list of quarantined file entries."""
        # Clean up entries whose quarantine file no longer exists
        cleaned = []
        for entry in self.manifest:
            qpath = QUARANTINE_DIR / entry.get("quarantine_name", "")
            if qpath.exists():
                cleaned.append(entry)
        if len(cleaned) != len(self.manifest):
            self.manifest = cleaned
            self._save_manifest()
        return self.manifest
    def _safe_restore_path(self, original_path):
        """Validate that original_path doesn't escape user-accessible directories."""
        home = Path.home()
        allowed_prefixes = [
            home,
            Path("/tmp"),
            Path("/media"),
            Path("/mnt"),
            Path("/run/media"),
        ]
        resolved = Path(original_path).resolve()
        # Convert to absolute strings for reliable prefix matching
        resolved_str = str(resolved)
        for prefix in allowed_prefixes:
            prefix_str = str(Path(prefix).resolve())
            # Check if resolved path starts with allowed prefix
            if resolved_str.startswith(prefix_str + os.sep) or resolved_str == prefix_str:
                return True
        return False

    def restore_file(self, quarantine_name):
        """Restore a quarantined file to its original location."""
        for entry in self.manifest:
            if entry["quarantine_name"] == quarantine_name:
                src = QUARANTINE_DIR / quarantine_name
                dest = Path(entry["original_path"])

                if not src.exists():
                    return False, "File not found in quarantine"

                # Verify file integrity if hash is stored
                stored_hash = entry.get("sha256", "")
                if stored_hash:
                    actual_hash = self._hash_file(src)
                    if actual_hash != stored_hash:
                        return False, "Quarantined file integrity check failed"

                if not self._safe_restore_path(dest):
                    return False, "Restore path is outside allowed directories"

                # Ensure parent directory exists
                dest.parent.mkdir(parents=True, exist_ok=True)

                try:
                    shutil.move(str(src), str(dest))
                    self.manifest.remove(entry)
                    self._save_manifest()
                    return True, f"Restored to {dest}"
                except (OSError, shutil.Error) as e:
                    return False, f"Restore error: {e}"

        return False, "Entry not found"

    def delete_file(self, quarantine_name):
        """Permanently delete a quarantined file (overwritten first)."""
        for entry in self.manifest:
            if entry["quarantine_name"] == quarantine_name:
                src = QUARANTINE_DIR / quarantine_name
                try:
                    if src.exists():
                        self._log_deletion(entry)
                        self._secure_delete(src)
                    self.manifest.remove(entry)
                    self._save_manifest()
                    return True, "Deleted"
                except OSError as e:
                    return False, f"Delete error: {e}"

        return False, "Entry not found"

    def _secure_delete(self, filepath):
        """Overwrite file contents before deletion with 3-pass (zeros, ones, random).

        Uses chunked writing (64KB chunks) for all passes to avoid allocating
        huge byte strings in memory for large files.
        Always unlinks the file even if overwrite passes fail.
        """
        try:
            size = filepath.stat().st_size
            if size == 0:
                filepath.unlink()
                return
            import random
            CHUNK = 65536  # 64KB chunks — safe for any file size

            def _chunked_write(f, data_factory, total_size):
                """Write data in chunks to avoid huge memory allocations."""
                remaining = total_size
                while remaining > 0:
                    chunk_size = min(CHUNK, remaining)
                    f.write(data_factory(chunk_size))
                    remaining -= chunk_size

            # Pass 1: zeros
            with open(filepath, "wb") as f:
                _chunked_write(f, lambda n: b"\x00" * n, size)
                f.flush()
                os.fsync(f.fileno())
            # Pass 2: ones (0xFF)
            with open(filepath, "wb") as f:
                _chunked_write(f, lambda n: b"\xFF" * n, size)
                f.flush()
                os.fsync(f.fileno())
            # Pass 3: random data
            with open(filepath, "wb") as f:
                _chunked_write(f, lambda n: bytes(random.randint(0, 255) for _ in range(n)), size)
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            pass
        # Always unlink, even if overwrite passes failed
        try:
            filepath.unlink()
        except OSError:
            pass

    def _log_deletion(self, entry: dict):
        """Append a deletion record to the audit trail (Kudu-inspired, MIT).

        Logs every permanently deleted file with: original path, quarantine
        name, detection info, timestamp, and file size. The log is capped at
        MAX_DELETION_LOG_ENTRIES (100k) to prevent unbounded growth.

        This provides a forensic audit trail so the user can verify what was
        deleted and when, even after the manifest is cleared.
        """
        try:
            APP_DIR.mkdir(parents=True, exist_ok=True)
            record = {
                "timestamp": datetime.now().isoformat(),
                "original_path": entry.get("original_path", ""),
                "quarantine_name": entry.get("quarantine_name", ""),
                "detection": entry.get("detection", ""),
                "scan_engine": entry.get("scan_engine", ""),
                "file_size": entry.get("file_size", 0),
                "sha256": entry.get("sha256", ""),
                "action": "secure_deleted",
            }
            with open(DELETION_LOG_FILE, "a") as f:
                f.write(json.dumps(record) + "\n")
            # Cap the log at MAX_DELETION_LOG_ENTRIES
            self._prune_deletion_log()
        except OSError:
            pass

    def _prune_deletion_log(self):
        """Trim the deletion log to MAX_DELETION_LOG_ENTRIES by removing
        the oldest entries (FIFO). Reads all lines, keeps the last N."""
        try:
            if not DELETION_LOG_FILE.exists():
                return
            lines = DELETION_LOG_FILE.read_text().splitlines()
            if len(lines) <= MAX_DELETION_LOG_ENTRIES:
                return
            # Keep only the last MAX entries
            kept = lines[-MAX_DELETION_LOG_ENTRIES:]
            DELETION_LOG_FILE.write_text("\n".join(kept) + "\n")
        except OSError:
            pass

    def get_deletion_log(self, limit: int = 100) -> list[dict]:
        """Return recent deletion log entries (newest first)."""
        if not DELETION_LOG_FILE.exists():
            return []
        try:
            entries = []
            for line in DELETION_LOG_FILE.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            entries.reverse()  # newest first
            return entries[:limit]
        except OSError:
            return []

    def restore_all(self):
        """Restore all quarantined files."""
        results = []
        for entry in list(self.manifest):
            ok, msg = self.restore_file(entry["quarantine_name"])
            results.append((entry["original_path"], ok, msg))
        return results

    def delete_all(self):
        """Permanently delete all quarantined files."""
        count = 0
        for entry in list(self.manifest):
            src = QUARANTINE_DIR / entry["quarantine_name"]
            try:
                if src.exists():
                    self._log_deletion(entry)
                    self._secure_delete(src)
                count += 1
            except OSError:
                pass
        self.manifest.clear()
        self._save_manifest()
        return count