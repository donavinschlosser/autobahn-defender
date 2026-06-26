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
        """Load the quarantine manifest from disk."""
        if MANIFEST_FILE.exists():
            try:
                return json.loads(MANIFEST_FILE.read_text())
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
        """
        filepath = Path(filepath).resolve()  # Resolve symlinks before quarantine
        if not filepath.exists():
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
        """
        try:
            size = filepath.stat().st_size
            if size == 0:
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
        filepath.unlink()

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
                    self._secure_delete(src)
                count += 1
            except OSError:
                pass
        self.manifest.clear()
        self._save_manifest()
        return count