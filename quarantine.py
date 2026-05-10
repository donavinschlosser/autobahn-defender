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
        os.chmod(str(QUARANTINE_DIR), 0o700)
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
        """Move a file to the quarantine directory."""
        filepath = Path(filepath)
        if not filepath.exists():
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
                "size": filepath.stat().st_size,
            }
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
        for prefix in allowed_prefixes:
            try:
                resolved.relative_to(prefix)
                return True
            except ValueError:
                continue
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
        """Overwrite file contents before deletion."""
        try:
            size = filepath.stat().st_size
            with open(filepath, "wb") as f:
                f.write(b"\x00" * size)
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