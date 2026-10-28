"""Unit tests for validation, security, and SQLite read-only inspection (src/wrs/validation.py)."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from wrs.utils import get_safe_destination_path, is_safe_path
from wrs.validation import ForensicValidator


class TestValidationModule(unittest.TestCase):
    """Test read-only SQLite inspection, crypt format assessment, and path traversal security."""

    def test_sqlite_readonly_inspection(self):
        """Verify non-destructive read-only inspection of valid SQLite database."""
        with tempfile.NamedTemporaryFile("wb", suffix=".db", delete=False) as f:
            db_path = Path(f.name)

        try:
            # Create a sample database
            conn = sqlite3.connect(str(db_path))
            cur = conn.cursor()
            cur.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, sender TEXT, body TEXT);")
            cur.execute("INSERT INTO messages (sender, body) VALUES ('alice', 'test message');")
            conn.commit()
            conn.close()

            # Inspect via ForensicValidator
            res = ForensicValidator.inspect_sqlite_readonly(db_path)
            self.assertTrue(res.is_sqlite)
            self.assertTrue(res.integrity_ok)
            self.assertIn("messages", res.tables)
            self.assertEqual(res.table_count, 1)
        finally:
            if db_path.exists():
                db_path.unlink()

    def test_non_sqlite_rejection(self):
        """Verify rejection of non-SQLite file."""
        with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as f:
            f.write(b"Not an SQLite database format")
            p = Path(f.name)

        try:
            res = ForensicValidator.inspect_sqlite_readonly(p)
            self.assertFalse(res.is_sqlite)
            self.assertFalse(res.integrity_ok)
        finally:
            if p.exists():
                p.unlink()

    def test_encrypted_database_assessment(self):
        """Verify candidate assessment without false decryption claims."""
        cand = ForensicValidator.assess_encrypted_database(
            filepath="/sdcard/WhatsApp/Databases/msgstore.db.crypt14",
            filename="msgstore.db.crypt14",
            size_bytes=1048576,
            header_sample=b"\x00\x01\x02\x03CRYPT14_HEADER_DATA",
        )
        self.assertEqual(cand.crypt_version, "crypt14")
        self.assertFalse(cand.is_dated_backup)
        self.assertIn("AES-GCM", cand.assessment)
        self.assertIn("inaccessible via standard unrooted ADB", cand.assessment)
        self.assertIn("No decryption or modification attempted", cand.assessment)

    def test_path_traversal_prevention(self):
        """Verify strict prevention of directory traversal attacks."""
        base_dir = Path("/tmp/wrs_test_base").resolve()

        # 1. Normal safe path
        safe = get_safe_destination_path(base_dir, "Images/photo.jpg")
        self.assertTrue(is_safe_path(base_dir, safe))

        # 2. Dangerous path traversal attempt
        with self.assertRaises(ValueError):
            # If an attempt tries to escape with ..
            # get_safe_destination_path sanitizes individual components or blocks escaping
            get_safe_destination_path(base_dir, "../../../etc/passwd")


if __name__ == "__main__":
    unittest.main()
