"""Unit tests for SHA-256 calculation and integrity evaluation (src/wrs/hashing.py)."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from wrs.hashing import (
    STATUS_FAILED,
    STATUS_HASH_MISMATCH,
    STATUS_SIZE_MISMATCH,
    STATUS_SOURCE_HASH_UNAVAILABLE,
    STATUS_VERIFIED,
    evaluate_acquisition_integrity,
    hash_local_file,
)


class TestHashingModule(unittest.TestCase):
    """Test local hashing, remote comparison, and status assignment."""

    def test_local_file_hashing_streaming(self):
        """Verify streaming SHA-256 calculation on synthetic file."""
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            content = b"WRS forensic integrity test data " * 1024  # ~32KB
            f.write(content)
            temp_path = Path(f.name)

        try:
            expected_hash = hashlib.sha256(content).hexdigest()
            calc_hash, sz, err = hash_local_file(temp_path, chunk_size=4096)

            self.assertIsNone(err)
            self.assertEqual(calc_hash, expected_hash)
            self.assertEqual(sz, len(content))
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_integrity_evaluation_verified(self):
        """When both source and destination hashes match, status must be VERIFIED."""
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"content")
            p = Path(f.name)

        try:
            h = hashlib.sha256(b"content").hexdigest()
            rec = evaluate_acquisition_integrity(
                source_path="/sdcard/WhatsApp/sample.jpg",
                dest_path=p,
                expected_size=7,
                source_hash=h,
                dest_hash=h,
                acquired_size=7,
            )
            self.assertEqual(rec.status, STATUS_VERIFIED)
            self.assertIsNone(rec.error_message)
        finally:
            if p.exists():
                p.unlink()

    def test_integrity_evaluation_source_unavailable(self):
        """When source hash could not be obtained on device, status must be SOURCE_HASH_UNAVAILABLE."""
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"content")
            p = Path(f.name)

        try:
            h = hashlib.sha256(b"content").hexdigest()
            rec = evaluate_acquisition_integrity(
                source_path="/sdcard/WhatsApp/sample.jpg",
                dest_path=p,
                expected_size=7,
                source_hash=None,  # Not available on device
                dest_hash=h,
                acquired_size=7,
            )
            self.assertEqual(rec.status, STATUS_SOURCE_HASH_UNAVAILABLE)
            self.assertIn("unavailable", rec.error_message.lower())
        finally:
            if p.exists():
                p.unlink()

    def test_integrity_evaluation_mismatch(self):
        """Hash mismatch and size mismatch tests."""
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"content")
            p = Path(f.name)

        try:
            # 1. Size mismatch
            rec_sz = evaluate_acquisition_integrity(
                source_path="/sdcard/WhatsApp/sample.jpg",
                dest_path=p,
                expected_size=100,  # mismatch
                source_hash="abcd",
                dest_hash="abcd",
                acquired_size=7,
            )
            self.assertEqual(rec_sz.status, STATUS_SIZE_MISMATCH)

            # 2. Hash mismatch
            rec_hm = evaluate_acquisition_integrity(
                source_path="/sdcard/WhatsApp/sample.jpg",
                dest_path=p,
                expected_size=7,
                source_hash="1111111111111111111111111111111111111111111111111111111111111111",
                dest_hash="2222222222222222222222222222222222222222222222222222222222222222",
                acquired_size=7,
            )
            self.assertEqual(rec_hm.status, STATUS_HASH_MISMATCH)
        finally:
            if p.exists():
                p.unlink()


if __name__ == "__main__":
    unittest.main()
