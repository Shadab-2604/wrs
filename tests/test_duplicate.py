"""Unit tests for staged duplicate content detection (src/wrs/duplicate.py)."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from wrs.duplicate import DuplicateDetector
from wrs.scanner import ScannedFile


class TestDuplicateDetector(unittest.TestCase):
    """Test size-bucketed SHA-256 duplicate detection and acquisition filtering."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_p = Path(self.temp_dir.name)

        # Create files on disk:
        # 1. file_a and file_b have identical content (20 bytes) -> DUPLICATE
        # 2. file_c has different content but same size (20 bytes) -> NOT DUPLICATE
        # 3. file_d has different size (30 bytes) -> NOT DUPLICATE
        content_dup = b"IDENTICAL_CONTENT_AB"
        content_diff = b"DIFFERENT_CONTENT_XX"
        content_d = b"LONGER_CONTENT_FOR_FILE_D_TEST"

        self.path_a = self.base_p / "file_a.jpg"
        self.path_b = self.base_p / "file_b.jpg"
        self.path_c = self.base_p / "file_c.jpg"
        self.path_d = self.base_p / "file_d.jpg"

        self.path_a.write_bytes(content_dup)
        self.path_b.write_bytes(content_dup)
        self.path_c.write_bytes(content_diff)
        self.path_d.write_bytes(content_d)

        self.hash_dup = hashlib.sha256(content_dup).hexdigest()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_staged_duplicate_detection_from_local_files(self):
        """Verify staged duplicate detection filters by size, then checks hash."""
        all_paths = [self.path_a, self.path_b, self.path_c, self.path_d]
        groups = DuplicateDetector.identify_duplicates_from_local_files(all_paths)

        # Exactly 1 duplicate group should be found (for file_a and file_b)
        self.assertEqual(len(groups), 1)
        expected_gid = f"dup_{self.hash_dup[:12]}"
        self.assertIn(expected_gid, groups)

        group = groups[expected_gid]
        self.assertEqual(group.primary_path, str(self.path_a))
        self.assertEqual(group.duplicate_paths, [str(self.path_b)])
        self.assertEqual(group.size_bytes, 20)
        self.assertEqual(group.wasted_bytes, 20)

    def test_filter_records_for_deduplicated_acquisition(self):
        """Verify duplicate candidates can be cleanly excluded while keeping the primary copy."""
        records = [
            ScannedFile(original_path=str(self.path_a), relative_path="file_a.jpg", filename="file_a.jpg", extension=".jpg", category="Images", size_bytes=20, size_human="20 B"),
            ScannedFile(original_path=str(self.path_b), relative_path="file_b.jpg", filename="file_b.jpg", extension=".jpg", category="Images", size_bytes=20, size_human="20 B"),
            ScannedFile(original_path=str(self.path_c), relative_path="file_c.jpg", filename="file_c.jpg", extension=".jpg", category="Images", size_bytes=20, size_human="20 B"),
        ]

        # Use helper hash func for records
        def get_hash(p: str) -> str:
            return hashlib.sha256(Path(p).read_bytes()).hexdigest()

        groups = DuplicateDetector.identify_duplicates_from_records(records, get_hash_func=get_hash)
        self.assertEqual(len(groups), 1)

        eligible, excluded = DuplicateDetector.filter_for_deduplicated_acquisition(records, groups)

        # Primary file_a and unique file_c remain; file_b is excluded
        self.assertEqual(len(eligible), 2)
        self.assertEqual(len(excluded), 1)

        kept_paths = [r.original_path for r in eligible]
        self.assertIn(str(self.path_a), kept_paths)
        self.assertIn(str(self.path_c), kept_paths)
        self.assertEqual(excluded[0].original_path, str(self.path_b))


if __name__ == "__main__":
    unittest.main()
