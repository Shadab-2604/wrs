"""Unit tests for case management, audit logging, and scan comparison (src/wrs/case.py)."""

import json
import tempfile
import unittest
from pathlib import Path

from wrs.case import CaseManager, generate_scan_id, redact_sensitive_dict


class TestCaseManagement(unittest.TestCase):
    """Test CaseManager audit logging, sensitive data redaction, and case comparisons."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_p = Path(self.temp_dir.name)
        self.case_dir = self.base_p / "recovery_case"
        self.case_dir.mkdir(parents=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generate_scan_id(self):
        """Verify scan ID format."""
        sid = generate_scan_id("Pixel 7a")
        self.assertTrue(sid.startswith("scan_Pixel7a_"))
        self.assertNotIn(" ", sid)

    def test_sensitive_dictionary_redaction(self):
        """Verify tokens, keys, passwords, and secrets are redacted before logging."""
        raw_dict = {
            "device_model": "Pixel 7a",
            "password": "SuperSecretPassword123!",
            "auth_token": "bearer_abc_xyz",
            "encryption_key": "1234567890abcdef1234567890abcdef",
            "safe_count": 42,
        }
        redacted = redact_sensitive_dict(raw_dict)
        self.assertEqual(redacted["device_model"], "Pixel 7a")
        self.assertEqual(redacted["safe_count"], 42)
        self.assertEqual(redacted["password"], "[REDACTED]")
        self.assertEqual(redacted["auth_token"], "[REDACTED]")
        self.assertEqual(redacted["encryption_key"], "[REDACTED]")

    def test_append_only_case_event_logging(self):
        """Verify events are logged to append-only case_events.jsonl file."""
        cm = CaseManager(case_dir=self.case_dir)

        cm.log_event("SCAN_TEST_001", "DEVICE_CONNECTED", {"serial": "SERIAL_001", "model": "Pixel 7a"})
        cm.log_event("SCAN_TEST_001", "STORAGE_DISCOVERED", {"locations_found": 2})
        cm.log_event("SCAN_TEST_001", "ACQUISITION_CONFIRMED", {"operator": "analyst"})

        events_file = self.case_dir / "metadata" / "case_events.jsonl"
        self.assertTrue(events_file.exists())

        loaded = cm.load_events()
        self.assertEqual(len(loaded), 3)
        self.assertEqual(loaded[0].event_type, "DEVICE_CONNECTED")
        self.assertEqual(loaded[0].details["serial"], "SERIAL_001")
        self.assertEqual(loaded[1].event_type, "STORAGE_DISCOVERED")
        self.assertEqual(loaded[2].event_type, "ACQUISITION_CONFIRMED")

    def test_compare_cases(self):
        """Verify comparison between two recovery cases (common, unique, modified)."""
        case1_dir = self.base_p / "case1"
        case2_dir = self.base_p / "case2"
        (case1_dir / "metadata").mkdir(parents=True)
        (case2_dir / "metadata").mkdir(parents=True)

        manifest1 = [
            {"source_path": "img1.jpg", "destination_sha256": "hash_a"},
            {"source_path": "img2.jpg", "destination_sha256": "hash_b"},
            {"source_path": "shared.jpg", "destination_sha256": "hash_common"},
            {"source_path": "modified.jpg", "destination_sha256": "hash_old"},
        ]
        manifest2 = [
            {"source_path": "img3.jpg", "destination_sha256": "hash_c"},
            {"source_path": "shared.jpg", "destination_sha256": "hash_common"},
            {"source_path": "modified.jpg", "destination_sha256": "hash_new"},
        ]

        (case1_dir / "metadata" / "acquisition_manifest.json").write_text(json.dumps(manifest1))
        (case2_dir / "metadata" / "acquisition_manifest.json").write_text(json.dumps(manifest2))

        comparison = CaseManager.compare_cases(case1_dir, case2_dir)

        self.assertEqual(comparison["total_files_a"], 4)
        self.assertEqual(comparison["total_files_b"], 3)
        self.assertEqual(comparison["common_identical_count"], 1)  # shared.jpg
        self.assertEqual(comparison["modified_content_count"], 1)  # modified.jpg
        self.assertEqual(comparison["unique_to_case1_count"], 2)  # img1.jpg, img2.jpg
        self.assertEqual(comparison["unique_to_case2_count"], 1)  # img3.jpg


if __name__ == "__main__":
    unittest.main()
