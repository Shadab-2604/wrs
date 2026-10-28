"""Unit tests for report generation and post-acquisition verifier (src/wrs/reporting.py)."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from wrs.categorizer import CAT_DATABASES, CAT_IMAGES
from wrs.device import DeviceInfo
from wrs.hashing import (
    STATUS_VERIFIED,
    VerificationRecord,
    hash_local_file,
)
from wrs.reporting import ReportGenerator, verify_recovery_directory
from wrs.scanner import ScannedFile, ScanResult


class TestReportingModule(unittest.TestCase):
    """Test HTML escaping, CSV/JSON consistency, and standalone verification."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="wrs_test_rep_")
        self.report_dir = Path(self.temp_dir) / "reports"
        self.report_dir.mkdir()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_html_escaping_and_report_generation(self):
        """Verify that filenames and metadata with HTML injection payloads are strictly escaped."""
        evil_filename = "<script>alert('xss')</script>&msgstore.db.crypt14"
        evil_serial = "DEV'\"<evil>"

        dev = DeviceInfo(serial=evil_serial, state="device", manufacturer="Evil<Corp>", model="Phone'\"")
        sfile = ScannedFile(
            original_path=f"/sdcard/WhatsApp/Databases/{evil_filename}",
            relative_path=f"Databases/{evil_filename}",
            filename=evil_filename,
            extension=".crypt14",
            category=CAT_DATABASES,
            size_bytes=1024,
            size_human="1.00 KiB",
        )
        scan_res = ScanResult(
            device_serial=evil_serial,
            location_path="/sdcard/WhatsApp",
            start_time="2026-10-28 10:00:00",
            end_time="2026-10-28 10:00:05",
            files=[sfile],
            total_files=1,
            total_bytes=1024,
        )

        gen = ReportGenerator(dev, scan_res, output_dir=self.report_dir)
        html_p, csv_p, json_p = gen.generate_all()

        self.assertTrue(html_p.exists())
        self.assertTrue(csv_p.exists())
        self.assertTrue(json_p.exists())

        html_text = html_p.read_text(encoding="utf-8")
        self.assertNotIn("<script>alert", html_text)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;&amp;msgstore.db.crypt14", html_text)
        self.assertIn("Evil&lt;Corp&gt;", html_text)

        # JSON validation
        json_data = json.loads(json_p.read_text(encoding="utf-8"))
        self.assertEqual(json_data["device"]["serial"], evil_serial)
        self.assertEqual(json_data["files"][0]["filename"], evil_filename)

    def test_standalone_recovery_verification(self):
        """Verify standalone integrity auditor detects intact, altered, and missing files."""
        recovery_root = Path(self.temp_dir) / "recovery_audit"
        meta_dir = recovery_root / "metadata"
        img_dir = recovery_root / "Images"
        meta_dir.mkdir(parents=True)
        img_dir.mkdir(parents=True)

        # Create two local files
        file1 = img_dir / "intact.jpg"
        file1.write_bytes(b"intact content 12345")
        h1, sz1, _ = hash_local_file(file1)

        file2 = img_dir / "tampered.jpg"
        file2.write_bytes(b"original content")
        h2, sz2, _ = hash_local_file(file2)

        file3_missing = img_dir / "missing.jpg"

        manifest = [
            {
                "source_path": "/sdcard/WhatsApp/intact.jpg",
                "destination_path": str(file1),
                "expected_size": sz1,
                "acquired_size": sz1,
                "source_sha256": h1,
                "destination_sha256": h1,
                "status": STATUS_VERIFIED,
                "timestamp": "2026-10-28 10:00:00",
            },
            {
                "source_path": "/sdcard/WhatsApp/tampered.jpg",
                "destination_path": str(file2),
                "expected_size": sz2,
                "acquired_size": sz2,
                "source_sha256": h2,
                "destination_sha256": h2,
                "status": STATUS_VERIFIED,
                "timestamp": "2026-10-28 10:00:00",
            },
            {
                "source_path": "/sdcard/WhatsApp/missing.jpg",
                "destination_path": str(file3_missing),
                "expected_size": 100,
                "acquired_size": 100,
                "source_sha256": "fake",
                "destination_sha256": "fake",
                "status": STATUS_VERIFIED,
                "timestamp": "2026-10-28 10:00:00",
            },
        ]
        with open(meta_dir / "acquisition_manifest.json", "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        # Alter file2 after manifest creation
        file2.write_bytes(b"tampered content modified!")

        audit = verify_recovery_directory(recovery_root)

        self.assertTrue(audit["success"])
        self.assertEqual(audit["total"], 3)
        self.assertEqual(audit["verified_count"], 1)  # Only file1
        self.assertEqual(audit["mismatch_count"], 1)  # file2 tampered
        self.assertEqual(audit["missing_count"], 1)   # file3 missing
        self.assertFalse(audit["is_fully_intact"])


if __name__ == "__main__":
    unittest.main()
