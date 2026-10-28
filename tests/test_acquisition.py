"""Unit tests for acquisition engine and directory management (src/wrs/acquisition.py)."""

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from wrs.acquisition import AcquisitionManager
from wrs.categorizer import CAT_BACKUPS, CAT_DATABASES, CAT_IMAGES, CAT_VOICE_NOTES
from wrs.device import AdbExecutor, DeviceInfo
from wrs.hashing import STATUS_VERIFIED
from wrs.scanner import ScannedFile, ScanResult


class TestAcquisitionModule(unittest.TestCase):
    """Test preview generation, recovery directory structure, and safe copying."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="wrs_test_acq_")
        self.recovery_root = Path(self.temp_dir) / "recovery"
        self.recovery_root.mkdir()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_preview_calculation(self):
        """Verify pre-acquisition preview numbers match synthetic scan inventory."""
        files = [
            ScannedFile("/sdcard/WhatsApp/Databases/msgstore.db.crypt14", "Databases/msgstore.db.crypt14", "msgstore.db.crypt14", ".crypt14", CAT_DATABASES, 1048576, "1.00 MiB"),
            ScannedFile("/sdcard/WhatsApp/Databases/msgstore-2026-10-25.1.db.crypt14", "Databases/msgstore-2026-10-25.1.db.crypt14", "msgstore-2026-10-25.1.db.crypt14", ".crypt14", CAT_BACKUPS, 524288, "512.00 KiB"),
            ScannedFile("/sdcard/WhatsApp/Media/WhatsApp Images/photo.jpg", "Media/WhatsApp Images/photo.jpg", "photo.jpg", ".jpg", CAT_IMAGES, 2097152, "2.00 MiB"),
        ]
        scan_res = ScanResult(
            device_serial="test_serial",
            location_path="/sdcard/WhatsApp",
            start_time="2026-10-28 10:00:00",
            end_time="2026-10-28 10:01:00",
            files=files,
            total_files=3,
            total_bytes=1048576 + 524288 + 2097152,
        )

        dev = DeviceInfo(serial="test_serial", state="device", manufacturer="Samsung", model="Galaxy S23")
        executor = AdbExecutor(adb_path="/usr/bin/adb")
        mgr = AcquisitionManager(executor, base_recovery_dir=self.recovery_root)

        preview = mgr.generate_preview(dev, scan_res)

        self.assertEqual(preview.total_files, 3)
        self.assertEqual(preview.total_bytes, 3670016)
        self.assertEqual(preview.category_counts[CAT_DATABASES], 1)
        self.assertEqual(preview.category_counts[CAT_BACKUPS], 1)
        self.assertEqual(preview.category_counts[CAT_IMAGES], 1)
        self.assertEqual(preview.database_backup_candidates, 2)
        self.assertTrue(preview.has_sufficient_space)

    def test_directory_tree_creation(self):
        """Verify standard recovery folder layout is created cleanly."""
        executor = AdbExecutor(adb_path="/usr/bin/adb")
        mgr = AcquisitionManager(executor, base_recovery_dir=self.recovery_root)
        dest_scan = self.recovery_root / "Pixel_7_scan_2026-10-28_10-00-00"

        tree = mgr.setup_recovery_tree(dest_scan)

        self.assertTrue((dest_scan / "metadata").is_dir())
        self.assertTrue((dest_scan / "reports").is_dir())
        self.assertTrue((dest_scan / "Databases").is_dir())
        self.assertTrue((dest_scan / "Backups").is_dir())
        self.assertTrue((dest_scan / "Voice_Notes").is_dir())
        self.assertTrue((dest_scan / "Images").is_dir())
        self.assertTrue((dest_scan / "Stickers").is_dir())

    def test_acquisition_with_mock_adb_and_resume(self):
        """Verify copying files over mocked ADB, hashing, and resuming without re-copying."""
        synthetic_content = b"Mock WhatsApp encrypted database content"
        content_hash = hashlib.sha256(synthetic_content).hexdigest()

        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            # adb pull remote local
            if "pull" in cmd_str:
                local_dest = Path(cmd[-1])
                local_dest.parent.mkdir(parents=True, exist_ok=True)
                with open(local_dest, "wb") as f:
                    f.write(synthetic_content)
                return subprocess.CompletedProcess(cmd, 0, "", "")
            # sha256sum remote
            if "sha256sum" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, f"{content_hash}  /sdcard/WhatsApp/Databases/msgstore.db.crypt14\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        mgr = AcquisitionManager(executor, base_recovery_dir=self.recovery_root)
        dev = DeviceInfo(serial="DEV_123", state="device", model="Realme GT")

        dest_scan = self.recovery_root / "Realme_GT_scan_2026-10-28_10-00-00"
        sfile = ScannedFile(
            original_path="/sdcard/WhatsApp/Databases/msgstore.db.crypt14",
            relative_path="Databases/msgstore.db.crypt14",
            filename="msgstore.db.crypt14",
            extension=".crypt14",
            category=CAT_DATABASES,
            size_bytes=len(synthetic_content),
            size_human="40 B",
        )
        scan_res = ScanResult(
            device_serial="DEV_123",
            location_path="/sdcard/WhatsApp",
            start_time="2026-10-28 10:00:00",
            end_time="2026-10-28 10:00:05",
            files=[sfile],
            total_files=1,
            total_bytes=len(synthetic_content),
        )

        # 1. Initial Acquisition
        records = mgr.acquire_files(dev, scan_res, destination_dir=dest_scan)
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec.status, STATUS_VERIFIED)
        self.assertEqual(rec.destination_sha256, content_hash)
        self.assertEqual(rec.source_sha256, content_hash)

        # Check metadata written
        manifest_p = dest_scan / "metadata" / "acquisition_manifest.json"
        self.assertTrue(manifest_p.exists())

        # 2. Re-run (Resume) Test: should skip file without calling adb pull
        pull_called = [False]
        def resume_runner(cmd, **kwargs):
            if "pull" in " ".join(cmd):
                pull_called[0] = True
            return subprocess.CompletedProcess(cmd, 0, "", "")

        resume_executor = AdbExecutor(adb_path="/usr/bin/adb", runner=resume_runner)
        resume_mgr = AcquisitionManager(resume_executor, base_recovery_dir=self.recovery_root)

        resume_records = resume_mgr.acquire_files(dev, scan_res, destination_dir=dest_scan)
        self.assertEqual(len(resume_records), 1)
        self.assertFalse(pull_called[0], "Resume should have skipped already acquired & verified file!")


if __name__ == "__main__":
    unittest.main()
