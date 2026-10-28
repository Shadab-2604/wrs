"""Unit tests for CLI User Experience, Navigation, and Progress displays (Phase 3).

Validates screen headers, confirmation prompts, recovery folder naming,
plain-text progress fallback, dry-run mode, and persistent configuration management.
"""

import io
import shutil
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from wrs.acquisition import AcquisitionManager, AcquisitionPreview
from wrs.cli import (
    ask_acquisition_confirmation,
    display_preview,
    display_scan_completed_summary,
    make_acquisition_progress_callback,
    make_discovery_progress_callback,
    print_screen_header,
    run_interactive_workflow,
)
from wrs.device import AdbExecutor, DeviceInfo
from wrs.errors import (
    ERR_ADB_NOT_FOUND,
    ERR_DEVICE_DISCONNECTED,
    ERR_INSUFFICIENT_SPACE,
    ERR_NO_WHATSAPP_STORAGE,
    format_actionable_error,
)
from wrs.scanner import ScanResult
from wrs.utils import load_settings, save_settings, validate_settings


class TestCliUX(unittest.TestCase):
    """Test CLI user experience, persistent headers, progress, previews, and settings."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_screen_header_device_name_visibility(self):
        """Rule: Selected device's name must remain visible on all screens."""
        dev = DeviceInfo(serial="SERIAL_ABC", state="device", manufacturer="Google", model="Pixel 7")
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_screen_header("STORAGE DISCOVERY", dev)

        out = buf.getvalue()
        self.assertIn("WRS — STORAGE DISCOVERY", out)
        self.assertIn("Selected Device : Google Pixel 7 (SERIAL_ABC)", out)

    def test_screen_header_with_serial_masking(self):
        """Rule: When serial masking is enabled, masked serial appears in screen headers."""
        dev = DeviceInfo(serial="28241FDH2006G7", state="device", manufacturer="Vivo", model="V2302")
        settings = {"ui": {"mask_device_serial": True}}
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_screen_header("ACQUISITION PREVIEW", dev, settings)

        out = buf.getvalue()
        self.assertIn("Vivo V2302 (2824****06G7)", out)
        self.assertNotIn("28241FDH2006G7", out)

    def test_acquisition_confirmation_displays_device_and_totals(self):
        """Requirement 6: Confirmation must show device name, file count, total size, and default No."""
        preview = AcquisitionPreview(
            scan_id="scan_test_01",
            device_name="Vivo V2302",
            serial="28241FDH2006G7",
            android_version="14",
            scan_date="2026-10-28 10:00:00",
            selected_locations=["/sdcard/WhatsApp/"],
            total_files=42,
            total_bytes=10485760,  # 10 MiB
            category_counts={"Databases": 2, "Images": 40},
            category_bytes={"Databases": 4194304, "Images": 6291456},
            unreadable_files=0,
            skipped_files=0,
            database_backup_candidates=2,
            destination_path=self.temp_dir / "recovery_01",
            available_space=50000000,
            required_space_with_margin=12000000,
            has_sufficient_space=True,
            space_message="Sufficient disk space available",
        )

        # Empty input -> defaults to False (No)
        with patch("builtins.input", return_value=""):
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                proceed = ask_acquisition_confirmation(preview)
            self.assertFalse(proceed)
            out = buf.getvalue()
            self.assertIn("Vivo V2302", out)
            self.assertIn("42", out)
            self.assertIn("10.00 MiB", out)

        # Explicit 'y' -> True
        with patch("builtins.input", return_value="y"):
            self.assertTrue(ask_acquisition_confirmation(preview))

    def test_recovery_folder_naming_with_metadata(self):
        """Requirement 7: Directory naming: recovery/DEVICE_NAME_scan_YYYY-MM-DD_HH-MM-SS/."""
        executor = AdbExecutor(adb_path="/usr/bin/adb")
        mgr = AcquisitionManager(executor, base_recovery_dir=self.temp_dir)

        # 1. Device with clean manufacturer & model
        dev1 = DeviceInfo(serial="DEV_1", state="device", manufacturer="vivo", model="I2302")
        ts = datetime(2026, 10, 28, 9, 30, 45)
        path1 = mgr._build_scan_dir_path(dev1, timestamp=ts)
        self.assertEqual(path1.name, "vivo_I2302_scan_2026-10-28_09-30-45")

        # 2. Unknown manufacturer and model -> fallback to Android_Device_<suffix>
        dev2 = DeviceInfo(serial="28241FDH2006G7", state="device")
        path2 = mgr._build_scan_dir_path(dev2, timestamp=ts)
        self.assertEqual(path2.name, "Android_Device_2006G7_scan_2026-10-28_09-30-45")

        # 3. Collision avoidance: repeated scan at same timestamp resolves unique path
        path1.mkdir(parents=True, exist_ok=True)
        path1_repeat = mgr._build_scan_dir_path(dev1, timestamp=ts)
        self.assertNotEqual(path1_repeat.name, path1.name)
        self.assertTrue(path1_repeat.name.startswith("vivo_I2302_scan_2026-10-28_09-30-45_"))

    def test_plain_text_progress_fallback(self):
        """Requirement 5: Provide clean plain-text progress output when rich/cursor formatting is disabled."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            disc_cb = make_discovery_progress_callback("Google Pixel 7", "/sdcard/WhatsApp", progress_enabled=False)
            disc_cb("Enumerating files", 5, 0, 1.2)
            disc_cb("Enumerating files", 250, 0, 2.5)

        out = buf.getvalue()
        self.assertIn("Scope: Accessible paths | Discovered: 5 files", out)
        self.assertIn("Scope: Accessible paths | Discovered: 250 files", out)
        self.assertNotIn("\r", out)  # No carriage return overwrites

        buf_acq = io.StringIO()
        with patch("sys.stdout", buf_acq):
            acq_cb = make_acquisition_progress_callback("Google Pixel 7", 50, progress_enabled=False)
            acq_cb(25, 25, 5242880, 10485760, "msgstore.db.crypt14", "VERIFIED", 3.0)

        out_acq = buf_acq.getvalue()
        self.assertIn("[25/50] Device: Google Pixel 7", out_acq)
        self.assertIn("msgstore.db.crypt14", out_acq)
        self.assertNotIn("\r", out_acq)

    def test_scan_completed_summary(self):
        """Requirement 9.C: Present concise scan summary screen."""
        dev = DeviceInfo(serial="DEV_01", state="device", manufacturer="Samsung", model="Galaxy S22")
        scan_res = ScanResult(
            device_serial="DEV_01",
            location_path="/sdcard/WhatsApp",
            start_time="2026-10-28 10:00:00",
            end_time="2026-10-28 10:00:10",
            total_files=150,
            total_bytes=52428800,  # 50 MB
            category_counts={"Databases": 3, "Images": 120, "Videos": 27},
            errors=["Inaccessible path: /sdcard/WhatsApp/.trash"],
        )
        rep_dir = self.temp_dir / "reports"

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            display_scan_completed_summary(dev, scan_res, rep_dir)

        out = buf.getvalue()
        self.assertIn("SCAN COMPLETED", out)
        self.assertIn("Samsung Galaxy S22", out)
        self.assertIn("Files discovered   : 150", out)
        self.assertIn("Total data         : 50.00 MiB", out)
        self.assertIn("Database candidates: 3", out)
        self.assertIn("Media files        : 147", out)
        self.assertIn("Inaccessible paths : 1", out)
        self.assertIn(str(rep_dir), out)

    def test_settings_validation_and_sanitization(self):
        """Requirement 9.B: Persistent configuration validation strips sensitive material and sanitizes invalid values."""
        bad_settings = {
            "app_name": "Test App",
            "ui": {
                "mask_device_serial": "NOT_A_BOOL",  # invalid type
                "progress_display_enabled": True,
            },
            "acquisition": {
                "safety_margin_bytes": -500,  # negative invalid
            },
            "auth_password": "supersecretpassword",  # prohibited!
            "private_key": "MIIBOgIBAAJBA...",  # prohibited!
        }
        clean = validate_settings(bad_settings)
        self.assertFalse(clean["ui"]["mask_device_serial"])
        self.assertGreater(clean["acquisition"]["safety_margin_bytes"], 0)
        self.assertNotIn("auth_password", clean)
        self.assertNotIn("private_key", clean)

        # Test save and reload
        cfg_file = self.temp_dir / "settings.json"
        saved = save_settings(clean, config_path=cfg_file)
        self.assertTrue(saved)
        reloaded = load_settings(config_path=cfg_file)
        self.assertEqual(reloaded["app_name"], "Test App")

    def test_structured_error_formatting(self):
        """Requirement 8: Structured error codes produce actionable user instructions."""
        err_adb = format_actionable_error(ERR_ADB_NOT_FOUND)
        self.assertIn("ERR_ADB_NOT_FOUND", err_adb)
        self.assertIn("sudo apt install -y adb", err_adb)

        err_space = format_actionable_error(ERR_INSUFFICIENT_SPACE, context="Need 5GB, have 2GB")
        self.assertIn("ERR_INSUFFICIENT_SPACE", err_space)
        self.assertIn("Need 5GB, have 2GB", err_space)

        err_storage = format_actionable_error(ERR_NO_WHATSAPP_STORAGE, device_name="Google Pixel 7")
        self.assertIn("ERR_NO_WHATSAPP_STORAGE", err_storage)
        self.assertIn("Google Pixel 7", err_storage)
        self.assertIn("app-private sandbox", err_storage)


if __name__ == "__main__":
    unittest.main()
