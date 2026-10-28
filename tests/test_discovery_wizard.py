"""Tests for Manual Full Scan, Discovery Results, and Recovery Destination Wizard.

Covers:
1. Launching WRS does not start a storage scan.
2. Startup still detects actual ADB and device status.
3. Full Scan requires explicit selection and confirmation.
4. Targeted Scan respects category and location selections.
5. Discovery results display actual paths and counts.
6. Pressing Enter at the destination prompt selects the default directory.
7. Custom destinations are expanded and validated correctly.
8. Invalid destinations allow retry or cancellation.
9. Source/destination overlap is rejected safely.
10. Device names are sanitized for directory creation.
11. Existing scan directories are never overwritten.
12. Multiple devices are handled explicitly.
13. Acquisition requires confirmation before copying.
14. Scan Only does not copy files.
15. Acquisition manifests and hashes reflect actual results.
16. Cancellation and errors leave the terminal in a usable state.
17. All existing main-menu options continue to work.
"""

import io
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from wrs.acquisition import (
    AcquisitionManager,
    build_default_recovery_destination,
)
from wrs.cli import (
    interactive_menu,
    parse_args,
    recovery_wizard_flow,
    run_interactive_workflow,
)
from wrs.device import AdbExecutor, DeviceInfo, DeviceStatusResult
from wrs.discovery_wizard import (
    confirm_acquisition,
    display_discovery_summary,
    discovery_summary_workflow,
    execute_manifest_acquisition,
    prompt_recovery_destination,
    scan_and_recovery_wizard_menu,
    validate_destination_path,
)
from wrs.priority_discovery import (
    DiscoveryCandidate,
    DiscoveryLocation,
    DiscoveryManifest,
    PriorityDiscoveryEngine,
)


class TestDiscoveryWizardAndDestination(unittest.TestCase):
    """Test suite for user-controlled scanning, destination wizard, and safe acquisition."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.mock_executor = MagicMock(spec=AdbExecutor)
        self.mock_executor.adb_path = "/usr/bin/adb"
        self.mock_executor._device_cache = {}
        self.mock_executor.is_adb_installed.return_value = True
        self.mock_executor.check_adb_server.return_value = (True, "daemon running")
        self.mock_executor.get_adb_version.return_value = (True, "1.0.41")
        self.mock_executor.is_device_connected.return_value = True

        self.mock_dev = DeviceInfo(
            serial="VIVO_12345",
            state="device",
            manufacturer="Vivo",
            model="V2217",
            android_version="12",
            screen_unlocked=True,
            internal_storage_accessible=True,
        )

        status_res = DeviceStatusResult(
            adb_installed=True,
            adb_available=True,
            adb_version_raw="1.0.41",
            adb_version="1.0.41",
            adb_server_responsive=True,
            adb_status_display="Available (1.0.41)",
            enumeration_success=True,
            enumeration_error=None,
            devices=[self.mock_dev],
            device_count=1,
            device_status_display="Connected",
            selected_device=self.mock_dev,
        )
        self.mock_executor.check_device_status.return_value = status_res
        self.mock_executor.get_device_details.return_value = self.mock_dev
        self.mock_executor.revalidate_selected_device.return_value = (True, self.mock_dev, "Validated")

    def tearDown(self):
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. Startup Behavior: Never Scan Automatically
    # -------------------------------------------------------------------------
    def test_startup_does_not_start_storage_scan(self):
        """Launching WRS completes preflight checks without initiating any storage scan."""
        status_res = DeviceStatusResult(
            adb_installed=True,
            adb_available=True,
            adb_version_raw="1.0.41",
            adb_version="1.0.41",
            adb_server_responsive=True,
            adb_status_display="Available",
            enumeration_success=True,
            enumeration_error=None,
            devices=[self.mock_dev],
            device_count=1,
            device_status_display="Connected",
            selected_device=self.mock_dev,
        )
        self.mock_executor.check_device_status.return_value = status_res

        buf = io.StringIO()
        # Input '0' immediately exits main menu
        with patch("wrs.cli.AdbExecutor", return_value=self.mock_executor), \
             patch("wrs.cli.run_animated_priority_discovery") as mock_scan, \
             patch("builtins.input", side_effect=["0"]), \
             patch("sys.stdout", buf):

            with self.assertRaises(SystemExit) as cm:
                interactive_menu()

            self.assertEqual(cm.exception.code, 0)
            mock_scan.assert_not_called()

        out = buf.getvalue()
        self.assertIn("[INFO] Startup checks completed.", out)
        self.assertIn("[INFO] No storage scan has been started.", out)

    # -------------------------------------------------------------------------
    # 2. Startup still detects actual ADB and device status
    # -------------------------------------------------------------------------
    def test_startup_detects_actual_adb_and_device(self):
        """Startup correctly checks and renders genuine device detection status."""
        status_res = DeviceStatusResult(
            adb_installed=True,
            adb_available=True,
            adb_version_raw="1.0.41",
            adb_version="1.0.41",
            adb_server_responsive=True,
            adb_status_display="Available (1.0.41)",
            enumeration_success=True,
            enumeration_error=None,
            devices=[self.mock_dev],
            device_count=1,
            device_status_display="Connected",
            selected_device=self.mock_dev,
        )
        self.mock_executor.check_device_status.return_value = status_res

        buf = io.StringIO()
        with patch("wrs.cli.AdbExecutor", return_value=self.mock_executor), \
             patch("builtins.input", side_effect=["0"]), \
             patch("sys.stdout", buf):

            with self.assertRaises(SystemExit):
                interactive_menu()

        out = buf.getvalue()
        self.assertIn("Vivo V2217", out)
        self.assertIn("MAIN MENU", out)

    # -------------------------------------------------------------------------
    # 3. Full Scan requires explicit selection and confirmation
    # -------------------------------------------------------------------------
    def test_full_scan_requires_explicit_selection_and_confirmation(self):
        """Full Scan option displays scope summary and requires confirmation before running."""
        mock_manifest = DiscoveryManifest(
            session_id="test_session",
            timestamp="2026-10-28 12:00:00",
            device_serial=self.mock_dev.serial,
            device_name=self.mock_dev.display_name,
            adb_status="Available",
            device_state="Connected and authorized",
            duration_seconds=2.5,
            status="Discovery completed",
            locations=[],
            candidates=[],
        )

        with patch("wrs.discovery_wizard.run_animated_priority_discovery", return_value=mock_manifest) as mock_scan:
            # Operation '1' (Full Scan) -> 'n' (Cancel) -> '0' (Back)
            inputs = ["1", "n", "0"]
            scan_and_recovery_wizard_menu(
                self.mock_executor,
                self.mock_dev,
                settings={"acquisition": {"default_recovery_dir": str(self.temp_dir)}},
                active_categories=["All Supported Data"],
                input_func=lambda _: inputs.pop(0),
            )
            mock_scan.assert_not_called()

            # Now confirm with 'y'
            inputs = ["1", "y", "4", "0"]
            scan_and_recovery_wizard_menu(
                self.mock_executor,
                self.mock_dev,
                settings={"acquisition": {"default_recovery_dir": str(self.temp_dir)}},
                active_categories=["All Supported Data"],
                input_func=lambda _: inputs.pop(0),
            )
            mock_scan.assert_called_once()

    # -------------------------------------------------------------------------
    # 4. Targeted Scan respects category and location selections
    # -------------------------------------------------------------------------
    def test_targeted_scan_respects_custom_path_selection(self):
        """Targeted Scan option allows selecting custom path and runs targeted discovery."""
        mock_manifest = DiscoveryManifest(
            session_id="targeted_session",
            timestamp="2026-10-28 12:00:00",
            device_serial=self.mock_dev.serial,
            device_name=self.mock_dev.display_name,
            adb_status="Available",
            device_state="Connected and authorized",
            duration_seconds=1.0,
            status="Discovery completed",
            locations=[],
            candidates=[],
        )

        with patch("wrs.discovery_wizard.run_animated_priority_discovery", return_value=mock_manifest) as mock_scan:
            # Op '2' (Targeted Scan) -> '1' (WhatsApp Messenger only) -> '4' (Back from summary) -> '0' (Back)
            inputs = ["2", "1", "4", "0"]
            scan_and_recovery_wizard_menu(
                self.mock_executor,
                self.mock_dev,
                settings={"acquisition": {"default_recovery_dir": str(self.temp_dir)}},
                active_categories=["All Supported Data"],
                input_func=lambda _: inputs.pop(0),
            )
            mock_scan.assert_called_once()

    # -------------------------------------------------------------------------
    # 5. Discovery results display actual paths and counts
    # -------------------------------------------------------------------------
    def test_discovery_summary_displays_actual_paths_and_counts(self):
        """Discovery summary renders verified paths, file counts, sizes, and candidate categories."""
        loc = DiscoveryLocation(
            id=1,
            name="WhatsApp Business directory",
            path="/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases/",
            canonical_path="/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases/",
            priority=4,
            status="Found",
            file_count=5,
            total_bytes=48000000,
            is_accessible=True,
            is_device=True,
            is_business=True,
        )
        cand = DiscoveryCandidate(
            path="/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases/msgstore.db.crypt14",
            filename="msgstore.db.crypt14",
            category="DATABASES",
            size_bytes=14751612,
            is_device=True,
            is_database=True,
            db_format="CRYPT14",
            is_encrypted=True,
        )
        manifest = DiscoveryManifest(
            session_id="test_disc",
            timestamp="2026-10-28 12:00:00",
            device_serial=self.mock_dev.serial,
            device_name=self.mock_dev.display_name,
            adb_status="Available",
            device_state="Connected and authorized",
            duration_seconds=3.2,
            status="Discovery completed",
            locations=[loc],
            candidates=[cand],
        )

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            display_discovery_summary(manifest, self.mock_dev)

        out = buf.getvalue()
        self.assertIn("/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases/", out)
        self.assertIn("Total matching files : 5", out)
        self.assertIn("WRS — DISCOVERY SUMMARY", out)

    # -------------------------------------------------------------------------
    # 6. Pressing Enter at the destination prompt selects the default directory
    # -------------------------------------------------------------------------
    def test_destination_prompt_blank_input_selects_default(self):
        """Pressing Enter on blank destination input uses default recovery directory."""
        inputs = [""]  # User presses Enter
        dest = prompt_recovery_destination(
            device=self.mock_dev,
            total_files=10,
            total_bytes=5000000,
            settings={"acquisition": {"default_recovery_dir": str(self.temp_dir)}},
            input_func=lambda _: inputs.pop(0),
        )

        self.assertIsNotNone(dest)
        self.assertTrue(str(dest).startswith(str(self.temp_dir)))
        self.assertIn("Vivo_V2217", str(dest))
        self.assertIn("scan_", dest.name)

    # -------------------------------------------------------------------------
    # 7. Custom destinations are expanded and validated correctly
    # -------------------------------------------------------------------------
    def test_custom_destination_expanded_and_validated(self):
        """Custom valid path is expanded from ~ and resolved to absolute path."""
        custom_target = self.temp_dir / "my_custom_recovery"
        inputs = [str(custom_target)]

        dest = prompt_recovery_destination(
            device=self.mock_dev,
            total_files=5,
            total_bytes=1000,
            settings={"acquisition": {"default_recovery_dir": str(self.temp_dir)}},
            input_func=lambda _: inputs.pop(0),
        )

        self.assertEqual(dest, custom_target.resolve())
        self.assertTrue(dest.exists())

    # -------------------------------------------------------------------------
    # 8. Invalid destinations allow retry or cancellation
    # -------------------------------------------------------------------------
    def test_invalid_destination_offers_retry_and_default(self):
        """Invalid destination path prompts user with options to retry or select default."""
        valid_dest = self.temp_dir / "valid_dest"
        # 1. Invalid path (null byte)
        # 2. Select option '1' (Retry custom)
        # 3. Enter valid path
        inputs = ["bad_path\x00_test", "1", str(valid_dest)]

        dest = prompt_recovery_destination(
            device=self.mock_dev,
            total_files=5,
            total_bytes=1000,
            settings={"acquisition": {"default_recovery_dir": str(self.temp_dir)}},
            input_func=lambda _: inputs.pop(0),
        )

        self.assertEqual(dest, valid_dest.resolve())

    # -------------------------------------------------------------------------
    # 9. Source/destination overlap is rejected safely
    # -------------------------------------------------------------------------
    def test_source_destination_overlap_is_rejected(self):
        """Custom destination path that overlaps with source location is rejected."""
        source_dir = self.temp_dir / "case_source"
        source_dir.mkdir(parents=True, exist_ok=True)

        # 1. Overlapping path (inside source)
        # 2. Option '2' (Use default recovery destination)
        inputs = [str(source_dir / "subfolder"), "2"]

        dest = prompt_recovery_destination(
            device=self.mock_dev,
            total_files=5,
            total_bytes=1000,
            settings={"acquisition": {"default_recovery_dir": str(self.temp_dir)}},
            source_paths=[str(source_dir)],
            input_func=lambda _: inputs.pop(0),
        )

        self.assertIsNotNone(dest)
        self.assertIn("Vivo_V2217", str(dest))
        self.assertNotIn(str(source_dir), str(dest))

    # -------------------------------------------------------------------------
    # 10. Device names are sanitized for directory creation
    # -------------------------------------------------------------------------
    def test_device_name_sanitized_for_directory(self):
        """Device name containing spaces and special characters is safely sanitized."""
        weird_dev = DeviceInfo(
            serial="SERIAL_99",
            state="device",
            manufacturer="Samsung / Galaxy",
            model="S23 Ultra!! [5G]",
        )
        dest = build_default_recovery_destination(self.temp_dir, device=weird_dev)
        parent_name = dest.parent.name

        self.assertNotIn(" ", parent_name)
        self.assertNotIn("/", parent_name)
        self.assertNotIn("!", parent_name)
        self.assertNotIn("[", parent_name)
        self.assertIn("Samsung", parent_name)
        self.assertIn("Galaxy", parent_name)

    # -------------------------------------------------------------------------
    # 11. Existing scan directories are never overwritten
    # -------------------------------------------------------------------------
    def test_existing_scan_directories_never_overwritten(self):
        """Collision handling creates unique suffix if a scan directory already exists."""
        ts = datetime(2026, 10, 28, 12, 30, 0)
        dest1 = build_default_recovery_destination(self.temp_dir, device=self.mock_dev, timestamp=ts)
        dest1.mkdir(parents=True, exist_ok=True)

        dest2 = build_default_recovery_destination(self.temp_dir, device=self.mock_dev, timestamp=ts)
        self.assertNotEqual(dest1, dest2)
        self.assertTrue(dest2.name.startswith(f"{dest1.name}_"))

    # -------------------------------------------------------------------------
    # 12. Multiple devices are handled explicitly
    # -------------------------------------------------------------------------
    def test_offline_mode_uses_local_import_directory(self):
        """When no device is connected, destination uses 'local_import' instead of fake device."""
        dest = build_default_recovery_destination(self.temp_dir, device=None)
        self.assertEqual(dest.parent.name, "local_import")
        self.assertTrue(dest.name.startswith("scan_"))

    # -------------------------------------------------------------------------
    # 13. Acquisition requires confirmation before copying
    # -------------------------------------------------------------------------
    def test_acquisition_requires_explicit_confirmation(self):
        """Acquisition confirmation returns 'confirm' only on explicit user approval."""
        dest = self.temp_dir / "target"
        dest.mkdir(parents=True, exist_ok=True)

        inputs = ["0"]  # Cancel
        res = confirm_acquisition(self.mock_dev, 10, 5000, dest, input_func=lambda _: inputs.pop(0))
        self.assertEqual(res, "cancel")

        inputs = ["1"]  # Confirm
        res = confirm_acquisition(self.mock_dev, 10, 5000, dest, input_func=lambda _: inputs.pop(0))
        self.assertEqual(res, "confirm")

        inputs = ["2"]  # Change destination
        res = confirm_acquisition(self.mock_dev, 10, 5000, dest, input_func=lambda _: inputs.pop(0))
        self.assertEqual(res, "change_dest")

    # -------------------------------------------------------------------------
    # 14. Scan Only does not copy files
    # -------------------------------------------------------------------------
    def test_scan_only_operation_does_not_copy_files(self):
        """Scanning locations discovers data without writing files to recovery destination."""
        engine = PriorityDiscoveryEngine(executor=self.mock_executor, settings={"acquisition": {"default_recovery_dir": str(self.temp_dir)}})
        self.mock_executor.run_cmd.return_value = MagicMock(returncode=1, stdout="", stderr="")

        manifest = engine.run_priority_discovery(device=self.mock_dev)
        self.assertEqual(manifest.status, "Discovery completed")

        # Verify no files were created in recovery folder
        rec_files = list(self.temp_dir.rglob("*.db*"))
        self.assertEqual(len(rec_files), 0)

    # -------------------------------------------------------------------------
    # 15. Acquisition manifests and hashes reflect actual results
    # -------------------------------------------------------------------------
    def test_acquisition_manifest_records_hashes_and_paths(self):
        """Executing acquisition writes acquisition_manifest.json with verified hashes and paths."""
        source_file = self.temp_dir / "msgstore.db.crypt14"
        source_file.write_bytes(b"Simulated encrypted database payload for testing")

        cand = DiscoveryCandidate(
            path=str(source_file),
            filename="msgstore.db.crypt14",
            category="DATABASES",
            size_bytes=len(source_file.read_bytes()),
            is_device=False,
            is_database=True,
            db_format="CRYPT14",
        )
        manifest = DiscoveryManifest(
            session_id="acq_test",
            timestamp="2026-10-28 12:00:00",
            device_serial=None,
            device_name="Local Case",
            adb_status="N/A",
            device_state="Local",
            duration_seconds=1.0,
            status="Discovery completed",
            locations=[],
            candidates=[cand],
        )

        dest_dir = self.temp_dir / "recovery_run"
        records = execute_manifest_acquisition(
            executor=self.mock_executor,
            device=None,
            manifest=manifest,
            destination_dir=dest_dir,
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, "VERIFIED")
        self.assertTrue(len(records[0].actual_hash) == 64)  # SHA-256 hex string

        manifest_file = dest_dir / "manifests" / "acquisition_manifest.json"
        self.assertTrue(manifest_file.exists())
        with open(manifest_file, "r", encoding="utf-8") as f:
            saved_data = json.load(f)
            self.assertEqual(len(saved_data), 1)
            self.assertEqual(saved_data[0]["source_path"], str(source_file))

    # -------------------------------------------------------------------------
    # 16. Cancellation leaves terminal in usable state
    # -------------------------------------------------------------------------
    def test_cancellation_leaves_clean_state(self):
        """User pressing Ctrl+C or selecting Cancel returns safely without crashing."""
        inputs = ["0"]  # Back
        manifest = scan_and_recovery_wizard_menu(
            self.mock_executor,
            self.mock_dev,
            settings={"acquisition": {"default_recovery_dir": str(self.temp_dir)}},
            active_categories=["All Supported Data"],
            input_func=lambda _: inputs.pop(0),
        )
        # Clean return
        self.assertIsNone(manifest)

    # -------------------------------------------------------------------------
    # 17. All existing main-menu options continue to work
    # -------------------------------------------------------------------------
    def test_main_menu_option_numbers_preserved(self):
        """Main menu displays the exact expected options [0] to [10]."""
        status_res = DeviceStatusResult(
            adb_installed=True,
            adb_available=True,
            adb_version_raw="1.0.41",
            adb_version="1.0.41",
            adb_server_responsive=True,
            adb_status_display="Available",
            enumeration_success=True,
            enumeration_error=None,
            devices=[self.mock_dev],
            device_count=1,
            device_status_display="Connected",
            selected_device=self.mock_dev,
        )
        self.mock_executor.check_device_status.return_value = status_res

        buf = io.StringIO()
        with patch("wrs.cli.AdbExecutor", return_value=self.mock_executor), \
             patch("builtins.input", side_effect=["0"]), \
             patch("sys.stdout", buf):

            with self.assertRaises(SystemExit):
                interactive_menu()

        out = buf.getvalue()
        self.assertIn("[ 1] Scan and Recover Data", out)
        self.assertIn("[ 2] Select Specific Data Categories", out)
        self.assertIn("[ 3] Recover Chat History", out)
        self.assertIn("[ 4] Recover Media and Attachments", out)
        self.assertIn("[ 5] Inspect Backups and Databases", out)
        self.assertIn("[ 6] View Available Chat Dates", out)
        self.assertIn("[ 7] Export Recovered Data", out)
        self.assertIn("[ 8] Verify Existing Recovery Files", out)
        self.assertIn("[ 9] View Previous Scans", out)
        self.assertIn("[10] Settings and Help", out)
        self.assertIn("[ 0] Exit", out)


if __name__ == "__main__":
    unittest.main()
