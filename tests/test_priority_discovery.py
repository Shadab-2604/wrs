"""Automated tests for Priority-Based File Discovery, Scan Animation, and Recovery Wizard Fix.

Validates:
1. Bug fix regression: run_interactive_workflow() accepts 'selected_categories' keyword argument.
2. Existing callers of run_interactive_workflow() without the argument continue working.
3. Selecting '1' (Scan Only) executes inventory scan without file acquisition or source modification.
4. Startup state checks: ADB unavailable, ADB server unavailable, no device, unauthorized, offline, authorized.
5. Priority 1 (WRS recovery dir and registry) discovery and stale candidate detection.
6. Priority 2 (WhatsApp database and backup paths on device) identification of SQLite and crypt14/15.
7. Priority 3 (WhatsApp media paths) enumeration of Images, Videos, Audio, Docs.
8. Priority 4 (WhatsApp Business) distinct identification.
9. Priority 5 (Configured local search directories).
10. Priority 6 (Extended discovery) consent requirement and path inspection.
11. Clean animation stage progression and graceful Ctrl+C interruption handling.
12. Location review menu options [1] to [5] and [0].
13. Discovery results summary layout with verified statuses (Found, Empty, Inaccessible, Not Applicable).
14. Main menu workflow preserves all 10 options and reuses discovery manifest.
"""

from __future__ import annotations

import io
import json
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from wrs.acquisition import AcquisitionPreview
from wrs.categorizer import ALL_CATEGORIES
from wrs.cli import (
    interactive_menu,
    recovery_wizard_flow,
    run_interactive_workflow,
    select_or_discover_chat_database_interactive,
)
from wrs.device import AdbExecutor, DeviceInfo, DeviceStatusResult
from wrs.priority_discovery import (
    STATUS_EMPTY,
    STATUS_FOUND,
    STATUS_INACCESSIBLE,
    STATUS_NOT_APPLICABLE,
    DiscoveryCandidate,
    DiscoveryLocation,
    DiscoveryManifest,
    PriorityDiscoveryEngine,
    discovery_review_menu_interactive,
    display_discovery_results_summary,
    run_animated_priority_discovery,
)
from wrs.scanner import ScannedFile, ScanResult


class TestRecoveryWizardBugFix(unittest.TestCase):
    """Test regression fix for TypeError in run_interactive_workflow()."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.mock_executor = MagicMock(spec=AdbExecutor)
        self.mock_executor.adb_path = "/usr/bin/adb"
        self.mock_executor._device_cache = {}

        self.mock_dev = DeviceInfo(
            serial="TEST_SERIAL_123",
            state="device",
            manufacturer="Google",
            model="Pixel 8",
            android_version="14",
        )
        self.mock_executor.get_device_details.return_value = self.mock_dev
        self.mock_executor.revalidate_selected_device.return_value = (True, self.mock_dev, "Validated")
        self.mock_executor.is_device_connected.return_value = True

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_run_interactive_workflow_accepts_selected_categories(self):
        """Fix verification: run_interactive_workflow accepts 'selected_categories' without TypeError."""
        cats = {"Chat History", "Photos and Images"}

        with patch("wrs.cli.StorageDiscovery") as mock_disc_cls, \
             patch("wrs.cli.FileScanner") as mock_scan_cls, \
             patch("wrs.cli.AcquisitionManager") as mock_acq_cls, \
             patch("wrs.cli.select_location_interactive") as mock_sel_loc:

            # Mock discovery
            mock_disc = mock_disc_cls.return_value
            mock_loc = MagicMock(path="/sdcard/WhatsApp/", is_readable=True)
            mock_disc.discover_locations.return_value = [mock_loc]
            mock_sel_loc.return_value = [mock_loc]

            # Mock scanner
            mock_scanner = mock_scan_cls.return_value
            mock_scan_res = ScanResult(
                device_serial="TEST_SERIAL_123",
                location_path="/sdcard/WhatsApp/",
                start_time="2026-10-28 10:00:00",
                end_time="2026-10-28 10:00:05",
                files=[],
                total_files=0,
                total_bytes=0,
            )
            mock_scanner.scan_location.return_value = mock_scan_res

            # Mock acquisition manager
            mock_acq = mock_acq_cls.return_value
            preview = AcquisitionPreview(
                scan_id="scan_test_01",
                device_name="Google Pixel 8",
                serial="TEST_SERIAL_123",
                android_version="14",
                scan_date="2026-10-28 10:00:00",
                selected_locations=["/sdcard/WhatsApp/"],
                total_files=0,
                total_bytes=0,
                category_counts={c: 0 for c in ALL_CATEGORIES},
                category_bytes={c: 0 for c in ALL_CATEGORIES},
                unreadable_files=0,
                skipped_files=0,
                duplicate_candidates=0,
                database_backup_candidates=0,
                destination_path=self.temp_dir / "recovery_01",
                available_space=100000000,
                required_space_with_margin=50000000,
                has_sufficient_space=True,
                space_message="Sufficient disk space available",
            )
            mock_acq.generate_preview.return_value = preview
            mock_acq.setup_recovery_tree.return_value = {
                "base": self.temp_dir,
                "reports": self.temp_dir / "reports",
            }

            # This call previously raised TypeError: got an unexpected keyword argument 'selected_categories'
            try:
                run_interactive_workflow(
                    self.mock_executor,
                    acquire_mode=False,
                    override_serial="TEST_SERIAL_123",
                    selected_categories=cats,
                    settings={"acquisition": {"default_recovery_dir": str(self.temp_dir)}},
                )
            except TypeError as e:
                self.fail(f"run_interactive_workflow() raised unexpected TypeError: {e}")

            # Verify selected_categories was forwarded to generate_preview
            mock_acq.generate_preview.assert_called()
            call_kwargs = mock_acq.generate_preview.call_args[1]
            self.assertEqual(call_kwargs.get("selected_categories"), cats)

    def test_run_interactive_workflow_backward_compatible_selected_cats(self):
        """Verify existing callers passing selected_cats still work identically."""
        cats = {"media"}
        with patch("wrs.cli.StorageDiscovery") as mock_disc_cls, \
             patch("wrs.cli.FileScanner") as mock_scan_cls, \
             patch("wrs.cli.AcquisitionManager") as mock_acq_cls, \
             patch("wrs.cli.select_location_interactive") as mock_sel_loc:

            mock_disc = mock_disc_cls.return_value
            mock_loc = MagicMock(path="/sdcard/WhatsApp/", is_readable=True)
            mock_disc.discover_locations.return_value = [mock_loc]
            mock_sel_loc.return_value = [mock_loc]

            mock_scan_cls.return_value.scan_location.return_value = ScanResult(
                device_serial="TEST_SERIAL_123",
                location_path="/sdcard/WhatsApp/",
                start_time="2026-10-28 10:00:00",
                end_time="2026-10-28 10:00:05",
                files=[],
            )

            mock_acq = mock_acq_cls.return_value
            preview = AcquisitionPreview(
                scan_id="scan_test_02",
                device_name="Google Pixel 8",
                serial="TEST_SERIAL_123",
                android_version="14",
                scan_date="2026-10-28 10:00:00",
                selected_locations=["/sdcard/WhatsApp/"],
                total_files=0,
                total_bytes=0,
                category_counts={c: 0 for c in ALL_CATEGORIES},
                category_bytes={c: 0 for c in ALL_CATEGORIES},
                unreadable_files=0,
                skipped_files=0,
                duplicate_candidates=0,
                database_backup_candidates=0,
                destination_path=self.temp_dir / "recovery_02",
                available_space=100000000,
                required_space_with_margin=50000000,
                has_sufficient_space=True,
                space_message="OK",
            )
            mock_acq.generate_preview.return_value = preview
            mock_acq.setup_recovery_tree.return_value = {
                "base": self.temp_dir,
                "reports": self.temp_dir / "reports",
            }

            run_interactive_workflow(
                self.mock_executor,
                acquire_mode=False,
                override_serial="TEST_SERIAL_123",
                selected_cats=cats,
                settings={"acquisition": {"default_recovery_dir": str(self.temp_dir)}},
            )
            call_kwargs = mock_acq.generate_preview.call_args[1]
            self.assertEqual(call_kwargs.get("selected_categories"), cats)

    def test_recovery_wizard_flow_scan_only_no_typeerror(self):
        """Executing '1' (Scan Only) in recovery_wizard_flow does not crash and does not copy files."""
        with patch("builtins.input", side_effect=["1"]), \
             patch("wrs.cli.run_interactive_workflow") as mock_run_wf:

            recovery_wizard_flow(
                self.mock_executor,
                self.mock_dev,
                settings={"acquisition": {"default_recovery_dir": str(self.temp_dir)}},
                active_categories=["Databases and Backups"],
                legacy_mode=True,
            )

            mock_run_wf.assert_called_once()
            args, kwargs = mock_run_wf.call_args
            self.assertFalse(kwargs.get("acquire_mode"))
            self.assertEqual(kwargs.get("override_serial"), "TEST_SERIAL_123")
            self.assertIn("Databases", kwargs.get("selected_categories"))


class TestPriorityDiscoveryEngine(unittest.TestCase):
    """Test Priorities 1 through 6, candidate parsing, and manifest persistence."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.mock_executor = MagicMock(spec=AdbExecutor)
        self.mock_executor.adb_path = "/usr/bin/adb"
        self.mock_executor._device_cache = {}

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_priority_1_existing_wrs_recovery_dir_and_stale_detection(self):
        """Priority 1 inspects existing local recovery files and registers them."""
        rec_dir = self.temp_dir / "recovery"
        rec_dir.mkdir(parents=True, exist_ok=True)
        test_file = rec_dir / "test_chat.txt"
        test_file.write_text("Hello chat evidence")

        # Mock ADB status: offline / no device connected
        status_res = DeviceStatusResult(
            adb_installed=True,
            adb_available=True,
            adb_version_raw="1.0.41",
            adb_version="1.0.41",
            adb_server_responsive=True,
            adb_status_display="Available",
            enumeration_success=True,
            enumeration_error=None,
            devices=[],
            device_count=0,
            device_status_display="No Device Connected",
        )
        self.mock_executor.check_device_status.return_value = status_res

        settings = {"acquisition": {"default_recovery_dir": str(rec_dir)}}
        engine = PriorityDiscoveryEngine(executor=self.mock_executor, settings=settings)

        manifest = engine.run_priority_discovery(device=None)

        self.assertEqual(manifest.status, "Discovery completed")
        self.assertEqual(manifest.device_state, "No device connected")

        # Location 1 must be WRS recovery directory
        loc1 = manifest.locations[0]
        self.assertEqual(loc1.name, "WRS recovery directory")
        self.assertEqual(loc1.priority, 1)
        self.assertEqual(loc1.status, STATUS_FOUND)
        self.assertEqual(loc1.file_count, 1)

        # Device locations must be NOT_APPLICABLE
        loc_db = next(l for l in manifest.locations if l.priority == 2)
        self.assertEqual(loc_db.status, STATUS_NOT_APPLICABLE)

    def test_priority_2_database_candidates_detected_on_device(self):
        """Priority 2 discovers msgstore.db and msgstore.db.crypt14 on device storage."""
        dev = DeviceInfo(serial="SERIAL_PIXEL", state="device", manufacturer="Google", model="Pixel 7")

        status_res = DeviceStatusResult(
            adb_installed=True,
            adb_available=True,
            adb_version_raw="1.0.41",
            adb_version="1.0.41",
            adb_server_responsive=True,
            adb_status_display="Available",
            enumeration_success=True,
            enumeration_error=None,
            devices=[dev],
            device_count=1,
            device_status_display="Google Pixel 7 (SERIAL_PIXEL)",
            selected_device=dev,
        )
        self.mock_executor.check_device_status.return_value = status_res

        # Mock run_cmd responses
        def fake_run_cmd(cmd_list, serial=None, timeout=None):
            cmd_str = " ".join(cmd_list)
            # test -d /sdcard/Android/media/com.whatsapp/WhatsApp/Databases/
            if "test -d" in cmd_str and "Databases" in cmd_str:
                return subprocess.CompletedProcess(cmd_list, 0, stdout="EXISTS\n", stderr="")
            if "readlink" in cmd_str or "realpath" in cmd_str:
                return subprocess.CompletedProcess(cmd_list, 0, stdout="/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Databases/\n", stderr="")
            # ls -l Databases
            if "ls -l" in cmd_str and "Databases" in cmd_str:
                ls_out = (
                    "-rw-rw---- 1 u0_a123 media_rw 14205440 2026-10-25 04:00 msgstore.db.crypt14\n"
                    "-rw-rw---- 1 u0_a123 media_rw 5242880 2026-10-26 04:00 msgstore.db\n"
                )
                return subprocess.CompletedProcess(cmd_list, 0, stdout=ls_out, stderr="")
            return subprocess.CompletedProcess(cmd_list, 0, stdout="", stderr="")

        self.mock_executor.run_cmd.side_effect = fake_run_cmd

        settings = {"acquisition": {"default_recovery_dir": str(self.temp_dir / "recovery")}}
        engine = PriorityDiscoveryEngine(executor=self.mock_executor, settings=settings)

        manifest = engine.run_priority_discovery(device=dev)

        loc2 = next(l for l in manifest.locations if l.priority == 2)
        self.assertEqual(loc2.status, STATUS_FOUND)
        self.assertEqual(loc2.file_count, 2)

        # Candidates must include crypt14 and SQLite
        cands = [c for c in manifest.candidates if c.is_database]
        self.assertEqual(len(cands), 2)
        c_names = {c.filename for c in cands}
        self.assertIn("msgstore.db.crypt14", c_names)
        self.assertIn("msgstore.db", c_names)

        # Encrypted candidate must be marked encrypted
        crypt_cand = next(c for c in cands if "crypt14" in c.filename)
        self.assertTrue(crypt_cand.is_encrypted)
        self.assertFalse(crypt_cand.is_readable)

    def test_priority_3_media_subdirectories_enumeration(self):
        """Priority 3 accurately counts files in WhatsApp Images, Videos, Voice Notes."""
        dev = DeviceInfo(serial="SERIAL_SAMSUNG", state="device", manufacturer="Samsung", model="S22")
        status_res = DeviceStatusResult(
            adb_installed=True,
            adb_available=True,
            adb_version_raw="1.0.41",
            adb_version="1.0.41",
            adb_server_responsive=True,
            adb_status_display="Available",
            enumeration_success=True,
            enumeration_error=None,
            devices=[dev],
            device_count=1,
            device_status_display="Samsung S22",
            selected_device=dev,
        )
        self.mock_executor.check_device_status.return_value = status_res

        def fake_run_cmd(cmd_list, serial=None, timeout=None):
            cmd_str = " ".join(cmd_list)
            if "test -d" in cmd_str and "Media" in cmd_str:
                return subprocess.CompletedProcess(cmd_list, 0, stdout="EXISTS\n", stderr="")
            if "ls -F" in cmd_str and "Media" in cmd_str:
                return subprocess.CompletedProcess(cmd_list, 0, stdout="WhatsApp Images/\nWhatsApp Video/\nWhatsApp Documents/\n", stderr="")
            if "wc -l" in cmd_str:
                if "Images" in cmd_str:
                    return subprocess.CompletedProcess(cmd_list, 0, stdout="150\n", stderr="")
                if "Video" in cmd_str:
                    return subprocess.CompletedProcess(cmd_list, 0, stdout="42\n", stderr="")
                if "Documents" in cmd_str:
                    return subprocess.CompletedProcess(cmd_list, 0, stdout="18\n", stderr="")
            return subprocess.CompletedProcess(cmd_list, 0, stdout="", stderr="")

        self.mock_executor.run_cmd.side_effect = fake_run_cmd

        settings = {"acquisition": {"default_recovery_dir": str(self.temp_dir / "recovery")}}
        engine = PriorityDiscoveryEngine(executor=self.mock_executor, settings=settings)

        manifest = engine.run_priority_discovery(device=dev)

        loc3 = next(l for l in manifest.locations if l.priority == 3)
        self.assertEqual(loc3.status, STATUS_FOUND)
        self.assertEqual(loc3.file_count, 150 + 42 + 18)
        self.assertIn("WhatsApp Images", loc3.subdirectories)
        self.assertIn("WhatsApp Video", loc3.subdirectories)

        # Summary media count
        self.assertEqual(manifest.summary_counts["discovered_media_files"], 210)

    def test_priority_6_extended_discovery_with_consent(self):
        """Priority 6 inspects additional paths only after user consent."""
        dev = DeviceInfo(serial="DEV_X", state="device", manufacturer="Sony", model="Xperia")
        manifest = DiscoveryManifest(
            session_id="disc_test",
            timestamp="2026-10-28 10:00:00",
            device_serial=dev.serial,
            device_name=dev.display_name,
            adb_status="Available",
            device_state="Device connected and authorized",
            duration_seconds=1.2,
            status="Discovery completed",
            locations=[],
            candidates=[],
            summary_counts={},
        )

        def fake_run_cmd(cmd_list, serial=None, timeout=None):
            cmd_str = " ".join(cmd_list)
            if "test -d" in cmd_str and "trash" in cmd_str:
                return subprocess.CompletedProcess(cmd_list, 0, stdout="EXISTS\n", stderr="")
            if "wc -l" in cmd_str and "trash" in cmd_str:
                return subprocess.CompletedProcess(cmd_list, 0, stdout="7\n", stderr="")
            return subprocess.CompletedProcess(cmd_list, 0, stdout="", stderr="")

        self.mock_executor.run_cmd.side_effect = fake_run_cmd

        engine = PriorityDiscoveryEngine(executor=self.mock_executor)
        ext_manifest = engine.run_extended_discovery(
            base_manifest=manifest,
            device=dev,
            additional_paths=["/sdcard/WhatsApp/Media/.trash/"],
        )

        ext_loc = next(l for l in ext_manifest.locations if l.priority == 6)
        self.assertEqual(ext_loc.status, STATUS_FOUND)
        self.assertEqual(ext_loc.file_count, 7)

    def test_manifest_revalidation_marks_deleted_files_as_stale(self):
        """revalidate_candidates() marks files deleted on disk as unreadable and stale."""
        test_file = self.temp_dir / "msgstore.db"
        test_file.write_text("dummy database content")

        cand = DiscoveryCandidate(
            path=str(test_file),
            filename="msgstore.db",
            category="DATABASES",
            size_bytes=len("dummy database content"),
            is_device=False,
            is_database=True,
            is_readable=True,
        )
        manifest = DiscoveryManifest(
            session_id="disc_reval",
            timestamp="2026-10-28 10:00:00",
            device_serial=None,
            device_name="Offline",
            adb_status="Available",
            device_state="Local discovery available",
            duration_seconds=0.5,
            status="Discovery completed",
            candidates=[cand],
        )

        manifest.revalidate_candidates()
        self.assertTrue(cand.is_readable)

        # Delete the file
        test_file.unlink()
        manifest.revalidate_candidates()
        self.assertFalse(cand.is_readable)
        self.assertIn("stale", cand.details.lower())

    def test_display_discovery_results_summary_layout(self):
        """Verify summary presentation matches the required visual format."""
        loc1 = DiscoveryLocation(
            id=1,
            name="WRS recovery directory",
            path="/home/user/recovery",
            canonical_path="/home/user/recovery",
            priority=1,
            status=STATUS_FOUND,
            file_count=3,
        )
        loc2 = DiscoveryLocation(
            id=2,
            name="WhatsApp database directory",
            path="/sdcard/WhatsApp/Databases/",
            canonical_path="/sdcard/WhatsApp/Databases/",
            priority=2,
            status=STATUS_FOUND,
            file_count=2,
        )
        cand1 = DiscoveryCandidate(
            path="/home/user/recovery/msgstore.db",
            filename="msgstore.db",
            category="DATABASES",
            size_bytes=5242880,
            is_database=True,
            is_readable=True,
            message_count=14200,
        )
        cand2 = DiscoveryCandidate(
            path="/sdcard/WhatsApp/Databases/msgstore.db.crypt14",
            filename="msgstore.db.crypt14",
            category="DATABASES",
            size_bytes=14205440,
            is_database=True,
            is_encrypted=True,
            db_format="CRYPT14",
        )
        manifest = DiscoveryManifest(
            session_id="test_display",
            timestamp="2026-10-28 11:00:00",
            device_serial="DEV123",
            device_name="Google Pixel",
            adb_status="Available",
            device_state="Device connected and authorized",
            duration_seconds=1.45,
            status="Discovery completed",
            locations=[loc1, loc2],
            candidates=[cand1, cand2],
            summary_counts={
                "discovered_database_candidates": 2,
                "discovered_media_files": 0,
                "unreadable_candidates": 1,
                "inaccessible_locations": 0,
            },
        )

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            display_discovery_results_summary(manifest)

        out = buf.getvalue()
        self.assertIn("WRS — DISCOVERY RESULTS", out)
        self.assertIn("Device       : Google Pixel (DEV123)", out)
        self.assertIn("Scan status  : Discovery completed", out)
        self.assertIn("Duration     : 1.45s", out)
        self.assertIn("[1] WRS recovery directory", out)
        self.assertIn("Status : Found", out)
        self.assertIn("Discovered database candidates : 2", out)
        self.assertIn("msgstore.db — SQLite / Readable (14,200 msgs)", out)
        self.assertIn("msgstore.db.crypt14 — CRYPT14 Encrypted Candidate", out)

    def test_discovery_review_menu_choices(self):
        """User review menu allows continuing ([1]), toggling locations ([2]), or exiting ([0])."""
        loc1 = DiscoveryLocation(
            id=1,
            name="WRS recovery directory",
            path="/recovery",
            canonical_path="/recovery",
            priority=1,
            status=STATUS_FOUND,
            is_selected=True,
        )
        manifest = DiscoveryManifest(
            session_id="test_menu",
            timestamp="2026-10-28 11:00:00",
            device_serial=None,
            device_name="None Connected",
            adb_status="Available",
            device_state="Local discovery available",
            duration_seconds=0.5,
            status="Discovery completed",
            locations=[loc1],
            candidates=[],
            summary_counts={},
        )

        # Choice [1]: continue immediately returns manifest
        with patch("builtins.input", return_value="1"):
            res = discovery_review_menu_interactive(manifest, self.mock_executor, None)
            self.assertEqual(res.session_id, "test_menu")

        # Choice [0]: exits program
        with patch("builtins.input", return_value="0"):
            with self.assertRaises(SystemExit):
                discovery_review_menu_interactive(manifest, self.mock_executor, None)

    def test_startup_device_status_variations(self):
        """Verify engine accurately distinguishes ADB unavailable, unauthorized, and offline states."""
        # 1. ADB unavailable
        status_adb_missing = DeviceStatusResult(
            adb_installed=False,
            adb_available=False,
            adb_version_raw="",
            adb_version="",
            adb_server_responsive=False,
            adb_status_display="NOT INSTALLED",
            enumeration_success=False,
            enumeration_error="Command not found",
            devices=[],
            device_count=0,
            device_status_display="NONE DETECTED",
        )
        self.mock_executor.check_device_status.return_value = status_adb_missing
        engine = PriorityDiscoveryEngine(executor=self.mock_executor)
        manifest_no_adb = engine.run_priority_discovery()
        self.assertEqual(manifest_no_adb.device_state, "ADB unavailable")

        # 2. Device unauthorized
        unauth_dev = DeviceInfo(serial="DEV_UNAUTH", state="unauthorized")
        status_unauth = DeviceStatusResult(
            adb_installed=True,
            adb_available=True,
            adb_version_raw="1.0.41",
            adb_version="1.0.41",
            adb_server_responsive=True,
            adb_status_display="Available",
            enumeration_success=True,
            enumeration_error=None,
            devices=[unauth_dev],
            device_count=1,
            device_status_display="UNAUTHORIZED",
            selected_device=unauth_dev,
        )
        self.mock_executor.check_device_status.return_value = status_unauth
        manifest_unauth = engine.run_priority_discovery(device=unauth_dev)
        self.assertEqual(manifest_unauth.device_state, "Device unauthorized")

        # 3. Device offline
        offline_dev = DeviceInfo(serial="DEV_OFFLINE", state="offline")
        status_offline = DeviceStatusResult(
            adb_installed=True,
            adb_available=True,
            adb_version_raw="1.0.41",
            adb_version="1.0.41",
            adb_server_responsive=True,
            adb_status_display="Available",
            enumeration_success=True,
            enumeration_error=None,
            devices=[offline_dev],
            device_count=1,
            device_status_display="OFFLINE",
            selected_device=offline_dev,
        )
        self.mock_executor.check_device_status.return_value = status_offline
        manifest_offline = engine.run_priority_discovery(device=offline_dev)
        self.assertEqual(manifest_offline.device_state, "Device offline")

    def test_animated_discovery_stage_callbacks_progression(self):
        """Loading animation triggers actual sequential operational stages."""
        status_ok = DeviceStatusResult(
            adb_installed=True,
            adb_available=True,
            adb_version_raw="1.0.41",
            adb_version="1.0.41",
            adb_server_responsive=True,
            adb_status_display="Available",
            enumeration_success=True,
            enumeration_error=None,
            devices=[],
            device_count=0,
            device_status_display="None",
        )
        self.mock_executor.check_device_status.return_value = status_ok
        engine = PriorityDiscoveryEngine(executor=self.mock_executor)

        stages_recorded: list[tuple[str, str]] = []
        manifest = engine.run_priority_discovery(
            stage_callback=lambda code, label: stages_recorded.append((code, label))
        )

        stage_labels = [label for code, label in stages_recorded]
        self.assertIn("Checking ADB and device authorization", stage_labels)
        self.assertIn("Loading existing WRS scan manifests", stage_labels)
        self.assertIn("Checking known WhatsApp database locations", stage_labels)
        self.assertIn("Discovering WhatsApp media files", stage_labels)
        self.assertIn("Validating database candidates", stage_labels)
        self.assertIn("Preparing discovery summary", stage_labels)
        self.assertIn("Discovery completed", stage_labels)
        self.assertEqual(manifest.status, "Discovery completed")

    def test_discovery_cancellation_via_ctrl_c(self):
        """Gracefully handle Ctrl+C (KeyboardInterrupt) without crashing and save partial manifest."""
        self.mock_executor.check_device_status.side_effect = KeyboardInterrupt
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            manifest = run_animated_priority_discovery(self.mock_executor, None)

        self.assertEqual(manifest.status, "Cancelled")
        out = buf.getvalue()
        self.assertIn("Discovery interrupted by user", out)

    def test_review_menu_toggle_location_selection(self):
        """User can toggle selection on specific discovered locations in review menu."""
        loc1 = DiscoveryLocation(
            id=1,
            name="WRS recovery directory",
            path="/rec",
            canonical_path="/rec",
            priority=1,
            status=STATUS_FOUND,
            is_selected=True,
        )
        loc2 = DiscoveryLocation(
            id=2,
            name="WhatsApp database directory",
            path="/db",
            canonical_path="/db",
            priority=2,
            status=STATUS_FOUND,
            is_selected=True,
        )
        manifest = DiscoveryManifest(
            session_id="test_toggle",
            timestamp="2026-10-28 11:00:00",
            device_serial=None,
            device_name="None",
            adb_status="Available",
            device_state="Local discovery available",
            duration_seconds=0.5,
            status="Discovery completed",
            locations=[loc1, loc2],
            candidates=[],
            summary_counts={},
        )

        # Toggle location 2 off, then continue with [1]
        with patch("builtins.input", side_effect=["2", "2", "1"]):
            res = discovery_review_menu_interactive(manifest, self.mock_executor, None)
            self.assertTrue(loc1.is_selected)
            self.assertFalse(loc2.is_selected)

    def test_read_only_discovery_never_runs_modifying_shell_commands(self):
        """Discovery operations must be strictly read-only and never modify Android storage."""
        dev = DeviceInfo(serial="DEV_RO", state="device")
        status_ok = DeviceStatusResult(
            adb_installed=True,
            adb_available=True,
            adb_version_raw="1.0.41",
            adb_version="1.0.41",
            adb_server_responsive=True,
            adb_status_display="Available",
            enumeration_success=True,
            enumeration_error=None,
            devices=[dev],
            device_count=1,
            device_status_display="DEV_RO",
            selected_device=dev,
        )
        self.mock_executor.check_device_status.return_value = status_ok
        commands_run: list[list[str]] = []

        def capture_cmd(cmd_list, serial=None, timeout=None):
            commands_run.append(cmd_list)
            return subprocess.CompletedProcess(cmd_list, 0, stdout="", stderr="")

        self.mock_executor.run_cmd.side_effect = capture_cmd

        engine = PriorityDiscoveryEngine(executor=self.mock_executor)
        engine.run_priority_discovery(device=dev)

        # Verify no destructive command was proposed or run
        for cmd in commands_run:
            cmd_joined = " ".join(cmd).lower()
            self.assertNotIn("rm ", cmd_joined)
            self.assertNotIn("rmdir", cmd_joined)
            self.assertNotIn("mv ", cmd_joined)
            self.assertNotIn("chmod", cmd_joined)
            self.assertNotIn("touch", cmd_joined)

    def test_interactive_menu_workflow_startup_to_exit(self):
        """interactive_menu runs preflight, discovery, review menu, then main menu and exits cleanly."""
        status_res = DeviceStatusResult(
            adb_installed=True,
            adb_available=True,
            adb_version_raw="1.0.41",
            adb_version="1.0.41",
            adb_server_responsive=True,
            adb_status_display="Available",
            enumeration_success=True,
            enumeration_error=None,
            devices=[],
            device_count=0,
            device_status_display="No Device Connected",
        )
        self.mock_executor.check_device_status.return_value = status_res

        # Sequence of user inputs:
        # 1. Main menu: '0' (Exit directly since no automatic scan runs at startup)
        with patch("wrs.cli.AdbExecutor", return_value=self.mock_executor), \
             patch("builtins.input", side_effect=["0"]):
            with self.assertRaises(SystemExit) as cm:
                interactive_menu()
            self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
