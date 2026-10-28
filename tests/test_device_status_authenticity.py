"""Comprehensive automated tests for authentic ADB status and Android device enumeration.

Validates the 10 bug-fix scenarios and real-time data authenticity:
1. ADB available, zero devices.
2. One authorized device.
3. One unauthorized device.
4. One offline device.
5. Multiple devices (explicit selection required).
6. ADB missing.
7. ADB timeout.
8. Nonzero return code (distinguishes enumeration failure from empty device list).
9. Malformed device list and ADB daemon startup noise filtering.
10. Device disconnection after initial detection.
11. Single source of truth / RuntimeStateManager lifecycles.
12. Filesystem & integrity authenticity (empty, error, mismatch).
"""

from __future__ import annotations

import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from wrs.cli import (
    detect_and_display_startup_devices,
    print_banner,
)
from wrs.device import AdbExecutor, DeviceInfo, DeviceStatusResult
from wrs.discovery import DiscoveredLocation
from wrs.hashing import (
    STATUS_HASH_MISMATCH,
    STATUS_SIZE_MISMATCH,
    STATUS_VERIFIED,
    evaluate_acquisition_integrity,
    hash_local_file,
)
from wrs.reporting import ReportGenerator
from wrs.scanner import FileScanner, ScanResult
from wrs.state import OperationState, RuntimeStateManager, ValueLifecycle


class TestDeviceStatusAuthenticity(unittest.TestCase):
    """Test authentic ADB and Android device state tracking and dynamic UI enforcement."""

    def setUp(self) -> None:
        RuntimeStateManager.reset_instance()

    def test_adb_available_zero_devices(self) -> None:
        """1. ADB available, zero devices: shows AVAILABLE and NONE DETECTED, never CONNECTED."""
        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "version" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "Android Debug Bridge version 1.0.41\nVersion 34.0.4-linux\n", "")
            if "devices" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "List of devices attached\n\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        status = executor.check_device_status()

        self.assertTrue(status.adb_installed)
        self.assertTrue(status.adb_available)
        self.assertEqual(status.adb_version, "1.0.41")
        self.assertIn("AVAILABLE (version 1.0.41)", status.adb_status_display)
        self.assertTrue(status.enumeration_success)
        self.assertEqual(status.device_count, 0)
        self.assertEqual(status.device_status_display, "NONE DETECTED")
        self.assertIsNone(status.selected_device)

        # Verify terminal banner rendering
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_banner(executor, device_status=status)
        out = buf.getvalue()

        self.assertIn("ADB Status      : AVAILABLE (version 1.0.41)", out)
        self.assertIn("Android Device  : NONE DETECTED", out)
        self.assertIn("Processing Mode : 100% Local Execution", out)
        self.assertNotIn("Android Device  : CONNECTED", out)

    def test_one_authorized_device(self) -> None:
        """2. One authorized device: displays CONNECTED AND AUTHORIZED and real properties."""
        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "version" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "Android Debug Bridge version 1.0.41\n", "")
            if "devices" in cmd_str:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    "List of devices attached\nPIXEL_8_SERIAL\tdevice product:shiba model:Pixel_8 device:shiba\n",
                    "",
                )
            if "getprop" in cmd_str:
                props = (
                    "[ro.product.manufacturer]: [Google]\n"
                    "[ro.product.model]: [Pixel 8]\n"
                    "[ro.build.version.release]: [14]\n"
                    "[ro.build.version.sdk]: [34]\n"
                )
                return subprocess.CompletedProcess(cmd, 0, props, "")
            if "get-state" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "device\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        status = executor.check_device_status()

        self.assertEqual(status.device_count, 1)
        self.assertIsNotNone(status.selected_device)
        self.assertTrue(status.selected_device.is_authorized)
        self.assertEqual(status.selected_device.display_name, "Google Pixel 8")
        self.assertEqual(status.device_status_display, "CONNECTED AND AUTHORIZED")

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_banner(executor, device=status.selected_device, device_status=status)
        out = buf.getvalue()

        self.assertIn("ADB Status      : AVAILABLE (version 1.0.41)", out)
        self.assertIn("Android Device  : Google Pixel 8 (CONNECTED AND AUTHORIZED)", out)

    def test_one_unauthorized_device(self) -> None:
        """3. One unauthorized device: reports UNAUTHORIZED, does NOT query properties."""
        queried_props = []

        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "version" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "Android Debug Bridge version 1.0.41\n", "")
            if "devices" in cmd_str:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    "List of devices attached\nUNAUTH_DEV_99\tunauthorized usb:1-1\n",
                    "",
                )
            if "getprop" in cmd_str:
                queried_props.append(cmd_str)
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        status = executor.check_device_status()

        self.assertEqual(status.device_count, 1)
        self.assertIsNotNone(status.selected_device)
        self.assertFalse(status.selected_device.is_authorized)
        self.assertEqual(status.selected_device.state, "unauthorized")
        self.assertEqual(status.device_status_display, "UNAUTHORIZED")
        # Ensure no property queries occurred against unauthorized device
        self.assertEqual(len(queried_props), 0)

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_banner(executor, device=status.selected_device, device_status=status)
        out = buf.getvalue()

        self.assertIn("Android Device  : UNAUTHORIZED (UNAUTH_DEV_99)", out)
        self.assertNotIn("CONNECTED AND AUTHORIZED", out)

    def test_one_offline_device(self) -> None:
        """4. One offline device: reports OFFLINE, does NOT query properties."""
        queried_props = []

        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "version" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "Android Debug Bridge version 1.0.41\n", "")
            if "devices" in cmd_str:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    "List of devices attached\nemulator-5554\toffline\n",
                    "",
                )
            if "getprop" in cmd_str:
                queried_props.append(cmd_str)
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        status = executor.check_device_status()

        self.assertEqual(status.device_count, 1)
        self.assertIsNotNone(status.selected_device)
        self.assertFalse(status.selected_device.is_authorized)
        self.assertEqual(status.selected_device.state, "offline")
        self.assertEqual(status.device_status_display, "OFFLINE")
        self.assertEqual(len(queried_props), 0)

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_banner(executor, device=status.selected_device, device_status=status)
        out = buf.getvalue()

        self.assertIn("Android Device  : OFFLINE (emulator-5554)", out)

    def test_multiple_devices_require_explicit_selection(self) -> None:
        """5. Multiple devices: shows actual count, prohibits implicit selection."""
        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "version" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "Android Debug Bridge version 1.0.41\n", "")
            if "devices" in cmd_str:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    "List of devices attached\n"
                    "DEV_A\tdevice product:pA model:Phone_A\n"
                    "DEV_B\tunauthorized\n",
                    "",
                )
            if "DEV_A" in cmd_str and "getprop" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "[ro.product.manufacturer]: [OEM_A]\n[ro.product.model]: [Phone A]\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        status = executor.check_device_status()

        self.assertEqual(status.device_count, 2)
        # MUST NOT implicitly select DEV_A
        self.assertIsNone(status.selected_device)
        self.assertIn("2 DETECTED (Selection Required)", status.device_status_display)

        # Explicit selection works when serial is provided
        status_with_sel = executor.check_device_status(selected_serial="DEV_A")
        self.assertIsNotNone(status_with_sel.selected_device)
        self.assertEqual(status_with_sel.selected_device.serial, "DEV_A")

    def test_adb_missing(self) -> None:
        """6. ADB executable missing: reports NOT INSTALLED."""
        executor = AdbExecutor(adb_path="/nonexistent/adb")
        with patch.object(executor, "is_adb_installed", return_value=False):
            status = executor.check_device_status()

        self.assertFalse(status.adb_installed)
        self.assertFalse(status.adb_available)
        self.assertEqual(status.adb_status_display, "NOT INSTALLED")
        self.assertEqual(status.device_count, 0)
        self.assertIn("UNAVAILABLE", status.device_status_display)

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_banner(executor, device_status=status)
        out = buf.getvalue()
        self.assertIn("ADB Status      : NOT INSTALLED", out)

    def test_adb_command_timeout(self) -> None:
        """7. ADB timeout: reports ERROR (Command timed out)."""
        def fake_runner(cmd, **kwargs):
            return subprocess.CompletedProcess(
                cmd, -1, "", "Command timed out after 10 seconds: timeout expired"
            )

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        with patch.object(executor, "is_adb_installed", return_value=True):
            status = executor.check_device_status()

        self.assertFalse(status.adb_available)
        self.assertIn("ERROR (Command timed out)", status.adb_status_display)

    def test_nonzero_return_code_distinguishes_failure_from_none_detected(self) -> None:
        """8. Nonzero return code: reports ENUMERATION FAILED, not 'NONE DETECTED'."""
        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "version" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "Android Debug Bridge version 1.0.41\n", "")
            if "devices" in cmd_str:
                return subprocess.CompletedProcess(cmd, 1, "", "error: could not connect to adb server")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        status = executor.check_device_status()

        self.assertTrue(status.adb_available)
        self.assertFalse(status.enumeration_success)
        self.assertIn("ENUMERATION FAILED", status.device_status_display)
        self.assertNotIn("NONE DETECTED", status.device_status_display)

    def test_daemon_startup_noise_and_malformed_entries(self) -> None:
        """9. Filters daemon startup messages (* daemon...) and ignores malformed entries."""
        raw_adb_devices = (
            "* daemon not running; starting now at tcp:5037\n"
            "* daemon started successfully\n"
            "List of devices attached\n"
            "* corrupted daemon output token\n"
            "GARBAGE_SINGLE_TOKEN\n"
            "VALID_SERIAL_01\tdevice product:tangorpro model:Pixel_Tablet device:tangorpro\n"
        )

        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "version" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "Android Debug Bridge version 1.0.41\n", "")
            if "devices" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, raw_adb_devices, "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        status = executor.check_device_status()

        self.assertTrue(status.enumeration_success)
        # Must have exactly 1 valid device, not 3 or 4
        self.assertEqual(status.device_count, 1)
        self.assertEqual(status.devices[0].serial, "VALID_SERIAL_01")
        self.assertEqual(status.devices[0].state, "device")
        # Ensure daemon was not treated as device
        for d in status.devices:
            self.assertFalse(d.serial.startswith("*"))
            self.assertNotEqual(d.serial, "daemon")

    def test_device_disconnection_after_initial_detection(self) -> None:
        """10. Device disconnection after startup marks state stale and prevents operations."""
        is_connected = [True]

        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "version" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "Android Debug Bridge version 1.0.41\n", "")
            if "devices" in cmd_str:
                if is_connected[0]:
                    return subprocess.CompletedProcess(
                        cmd, 0,
                        "List of devices attached\nDEV_HOTPLUG\tdevice\n",
                        "",
                    )
                return subprocess.CompletedProcess(cmd, 0, "List of devices attached\n\n", "")
            if "get-state" in cmd_str:
                if is_connected[0]:
                    return subprocess.CompletedProcess(cmd, 0, "device\n", "")
                return subprocess.CompletedProcess(cmd, 1, "", "error: device 'DEV_HOTPLUG' not found\n")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)

        # Step A: Initially connected
        valid, dev, msg = executor.revalidate_selected_device("DEV_HOTPLUG")
        self.assertTrue(valid)
        self.assertIsNotNone(dev)

        # Step B: Device physically unplugged
        is_connected[0] = False
        valid2, dev2, msg2 = executor.revalidate_selected_device("DEV_HOTPLUG")
        self.assertFalse(valid2)
        self.assertIn("no longer connected", msg2)

        # Check state manager invalidated device
        sm = RuntimeStateManager.get_instance()
        self.assertIsNone(sm.selected_device)
        self.assertIn("DISCONNECTED", sm.device_status_display)

    def test_single_source_of_truth_runtime_state_manager(self) -> None:
        """11. Single source of truth tracks ValueLifecycle and OperationState."""
        sm = RuntimeStateManager.get_instance()
        sm.set_entry("target_dir", "/recovery/case_1", ValueLifecycle.CONFIGURED, "settings.json")
        sm.set_operation_state("scan", OperationState.IN_PROGRESS)

        self.assertEqual(sm.scan_state, OperationState.IN_PROGRESS)
        entry = sm.get_entry("scan_state")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.value, "IN_PROGRESS")
        self.assertEqual(entry.lifecycle, ValueLifecycle.OBSERVED)

        sm.set_operation_state("scan", OperationState.COMPLETED)
        self.assertEqual(sm.scan_state, OperationState.COMPLETED)
        self.assertEqual(sm.get_entry("scan_state").lifecycle, ValueLifecycle.COMPLETED)

    def test_filesystem_authenticity_and_verification_integrity(self) -> None:
        """12. Authenticity: Empty directories, file size mismatches, and hash checks."""
        with tempfile.TemporaryDirectory() as tmp_dir_str:
            tmp_path = Path(tmp_dir_str)
            src_file = tmp_path / "test_file.txt"
            src_file.write_text("authentic_forensic_content", encoding="utf-8")

            # Calculate SHA-256
            import hashlib
            expected_hash = hashlib.sha256(b"authentic_forensic_content").hexdigest()

            # Compute hash
            hash_str, f_size, err = hash_local_file(src_file)
            self.assertEqual(hash_str, expected_hash)
            self.assertEqual(f_size, src_file.stat().st_size)
            self.assertIsNone(err)

            # Positive match
            rec_ok = evaluate_acquisition_integrity(
                source_path="/sdcard/WhatsApp/test_file.txt",
                dest_path=src_file,
                expected_size=src_file.stat().st_size,
                source_hash=expected_hash,
                dest_hash=hash_str,
                acquired_size=f_size,
            )
            self.assertEqual(rec_ok.status, STATUS_VERIFIED)

            # Modified file (mismatch)
            tampered_file = tmp_path / "tampered.txt"
            tampered_file.write_text("tampered_content", encoding="utf-8")
            t_hash, t_size, _ = hash_local_file(tampered_file)

            rec_fail = evaluate_acquisition_integrity(
                source_path="/sdcard/WhatsApp/test_file.txt",
                dest_path=tampered_file,
                expected_size=src_file.stat().st_size,
                source_hash=expected_hash,
                dest_hash=t_hash,
                acquired_size=t_size,
            )
            self.assertIn(rec_fail.status, (STATUS_HASH_MISMATCH, STATUS_SIZE_MISMATCH))
            self.assertIsNotNone(rec_fail.error_message)

    def test_report_authenticity_no_hardcoded_placeholders(self) -> None:
        """13. Reports must reflect actual scan results and contain no placeholder strings."""
        with tempfile.TemporaryDirectory() as tmp_dir_str:
            rep_dir = Path(tmp_dir_str)
            dev = DeviceInfo(serial="DEV_REAL_001", state="device", manufacturer="Motorola", model="Moto G")
            scan_res = ScanResult(
                device_serial="DEV_REAL_001",
                location_path="/sdcard/WhatsApp",
                start_time="2026-10-28 10:00:00",
                end_time="2026-10-28 10:01:00",
                total_files=2,
                total_bytes=1048576,
                files=[],
                errors=[],
            )

            rep_gen = ReportGenerator(device=dev, scan_result=scan_res, output_dir=rep_dir)
            html_p, csv_p, json_p = rep_gen.generate_all()

            json_content = json_p.read_text(encoding="utf-8")
            self.assertIn("DEV_REAL_001", json_content)
            self.assertIn('"manufacturer": "Motorola"', json_content)
            self.assertIn('"model": "Moto G"', json_content)
            self.assertIn("1048576", json_content)
            # Ensure no mock / fake test serials leaked into production report structure
            self.assertNotIn("DEMO_SERIAL", json_content)
            self.assertNotIn("FAKE_DEVICE", json_content)

            html_content = html_p.read_text(encoding="utf-8")
            self.assertIn("Motorola Moto G", html_content)


if __name__ == "__main__":
    unittest.main()
