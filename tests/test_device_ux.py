"""Unit tests for Device-Aware CLI and UX enhancements (Phase 3).

Validates device enumeration, startup preflight banners, single/multiple device selection,
unauthorized/offline/disconnected states, fallback naming, Unicode handling, and serial masking.
"""

import io
import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from wrs.cli import (
    detect_and_display_startup_devices,
    get_environment_name,
    print_banner,
    select_device_interactive,
)
from wrs.device import AdbExecutor, DeviceInfo, generate_device_identifier
from wrs.errors import (
    ERR_DEVICE_DISCONNECTED,
    ERR_DEVICE_OFFLINE,
    ERR_DEVICE_UNAUTHORIZED,
    format_actionable_error,
)
from wrs.utils import mask_serial


class TestDeviceUX(unittest.TestCase):
    """Test device-aware UX, startup preflight, stability, and failure handling."""

    def test_environment_detection(self):
        """Verify environment name detection produces non-empty string."""
        env_name = get_environment_name()
        self.assertTrue(len(env_name) > 0)

    def test_no_devices_connected_banner_and_advisory(self):
        """Requirement 2: Zero devices connected must display actionable 5-step advisory."""
        def fake_runner(cmd, **kwargs):
            if "version" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "Android Debug Bridge version 1.0.41\n", "")
            if "devices" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "List of devices attached\n\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            devices, selected = detect_and_display_startup_devices(executor)

        out = buf.getvalue()
        self.assertEqual(len(devices), 0)
        self.assertIsNone(selected)
        self.assertIn("Connected Devices : 0", out)
        self.assertIn("[!] No authorized Android device detected.", out)
        self.assertIn("Enable USB debugging", out)
        self.assertIn("[R] Retry", out)
        self.assertIn("[Q] Exit", out)
        self.assertIn("Selected Device  : None", out)

    def test_one_authorized_device_auto_selection(self):
        """Requirement 2: Exactly one authorized device is highlighted and selected automatically."""
        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "version" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "Android Debug Bridge version 1.0.41\n", "")
            if "devices" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    "List of devices attached\n28241FDH2006G7\tdevice product:cheetah model:Pixel_7 device:cheetah\n",
                    "",
                )
            if "getprop" in cmd_str:
                props = (
                    "[ro.product.manufacturer]: [Google]\n"
                    "[ro.product.model]: [Pixel 7]\n"
                    "[ro.build.version.release]: [14]\n"
                    "[ro.build.version.sdk]: [34]\n"
                )
                return subprocess.CompletedProcess(cmd, 0, props, "")
            if "get-state" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "device\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            devices, selected = detect_and_display_startup_devices(executor)

        out = buf.getvalue()
        self.assertEqual(len(devices), 1)
        self.assertIsNotNone(selected)
        self.assertEqual(selected.display_name, "Google Pixel 7")
        self.assertEqual(selected.manufacturer, "Google")
        self.assertEqual(selected.model, "Pixel 7")
        self.assertEqual(selected.android_version, "14")
        self.assertIn("Google Pixel 7", out)
        self.assertIn("CONNECTED / AUTHORIZED", out)
        self.assertIn("Selected Device  : Google Pixel 7", out)

    def test_multiple_devices_numbered_selection(self):
        """Requirement 2: Multiple devices display numbered table and require explicit selection."""
        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "version" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "Android Debug Bridge version 1.0.41\n", "")
            if "devices" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    "List of devices attached\n"
                    "DEV_PIXEL\tdevice product:cheetah model:Pixel_7 device:cheetah\n"
                    "DEV_SAMSUNG\tdevice product:dm3q model:SM_S918B device:dm3q\n",
                    "",
                )
            if "DEV_PIXEL" in cmd_str and "getprop" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "[ro.product.manufacturer]: [Google]\n[ro.product.model]: [Pixel 7]\n", "")
            if "DEV_SAMSUNG" in cmd_str and "getprop" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "[ro.product.manufacturer]: [Samsung]\n[ro.product.model]: [Galaxy S23]\n", "")
            if "get-state" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "device\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        buf = io.StringIO()
        # User selects device 2 (Samsung Galaxy S23)
        with patch("sys.stdout", buf), patch("builtins.input", return_value="2"):
            devices, selected = detect_and_display_startup_devices(executor)

        out = buf.getvalue()
        self.assertEqual(len(devices), 2)
        self.assertIsNotNone(selected)
        self.assertEqual(selected.serial, "DEV_SAMSUNG")
        self.assertEqual(selected.display_name, "Samsung Galaxy S23")
        self.assertIn("[1] Google Pixel 7", out)
        self.assertIn("[2] Samsung Galaxy S23", out)
        self.assertIn("Selected Device  : Samsung Galaxy S23", out)

    def test_unauthorized_device_state_and_guidance(self):
        """Requirement 2: Unauthorized device displays UNAUTHORIZED status and actionable instructions."""
        def fake_runner(cmd, **kwargs):
            if "version" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "Android Debug Bridge version 1.0.41\n", "")
            if "devices" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    "List of devices attached\nUNAUTH_123\tunauthorized\n",
                    "",
                )
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            devices, selected = detect_and_display_startup_devices(executor)

        out = buf.getvalue()
        self.assertEqual(len(devices), 1)
        self.assertEqual(selected.status_display, "UNAUTHORIZED")
        self.assertFalse(selected.is_accessible)
        self.assertIn("UNAUTHORIZED", out)
        self.assertIn("USB Debugging Unauthorized", out)
        self.assertIn("Allow USB debugging", out)

    def test_offline_device_state_and_guidance(self):
        """Requirement 2: Offline device displays OFFLINE status and reconnection instructions."""
        def fake_runner(cmd, **kwargs):
            if "version" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "Android Debug Bridge version 1.0.41\n", "")
            if "devices" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    "List of devices attached\nOFFLINE_123\toffline\n",
                    "",
                )
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            devices, selected = detect_and_display_startup_devices(executor)

        out = buf.getvalue()
        self.assertEqual(len(devices), 1)
        self.assertEqual(selected.status_display, "OFFLINE")
        self.assertFalse(selected.is_accessible)
        self.assertIn("OFFLINE", out)
        self.assertIn("Device is Offline", out)
        self.assertIn("Disconnect and firmly reconnect the USB cable", out)

    def test_missing_properties_fallback_naming(self):
        """Requirement 1: Device without manufacturer/model falls back to neutral Android Device (<suffix>)."""
        dev = DeviceInfo(serial="XYZ987654321", state="device")
        # Manufacturer and model are Unknown
        self.assertEqual(dev.display_name, "Android Device (654321)")

        dev_short = DeviceInfo(serial="ABC", state="device")
        self.assertEqual(dev_short.display_name, "Android Device (ABC)")

    def test_unicode_manufacturer_and_model_names(self):
        """Requirement 10: Unicode model and manufacturer names handled without corruption."""
        dev = DeviceInfo(
            serial="HW_UNICODE_123",
            state="device",
            manufacturer="华为",
            model="P50 Pro 典藏版",
        )
        self.assertEqual(dev.display_name, "华为 P50 Pro 典藏版")

        # Duplicate manufacturer prefix in model should not be repeated
        dev_dupe = DeviceInfo(
            serial="SAMS_1",
            state="device",
            manufacturer="Samsung",
            model="Samsung Galaxy S24 Ultra",
        )
        self.assertEqual(dev_dupe.display_name, "Samsung Galaxy S24 Ultra")

    def test_serial_masking(self):
        """Requirement 9.B: Serial masking hides middle characters for privacy in console displays."""
        self.assertEqual(mask_serial("28241FDH2006G7"), "2824****06G7")
        self.assertEqual(mask_serial("1234567890"), "1234****7890")
        self.assertEqual(mask_serial("ABC12"), "****12")
        self.assertEqual(mask_serial(""), "")

        dev = DeviceInfo(serial="28241FDH2006G7", state="device")
        self.assertEqual(dev.get_display_serial(masked=False), "28241FDH2006G7")
        self.assertEqual(dev.get_display_serial(masked=True), "2824****06G7")

    def test_device_selection_stability(self):
        """Requirement 3: Device session maintains explicit target serial across operations."""
        executed_cmds = []

        def tracking_runner(cmd, **kwargs):
            executed_cmds.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, "device\n", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=tracking_runner)
        serial = "EXPLICIT_SERIAL_888"

        # Verify command execution includes -s serial
        executor.run_cmd(["shell", "ls", "/sdcard"], serial=serial)
        self.assertTrue(any("-s" in c and serial in c for c in executed_cmds))

    def test_device_disconnection_detection(self):
        """Requirement 3 & 8: Interruption when phone disconnects is detected and structured error returned."""
        def disconnected_runner(cmd, **kwargs):
            # adb get-state fails when disconnected
            return subprocess.CompletedProcess(cmd, 1, "", "error: device 'DISC_123' not found\n")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=disconnected_runner)
        is_conn = executor.is_device_connected("DISC_123")
        self.assertFalse(is_conn)

        err_msg = format_actionable_error(ERR_DEVICE_DISCONNECTED, device_name="Google Pixel 7")
        self.assertIn("Device Disconnected During Operation", err_msg)
        self.assertIn("Google Pixel 7", err_msg)
        self.assertIn("reconnect", err_msg.lower())

    def test_disconnection_during_file_acquisition_preserves_data(self):
        """Requirement 3: Disconnection during acquisition preserves completed files and saves interrupted record."""
        import tempfile
        import shutil
        from wrs.acquisition import AcquisitionManager
        from wrs.categorizer import CAT_IMAGES
        from wrs.scanner import ScannedFile, ScanResult

        temp_root = Path(tempfile.mkdtemp())
        try:
            call_count = [0]
            def pull_then_disconnect_runner(cmd, **kwargs):
                cmd_str = " ".join(cmd)
                if "pull" in cmd_str:
                    call_count[0] += 1
                    if call_count[0] == 1:
                        # First file succeeds
                        dest = Path(cmd[-1])
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(b"File 1 content")
                        return subprocess.CompletedProcess(cmd, 0, "", "")
                    else:
                        # Second file fails due to disconnection
                        return subprocess.CompletedProcess(cmd, 1, "", "error: device offline\n")
                if "get-state" in cmd_str:
                    if call_count[0] >= 1:
                        return subprocess.CompletedProcess(cmd, 1, "", "error: device offline\n")
                    return subprocess.CompletedProcess(cmd, 0, "device\n", "")
                return subprocess.CompletedProcess(cmd, 0, "", "")

            executor = AdbExecutor(adb_path="/usr/bin/adb", runner=pull_then_disconnect_runner)
            mgr = AcquisitionManager(executor, base_recovery_dir=temp_root)
            dev = DeviceInfo(serial="DEV_DISC", state="device", manufacturer="Google", model="Pixel 7")

            f1 = ScannedFile(
                original_path="/sdcard/WhatsApp/Media/img1.jpg",
                relative_path="Media/img1.jpg",
                filename="img1.jpg",
                extension=".jpg",
                category=CAT_IMAGES,
                size_bytes=14,
                size_human="14 B",
            )
            f2 = ScannedFile(
                original_path="/sdcard/WhatsApp/Media/img2.jpg",
                relative_path="Media/img2.jpg",
                filename="img2.jpg",
                extension=".jpg",
                category=CAT_IMAGES,
                size_bytes=20,
                size_human="20 B",
            )
            scan_res = ScanResult(
                device_serial="DEV_DISC",
                location_path="/sdcard/WhatsApp",
                start_time="2026-10-28 10:00:00",
                end_time="2026-10-28 10:00:05",
                files=[f1, f2],
                total_files=2,
                total_bytes=34,
            )

            dest_dir = temp_root / "test_interrupted_scan"
            records = mgr.acquire_files(dev, scan_res, destination_dir=dest_dir)

            # First file was completed and preserved
            self.assertEqual(len(records), 1)
            self.assertTrue((dest_dir / "Images" / "Media" / "img1.jpg").exists())

            # Manifest was preserved
            manifest_p = dest_dir / "metadata" / "acquisition_manifest.json"
            self.assertTrue(manifest_p.exists())

            # Interrupted record was written
            interrupted_p = dest_dir / "metadata" / "interrupted.json"
            self.assertTrue(interrupted_p.exists())
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
