"""Unit tests for device detection and inspection module (src/wrs/device.py)."""

import subprocess
import unittest
from unittest.mock import MagicMock

from wrs.device import AdbExecutor, DeviceInfo


class TestDeviceModule(unittest.TestCase):
    """Test device enumeration, property parsing, and error handling."""

    def test_list_devices_parsing(self):
        """Verify parsing of 'adb devices -l' with multiple devices and states."""
        mock_output = (
            "List of devices attached\n"
            "emulator-5554          device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64 device:emu64x transport_id:1\n"
            "988a1b424d554a434d     unauthorized usb:1-1 transport_id:2\n"
            "RF8M10XXXX             offline transport_id:3\n"
        )
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(
            args=["adb", "devices", "-l"],
            returncode=0,
            stdout=mock_output,
            stderr="",
        ))

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=mock_runner)
        devices = executor.list_devices()

        self.assertEqual(len(devices), 3)

        dev1 = devices[0]
        self.assertEqual(dev1.serial, "emulator-5554")
        self.assertEqual(dev1.state, "device")
        self.assertEqual(dev1.product_name, "sdk_gphone64_x86_64")

        dev2 = devices[1]
        self.assertEqual(dev2.serial, "988a1b424d554a434d")
        self.assertEqual(dev2.state, "unauthorized")
        self.assertIn("unlock your phone", dev2.error_message)

        dev3 = devices[2]
        self.assertEqual(dev3.serial, "RF8M10XXXX")
        self.assertEqual(dev3.state, "offline")
        self.assertIn("offline", dev3.error_message)

    def test_get_device_details_success(self):
        """Verify querying device hardware and OS properties."""
        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "devices -l" in cmd_str:
                out = "List of devices attached\n123456789 device model:Pixel_7\n"
                return subprocess.CompletedProcess(cmd, 0, out, "")
            elif "getprop" in cmd_str:
                props = (
                    "[ro.product.manufacturer]: [Google]\n"
                    "[ro.product.model]: [Pixel 7]\n"
                    "[ro.build.version.release]: [14]\n"
                    "[ro.build.version.sdk]: [34]\n"
                    "[ro.product.name]: [cheetah]\n"
                )
                return subprocess.CompletedProcess(cmd, 0, props, "")
            elif "ls -d /sdcard" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "/sdcard\n", "")
            elif "ls /storage/" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "emulated self 9C33-6BBD\n", "")
            elif "ls /storage/9C33-6BBD" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "Android DCIM\n", "")
            elif "dumpsys window" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "mKeyguardShowing=false\n", "")
            elif "id" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "uid=2000(shell) gid=2000(shell)\n", "")
            elif "which su" in cmd_str:
                return subprocess.CompletedProcess(cmd, 1, "", "not found\n")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        details = executor.get_device_details("123456789")

        self.assertEqual(details.serial, "123456789")
        self.assertEqual(details.manufacturer, "Google")
        self.assertEqual(details.model, "Pixel 7")
        self.assertEqual(details.android_version, "14")
        self.assertEqual(details.sdk_version, "34")
        self.assertTrue(details.internal_storage_accessible)
        self.assertTrue(details.removable_storage_accessible)
        self.assertIn("/storage/9C33-6BBD", details.removable_mounts)
        self.assertTrue(details.screen_unlocked)
        self.assertEqual(details.root_status, "NOT_DETECTED")
        self.assertTrue(details.is_accessible)

    def test_missing_adb_executable(self):
        """Verify behavior when ADB is not installed or invalid path given."""
        executor = AdbExecutor(adb_path="/nonexistent/adb")
        ok, msg = executor.get_adb_version()
        self.assertFalse(ok)
        self.assertIn("not found", msg)
        self.assertEqual(executor.list_devices(), [])


if __name__ == "__main__":
    unittest.main()
