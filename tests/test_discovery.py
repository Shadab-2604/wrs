"""Unit tests for storage discovery module (src/wrs/discovery.py)."""

import subprocess
import unittest

from wrs.device import AdbExecutor, DeviceInfo
from wrs.discovery import StorageDiscovery


class TestDiscoveryModule(unittest.TestCase):
    """Test candidate inspection, symlink normalization, and deduplication."""

    def test_discovery_normalization_and_deduplication(self):
        """Verify that symlinks (/sdcard vs /storage/emulated/0) are normalized and deduplicated."""
        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            # Both /sdcard/WhatsApp/ and /storage/emulated/0/WhatsApp/ exist
            if "test -d" in cmd_str:
                if "/sdcard/WhatsApp/" in cmd_str or "/storage/emulated/0/WhatsApp/" in cmd_str:
                    return subprocess.CompletedProcess(cmd, 0, "EXISTS\n", "")
                return subprocess.CompletedProcess(cmd, 1, "", "")

            # readlink/realpath resolves /sdcard/WhatsApp/ to /storage/emulated/0/WhatsApp/
            if "readlink -f" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "/storage/emulated/0/WhatsApp/\n", "")

            # Directory is readable
            if "ls -d" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "Databases Media Backups\n", "")

            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        discovery = StorageDiscovery(executor)

        device = DeviceInfo(serial="mock_dev", state="device")
        locations = discovery.discover_locations(
            device=device,
            custom_candidates=[
                "/sdcard/WhatsApp/",
                "/storage/emulated/0/WhatsApp/",
            ],
        )

        # Only 1 unique canonical location should be returned
        self.assertEqual(len(locations), 1)
        loc = locations[0]
        self.assertEqual(loc.canonical_path, "/storage/emulated/0/WhatsApp/")
        self.assertTrue(loc.exists)
        self.assertTrue(loc.is_readable)
        self.assertEqual(loc.app_type, "WhatsApp Standard")
        # The alternate path should be recorded as an alias
        self.assertTrue(len(loc.aliases) > 0 or loc.path == "/sdcard/WhatsApp/")

    def test_whatsapp_business_detection(self):
        """Verify detection of WhatsApp Business package storage."""
        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "test -d" in cmd_str and "com.whatsapp.w4b" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "EXISTS\n", "")
            if "readlink" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp/\n", "")
            if "ls -d" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, "Media\n", "")
            return subprocess.CompletedProcess(cmd, 1, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        discovery = StorageDiscovery(executor)

        device = DeviceInfo(serial="mock_dev", state="device")
        locations = discovery.discover_locations(
            device=device,
            custom_candidates=["/sdcard/Android/media/com.whatsapp.w4b/WhatsApp/"],
        )

        self.assertEqual(len(locations), 1)
        self.assertEqual(locations[0].app_type, "WhatsApp Business")


if __name__ == "__main__":
    unittest.main()
