"""Unit tests for recursive scanner module (src/wrs/scanner.py)."""

import subprocess
import unittest
from datetime import datetime

from wrs.categorizer import CAT_IMAGES, CAT_VOICE_NOTES
from wrs.device import AdbExecutor
from wrs.discovery import DiscoveredLocation
from wrs.scanner import FileScanner


class TestScannerModule(unittest.TestCase):
    """Test find+stat batch enumeration, ls -la fallback, and aggregation."""

    def test_find_stat_enumeration_with_spaces_and_unicode(self):
        """Verify parsing of stat line output with spaces, unicode, and correct metadata."""
        now_epoch = int(datetime(2026, 10, 28, 10, 30, 0).timestamp())
        mock_output = (
            f"1048576|{now_epoch}|/sdcard/WhatsApp/Media/WhatsApp Images/photo with spaces.jpg\n"
            f"524288|{now_epoch}|/sdcard/WhatsApp/Media/WhatsApp Voice Notes/202643/PTT-Éléphant.opus\n"
        )

        def fake_runner(cmd, **kwargs):
            if "find" in " ".join(cmd):
                return subprocess.CompletedProcess(cmd, 0, mock_output, "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        scanner = FileScanner(executor)
        loc = DiscoveredLocation(
            path="/sdcard/WhatsApp/",
            canonical_path="/storage/emulated/0/WhatsApp/",
            app_type="WhatsApp Standard",
            exists=True,
            is_readable=True,
        )

        res = scanner.scan_location("SERIAL_TEST", loc)

        self.assertEqual(res.total_files, 2)
        self.assertEqual(res.total_bytes, 1048576 + 524288)

        f1 = res.files[0]
        self.assertEqual(f1.filename, "photo with spaces.jpg")
        self.assertEqual(f1.category, CAT_IMAGES)
        self.assertEqual(f1.size_bytes, 1048576)

        f2 = res.files[1]
        self.assertEqual(f2.filename, "PTT-Éléphant.opus")
        self.assertEqual(f2.category, CAT_VOICE_NOTES)
        self.assertEqual(f2.size_bytes, 524288)

    def test_fallback_walk_enumeration(self):
        """Verify fallback recursive walk when find command returns empty or fails."""
        def fake_runner(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            # find fails
            if "find" in cmd_str:
                return subprocess.CompletedProcess(cmd, 1, "", "find error")
            # ls -la on root
            if "ls -la" in cmd_str and "/sdcard/WhatsApp" in cmd_str:
                out = (
                    "total 16\n"
                    "drwxrwx--x 3 root sdcard_rw 4096 2026-10-28 10:00 .\n"
                    "drwxrwx--x 4 root sdcard_rw 4096 2026-10-28 09:00 ..\n"
                    "-rw-rw---- 1 root sdcard_rw 2048 2026-10-28 10:00 .nomedia\n"
                )
                return subprocess.CompletedProcess(cmd, 0, out, "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        executor = AdbExecutor(adb_path="/usr/bin/adb", runner=fake_runner)
        scanner = FileScanner(executor)
        loc = DiscoveredLocation(
            path="/sdcard/WhatsApp/",
            canonical_path="/storage/emulated/0/WhatsApp/",
            app_type="WhatsApp Standard",
            exists=True,
            is_readable=True,
        )

        res = scanner.scan_location("SERIAL_TEST", loc)
        self.assertEqual(res.total_files, 1)
        self.assertEqual(res.files[0].filename, ".nomedia")
        self.assertEqual(res.files[0].size_bytes, 2048)


if __name__ == "__main__":
    unittest.main()
