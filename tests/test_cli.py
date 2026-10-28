"""Unit tests for CLI dispatcher and argument parsing (src/wrs/cli.py)."""

import io
import unittest
from unittest.mock import patch

from wrs.cli import ask_acquisition_confirmation, parse_args, print_banner
from wrs.device import AdbExecutor


class TestCliModule(unittest.TestCase):
    """Test argument parsing, banner output, and confirmation prompts."""

    def test_parse_arguments(self):
        """Verify parsing of CLI arguments for headless automation."""
        with patch("sys.argv", ["wrs.py", "--device", "SERIAL_123", "--acquire", "--output", "./custom_rec", "--unattended"]):
            args = parse_args()
            self.assertEqual(args.device, "SERIAL_123")
            self.assertTrue(args.acquire)
            self.assertEqual(args.output, "./custom_rec")
            self.assertTrue(args.unattended)

    def test_confirmation_prompt_default_no(self):
        """Rule: Mandatory confirmation must default to No and reject empty or 'n' inputs."""
        # Empty input -> False
        with patch("builtins.input", return_value=""):
            self.assertFalse(ask_acquisition_confirmation("/fake/path"))

        # Explicit 'n' -> False
        with patch("builtins.input", return_value="n"):
            self.assertFalse(ask_acquisition_confirmation("/fake/path"))

        # 'no' -> False
        with patch("builtins.input", return_value="no"):
            self.assertFalse(ask_acquisition_confirmation("/fake/path"))

        # Explicit 'y' -> True
        with patch("builtins.input", return_value="y"):
            self.assertTrue(ask_acquisition_confirmation("/fake/path"))

        # Explicit 'yes' -> True
        with patch("builtins.input", return_value="YES"):
            self.assertTrue(ask_acquisition_confirmation("/fake/path"))

    def test_banner_printing(self):
        """Verify banner displays version and local processing status."""
        executor = AdbExecutor(adb_path="/usr/bin/adb")
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_banner(executor)
        out = buf.getvalue()
        self.assertIn("WRS — WhatsApp Recovery Scanner", out)
        self.assertIn("100% Local Execution", out)


if __name__ == "__main__":
    unittest.main()
