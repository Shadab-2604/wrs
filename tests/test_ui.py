"""Unit tests for WRS Terminal UI Styling and Rich Rendering Engine (src/wrs/ui.py)."""

from __future__ import annotations

import io
import os
import unittest
from unittest.mock import MagicMock, patch

from wrs.cli import parse_args
from wrs.ui import (
    get_console,
    is_color_enabled,
    make_rich_acquisition_progress_callback,
    make_rich_discovery_progress_callback,
    print_acquire,
    print_app_banner,
    print_category_selection_screen,
    print_confirmation_box,
    print_error,
    print_header,
    print_info,
    print_rich_missing_advisory,
    print_scan,
    print_success,
    print_table_data,
    print_warning,
    set_force_no_color,
)


class TestUIModule(unittest.TestCase):
    """Test suite for terminal color policy, status helpers, panels, tables, and progress."""

    def setUp(self) -> None:
        set_force_no_color(False)
        self.original_no_color = os.environ.get("NO_COLOR")
        self.original_term = os.environ.get("TERM")

    def tearDown(self) -> None:
        set_force_no_color(False)
        if self.original_no_color is not None:
            os.environ["NO_COLOR"] = self.original_no_color
        else:
            os.environ.pop("NO_COLOR", None)
        if self.original_term is not None:
            os.environ["TERM"] = self.original_term
        else:
            os.environ.pop("TERM", None)

    def test_color_policy_no_color_environment(self) -> None:
        """Requirement 9: is_color_enabled must return False when NO_COLOR is set."""
        os.environ["NO_COLOR"] = "1"
        self.assertFalse(is_color_enabled())

    def test_color_policy_term_dumb(self) -> None:
        """Requirement 9: is_color_enabled must return False when TERM=dumb."""
        os.environ.pop("NO_COLOR", None)
        os.environ["TERM"] = "dumb"
        self.assertFalse(is_color_enabled())

    def test_color_policy_force_disabled(self) -> None:
        """Requirement 9: set_force_no_color(True) disables color regardless of tty."""
        os.environ.pop("NO_COLOR", None)
        os.environ["TERM"] = "xterm-256color"
        set_force_no_color(True)
        self.assertFalse(is_color_enabled())

    def test_color_policy_non_tty_redirection(self) -> None:
        """Requirement 9: Non-tty output (pipes, files, StringIO) defaults to color-disabled."""
        os.environ.pop("NO_COLOR", None)
        os.environ["TERM"] = "xterm-256color"
        set_force_no_color(False)
        # sys.stdout in test runners is not an interactive tty
        mock_stdout = io.StringIO()
        with patch("sys.stdout", mock_stdout):
            self.assertFalse(is_color_enabled())

    def test_reusable_status_helpers_plain_text(self) -> None:
        """Requirement 5: Reusable helpers [SUCCESS], [INFO], [WARNING], [ERROR], [SCAN], [ACQUIRE]."""
        set_force_no_color(True)

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_success("Device authorized and ready.")
            print_info("Scanning accessible shared storage.")
            print_warning("Encrypted database detected; readability is not yet verified.")
            print_error("Device is unauthorized. Approve the debugging prompt on the phone.")
            print_scan("Scanning WhatsApp storage candidate locations.")
            print_acquire("Acquiring 42 selected files.")

        out = buf.getvalue()
        self.assertIn("[SUCCESS] Device authorized and ready.", out)
        self.assertIn("[INFO]    Scanning accessible shared storage.", out)
        self.assertIn("[WARNING] Encrypted database detected; readability is not yet verified.", out)
        self.assertIn("[ERROR]   Device is unauthorized. Approve the debugging prompt on the phone.", out)
        self.assertIn("[SCAN]    Scanning WhatsApp storage candidate locations.", out)
        self.assertIn("[ACQUIRE] Acquiring 42 selected files.", out)

    def test_screen_header_fallback(self) -> None:
        """Requirement 1 & 7: Headers display uppercase title and selected device cleanly."""
        set_force_no_color(True)
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_header("Chat Recovery", "Google Pixel 8 (SERIAL123)")

        out = buf.getvalue()
        self.assertIn("WRS — CHAT RECOVERY", out)
        self.assertIn("Selected Device : Google Pixel 8 (SERIAL123)", out)

    def test_app_banner_formatting(self) -> None:
        """Requirement 3: Professional banner displays title, subtitle, and runtime statuses."""
        set_force_no_color(True)
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_app_banner(
                version="2.0.0",
                adb_status_str="AVAILABLE (version 1.0.41)",
                device_status_str="Google Pixel 8 (CONNECTED AND AUTHORIZED)",
                scan_status_str="READY",
                timestamp_str="2026-10-28 10:00:00",
            )

        out = buf.getvalue()
        self.assertIn("WRS — WhatsApp Recovery Scanner", out)
        self.assertIn("Processing Mode : 100% Local Execution", out)
        self.assertIn("ADB Status      : AVAILABLE (version 1.0.41)", out)
        self.assertIn("Android Device  : Google Pixel 8 (CONNECTED AND AUTHORIZED)", out)
        self.assertIn("Version         : v2.0.0", out)
        self.assertIn("Timestamp       : 2026-10-28 10:00:00", out)

    def test_category_selection_screen_visual_distinction(self) -> None:
        """Requirement 4: Selected categories are visually distinguished with [●] vs [○]."""
        set_force_no_color(True)
        cat_map = {
            1: "All Supported Data",
            2: "Chat History",
            3: "Photos and Images",
            4: "Videos",
        }
        selected = {"Chat History", "Videos"}

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_category_selection_screen(cat_map, selected)

        out = buf.getvalue()
        self.assertIn("SELECT DATA CATEGORIES", out)
        self.assertIn("[●] [2 ] Chat History", out)
        self.assertIn("[○] [3 ] Photos and Images", out)
        self.assertIn("[●] [4 ] Videos", out)
        self.assertIn("[A] Select All Categories", out)
        self.assertIn("[C] Clear Selection", out)
        self.assertIn("[0] / [B] Back", out)
        self.assertIn("Selected: Chat History, Videos", out)

    def test_structured_table_rendering(self) -> None:
        """Requirement 2 & 7: Structured table renders headers and rows consistently."""
        set_force_no_color(True)
        headers = ["#", "Category", "Files", "Size"]
        rows = [
            ["[1]", "Databases", "3", "12.50 MiB"],
            ["[2]", "Images", "150", "45.00 MiB"],
        ]

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_table_data("Inventory Summary", headers, rows)

        out = buf.getvalue()
        self.assertIn("Inventory Summary", out)
        self.assertIn("Category", out)
        self.assertIn("Databases", out)
        self.assertIn("12.50 MiB", out)
        self.assertIn("Images", out)

    def test_confirmation_box_rendering(self) -> None:
        """Requirement 8: Confirmation box displays action description and key details."""
        set_force_no_color(True)
        details = {
            "Device": "Pixel 8",
            "Files": "42",
            "Total Size": "10.00 MiB",
            "Destination": "/recovery/dir",
        }

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_confirmation_box("The scanner is ready to copy files.", details)

        out = buf.getvalue()
        self.assertIn("ACQUISITION PREVIEW & CONFIRMATION", out)
        self.assertIn("Device", out)
        self.assertIn("Pixel 8", out)
        self.assertIn("Files", out)
        self.assertIn("42", out)
        self.assertIn("Destination", out)
        self.assertIn("No source files will be deleted or modified", out)

    def test_rich_missing_advisory(self) -> None:
        """Requirement 2: Friendly advisory when rich is absent, without raising errors."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_rich_missing_advisory()

        out = buf.getvalue()
        self.assertIn("Rich library is not installed", out)
        self.assertIn("pip install rich>=13.0.0", out)

    def test_parse_args_no_color_flag(self) -> None:
        """Requirement 9: Support --no-color command-line flag."""
        with patch("sys.argv", ["wrs.py", "--no-color", "--scan"]):
            args = parse_args()
            self.assertTrue(args.no_color)
            self.assertTrue(args.scan)

    def test_progress_callbacks_non_tty_behavior(self) -> None:
        """Requirement 6: Non-tty progress callbacks print clean periodic progress without carriage returns."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            disc_cb = make_rich_discovery_progress_callback("Vivo V2302", "/sdcard/WhatsApp", progress_enabled=False)
            disc_cb("Scanning", 5, 0, 0.5)
            disc_cb("Scanning", 250, 0, 1.2)

        out = buf.getvalue()
        self.assertIn("Scope: Accessible paths | Discovered: 5 files", out)
        self.assertIn("Scope: Accessible paths | Discovered: 250 files", out)
        self.assertNotIn("\r", out)

        buf_acq = io.StringIO()
        with patch("sys.stdout", buf_acq):
            acq_cb = make_rich_acquisition_progress_callback("Vivo V2302", 100, progress_enabled=False)
            acq_cb(25, 75, 1048576, 4194304, "msgstore.db.crypt14", "VERIFIED", 2.0)

        out_acq = buf_acq.getvalue()
        self.assertIn("[25/100] Device: Vivo V2302", out_acq)
        self.assertIn("msgstore.db.crypt14", out_acq)
        self.assertIn("VERIFIED", out_acq)
        self.assertNotIn("\r", out_acq)


if __name__ == "__main__":
    unittest.main()
