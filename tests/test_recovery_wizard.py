"""Automated tests for Recovery Selection Wizard & Date-Range Filtering (Phase 4).

Validates:
- Category selection parsing (all, multiple, comma-separated, dedup, invalid, clear, back).
- Chat timeline extraction (oldest, newest, message counts, missing timestamps, calendar counts).
- Date range parsing & validation (calendar validity, reject 31-02-2024, end < start,
  ranges outside history, partial overlaps, inclusive boundaries).
- Filtering conversations by date range and by specific dates.
- Associated media handling and preview calculations.
"""

from __future__ import annotations

import unittest
from datetime import datetime
from pathlib import Path
import tempfile
import shutil

from wrs.chat import Conversation, ReconstructedMessage
from wrs.wizard import (
    CATEGORY_MENU_MAP,
    DateRangeEngine,
    RecoverySelectionPreview,
    parse_category_selection,
    parse_date_dd_mm_yyyy,
    resolve_storage_categories,
    message_to_datetime,
)
from wrs.categorizer import (
    CAT_IMAGES,
    CAT_VIDEOS,
    CAT_DOCUMENTS,
    CAT_DATABASES,
    CAT_BACKUPS,
    ALL_CATEGORIES,
)


class TestRecoveryWizard(unittest.TestCase):
    """Test category parsing, date validation, chat timeline extraction, and previews."""

    def test_parse_category_selection_all_data(self):
        """Selecting [1], 'A', or 'ALL' selects every supported category."""
        # '1'
        ok, cats, has_chat, msg = parse_category_selection("1")
        self.assertTrue(ok)
        self.assertTrue(has_chat)
        self.assertEqual(len(cats), 11)  # All categories from 2 to 12
        self.assertIn("Chat History", cats)
        self.assertIn("Photos and Images", cats)
        self.assertIn("Databases and Backups", cats)

        # 'A'
        ok, cats, has_chat, _ = parse_category_selection("A")
        self.assertTrue(ok)
        self.assertTrue(has_chat)
        self.assertEqual(len(cats), 11)

        # 'all'
        ok, cats, has_chat, _ = parse_category_selection("all")
        self.assertTrue(ok)
        self.assertTrue(has_chat)

    def test_parse_category_selection_multiple_and_deduplication(self):
        """Input '2,4,7' selects Chat History, Videos, Documents without duplication."""
        ok, cats, has_chat, msg = parse_category_selection("2, 4, 7")
        self.assertTrue(ok)
        self.assertTrue(has_chat)
        self.assertEqual(cats, ["Chat History", "Videos", "Documents and Files"])

        # Repeated selection '2,2,4,7,4' is normalized and deduplicated
        ok, cats_dedup, has_chat, _ = parse_category_selection("2, 2, 4, 7, 4")
        self.assertTrue(ok)
        self.assertEqual(cats_dedup, ["Chat History", "Videos", "Documents and Files"])

    def test_parse_category_selection_clear_and_back(self):
        """Selecting 'C' clears selection; selecting '0' or 'BACK' returns back signal."""
        ok, cats, has_chat, msg = parse_category_selection("C")
        self.assertTrue(ok)
        self.assertEqual(cats, [])
        self.assertIn("cleared", msg.lower())

        ok, cats, has_chat, msg = parse_category_selection("0")
        self.assertTrue(ok)
        self.assertEqual(msg, "BACK")

        ok, cats, has_chat, msg = parse_category_selection("back")
        self.assertTrue(ok)
        self.assertEqual(msg, "BACK")

    def test_parse_category_selection_invalid_tokens_and_out_of_range(self):
        """Invalid tokens or numbers outside 1-12 return descriptive error."""
        # Non-numeric token
        ok, cats, has_chat, msg = parse_category_selection("2,abc,7")
        self.assertFalse(ok)
        self.assertIn("Invalid category token 'abc'", msg)

        # Number out of range
        ok, cats, has_chat, msg = parse_category_selection("2,15")
        self.assertFalse(ok)
        self.assertIn("out of range", msg)

        # Empty string
        ok, cats, has_chat, msg = parse_category_selection("   ")
        self.assertFalse(ok)
        self.assertIn("No selection entered", msg)

    def test_resolve_storage_categories(self):
        """Translates human-readable category labels into internal categorizer strings."""
        labels = ["Photos and Images", "Videos", "Databases and Backups"]
        resolved = resolve_storage_categories(labels)
        self.assertIn(CAT_IMAGES, resolved)
        self.assertIn(CAT_VIDEOS, resolved)
        self.assertIn(CAT_DATABASES, resolved)
        self.assertIn(CAT_BACKUPS, resolved)
        self.assertNotIn(CAT_DOCUMENTS, resolved)

        # All Supported Data maps to ALL_CATEGORIES
        all_resolved = resolve_storage_categories(["All Supported Data"])
        self.assertEqual(all_resolved, set(ALL_CATEGORIES))

    def test_date_parsing_calendar_validity(self):
        """parse_date_dd_mm_yyyy accepts real calendar dates and rejects invalid ones like 31-02-2024."""
        # Valid date
        dt = parse_date_dd_mm_yyyy("15-08-2024")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.day, 15)
        self.assertEqual(dt.month, 8)
        self.assertEqual(dt.year, 2024)

        # Leap year 29-02-2024 is valid
        leap = parse_date_dd_mm_yyyy("29-02-2024")
        self.assertIsNotNone(leap)

        # Non-leap year 29-02-2023 is invalid
        non_leap = parse_date_dd_mm_yyyy("29-02-2023")
        self.assertIsNone(non_leap)

        # Impossible calendar date 31-02-2024
        self.assertIsNone(parse_date_dd_mm_yyyy("31-02-2024"))

        # Malformed format
        self.assertIsNone(parse_date_dd_mm_yyyy("2024-05-10"))
        self.assertIsNone(parse_date_dd_mm_yyyy("invalid"))

    def test_extract_timeline_and_calendar_counts(self):
        """DateRangeEngine extracts chronological boundaries and message counts per date."""
        # Create synthetic conversation fixture with known timestamps
        # 1704067200 -> 2024-01-01 00:00:00 UTC
        # 1704153600 -> 2024-01-02 00:00:00 UTC
        # 1704240000 -> 2024-01-03 00:00:00 UTC
        msg1 = ReconstructedMessage(message_id="m1", conversation_id="conv_1", sender_id="Alice", timestamp=1704067200, text_content="Hello")
        msg2 = ReconstructedMessage(message_id="m2", conversation_id="conv_1", sender_id="Bob", timestamp=1704153600, text_content="Hi")
        msg3 = ReconstructedMessage(message_id="m3", conversation_id="conv_1", sender_id="Alice", timestamp=1704154000, text_content="How are you?")
        msg_missing = ReconstructedMessage(message_id="m4", conversation_id="conv_1", sender_id="Bob", timestamp=0, text_content="No timestamp")

        conv = Conversation(
            conversation_id="conv_1",
            display_name="Alice",
            messages=[msg1, msg2, msg3, msg_missing],
            message_count=4,
        )

        timeline = DateRangeEngine.extract_timeline([conv])
        self.assertEqual(timeline.total_messages, 4)
        self.assertEqual(timeline.total_conversations, 1)
        self.assertEqual(timeline.missing_timestamps_count, 1)
        self.assertIsNotNone(timeline.oldest_dt)
        self.assertIsNotNone(timeline.newest_dt)
        self.assertLess(timeline.oldest_dt, timeline.newest_dt)

        # Calendar should reflect messages grouped by date
        self.assertGreaterEqual(len(timeline.dates_calendar), 2)

    def test_validate_date_range_boundaries(self):
        """DateRangeEngine.validate_date_range enforces strict boundary and ordering checks."""
        min_dt = datetime(2024, 1, 1, 10, 0, 0)
        max_dt = datetime(2024, 12, 31, 20, 0, 0)

        # 1. Valid range within boundaries
        ok, s, e, msg = DateRangeEngine.validate_date_range("01-06-2024", "30-06-2024", min_dt, max_dt)
        self.assertTrue(ok)
        self.assertEqual(s.day, 1)
        self.assertEqual(s.month, 6)
        self.assertEqual(s.hour, 0)
        self.assertEqual(e.day, 30)
        self.assertEqual(e.hour, 23)
        self.assertEqual(e.minute, 59)

        # 2. End date earlier than start date
        ok, s, e, msg = DateRangeEngine.validate_date_range("30-06-2024", "01-06-2024", min_dt, max_dt)
        self.assertFalse(ok)
        self.assertIn("cannot be earlier", msg)

        # 3. Invalid calendar date
        ok, s, e, msg = DateRangeEngine.validate_date_range("31-02-2024", "01-03-2024", min_dt, max_dt)
        self.assertFalse(ok)
        self.assertIn("Invalid Start Date", msg)

        # 4. Entirely outside available history
        ok, s, e, msg = DateRangeEngine.validate_date_range("01-01-2022", "31-12-2022", min_dt, max_dt)
        self.assertFalse(ok)
        self.assertIn("entirely outside available history", msg)

        # 5. Partial overlap (start precedes history)
        ok, s, e, msg = DateRangeEngine.validate_date_range("01-01-2023", "15-06-2024", min_dt, max_dt)
        self.assertTrue(ok)
        self.assertIn("Partial overlap", msg)
        self.assertEqual(s.year, 2024)  # Adjusted to min_day

    def test_filter_conversations_by_date(self):
        """filter_conversations_by_date extracts messages within inclusive boundaries."""
        # 1704067200 -> 2024-01-01
        # 1705320000 -> 2024-01-15
        # 1706745600 -> 2024-02-01
        msg1 = ReconstructedMessage(message_id="1", conversation_id="conv_test", sender_id="A", timestamp=1704067200, text_content="Jan 1")
        msg2 = ReconstructedMessage(message_id="2", conversation_id="conv_test", sender_id="A", timestamp=1705320000, text_content="Jan 15")
        msg3 = ReconstructedMessage(message_id="3", conversation_id="conv_test", sender_id="A", timestamp=1706745600, text_content="Feb 1")
        msg_no_ts = ReconstructedMessage(message_id="4", conversation_id="conv_test", sender_id="A", timestamp=0, text_content="No TS")

        conv = Conversation(
            conversation_id="conv_test",
            display_name="Test Thread",
            messages=[msg1, msg2, msg3, msg_no_ts],
            message_count=4,
        )

        start_dt = datetime(2024, 1, 10, 0, 0, 0)
        end_dt = datetime(2024, 1, 20, 23, 59, 59)

        filtered, excluded_missing = DateRangeEngine.filter_conversations_by_date([conv], start_dt, end_dt)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(len(filtered[0].messages), 1)
        self.assertEqual(filtered[0].messages[0].message_id, "2")
        self.assertEqual(excluded_missing, 1)

    def test_filter_conversations_by_specific_dates(self):
        """filter_conversations_by_specific_dates matches only selected calendar dates."""
        msg1 = ReconstructedMessage(message_id="1", conversation_id="c1", sender_id="A", timestamp=1704067200, text_content="Jan 1")
        msg2 = ReconstructedMessage(message_id="2", conversation_id="c1", sender_id="A", timestamp=1705320000, text_content="Jan 15")

        dt1 = message_to_datetime(msg1)
        date1_str = dt1.strftime("%d-%m-%Y") if dt1 else "01-01-2024"

        conv = Conversation(
            conversation_id="c1",
            display_name="Calendar Test",
            messages=[msg1, msg2],
            message_count=2,
        )

        filtered, _ = DateRangeEngine.filter_conversations_by_specific_dates([conv], {date1_str})
        self.assertEqual(len(filtered), 1)
        self.assertEqual(len(filtered[0].messages), 1)
        self.assertEqual(filtered[0].messages[0].message_id, "1")

    def test_recovery_selection_preview(self):
        """RecoverySelectionPreview holds authentic counts, sizes, and formats."""
        prev = RecoverySelectionPreview(
            device_name="Google Pixel 7",
            operation="Export Readable Chats",
            categories=["Chat History"],
            chat_source_status="msgstore.db (Reconstructed)",
            oldest_available_date="01-01-2024 10:00",
            newest_available_date="31-12-2024 22:00",
            requested_range="01-06-2024 to 30-06-2024",
            selected_conversations_count=5,
            selected_messages_count=120,
            selected_files_count=0,
            total_selected_size_bytes=524288,
            unreadable_records_count=0,
            missing_timestamps_count=2,
            unmatched_media_count=0,
            destination_path="/tmp/recovery/export_01",
        )
        self.assertEqual(prev.total_selected_size_human, "512.00 KiB")
        self.assertEqual(prev.selected_messages_count, 120)
        self.assertEqual(prev.missing_timestamps_count, 2)

    def test_conversations_with_different_date_ranges(self):
        """Conversations with disparate date ranges are filtered independently without assuming uniform timeline."""
        # Conv 1: 2023 messages (1672531200 -> 2023-01-01)
        m1 = ReconstructedMessage("m1", "c1", "Alice", timestamp=1672531200, text_content="2023 message")
        conv1 = Conversation("c1", "Alice 2023", [m1], message_count=1)

        # Conv 2: 2024 messages (1704067200 -> 2024-01-01)
        m2 = ReconstructedMessage("m2", "c2", "Bob", timestamp=1704067200, text_content="2024 message")
        conv2 = Conversation("c2", "Bob 2024", [m2], message_count=1)

        start_2024 = datetime(2024, 1, 1, 0, 0, 0)
        end_2024 = datetime(2024, 12, 31, 23, 59, 59)

        res, excluded = DateRangeEngine.filter_conversations_by_date([conv1, conv2], start_2024, end_2024)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].conversation_id, "c2")
        self.assertEqual(res[0].display_name, "Bob 2024")

    def test_timezone_aware_timestamp_handling(self):
        """message_to_datetime properly converts second and millisecond timestamps to local naive datetime."""
        # Seconds: 1704067200
        msg_sec = ReconstructedMessage("m1", "c1", "A", timestamp=1704067200)
        dt_sec = message_to_datetime(msg_sec)
        self.assertIsNotNone(dt_sec)
        self.assertIsNone(dt_sec.tzinfo)

        # Milliseconds: 1704067200000
        msg_ms = ReconstructedMessage("m2", "c1", "A", timestamp=1704067200000)
        dt_ms = message_to_datetime(msg_ms)
        self.assertIsNotNone(dt_ms)
        self.assertIsNone(dt_ms.tzinfo)
        self.assertEqual(dt_sec, dt_ms)

        # Invalid, negative, or zero timestamp
        msg_zero = ReconstructedMessage("m3", "c1", "A", timestamp=0)
        self.assertIsNone(message_to_datetime(msg_zero))
        msg_neg = ReconstructedMessage("m4", "c1", "A", timestamp=-100)
        self.assertIsNone(message_to_datetime(msg_neg))
        msg_none = ReconstructedMessage("m5", "c1", "A", timestamp=None)
        self.assertIsNone(message_to_datetime(msg_none))

    def test_chat_export_to_formats_and_zip(self):
        """Reconstructed conversations export to TXT, HTML, JSON, and ZIP with manifest."""
        temp_d = Path(tempfile.mkdtemp())
        try:
            m1 = ReconstructedMessage("m1", "c1", "Alice", timestamp=1704067200, formatted_time="2024-01-01 10:00:00", text_content="Export test")
            conv = Conversation("c1", "Test Export Conv", [m1], message_count=1)

            from wrs.exporter import ChatExporter, ZipPackager
            out_chats = temp_d / "chats"
            out_chats.mkdir(parents=True, exist_ok=True)

            txt_file = out_chats / "conv.txt"
            html_file = out_chats / "conv.html"
            json_file = out_chats / "conv.json"

            ChatExporter.export_conversation_txt(conv, txt_file)
            ChatExporter.export_conversation_html(conv, html_file)
            ChatExporter.export_conversation_json(conv, json_file)

            self.assertTrue(txt_file.exists())
            self.assertTrue(html_file.exists())
            self.assertTrue(json_file.exists())
            self.assertIn("Export test", txt_file.read_text(encoding="utf-8"))

            zip_dest = temp_d / "export.zip"
            ok, zpath, err = ZipPackager.package_recovery_archive(out_chats, zip_dest)
            self.assertTrue(ok)
            self.assertTrue(zip_dest.exists())
            self.assertGreater(zip_dest.stat().st_size, 0)
        finally:
            shutil.rmtree(temp_d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

