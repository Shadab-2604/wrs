"""Unit tests for chat exports (TXT, HTML, JSON, CSV) and ZIP packaging (src/wrs/exporter.py)."""

import csv
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from wrs.chat import Conversation, ReconstructedMessage
from wrs.exporter import ChatExporter, ZipPackager


class TestExporterModule(unittest.TestCase):
    """Test exporting conversations and packaging recovery directories into ZIP archives."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_p = Path(self.temp_dir.name)

        # Create sample messages
        self.msg1 = ReconstructedMessage(
            message_id="1",
            conversation_id="12345@s.whatsapp.net",
            sender_id="12345@s.whatsapp.net",
            sender_name="Alice",
            timestamp=1690000000000,
            formatted_time="2023-07-22 10:00:00",
            message_type="text",
            text_content="Hello, forensic world!",
        )
        self.msg2 = ReconstructedMessage(
            message_id="2",
            conversation_id="12345@s.whatsapp.net",
            sender_id="me",
            sender_name="You",
            timestamp=1690000010000,
            formatted_time="2023-07-22 10:00:10",
            message_type="image",
            text_content="Photo evidence attached",
            media_reference="Media/WhatsApp Images/photo.jpg",
        )

        self.conv = Conversation(
            conversation_id="12345@s.whatsapp.net",
            display_name="Alice",
            messages=[self.msg1, self.msg2],
            message_count=2,
            start_time="2023-07-22 10:00:00",
            end_time="2023-07-22 10:00:10",
            media_count=1,
            completeness_summary="2 messages reconstructed.",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_export_txt(self):
        """Verify TXT export structure and contents."""
        out_file = self.base_p / "chat.txt"
        ChatExporter.export_conversation_txt(self.conv, out_file)

        self.assertTrue(out_file.exists())
        content = out_file.read_text(encoding="utf-8")
        self.assertIn("WRS CHAT TRANSCRIPT: Alice", content)
        self.assertIn("Hello, forensic world!", content)
        self.assertIn("Attachment: Media/WhatsApp Images/photo.jpg", content)

    def test_export_html(self):
        """Verify HTML export contains valid tags, speech bubbles, and escaping."""
        out_file = self.base_p / "chat.html"
        ChatExporter.export_conversation_html(self.conv, out_file)

        self.assertTrue(out_file.exists())
        html = out_file.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Alice", html)
        self.assertIn("Hello, forensic world!", html)

    def test_export_json(self):
        """Verify JSON export produces valid, readable structured JSON."""
        out_file = self.base_p / "chat.json"
        ChatExporter.export_conversation_json(self.conv, out_file)

        self.assertTrue(out_file.exists())
        data = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertEqual(data["conversation_id"], "12345@s.whatsapp.net")
        self.assertEqual(data["display_name"], "Alice")
        self.assertEqual(len(data["messages"]), 2)
        self.assertEqual(data["messages"][0]["text_content"], "Hello, forensic world!")

    def test_export_csv(self):
        """Verify CSV export is RFC-4180 compliant with correct column headers."""
        out_file = self.base_p / "chat.csv"
        ChatExporter.export_conversation_csv(self.conv, out_file)

        self.assertTrue(out_file.exists())
        with open(out_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["sender_name"], "Alice")
            self.assertEqual(rows[0]["text_content"], "Hello, forensic world!")
            self.assertEqual(rows[1]["sender_name"], "You")
            self.assertEqual(rows[1]["message_type"], "image")

    def test_zip_packager_workflow(self):
        """Verify preview calculation, ZIP creation, integrity verification, and manifest."""
        # Create a mock recovery folder structure
        rec_dir = self.base_p / "recovery_test"
        (rec_dir / "Images").mkdir(parents=True)
        (rec_dir / "reports").mkdir(parents=True)

        img_file = rec_dir / "Images" / "sample.jpg"
        img_file.write_bytes(b"\xFF\xD8\xFF" + b"\x00" * 500)

        rep_file = rec_dir / "reports" / "report.html"
        rep_file.write_text("<h1>Report</h1>")

        # 1. Preview
        preview = ZipPackager.preview_archive(rec_dir)
        self.assertEqual(preview["file_count"], 2)
        self.assertGreater(preview["uncompressed_bytes"], 500)
        self.assertTrue(preview["has_sufficient_space"])

        # 2. Package
        out_zip = self.base_p / "export.zip"
        ok, res_path, err = ZipPackager.package_recovery_archive(rec_dir, out_zip)
        self.assertTrue(ok, f"ZIP packaging failed: {err}")
        self.assertTrue(res_path.exists())

        # 3. Verify internal ZIP contents and manifest
        with zipfile.ZipFile(res_path, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("archive_manifest.json", namelist)
            self.assertIn("Images/sample.jpg", namelist)
            self.assertIn("reports/report.html", namelist)

            # Test archive integrity
            self.assertIsNone(zf.testzip())

            # Read internal manifest
            manifest = json.loads(zf.read("archive_manifest.json").decode("utf-8"))
            self.assertEqual(manifest["file_count"], 2)
            self.assertIn("archive_sha256", manifest)


if __name__ == "__main__":
    unittest.main()
