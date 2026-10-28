"""Unit tests for file categorizer module (src/wrs/categorizer.py)."""

import unittest

from wrs.categorizer import (
    CAT_ANIMATED_GIFS,
    CAT_AUDIO,
    CAT_BACKUPS,
    CAT_DATABASES,
    CAT_DOCUMENTS,
    CAT_IMAGES,
    CAT_OTHER,
    CAT_STICKERS,
    CAT_THUMBNAILS,
    CAT_VIDEOS,
    CAT_VOICE_NOTES,
    Categorizer,
)


class TestCategorizer(unittest.TestCase):
    """Test classification rules and edge cases."""

    def setUp(self):
        self.cat = Categorizer()

    def test_active_databases(self):
        """Active and undated databases must be classified as Databases."""
        c, _ = self.cat.categorize("msgstore.db.crypt14", "Databases/msgstore.db.crypt14")
        self.assertEqual(c, CAT_DATABASES)

        c, _ = self.cat.categorize("msgstore.db.crypt15", "Databases/msgstore.db.crypt15")
        self.assertEqual(c, CAT_DATABASES)

        c, _ = self.cat.categorize("wa.db", "Databases/wa.db")
        self.assertEqual(c, CAT_DATABASES)

    def test_dated_backups(self):
        """Dated msgstore backups must be classified as Backups."""
        c, _ = self.cat.categorize("msgstore-2026-10-25.1.db.crypt14", "Databases/msgstore-2026-10-25.1.db.crypt14")
        self.assertEqual(c, CAT_BACKUPS)

        c, _ = self.cat.categorize("msgstore-2025-12-01.db.crypt15", "Databases/msgstore-2025-12-01.db.crypt15")
        self.assertEqual(c, CAT_BACKUPS)

    def test_non_backup_with_backup_in_name(self):
        """Rule: Do not classify a file as backup solely because 'backup' is in the name."""
        c, _ = self.cat.categorize("family_vacation_backup.jpg", "Media/WhatsApp Images/family_vacation_backup.jpg")
        self.assertEqual(c, CAT_IMAGES)

    def test_voice_notes_vs_audio(self):
        """Rule: OPUS in PTT or Voice Notes directory must be Voice Notes, not generic audio."""
        c, _ = self.cat.categorize("PTT-20261025-WA0001.opus", "Media/WhatsApp Voice Notes/202643/PTT-20261025-WA0001.opus")
        self.assertEqual(c, CAT_VOICE_NOTES)

        # Standard song in WhatsApp Audio
        c, _ = self.cat.categorize("podcast.mp3", "Media/WhatsApp Audio/podcast.mp3")
        self.assertEqual(c, CAT_AUDIO)

    def test_stickers_and_animated_gifs(self):
        """Verify stickers and animated GIFs classification."""
        c, _ = self.cat.categorize("sticker_01.webp", "Media/WhatsApp Stickers/sticker_01.webp")
        self.assertEqual(c, CAT_STICKERS)

        c, _ = self.cat.categorize("loop.mp4", "Media/WhatsApp Animated Gifs/loop.mp4")
        self.assertEqual(c, CAT_ANIMATED_GIFS)

    def test_thumbnails(self):
        """Verify thumbnail detection."""
        c, _ = self.cat.categorize(".thumb_001", "Media/.thumbs/.thumb_001")
        self.assertEqual(c, CAT_THUMBNAILS)

    def test_unicode_and_spaces(self):
        """Verify handling of Unicode and filenames with spaces."""
        c, _ = self.cat.categorize("Photos de vacances 2026 (Éléphant).jpg", "Media/WhatsApp Images/Photos de vacances 2026 (Éléphant).jpg")
        self.assertEqual(c, CAT_IMAGES)

    def test_magic_byte_sniffing(self):
        """Verify signature-based fallback identification."""
        jpeg_header = b"\xFF\xD8\xFF\xE0\x00\x10JFIF"
        c, _ = self.cat.categorize("unnamed_binary", "Media/Unknown/unnamed_binary", header_bytes=jpeg_header)
        self.assertEqual(c, CAT_IMAGES)

        sqlite_header = b"SQLite format 3\x00\x10\x00\x01\x01"
        c, _ = self.cat.categorize("custom_data", "Media/custom_data", header_bytes=sqlite_header)
        self.assertEqual(c, CAT_DATABASES)


if __name__ == "__main__":
    unittest.main()
