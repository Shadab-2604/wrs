"""Unit tests for media association and forensic evidence levels (src/wrs/media.py)."""

import tempfile
import unittest
from pathlib import Path

from wrs.chat import Conversation, ReconstructedMessage
from wrs.media import (
    EVIDENCE_EXACT_REFERENCE,
    EVIDENCE_MATCHED_FILENAME,
    EVIDENCE_MATCHED_RELATIVE,
    EVIDENCE_UNMATCHED,
    MediaAssociator,
)


class TestMediaAssociator(unittest.TestCase):
    """Test media resolution against acquired files and verification levels."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_p = Path(self.temp_dir.name)

        # Create sample acquired media files
        self.exact_file = self.base_p / "Media" / "WhatsApp Images" / "IMG_001.jpg"
        self.exact_file.parent.mkdir(parents=True, exist_ok=True)
        self.exact_file.write_bytes(b"\xFF\xD8\xFF\xE0" + b"\x00" * 100)  # JPEG magic bytes

        self.match_fn_file = self.base_p / "Images" / "IMG_002.jpg"
        self.match_fn_file.parent.mkdir(parents=True, exist_ok=True)
        self.match_fn_file.write_bytes(b"\xFF\xD8\xFF\xE0" + b"\x00" * 100)

        self.acquired_files = [self.exact_file, self.match_fn_file]

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_associate_media_evidence_levels(self):
        """Verify media association assigns appropriate forensic evidence levels."""
        # Message 1: Exact path / relative match
        msg_exact = ReconstructedMessage(
            message_id="1",
            conversation_id="chat1",
            sender_id="sender1",
            message_type="image",
            media_reference="Media/WhatsApp Images/IMG_001.jpg",
        )
        # Message 2: Filename match only (different relative path)
        msg_fn = ReconstructedMessage(
            message_id="2",
            conversation_id="chat1",
            sender_id="sender1",
            message_type="image",
            media_reference="Some/Other/Path/IMG_002.jpg",
        )
        # Message 3: Missing media (unmatched)
        msg_unmatched = ReconstructedMessage(
            message_id="3",
            conversation_id="chat1",
            sender_id="sender1",
            message_type="image",
            media_reference="Media/WhatsApp Images/MISSING_IMG_999.jpg",
        )

        conv = Conversation(
            conversation_id="chat1",
            display_name="Test Chat",
            messages=[msg_exact, msg_fn, msg_unmatched],
        )

        assoc_map = MediaAssociator.associate_media([conv], self.acquired_files)

        # Check Message 1
        rec1 = assoc_map["Media/WhatsApp Images/IMG_001.jpg"]
        self.assertIn(rec1.evidence_level, (EVIDENCE_EXACT_REFERENCE, EVIDENCE_MATCHED_RELATIVE))
        self.assertEqual(msg_exact.media_resolved_path, str(self.exact_file))

        # Check Message 2
        rec2 = assoc_map["Some/Other/Path/IMG_002.jpg"]
        self.assertEqual(rec2.evidence_level, EVIDENCE_MATCHED_FILENAME)
        self.assertEqual(msg_fn.media_resolved_path, str(self.match_fn_file))

        # Check Message 3
        rec3 = assoc_map["Media/WhatsApp Images/MISSING_IMG_999.jpg"]
        self.assertEqual(rec3.evidence_level, EVIDENCE_UNMATCHED)
        self.assertIsNone(msg_unmatched.media_resolved_path)


if __name__ == "__main__":
    unittest.main()
