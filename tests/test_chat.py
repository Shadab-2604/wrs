"""Unit tests for chat reconstruction engine (src/wrs/chat.py)."""

import unittest

from wrs.chat import ChatReconstructionEngine, Conversation, ReconstructedMessage


class TestChatReconstruction(unittest.TestCase):
    """Test message normalization, chronological ordering, and conversation grouping."""

    def test_reconstruct_multiple_conversations(self):
        """Verify messages from different chats are grouped and sorted chronologically."""
        raw_records = [
            # Chat 1 message later
            {
                "message_id": "2",
                "conversation_id": "user_a@s.whatsapp.net",
                "sender_id": "user_a@s.whatsapp.net",
                "timestamp": 1690000020000,
                "message_type": 0,
                "text_content": "Second message from Alice",
            },
            # Chat 1 message earlier
            {
                "message_id": "1",
                "conversation_id": "user_a@s.whatsapp.net",
                "sender_id": "me",
                "timestamp": 1690000010000,
                "message_type": 0,
                "text_content": "First message to Alice",
            },
            # Chat 2 message
            {
                "message_id": "3",
                "conversation_id": "group_team@g.us",
                "sender_id": "bob@s.whatsapp.net",
                "timestamp": 1690000015000,
                "message_type": 1,  # image
                "text_content": "Check this screenshot",
                "media_path": "Media/WhatsApp Images/screen.jpg",
            },
        ]

        contacts = {"user_a@s.whatsapp.net": "Alice Smith", "group_team@g.us": "Dev Team"}
        convs = ChatReconstructionEngine.reconstruct_conversations(raw_records, contacts_map=contacts)

        # 2 conversations expected
        self.assertEqual(len(convs), 2)

        # Find Alice conversation
        alice_conv = next((c for c in convs if c.conversation_id == "user_a@s.whatsapp.net"), None)
        self.assertIsNotNone(alice_conv)
        self.assertEqual(alice_conv.display_name, "Alice Smith")
        self.assertEqual(len(alice_conv.messages), 2)

        # Verify chronological order in Alice chat (message 1 then message 2)
        self.assertEqual(alice_conv.messages[0].message_id, "1")
        self.assertEqual(alice_conv.messages[0].text_content, "First message to Alice")
        self.assertEqual(alice_conv.messages[0].sender_id, "me")
        self.assertEqual(alice_conv.messages[1].message_id, "2")
        self.assertEqual(alice_conv.messages[1].text_content, "Second message from Alice")
        self.assertEqual(alice_conv.messages[1].sender_id, "user_a@s.whatsapp.net")

        # Find Team conversation
        team_conv = next((c for c in convs if c.conversation_id == "group_team@g.us"), None)
        self.assertIsNotNone(team_conv)
        self.assertEqual(team_conv.display_name, "Dev Team")
        self.assertEqual(len(team_conv.messages), 1)
        self.assertEqual(team_conv.messages[0].message_type, "image")
        self.assertEqual(team_conv.messages[0].media_reference, "Media/WhatsApp Images/screen.jpg")

    def test_message_type_mapping(self):
        """Verify numeric message types are converted to descriptive strings."""
        types_to_test = [
            (0, "text"),
            (1, "image"),
            (2, "audio"),
            (3, "video"),
            (8, "document"),
            (15, "sticker"),
        ]
        for num_type, expected_str in types_to_test:
            mapped = ChatReconstructionEngine.TYPE_MAP.get(num_type)
            self.assertEqual(mapped, expected_str)


if __name__ == "__main__":
    unittest.main()
