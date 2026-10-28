"""Unit tests for WhatsApp database analyzer, schema adapters, and AES-GCM crypt decryption (src/wrs/database.py)."""

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from wrs.database import WhatsAppDatabaseAnalyzer


class TestDatabaseAnalyzer(unittest.TestCase):
    """Test SQLite schema inspection, table adapters, Crypt14/15 detection, and AES-GCM decryption."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_p = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_identify_classic_v1_sqlite_database(self):
        """Verify identification of classic WhatsApp SQLite schema with 'messages' table."""
        db_path = self.base_p / "msgstore_v1.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE messages (
                    _id INTEGER PRIMARY KEY,
                    key_remote_jid TEXT,
                    key_from_me INTEGER,
                    data TEXT,
                    timestamp INTEGER,
                    media_url TEXT,
                    media_mime_type TEXT,
                    media_size INTEGER
                )
            """)
            conn.execute("""
                INSERT INTO messages VALUES (1, '123456@s.whatsapp.net', 0, 'Hello from Alice', 1690000000000, NULL, NULL, NULL)
            """)
            conn.commit()

        meta = WhatsAppDatabaseAnalyzer.identify_database(db_path)
        self.assertTrue(meta.is_sqlite)
        self.assertFalse(meta.is_encrypted)
        self.assertEqual(meta.format_type, "SQLITE")
        self.assertIn("messages", meta.tables)

        raw_msgs = WhatsAppDatabaseAnalyzer.extract_raw_messages(db_path)
        self.assertEqual(len(raw_msgs), 1)
        self.assertEqual(raw_msgs[0]["text_content"], "Hello from Alice")
        self.assertEqual(raw_msgs[0]["conversation_id"], "123456@s.whatsapp.net")

    def test_identify_modern_v2_sqlite_database(self):
        """Verify identification of modern WhatsApp SQLite schema with 'message' table."""
        db_path = self.base_p / "msgstore_v2.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE message (
                    _id INTEGER PRIMARY KEY,
                    chat_row_id INTEGER,
                    from_me INTEGER,
                    text_data TEXT,
                    timestamp INTEGER,
                    message_type INTEGER
                )
            """)
            conn.execute("""
                CREATE TABLE chat (
                    _id INTEGER PRIMARY KEY,
                    jid_row_id INTEGER
                )
            """)
            conn.execute("""
                CREATE TABLE jid (
                    _id INTEGER PRIMARY KEY,
                    raw_string TEXT
                )
            """)
            conn.execute("INSERT INTO jid VALUES (5, 'group99@g.us')")
            conn.execute("INSERT INTO chat VALUES (10, 5)")
            conn.execute("INSERT INTO message VALUES (1, 10, 1, 'Modern message schema', 1695000000000, 0)")
            conn.commit()

        meta = WhatsAppDatabaseAnalyzer.identify_database(db_path)
        self.assertTrue(meta.is_sqlite)
        self.assertFalse(meta.is_encrypted)
        self.assertEqual(meta.format_type, "SQLITE")
        self.assertIn("message", meta.tables)

        raw_msgs = WhatsAppDatabaseAnalyzer.extract_raw_messages(db_path)
        self.assertEqual(len(raw_msgs), 1)
        self.assertEqual(raw_msgs[0]["text_content"], "Modern message schema")
        self.assertEqual(raw_msgs[0]["conversation_id"], "group99@g.us")
        self.assertEqual(raw_msgs[0]["sender_id"], "me")

    def test_crypt14_crypt15_identification(self):
        """Verify detection of crypt14 and crypt15 format headers and extensions."""
        crypt_path = self.base_p / "msgstore.db.crypt14"
        # Minimum synthetic crypt header (191 bytes)
        fake_header = b"\x00" * 191
        crypt_path.write_bytes(fake_header + b"CIPHERTEXT_PAYLOAD_BYTES")

        meta = WhatsAppDatabaseAnalyzer.identify_database(crypt_path)
        self.assertFalse(meta.is_sqlite)
        self.assertTrue(meta.is_encrypted)
        self.assertEqual(meta.format_type, "CRYPT14")
        self.assertIn("key", meta.notes.lower())

    def test_aes_gcm_crypt_decryption_with_key(self):
        """Verify AES-GCM decryption of crypt14/15 database using valid user key material."""
        # 1. Create a real plaintext SQLite database
        plain_db = self.base_p / "original_plain.db"
        with sqlite3.connect(plain_db) as conn:
            conn.execute("CREATE TABLE test_data (id INT, note TEXT)")
            conn.execute("INSERT INTO test_data VALUES (42, 'Confidential forensic evidence')")
            conn.commit()
        plain_bytes = plain_db.read_bytes()

        # 2. Generate a 32-byte AES key
        aes_key = os.urandom(32)

        # 3. Create a synthetic 158-byte WhatsApp key file (key at offset 126..158)
        key_file_path = self.base_p / "whatsapp.key"
        key_file_bytes = b"\x00" * 126 + aes_key
        key_file_path.write_bytes(key_file_bytes)

        # 4. Encrypt the plaintext using AES-GCM
        iv_16 = os.urandom(16)
        nonce_12 = iv_16[:12]
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce_12, plain_bytes, None)

        header = bytearray(191)
        header[67:83] = iv_16

        crypt_file_path = self.base_p / "msgstore.db.crypt14"
        crypt_file_path.write_bytes(bytes(header) + ciphertext)

        # 5. Run WhatsAppDatabaseAnalyzer.decrypt_crypt_database
        decrypted_out = self.base_p / "msgstore_decrypted.db"
        success, err = WhatsAppDatabaseAnalyzer.decrypt_crypt_database(
            crypt_file_path, key_file_path, decrypted_out
        )

        self.assertTrue(success, f"Decryption should succeed, got error: {err}")
        self.assertTrue(decrypted_out.exists())

        # Verify decrypted database can be queried as valid SQLite
        with sqlite3.connect(decrypted_out) as conn:
            cur = conn.cursor()
            cur.execute("SELECT note FROM test_data WHERE id=42")
            row = cur.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], "Confidential forensic evidence")

    def test_decryption_with_invalid_key_fails_safely(self):
        """Verify decryption fails gracefully without crash when invalid key is provided."""
        crypt_file = self.base_p / "msgstore.db.crypt14"
        crypt_file.write_bytes(b"\x00" * 191 + b"INVALID_CIPHERTEXT")

        bad_key_file = self.base_p / "bad.key"
        bad_key_file.write_bytes(b"\x00" * 158)

        dec_out = self.base_p / "fail.db"
        success, err = WhatsAppDatabaseAnalyzer.decrypt_crypt_database(crypt_file, bad_key_file, dec_out)
        self.assertFalse(success)
        self.assertIn("failed", err.lower())


if __name__ == "__main__":
    unittest.main()
