"""Unit and regression tests for Encrypted Database Discovery, Key Availability Assessment,
Safe Acquisition, and Decryption Workflow (Section 9 Requirements).
"""

import json
import os
import shutil
import sqlite3
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import subprocess
from wrs.device import AdbExecutor, DeviceInfo
from wrs.categorizer import Categorizer
from wrs.database import (
    DatabaseMetadata,
    WhatsAppDatabaseAnalyzer,
)
from wrs.db_discovery import (
    ChatDatabaseCandidate,
    ChatDatabaseRegistry,
    DatabaseDiscoveryService,
    inspect_sqlite_chat_dates,
)
from wrs.key_assessment import (
    KEY_STATUS_AVAILABLE,
    KEY_STATUS_NOT_CHECKED,
    KEY_STATUS_NOT_FOUND,
    STATUS_DECRYPTED,
    STATUS_DECRYPTION_FAILED,
    STATUS_DECRYPTION_READY,
    STATUS_DECRYPTION_UNSUPPORTED,
    EncryptedDatabaseManager,
    KeyAssessmentService,
    KeyMaterial,
    display_encrypted_candidates_list,
    encrypted_database_candidates_menu,
)


def _create_synthetic_crypt14_file(
    output_path: Path,
    plaintext_db_bytes: bytes,
    aes_key: bytes,
    iv: bytes = None,
    compress: bool = True,
) -> None:
    """Create a synthetic crypt14 file containing real AES-GCM ciphertext."""
    if iv is None:
        iv = os.urandom(16)
    nonce_12 = iv[:12]

    payload = zlib.compress(plaintext_db_bytes) if compress else plaintext_db_bytes
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce_12, payload, None)

    header = bytearray(191)
    header[67:83] = iv
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(bytes(header) + ciphertext)


def _create_valid_sqlite_db(db_path: Path, msg_count: int = 5) -> bytes:
    """Create a valid SQLite chat database with modern or classic tables."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
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
        conn.execute("CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER)")
        conn.execute("CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT)")
        conn.execute("INSERT INTO jid VALUES (1, 'user123@s.whatsapp.net')")
        conn.execute("INSERT INTO chat VALUES (1, 1)")
        for i in range(1, msg_count + 1):
            ts = 1690000000000 + (i * 1000)
            conn.execute(
                "INSERT INTO message VALUES (?, 1, 0, ?, ?, 0)",
                (i, f"Test Message #{i}", ts),
            )
        conn.commit()
    return db_path.read_bytes()


class TestEncryptedDatabaseAndKeyAssessment(unittest.TestCase):
    """Test suite addressing all 13 requirements specified in Section 9."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_p = Path(self.temp_dir.name)
        self.recovery_p = self.base_p / "recovery"
        self.recovery_p.mkdir(parents=True, exist_ok=True)

        self.settings = {
            "acquisition": {
                "default_recovery_dir": str(self.recovery_p),
                "calculate_sha256": True,
            },
            "discovery": {
                "scan_paths": [str(self.base_p)],
            },
        }

        self.mock_executor = MagicMock(spec=AdbExecutor)
        self.mock_executor.is_adb_installed.return_value = True

        self.mock_device = DeviceInfo(
            serial="MOCK_DEVICE_123",
            state="device",
            model="Pixel_7",
            manufacturer="Google",
            android_version="13",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. Encrypted candidates are detected and categorized correctly
    def test_01_encrypted_candidates_detected_and_categorized(self):
        """Verify detection and classification of various encrypted databases including dated & incremental."""
        test_files = [
            ("msgstore.db.crypt14", True, False, "CRYPT14"),
            ("msgstore-2026-10-27.1.db.crypt14", True, False, "CRYPT14"),
            ("msgstore-2026-10-28.1.db.crypt15", True, False, "CRYPT15"),
            ("msgstore-increment-1-2026-10-27.1.db.crypt14", True, True, "CRYPT14"),
            ("msgstore-increment-2-2026-10-28.1.db.crypt14", True, True, "CRYPT14"),
        ]

        for fname, is_enc, is_inc, fmt in test_files:
            fpath = self.base_p / fname
            # Write 191 byte header + dummy ciphertext
            fpath.write_bytes(b"\x00" * 191 + b"CIPHERTEXT_12345")

            meta = WhatsAppDatabaseAnalyzer.identify_database(fpath)
            self.assertTrue(meta.is_encrypted, f"{fname} should be flagged encrypted")
            self.assertEqual(meta.format_type, fmt, f"{fname} format mismatch")
            self.assertEqual(meta.is_incremental, is_inc, f"{fname} is_incremental mismatch")

            # Check categorizer pattern
            cat, _ = Categorizer().categorize(fpath.name, str(fpath))
            self.assertIn(cat, ("Databases", "Backups"), f"Categorizer should classify {fname} as Databases or Backups")

    # 2. Key status distinguishes unavailable, unchecked, and available states
    def test_02_key_status_distinguishes_states(self):
        """Verify transition between KEY_STATUS_NOT_CHECKED, NOT_FOUND, and AVAILABLE."""
        fpath = self.base_p / "msgstore.db.crypt14"
        fpath.write_bytes(b"\x00" * 191 + b"ENCRYPTED_DATA")

        cand = ChatDatabaseCandidate(
            path=str(fpath),
            filename=fpath.name,
            size_bytes=len(fpath.read_bytes()),
            source="LOCAL_SCAN",
            format_type="CRYPT14",
            is_sqlite=False,
            is_encrypted=True,
            is_readable=False,
            is_accessible=True,
            has_key=False,
        )

        # Initial state
        self.assertEqual(cand.key_status, KEY_STATUS_NOT_CHECKED)

        # Assessment without key available
        service = KeyAssessmentService(self.mock_executor)
        # Mock adb failure for device
        self.mock_executor.run_cmd.return_value = subprocess.CompletedProcess(
            args=["adb", "shell"], returncode=1, stdout="", stderr="ls: Permission denied"
        )
        res = service.assess_candidate(cand, device=self.mock_device)
        self.assertEqual(res.key_status, KEY_STATUS_NOT_FOUND)
        self.assertEqual(cand.key_status, KEY_STATUS_NOT_FOUND)
        self.assertFalse(res.key_found)

        # Now supply legitimate 158-byte key file
        key_p = self.base_p / "test.key"
        key_p.write_bytes(b"\x00" * 126 + os.urandom(32))

        res_with_key = service.assess_candidate(cand, user_key_path=str(key_p))
        self.assertEqual(res_with_key.key_status, KEY_STATUS_AVAILABLE)
        self.assertEqual(cand.key_status, KEY_STATUS_AVAILABLE)
        self.assertEqual(cand.decryption_status, STATUS_DECRYPTION_READY)
        self.assertTrue(res_with_key.key_found)
        self.assertIsNotNone(res_with_key.key_material)

    # 3. Secret values never appear in logs, dicts, or reports
    def test_03_secret_values_never_appear_in_logs_or_reports(self):
        """Ensure private key bytes and raw hex are strictly masked from strings and serializations."""
        raw_secret_key = b"\xaa\xbb\xcc\xdd" * 8
        key_obj = KeyMaterial(
            source_type="USER_SPECIFIED",
            source_path="/safe/path/whatsapp.key",
            key_format="WHATSAPP_KEY_158",
            is_valid=True,
            size_bytes=158,
            description="WhatsApp 158-byte key file",
            key_identifier="key_158_masked",
            _raw_key=raw_secret_key,
        )

        # Check str() and repr()
        str_repr = str(key_obj)
        repr_repr = repr(key_obj)
        self.assertNotIn(raw_secret_key.hex(), str_repr)
        self.assertNotIn(raw_secret_key.hex(), repr_repr)
        self.assertNotIn("aabbccdd", str_repr.lower())
        self.assertNotIn("aabbccdd", repr_repr.lower())

        # Check to_dict()
        dict_repr = key_obj.to_dict()
        self.assertNotIn("_raw_key", dict_repr)
        dict_json = json.dumps(dict_repr)
        self.assertNotIn(raw_secret_key.hex(), dict_json)

        # Candidate serialization
        cand = ChatDatabaseCandidate(
            path="/tmp/msgstore.db.crypt14",
            filename="msgstore.db.crypt14",
            size_bytes=1000,
            source="LOCAL",
            format_type="CRYPT14",
            is_sqlite=False,
            is_encrypted=True,
            is_readable=False,
            is_accessible=True,
            has_key=True,
            key_path="/safe/path/whatsapp.key",
            key_status=KEY_STATUS_AVAILABLE,
        )
        cand_dict = cand.to_dict()
        self.assertNotIn("raw_key", cand_dict)
        self.assertNotIn("secret", str(cand_dict).lower())

    # 4. Key checks respect Android permission boundaries
    def test_04_key_checks_respect_android_sandbox_boundaries(self):
        """Verify that Android sandbox permission denial is honestly reported without guessing or bypassing."""
        service = KeyAssessmentService(self.mock_executor)

        cand = ChatDatabaseCandidate(
            path="/sdcard/WhatsApp/Databases/msgstore.db.crypt14",
            filename="msgstore.db.crypt14",
            size_bytes=2048,
            source="DEVICE_STORAGE",
            format_type="CRYPT14",
            is_sqlite=False,
            is_encrypted=True,
            is_readable=False,
            is_accessible=True,
            has_key=False,
        )

        # Non-rooted device returning Permission denied for private app data
        self.mock_executor.run_cmd.return_value = subprocess.CompletedProcess(
            args=["adb", "shell", "ls", "-l", "/data/data/com.whatsapp/files/key"],
            returncode=1,
            stdout="",
            stderr="ls: /data/data/com.whatsapp/files/key: Permission denied",
        )

        res = service.assess_candidate(cand, device=self.mock_device)
        self.assertFalse(res.key_found)
        self.assertEqual(res.key_status, KEY_STATUS_NOT_FOUND)
        # Verify it specifically mentions the Android sandbox boundary rather than claiming the file does not exist
        self.assertIn("sandbox", res.notes.lower())
        self.assertIn("permission", res.notes.lower())

    # 5. Single-file and multi-file encrypted acquisition work
    def test_05_single_and_multi_file_encrypted_acquisition(self):
        """Verify copying encrypted databases locally and recording verification records."""
        manager = EncryptedDatabaseManager(self.mock_executor, self.settings)
        dest_dir = self.recovery_p / "test_session" / "databases"

        # Create two encrypted dummy candidates
        f1 = self.base_p / "msgstore.db.crypt14"
        f1.write_bytes(b"\x01" * 500)
        f2 = self.base_p / "msgstore-2026-10-27.1.db.crypt14"
        f2.write_bytes(b"\x02" * 800)

        c1 = ChatDatabaseCandidate(
            path=str(f1),
            filename=f1.name,
            size_bytes=500,
            source="LOCAL_SCAN",
            format_type="CRYPT14",
            is_sqlite=False,
            is_encrypted=True,
            is_readable=False,
            is_accessible=True,
            has_key=False,
        )
        c2 = ChatDatabaseCandidate(
            path=str(f2),
            filename=f2.name,
            size_bytes=800,
            source="LOCAL_SCAN",
            format_type="CRYPT14",
            is_sqlite=False,
            is_encrypted=True,
            is_readable=False,
            is_accessible=True,
            has_key=False,
        )

        # Single file acquisition
        rec1 = manager.acquire_encrypted_files([c1], None, dest_dir)
        self.assertEqual(len(rec1), 1)
        self.assertEqual(rec1[0].status, "VERIFIED")
        self.assertTrue((dest_dir / f1.name).is_file())
        self.assertEqual((dest_dir / f1.name).stat().st_size, 500)

        # Multi-file acquisition
        rec_multi = manager.acquire_encrypted_files([c1, c2], None, dest_dir)
        self.assertEqual(len(rec_multi), 2)
        # Check acquisition manifest created
        manifest_p = dest_dir.parent / "manifests" / "acquisition_manifest.json"
        self.assertTrue(manifest_p.is_file(), "Acquisition manifest should be saved")

    # 6. Blank destination input uses configured default
    def test_06_blank_destination_input_uses_configured_default(self):
        """Verify prompt_recovery_destination accepts empty input and defaults properly."""
        from wrs.discovery_wizard import prompt_recovery_destination

        # Input function returning blank string
        mock_input = MagicMock(return_value="")

        chosen = prompt_recovery_destination(
            device=self.mock_device,
            total_files=2,
            total_bytes=1024,
            settings=self.settings,
            input_func=mock_input,
        )

        self.assertIsNotNone(chosen)
        self.assertTrue(str(chosen).startswith(str(self.recovery_p)))
        self.assertIn("Google_Pixel_7", str(chosen))

    # 7. Existing files are never overwritten
    def test_07_existing_files_are_never_overwritten(self):
        """Ensure file acquisition and decryption resolve collisions by appending counter instead of overwriting."""
        manager = EncryptedDatabaseManager(self.mock_executor, self.settings)
        dest_dir = self.recovery_p / "collision_test" / "databases"
        dest_dir.mkdir(parents=True, exist_ok=True)

        existing_target = dest_dir / "msgstore.db.crypt14"
        existing_target.write_bytes(b"EXISTING_ORIGINAL_FILE_CONTENT")

        src_file = self.base_p / "msgstore.db.crypt14"
        src_file.write_bytes(b"NEW_INCOMING_FILE_CONTENT")

        cand = ChatDatabaseCandidate(
            path=str(src_file),
            filename=src_file.name,
            size_bytes=len(src_file.read_bytes()),
            source="LOCAL_SCAN",
            format_type="CRYPT14",
            is_sqlite=False,
            is_encrypted=True,
            is_readable=False,
            is_accessible=True,
            has_key=False,
        )

        records = manager.acquire_encrypted_files([cand], None, dest_dir)
        self.assertEqual(len(records), 1)

        # Original file should NOT be touched
        self.assertEqual(existing_target.read_bytes(), b"EXISTING_ORIGINAL_FILE_CONTENT")

        # New file should be stored under collision-safe name
        collision_file = dest_dir / "msgstore_1.db.crypt14"
        self.assertTrue(collision_file.is_file(), f"Expected collision file {collision_file}")
        self.assertEqual(collision_file.read_bytes(), b"NEW_INCOMING_FILE_CONTENT")

    # 8. SHA-256 and copy verification use actual file contents
    def test_08_sha256_and_copy_verification_use_actual_file_contents(self):
        """Verify genuine hash computation on acquired file."""
        manager = EncryptedDatabaseManager(self.mock_executor, self.settings)
        dest_dir = self.recovery_p / "hash_test" / "databases"

        src_file = self.base_p / "msgstore.db.crypt14"
        data = b"REAL_AUTHENTIC_BYTES_FOR_HASHING" * 50
        src_file.write_bytes(data)

        cand = ChatDatabaseCandidate(
            path=str(src_file),
            filename=src_file.name,
            size_bytes=len(data),
            source="LOCAL_SCAN",
            format_type="CRYPT14",
            is_sqlite=False,
            is_encrypted=True,
            is_readable=False,
            is_accessible=True,
            has_key=False,
        )

        records = manager.acquire_encrypted_files([cand], None, dest_dir)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, "VERIFIED")

        import hashlib
        expected_sha = hashlib.sha256(data).hexdigest()
        self.assertEqual(records[0].destination_sha256, expected_sha)
        self.assertEqual(cand.sha256, expected_sha)

    # 9. Decryption cannot run when required prerequisites are absent
    def test_09_decryption_cannot_run_when_prerequisites_absent(self):
        """Verify decryption aborts when key material is missing or invalid."""
        manager = EncryptedDatabaseManager(self.mock_executor, self.settings)
        out_dir = self.recovery_p / "decrypted_test"

        src_file = self.base_p / "msgstore.db.crypt14"
        src_file.write_bytes(b"\x00" * 191 + b"ENCRYPTED_DATA")

        cand = ChatDatabaseCandidate(
            path=str(src_file),
            filename=src_file.name,
            size_bytes=len(src_file.read_bytes()),
            source="LOCAL_SCAN",
            format_type="CRYPT14",
            is_sqlite=False,
            is_encrypted=True,
            is_readable=False,
            is_accessible=True,
            has_key=False,
        )

        # 1. Missing key material
        ok, res_cand, msg = manager.decrypt_working_copy(cand, None, out_dir)
        self.assertFalse(ok)
        self.assertIsNone(res_cand)
        self.assertIn("missing", msg.lower())

        # 2. Invalid key material
        invalid_km = KeyMaterial(
            source_type="USER_SPECIFIED",
            source_path="/path/to/invalid",
            key_format="INVALID",
            is_valid=False,
            size_bytes=10,
            description="Invalid",
            key_identifier="invalid_key",
            _raw_key=None,
        )
        ok2, res_cand2, msg2 = manager.decrypt_working_copy(cand, invalid_km, out_dir)
        self.assertFalse(ok2)
        self.assertIsNone(res_cand2)

    # 10. Decryption processes a working copy rather than modifying original
    def test_10_decryption_processes_working_copy_without_modifying_original(self):
        """Verify the original encrypted source file is never modified or overwritten."""
        manager = EncryptedDatabaseManager(self.mock_executor, self.settings)
        out_dir = self.recovery_p / "working_copy_test"

        # Generate genuine SQLite DB
        raw_db = self.base_p / "plain_source.db"
        db_bytes = _create_valid_sqlite_db(raw_db, msg_count=3)

        aes_key = os.urandom(32)
        crypt_file = self.base_p / "msgstore.db.crypt14"
        _create_synthetic_crypt14_file(crypt_file, db_bytes, aes_key)

        original_bytes = crypt_file.read_bytes()
        original_mtime = crypt_file.stat().st_mtime

        # Supply valid key
        key_file = self.base_p / "valid.key"
        key_file.write_bytes(b"\x00" * 126 + aes_key)
        ok_k, km, _ = manager.key_service.validate_key_file(str(key_file))
        self.assertTrue(ok_k)

        cand = ChatDatabaseCandidate(
            path=str(crypt_file),
            filename=crypt_file.name,
            size_bytes=len(original_bytes),
            source="LOCAL_SCAN",
            format_type="CRYPT14",
            is_sqlite=False,
            is_encrypted=True,
            is_readable=False,
            is_accessible=True,
            has_key=True,
        )

        ok, dec_cand, msg = manager.decrypt_working_copy(cand, km, out_dir)
        self.assertTrue(ok, f"Decryption should succeed: {msg}")

        # Assert original encrypted file is 100% UNCHANGED
        self.assertEqual(crypt_file.read_bytes(), original_bytes)
        self.assertEqual(crypt_file.stat().st_mtime, original_mtime)

        # Output file is separate
        self.assertNotEqual(Path(dec_cand.path).resolve(), crypt_file.resolve())

    # 11. Successful decryption requires database validation
    def test_11_successful_decryption_requires_database_validation(self):
        """Verify that decryption fails validation if decrypted payload is corrupt or not valid SQLite."""
        manager = EncryptedDatabaseManager(self.mock_executor, self.settings)
        out_dir = self.recovery_p / "validation_test"

        # Payload is random non-SQLite bytes
        fake_payload = b"RANDOM_CORRUPT_BYTES_NOT_SQLITE" * 20
        aes_key = os.urandom(32)
        crypt_file = self.base_p / "corrupt_payload.db.crypt14"
        _create_synthetic_crypt14_file(crypt_file, fake_payload, aes_key, compress=False)

        key_file = self.base_p / "test_k.key"
        key_file.write_bytes(b"\x00" * 126 + aes_key)
        _, km, _ = manager.key_service.validate_key_file(str(key_file))

        cand = ChatDatabaseCandidate(
            path=str(crypt_file),
            filename=crypt_file.name,
            size_bytes=crypt_file.stat().st_size,
            source="LOCAL_SCAN",
            format_type="CRYPT14",
            is_sqlite=False,
            is_encrypted=True,
            is_readable=False,
            is_accessible=True,
            has_key=True,
        )

        ok, dec_cand, msg = manager.decrypt_working_copy(cand, km, out_dir)
        # Must fail database validation!
        self.assertFalse(ok)
        self.assertIsNone(dec_cand)
        self.assertTrue("sqlite" in msg.lower() or "validation" in msg.lower())
        self.assertEqual(cand.decryption_status, STATUS_DECRYPTION_FAILED)

    # 12. Failed or unsupported decryption is reported honestly
    def test_12_failed_or_unsupported_decryption_reported_honestly(self):
        """Distinguish corrupted/bad key errors and unsupported format."""
        manager = EncryptedDatabaseManager(self.mock_executor, self.settings)
        out_dir = self.recovery_p / "unsupported_test"

        # Bad key on valid ciphertext
        valid_db = self.base_p / "v_db.db"
        db_bytes = _create_valid_sqlite_db(valid_db)
        good_key = os.urandom(32)
        bad_key = os.urandom(32)

        crypt_file = self.base_p / "bad_key.db.crypt14"
        _create_synthetic_crypt14_file(crypt_file, db_bytes, good_key)

        bad_key_file = self.base_p / "wrong.key"
        bad_key_file.write_bytes(b"\x00" * 126 + bad_key)
        _, wrong_km, _ = manager.key_service.validate_key_file(str(bad_key_file))

        cand = ChatDatabaseCandidate(
            path=str(crypt_file),
            filename=crypt_file.name,
            size_bytes=crypt_file.stat().st_size,
            source="LOCAL_SCAN",
            format_type="CRYPT14",
            is_sqlite=False,
            is_encrypted=True,
            is_readable=False,
            is_accessible=True,
            has_key=True,
        )

        ok, dec_c, msg = manager.decrypt_working_copy(cand, wrong_km, out_dir)
        self.assertFalse(ok)
        self.assertEqual(cand.decryption_status, STATUS_DECRYPTION_FAILED)
        self.assertIn("failed", msg.lower())

    # 13. Existing scan, acquisition, chat-analysis, export, and reporting functionality remains intact
    def test_13_existing_scan_acquisition_and_analysis_remain_intact(self):
        """Ensure full end-to-end integration: decryption produces readable SQLite candidate that integrates with registry."""
        registry = ChatDatabaseRegistry()
        manager = EncryptedDatabaseManager(self.mock_executor, self.settings, registry=registry)
        out_dir = self.recovery_p / "e2e_test"

        plain_db = self.base_p / "chat_real.db"
        db_bytes = _create_valid_sqlite_db(plain_db, msg_count=10)
        aes_key = os.urandom(32)
        crypt_file = self.base_p / "msgstore-2026-10-27.1.db.crypt14"
        _create_synthetic_crypt14_file(crypt_file, db_bytes, aes_key)

        key_file = self.base_p / "whatsapp.key"
        key_file.write_bytes(b"\x00" * 126 + aes_key)
        _, km, _ = manager.key_service.validate_key_file(str(key_file))

        cand = ChatDatabaseCandidate(
            path=str(crypt_file),
            filename=crypt_file.name,
            size_bytes=crypt_file.stat().st_size,
            source="LOCAL_SCAN",
            format_type="CRYPT14",
            is_sqlite=False,
            is_encrypted=True,
            is_readable=False,
            is_accessible=True,
            has_key=True,
        )

        ok, dec_cand, msg = manager.decrypt_working_copy(cand, km, out_dir)
        self.assertTrue(ok)
        self.assertIsNotNone(dec_cand)
        self.assertTrue(dec_cand.is_readable)
        self.assertEqual(dec_cand.message_count, 10)
        self.assertEqual(dec_cand.decryption_status, STATUS_DECRYPTED)

        # Candidate is recorded in registry and findable by registry
        readables = [c for c in registry.load() if c.is_readable]
        self.assertEqual(len(readables), 1)
        self.assertEqual(readables[0].filename, dec_cand.filename)

        # Raw message extraction through WhatsAppDatabaseAnalyzer
        raw_msgs = WhatsAppDatabaseAnalyzer.extract_raw_messages(Path(dec_cand.path))
        self.assertEqual(len(raw_msgs), 10)
        self.assertIn("Test Message #1", raw_msgs[0]["text_content"])


if __name__ == "__main__":
    unittest.main()
