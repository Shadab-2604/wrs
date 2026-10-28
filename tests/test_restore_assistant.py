"""Automated tests for Recovery & Restore Assistant module (src/wrs/restore.py).

Validates:
- Candidate discovery across local recovery and remote device storage.
- Forensic classification lifecycle: DISCOVERED, ACQUIRED, VALIDATED, PARSEABLE, RESTORABLE, UNSUPPORTED.
- Source assessment: LOCAL_BACKUP, SUPPORTED_READABLE_DATABASE, MEDIA_ONLY_COLLECTION, UNSUPPORTED_ARTIFACT.
- Rule: Never classify encrypted database as restorable solely from its filename (zero-byte or invalid headers).
- Safe restoration preparation and staging manifest.
- Local staging collision protection.
- Device destination collision refusal (never overwrite existing backups on Android).
- Affirmative user confirmation requirement (refuses to push when unconfirmed).
- Push verification against remote size.
- Pre-restoration prerequisites and post-restoration verification checklists.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
import unittest
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from wrs.device import AdbExecutor
from wrs.restore import (
    CandidateSourceType,
    RestoreAssistant,
    RestoreCandidate,
    RestoreCandidateStatus,
)


class TestRestoreAssistant(unittest.TestCase):
    """Test candidate evaluation, restoration staging, collision prevention, and checklists."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.recovery_dir = self.temp_dir / "recovery"
        self.recovery_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_synthetic_sqlite_db(self, path: Path) -> Path:
        """Helper to create a valid SQLite database with a message table."""
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path))
        cur = conn.cursor()
        cur.execute("CREATE TABLE message (key_id TEXT, text_data TEXT, timestamp INTEGER);")
        cur.execute("INSERT INTO message VALUES ('1', 'Hello world', 1704067200);")
        conn.commit()
        conn.close()
        return path

    def _create_synthetic_crypt14(self, path: Path, size: int = 1024) -> Path:
        """Helper to create a synthetic encrypted container with valid crypt14 magic header."""
        path.parent.mkdir(parents=True, exist_ok=True)
        header = b"WhatsApp Crypt14\x00\x00\x01\x02\x03\x04"
        payload = header + b"\x00" * max(0, size - len(header))
        path.write_bytes(payload)
        return path

    def test_never_classify_encrypted_database_from_filename_alone(self):
        """Rule: A file named 'msgstore.db.crypt14' that is 0-bytes or corrupted must NOT be marked RESTORABLE."""
        zero_byte_crypt = self.recovery_dir / "msgstore.db.crypt14"
        zero_byte_crypt.write_bytes(b"")

        cands = RestoreAssistant.scan_local_recovery_candidates(self.recovery_dir)
        self.assertEqual(len(cands), 1)
        cand = cands[0]
        self.assertEqual(cand.filename, "msgstore.db.crypt14")
        self.assertEqual(cand.status, RestoreCandidateStatus.UNSUPPORTED)
        self.assertEqual(cand.source_type, CandidateSourceType.UNSUPPORTED_ARTIFACT)
        self.assertIn("0 bytes", cand.validation_notes)

        # File with non-zero bytes but invalid header content (< 512 bytes)
        corrupt_crypt = self.recovery_dir / "corrupt_msgstore.db.crypt14"
        corrupt_crypt.write_bytes(b"NOT_A_CRYPT_HEADER_TRUNCATED")
        cands2 = RestoreAssistant.scan_local_recovery_candidates(self.recovery_dir)
        corrupt_cand = next(c for c in cands2 if c.filename == "corrupt_msgstore.db.crypt14")
        self.assertNotEqual(corrupt_cand.status, RestoreCandidateStatus.RESTORABLE)
        self.assertEqual(corrupt_cand.status, RestoreCandidateStatus.UNSUPPORTED)

    def test_evaluate_valid_restorable_crypt_backup(self):
        """A valid crypt14 container with proper header and size is classified as RESTORABLE."""
        valid_crypt = self.recovery_dir / "msgstore-2024-05-01.1.db.crypt14"
        self._create_synthetic_crypt14(valid_crypt, size=2048)

        cands = RestoreAssistant.scan_local_recovery_candidates(self.recovery_dir)
        self.assertEqual(len(cands), 1)
        cand = cands[0]
        self.assertEqual(cand.status, RestoreCandidateStatus.RESTORABLE)
        self.assertEqual(cand.source_type, CandidateSourceType.LOCAL_BACKUP)
        self.assertTrue(cand.is_encrypted)
        self.assertTrue(cand.is_dated_backup)
        self.assertEqual(cand.restorable_target_name, "msgstore.db.crypt14")
        self.assertIn("Valid", cand.validation_notes)

    def test_evaluate_sqlite_database_as_parseable(self):
        """An unencrypted SQLite database is marked PARSEABLE (not directly restorable without keys)."""
        db_file = self.recovery_dir / "msgstore.db"
        self._create_synthetic_sqlite_db(db_file)

        cands = RestoreAssistant.scan_local_recovery_candidates(self.recovery_dir)
        self.assertEqual(len(cands), 1)
        cand = cands[0]
        self.assertEqual(cand.status, RestoreCandidateStatus.PARSEABLE)
        self.assertEqual(cand.source_type, CandidateSourceType.SUPPORTED_READABLE_DATABASE)
        self.assertTrue(cand.is_sqlite)
        self.assertFalse(cand.is_encrypted)
        self.assertGreater(cand.table_count, 0)

    def test_assess_source_classifications(self):
        """RestoreAssistant.assess_source distinguishes backups, databases, media-only, and unsupported artifacts."""
        # 1. Directory with media files only
        media_dir = self.temp_dir / "media_only"
        media_dir.mkdir(parents=True, exist_ok=True)
        (media_dir / "sample.jpg").write_bytes(b"FAKE_JPEG_DATA")
        (media_dir / "sample.mp4").write_bytes(b"FAKE_VIDEO_DATA")

        stype, cands, notes = RestoreAssistant.assess_source(media_dir)
        self.assertEqual(stype, CandidateSourceType.MEDIA_ONLY_COLLECTION)
        self.assertIn("media file(s)", notes)

        # 2. Directory with restorable backup
        backup_dir = self.temp_dir / "backup_case"
        self._create_synthetic_crypt14(backup_dir / "msgstore.db.crypt14", size=4096)
        stype2, cands2, _ = RestoreAssistant.assess_source(backup_dir)
        self.assertEqual(stype2, CandidateSourceType.LOCAL_BACKUP)
        self.assertEqual(len(cands2), 1)

        # 3. Directory with unencrypted SQLite database
        sqlite_dir = self.temp_dir / "sqlite_case"
        self._create_synthetic_sqlite_db(sqlite_dir / "msgstore.db")
        stype3, cands3, _ = RestoreAssistant.assess_source(sqlite_dir)
        self.assertEqual(stype3, CandidateSourceType.SUPPORTED_READABLE_DATABASE)

        # 4. Empty or unsupported directory
        empty_dir = self.temp_dir / "empty_dir"
        empty_dir.mkdir(parents=True, exist_ok=True)
        stype4, _, notes4 = RestoreAssistant.assess_source(empty_dir)
        self.assertEqual(stype4, CandidateSourceType.UNSUPPORTED_ARTIFACT)

    def test_prepare_restoration_bundle(self):
        """prepare_restoration_bundle safely copies dated backup to active restore target name in staging."""
        source_crypt = self.recovery_dir / "msgstore-2024-06-15.1.db.crypt14"
        self._create_synthetic_crypt14(source_crypt, size=4096)

        cands = RestoreAssistant.scan_local_recovery_candidates(self.recovery_dir)
        cand = cands[0]

        staging_dir = self.temp_dir / "staging_01"
        ok, msg, staged_path = RestoreAssistant.prepare_restoration_bundle(cand, staging_dir)
        self.assertTrue(ok)
        self.assertIsNotNone(staged_path)
        self.assertEqual(staged_path.name, "msgstore.db.crypt14")
        self.assertTrue(staged_path.exists())

        # Original candidate remains untouched
        self.assertTrue(source_crypt.exists())
        self.assertEqual(source_crypt.stat().st_size, staged_path.stat().st_size)

        # Manifest created in staging directory
        manifest_file = staging_dir / "restoration_manifest.json"
        self.assertTrue(manifest_file.exists())
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        self.assertEqual(manifest["original_filename"], "msgstore-2024-06-15.1.db.crypt14")
        self.assertEqual(manifest["staged_target_filename"], "msgstore.db.crypt14")
        self.assertIn("prerequisites", manifest)

    def test_staging_collision_detection(self):
        """prepare_restoration_bundle refuses to overwrite conflicting staged file."""
        source_crypt = self.recovery_dir / "msgstore-2024-06-15.1.db.crypt14"
        self._create_synthetic_crypt14(source_crypt, size=4096)
        cand = RestoreAssistant.scan_local_recovery_candidates(self.recovery_dir)[0]

        staging_dir = self.temp_dir / "staging_collision"
        staging_dir.mkdir(parents=True, exist_ok=True)
        # Pre-create conflicting destination file with different contents
        conflicting = staging_dir / "msgstore.db.crypt14"
        conflicting.write_bytes(b"CONFLICTING_STAGED_PAYLOAD_DIFFERENT_HASH")

        ok, msg, staged = RestoreAssistant.prepare_restoration_bundle(cand, staging_dir)
        self.assertFalse(ok)
        self.assertIsNone(staged)
        self.assertIn("Staging collision", msg)

    def test_staging_fails_for_unsupported_candidate(self):
        """prepare_restoration_bundle refuses candidates marked UNSUPPORTED."""
        cand = RestoreCandidate(
            source_path="/fake/path",
            filename="bad.db",
            size_bytes=0,
            modified_timestamp="2026-10-28 10:00:00",
            sha256_hash="",
            detected_format="EMPTY",
            status=RestoreCandidateStatus.UNSUPPORTED,
            source_type=CandidateSourceType.UNSUPPORTED_ARTIFACT,
        )
        ok, msg, staged = RestoreAssistant.prepare_restoration_bundle(cand, self.temp_dir / "staging_bad")
        self.assertFalse(ok)
        self.assertIn("Not eligible", msg)

    def test_push_staged_backup_requires_affirmative_confirmation(self):
        """Rule: Any write back to Android device strictly requires explicit affirmative confirmation."""
        staged_file = self.temp_dir / "msgstore.db.crypt14"
        staged_file.write_bytes(b"DUMMY_CRYPT_PAYLOAD")

        executor = MagicMock(spec=AdbExecutor)
        # confirmed=False (default or user said 'n')
        ok, msg = RestoreAssistant.push_staged_backup_to_device(
            staged_file, "SERIAL_123", executor, confirmed=False
        )
        self.assertFalse(ok)
        self.assertIn("affirmative confirmation required", msg)
        executor.run_cmd.assert_not_called()

    def test_push_staged_backup_device_collision_refusal(self):
        """Rule: Never overwrite existing backups on Android device. Refuse push if remote file exists."""
        staged_file = self.temp_dir / "msgstore.db.crypt14"
        staged_file.write_bytes(b"DUMMY_CRYPT_PAYLOAD")

        executor = MagicMock(spec=AdbExecutor)
        executor.is_device_connected.return_value = True

        # Remote file existence check returns EXISTS
        executor.run_cmd.return_value = subprocess.CompletedProcess(
            args=["shell"],
            returncode=0,
            stdout="EXISTS\n",
            stderr="",
        )

        ok, msg = RestoreAssistant.push_staged_backup_to_device(
            staged_file, "SERIAL_123", executor, confirmed=True
        )
        self.assertFalse(ok)
        self.assertIn("Destination collision on device", msg)
        self.assertIn("refuses to overwrite existing device backups", msg)

    def test_push_staged_backup_successful_deployment(self):
        """Successful push checks collision, makes remote dir, pushes file, and verifies size."""
        staged_file = self.temp_dir / "msgstore.db.crypt14"
        payload = b"VALID_CRYPT_PAYLOAD_FOR_PUSH_TEST"
        staged_file.write_bytes(payload)

        executor = MagicMock(spec=AdbExecutor)
        executor.is_device_connected.return_value = True

        def mock_run_cmd(cmd, serial=None, timeout=None):
            cmd_str = " ".join(cmd)
            if "test -f" in cmd_str:
                # File not found on remote (no collision)
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="NOT_FOUND\n", stderr="")
            elif "mkdir -p" in cmd_str:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            elif cmd[0] == "push":
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="1 file pushed", stderr="")
            elif "ls -l" in cmd_str:
                # Returns matching remote size
                sz = len(payload)
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=0,
                    stdout=f"-rw-rw---- 1 u0_a123 media_rw {sz} 2026-10-28 10:00 msgstore.db.crypt14",
                    stderr="",
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        executor.run_cmd.side_effect = mock_run_cmd

        ok, msg = RestoreAssistant.push_staged_backup_to_device(
            staged_file, "SERIAL_123", executor, confirmed=True
        )
        self.assertTrue(ok)
        self.assertIn("Successfully deployed", msg)

    def test_prerequisites_and_verification_checklists(self):
        """Restoration workstation provides actionable prerequisites and verification checklists."""
        prereqs = RestoreAssistant.get_prerequisites_list()
        self.assertGreaterEqual(len(prereqs), 5)
        self.assertTrue(any("Phone Number" in p for p in prereqs))
        self.assertTrue(any("Fresh WhatsApp" in p for p in prereqs))
        self.assertTrue(any("Google Drive" in p for p in prereqs))

        checklist = RestoreAssistant.get_verification_checklist()
        self.assertGreaterEqual(len(checklist), 4)
        self.assertTrue(any("chat threads" in c for c in checklist))
        self.assertTrue(any("most recent message" in c for c in checklist))

        safeguards = RestoreAssistant.get_rollback_precautions()
        self.assertGreaterEqual(len(safeguards), 4)
        self.assertTrue(any("Collision" in s for s in safeguards))


if __name__ == "__main__":
    unittest.main()
