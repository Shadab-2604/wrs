"""Automated test suite for WRS automatic chat database discovery and date discovery.

Verifies:
1. One readable database is detected and selected automatically.
2. Multiple readable databases display a selection menu.
3. Encrypted databases are distinguished from readable databases.
4. Unsupported files are not falsely identified as valid databases.
5. No candidates trigger additional configured discovery before the final error.
6. Local database discovery works when no phone is connected.
7. Disconnected, unauthorized, offline, and inaccessible ADB conditions are handled correctly.
8. Stale registry entries are detected.
9. Invalid or unreadable databases do not crash the program.
10. Oldest and newest dates come from actual parsed message timestamps.
11. Date-range filtering is correct and inclusive.
12. Original source files remain unchanged.
13. Existing WRS functionality and CLI arguments continue working.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from wrs.chat import ChatReconstructionEngine, Conversation, ReconstructedMessage
from wrs.cli import (
    find_chat_database_candidates,
    parse_args,
    recover_chat_history_interactive,
    select_or_discover_chat_database_interactive,
    view_available_chat_dates_interactive,
)
from wrs.database import WhatsAppDatabaseAnalyzer
from wrs.db_discovery import (
    ChatDatabaseCandidate,
    ChatDatabaseRegistry,
    DatabaseDiscoveryResult,
    DatabaseDiscoveryService,
    inspect_sqlite_chat_dates,
)
from wrs.device import AdbExecutor, DeviceInfo, DeviceStatusResult
from wrs.wizard import DateRangeEngine


def make_device_status_result(
    adb_available: bool = True,
    adb_status_display: str = "Available (v1.0.41)",
    device_status_display: str = "No Device Connected",
    devices: list[DeviceInfo] | None = None,
    selected_device: DeviceInfo | None = None,
) -> DeviceStatusResult:
    dev_list = devices or []
    return DeviceStatusResult(
        adb_installed=adb_available,
        adb_available=adb_available,
        adb_version_raw="1.0.41" if adb_available else "",
        adb_version="1.0.41" if adb_available else "",
        adb_server_responsive=adb_available,
        adb_status_display=adb_status_display,
        enumeration_success=True,
        enumeration_error=None,
        devices=dev_list,
        device_count=len(dev_list),
        device_status_display=device_status_display,
        selected_device=selected_device,
        timestamp="2026-10-28 12:00:00",
    )


def create_sample_sqlite_whatsapp_db(
    db_path: Path,
    messages_data: list[tuple[int, str, int, str]],  # (id, jid, timestamp_ms, text)
    use_modern_schema: bool = True,
) -> None:
    """Helper to construct a valid SQLite WhatsApp message database for testing."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    if use_modern_schema:
        cur.execute(
            """
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                chat_row_id INTEGER,
                from_me INTEGER DEFAULT 0,
                timestamp INTEGER,
                message_type INTEGER DEFAULT 0,
                text_data TEXT
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE chat (
                _id INTEGER PRIMARY KEY,
                raw_string_jid TEXT
            );
            """
        )
        for mid, jid, ts, text in messages_data:
            cur.execute("INSERT OR IGNORE INTO chat (_id, raw_string_jid) VALUES (?, ?);", (mid, jid))
            cur.execute(
                "INSERT INTO message (_id, chat_row_id, from_me, timestamp, message_type, text_data) VALUES (?, ?, 0, ?, 0, ?);",
                (mid, mid, ts, text),
            )
    else:
        cur.execute(
            """
            CREATE TABLE messages (
                _id INTEGER PRIMARY KEY,
                key_remote_jid TEXT,
                key_from_me INTEGER DEFAULT 0,
                timestamp INTEGER,
                media_wa_type INTEGER DEFAULT 0,
                data TEXT
            );
            """
        )
        for mid, jid, ts, text in messages_data:
            cur.execute(
                "INSERT INTO messages (_id, key_remote_jid, key_from_me, timestamp, media_wa_type, data) VALUES (?, ?, 0, ?, 0, ?);",
                (mid, jid, ts, text),
            )

    conn.commit()
    conn.close()


class TestAutomaticDatabaseDetectionAndDateDiscovery:
    """Comprehensive test suite for WRS Chat Database Detection & Date Discovery."""

    def test_01_one_readable_database_auto_selected(self, tmp_path: Path) -> None:
        """1. One readable database is detected and selected automatically without manual input."""
        db_file = tmp_path / "msgstore.db"
        # 2 messages: 01-01-2023 and 02-01-2023
        create_sample_sqlite_whatsapp_db(
            db_file,
            [
                (1, "12345@s.whatsapp.net", 1672531200000, "Hello 2023"),
                (2, "12345@s.whatsapp.net", 1672617600000, "Second message"),
            ],
        )

        reg_file = tmp_path / "registry.json"
        registry = ChatDatabaseRegistry(reg_file)
        settings = {"acquisition": {"default_recovery_dir": str(tmp_path)}, "storage": {"local_search_paths": []}}

        mock_executor = MagicMock(spec=AdbExecutor)
        mock_executor.check_device_status.return_value = make_device_status_result(
            adb_available=False,
            adb_status_display="ADB Not Installed",
            device_status_display="No Device Connected",
            devices=[],
        )

        service = DatabaseDiscoveryService(executor=mock_executor, settings=settings, registry=registry)
        result = service.discover_all()

        assert len(result.readable_candidates) == 1
        cand = result.readable_candidates[0]
        assert cand.filename == "msgstore.db"
        assert cand.is_readable is True
        assert cand.is_sqlite is True
        assert cand.is_encrypted is False
        assert cand.message_count == 2

        # Verify that select_or_discover_chat_database_interactive auto-selects it without prompting for input
        with patch("builtins.input", side_effect=AssertionError("input() should not be called when 1 readable DB exists!")):
            selected = select_or_discover_chat_database_interactive(executor=mock_executor, settings=settings, registry=registry)
            assert selected is not None
            assert selected.path == str(db_file.resolve())
            assert selected.message_count == 2

    def test_02_multiple_readable_databases_display_selection_menu(self, tmp_path: Path) -> None:
        """2. Multiple readable databases display a selection menu and allow selection or newest file."""
        db1 = tmp_path / "msgstore_backup1.db"
        db2 = tmp_path / "msgstore_backup2.db"

        create_sample_sqlite_whatsapp_db(db1, [(1, "user1@s.whatsapp.net", 1600000000000, "Msg 1")])
        create_sample_sqlite_whatsapp_db(db2, [(1, "user2@s.whatsapp.net", 1700000000000, "Msg 2")])

        # Ensure different mtimes
        os.utime(db1, (100000, 100000))
        os.utime(db2, (200000, 200000))

        settings = {"acquisition": {"default_recovery_dir": str(tmp_path)}, "storage": {"local_search_paths": []}}
        mock_executor = MagicMock(spec=AdbExecutor)
        mock_executor.check_device_status.return_value = make_device_status_result(
            adb_available=False,
            adb_status_display="ADB Not Installed",
            device_status_display="No Device Connected",
            devices=[],
        )

        reg = ChatDatabaseRegistry(tmp_path / "reg.json")
        service = DatabaseDiscoveryService(executor=mock_executor, settings=settings, registry=reg)
        result = service.discover_all()
        assert len(result.readable_candidates) == 2

        # Test selecting option '1'
        with patch("builtins.input", return_value="1"):
            sel1 = select_or_discover_chat_database_interactive(executor=mock_executor, settings=settings, registry=reg)
            assert sel1 is not None

        # Test selecting option 'N' (newest by verified filesystem metadata)
        with patch("builtins.input", return_value="N"):
            sel_new = select_or_discover_chat_database_interactive(executor=mock_executor, settings=settings, registry=reg)
            assert sel_new is not None
            assert sel_new.path == str(db2.resolve())

    def test_03_encrypted_databases_distinguished_from_readable(self, tmp_path: Path) -> None:
        """3. Encrypted databases are distinguished from readable databases."""
        readable_db = tmp_path / "msgstore.db"
        create_sample_sqlite_whatsapp_db(readable_db, [(1, "u@s.whatsapp.net", 1650000000000, "Plain")])

        crypt14_file = tmp_path / "msgstore.db.crypt14"
        crypt14_file.write_bytes(b"\x00" * 200)

        crypt15_file = tmp_path / "msgstore.db.crypt15"
        crypt15_file.write_bytes(b"\x00" * 300)

        settings = {"acquisition": {"default_recovery_dir": str(tmp_path)}, "storage": {"local_search_paths": []}}
        mock_executor = MagicMock(spec=AdbExecutor)
        mock_executor.check_device_status.return_value = make_device_status_result(
            adb_available=False,
            adb_status_display="ADB Not Installed",
            device_status_display="No Device Connected",
            devices=[],
        )

        reg = ChatDatabaseRegistry(tmp_path / "reg.json")
        service = DatabaseDiscoveryService(executor=mock_executor, settings=settings, registry=reg)
        result = service.discover_all()

        assert len(result.readable_candidates) == 1
        assert result.readable_candidates[0].filename == "msgstore.db"
        assert result.readable_candidates[0].is_readable is True

        assert len(result.encrypted_candidates) == 2
        enc_names = {c.filename for c in result.encrypted_candidates}
        assert "msgstore.db.crypt14" in enc_names
        assert "msgstore.db.crypt15" in enc_names
        for c in result.encrypted_candidates:
            assert c.is_readable is False
            assert c.is_encrypted is True
            assert c.format_type in ("CRYPT14", "CRYPT15")

    def test_04_unsupported_files_not_falsely_identified(self, tmp_path: Path) -> None:
        """4. Unsupported files are not falsely identified as valid databases."""
        text_file = tmp_path / "msgstore.txt"
        text_file.write_text("Hello, this is not a database.")

        corrupt_db = tmp_path / "fake.db"
        corrupt_db.write_bytes(b"NOT A SQLITE HEADER AT ALL 1234567890")

        empty_db = tmp_path / "empty.db"
        empty_db.write_bytes(b"")

        settings = {"acquisition": {"default_recovery_dir": str(tmp_path)}, "storage": {"local_search_paths": []}}
        mock_executor = MagicMock(spec=AdbExecutor)
        mock_executor.check_device_status.return_value = make_device_status_result(
            adb_available=False,
            adb_status_display="ADB Not Installed",
            device_status_display="No Device Connected",
            devices=[],
        )

        reg = ChatDatabaseRegistry(tmp_path / "reg.json")
        service = DatabaseDiscoveryService(executor=mock_executor, settings=settings, registry=reg)
        result = service.discover_all()

        assert len(result.readable_candidates) == 0
        assert len(result.encrypted_candidates) == 0
        for cand in result.candidates:
            assert cand.is_readable is False
            assert cand.format_type in ("EMPTY", "UNKNOWN")

    def test_05_no_candidates_triggers_additional_discovery_before_error(self, tmp_path: Path) -> None:
        """5. No candidates trigger configured discovery pass before displaying final result."""
        empty_rec = tmp_path / "recovery"
        empty_rec.mkdir()
        extra_cfg = tmp_path / "extra_scan"
        extra_cfg.mkdir()

        settings = {
            "acquisition": {"default_recovery_dir": str(empty_rec)},
            "storage": {"local_search_paths": [str(extra_cfg)]},
        }

        mock_executor = MagicMock(spec=AdbExecutor)
        mock_executor.check_device_status.return_value = make_device_status_result(
            adb_available=True,
            adb_status_display="Available (v1.0.41)",
            device_status_display="No Device Connected",
            devices=[],
        )

        reg = ChatDatabaseRegistry(tmp_path / "reg.json")
        service = DatabaseDiscoveryService(executor=mock_executor, settings=settings, registry=reg)
        result = service.discover_all()

        assert len(result.candidates) == 0
        assert str(empty_rec.resolve()) in result.locations_searched
        assert str(extra_cfg.resolve()) in result.locations_searched

        # Verify CLI presents report and handles exit '0'
        with patch("builtins.input", return_value="0"):
            sel = select_or_discover_chat_database_interactive(executor=mock_executor, settings=settings, registry=reg)
            assert sel is None

    def test_06_local_database_discovery_works_when_no_phone_connected(self, tmp_path: Path) -> None:
        """6. Local database discovery works when no phone is connected."""
        local_db = tmp_path / "acquired_msgstore.db"
        create_sample_sqlite_whatsapp_db(local_db, [(1, "friend@s.whatsapp.net", 1660000000000, "Hi")])

        settings = {"acquisition": {"default_recovery_dir": str(tmp_path)}, "storage": {"local_search_paths": []}}

        mock_executor = MagicMock(spec=AdbExecutor)
        mock_executor.check_device_status.return_value = make_device_status_result(
            adb_available=True,
            adb_status_display="Available",
            device_status_display="No Device Connected",
            devices=[],
        )

        reg = ChatDatabaseRegistry(tmp_path / "reg.json")
        service = DatabaseDiscoveryService(executor=mock_executor, settings=settings, registry=reg)
        result = service.discover_all(device=None)

        assert len(result.readable_candidates) == 1
        assert result.readable_candidates[0].filename == "acquired_msgstore.db"
        assert result.readable_candidates[0].is_readable is True

    def test_07_adb_conditions_handled_cleanly(self, tmp_path: Path) -> None:
        """7. Disconnected, unauthorized, offline, and inaccessible ADB conditions are handled correctly."""
        settings = {"acquisition": {"default_recovery_dir": str(tmp_path)}, "storage": {"local_search_paths": []}}

        conditions = [
            ("ADB Not Installed", "ADB Unavailable", False, None),
            ("Available", "Unauthorized (Phone Screen Locked)", True, DeviceInfo(serial="DEV1", state="unauthorized")),
            ("Available", "Offline (Connection Unstable)", True, DeviceInfo(serial="DEV2", state="offline")),
            ("Available", "Connected and Authorized", True, DeviceInfo(serial="DEV3", state="device")),
        ]

        for adb_disp, dev_disp, adb_ok, dev_info in conditions:
            mock_executor = MagicMock(spec=AdbExecutor)
            mock_executor.check_device_status.return_value = make_device_status_result(
                adb_available=adb_ok,
                adb_status_display=adb_disp,
                device_status_display=dev_disp,
                devices=[dev_info] if dev_info else [],
                selected_device=dev_info,
            )

            reg = ChatDatabaseRegistry(tmp_path / "reg.json")
            service = DatabaseDiscoveryService(executor=mock_executor, settings=settings, registry=reg)
            res = service.discover_all(device=dev_info)

            assert res.adb_available == adb_ok
            assert res.adb_status_str == adb_disp
            assert res.device_status_str == dev_disp

    def test_08_stale_registry_entries_detected(self, tmp_path: Path) -> None:
        """8. Stale registry entries are detected when files are deleted or modified on disk."""
        db_file = tmp_path / "temp_msgstore.db"
        create_sample_sqlite_whatsapp_db(db_file, [(1, "u@s.whatsapp.net", 1670000000000, "Msg")])

        reg_file = tmp_path / "registry.json"
        registry = ChatDatabaseRegistry(reg_file)

        cand = ChatDatabaseCandidate(
            path=str(db_file.resolve()),
            filename=db_file.name,
            size_bytes=db_file.stat().st_size,
            source="ACQUISITION_DIRECTORY",
            format_type="SQLITE",
            is_sqlite=True,
            is_readable=True,
        )
        registry.register(cand)

        # 1. Verify initially not stale
        loaded = registry.load()
        assert len(loaded) == 1
        assert loaded[0].is_stale is False

        # 2. Delete the file on disk
        db_file.unlink()

        # 3. Reload registry and verify stale detection
        stale_loaded = registry.load()
        assert len(stale_loaded) == 1
        assert stale_loaded[0].is_stale is True
        assert stale_loaded[0].is_accessible is False
        assert "deleted" in stale_loaded[0].validation_notes.lower()

    def test_09_invalid_or_unreadable_databases_do_not_crash(self, tmp_path: Path) -> None:
        """9. Invalid or unreadable databases do not crash the program."""
        bad_sqlite = tmp_path / "corrupted.db"
        # Starts with SQLite magic header but rest is invalid garbage
        bad_sqlite.write_bytes(b"SQLite format 3\x00" + b"\xff" * 200)

        ok, cnt, old_s, new_s, old_dt, new_dt, notes = inspect_sqlite_chat_dates(bad_sqlite)
        assert ok is False
        assert cnt == 0
        assert "failed" in notes.lower() or "error" in notes.lower()

        # Database missing timestamp column
        no_ts_db = tmp_path / "no_ts.db"
        conn = sqlite3.connect(no_ts_db)
        conn.execute("CREATE TABLE message (_id INTEGER PRIMARY KEY, text_data TEXT);")
        conn.commit()
        conn.close()

        ok2, cnt2, _, _, _, _, notes2 = inspect_sqlite_chat_dates(no_ts_db)
        assert ok2 is False
        assert "missing timestamp" in notes2.lower()

    def test_10_oldest_and_newest_dates_from_actual_timestamps(self, tmp_path: Path) -> None:
        """10. Oldest and newest dates come from actual parsed message timestamps, not filesystem mtime."""
        db_file = tmp_path / "msgstore_timeline.db"
        # Millisecond epochs:
        # Msg 1: 01-01-2022 10:00:00 UTC -> 1641031200000
        # Msg 2: 15-06-2022 12:00:00 UTC -> 1655294400000
        # Msg 3: 31-10-2022 10:00:00 UTC -> 1667210400000
        create_sample_sqlite_whatsapp_db(
            db_file,
            [
                (1, "chat@s.whatsapp.net", 1641031200000, "Oldest"),
                (2, "chat@s.whatsapp.net", 1655294400000, "Middle"),
                (3, "chat@s.whatsapp.net", 1667210400000, "Newest"),
            ],
        )

        # Alter filesystem mtime to year 2026 to ensure dates do NOT come from filesystem
        future_mtime = 1798761600.0  # Year 2026
        os.utime(db_file, (future_mtime, future_mtime))

        ok, cnt, old_s, new_s, old_dt, new_dt, notes = inspect_sqlite_chat_dates(db_file)
        assert ok is True
        assert cnt == 3
        assert old_dt is not None
        assert new_dt is not None
        assert old_dt.year == 2022
        assert new_dt.year == 2022
        # Ensure it didn't take filesystem mtime (2026)
        assert old_dt.year != 2026
        assert new_dt.year != 2026

    def test_11_date_range_filtering_is_correct_and_inclusive(self) -> None:
        """11. Date-range filtering is strictly validated and inclusive."""
        min_dt = datetime(2023, 1, 10, 8, 0, 0)
        max_dt = datetime(2023, 1, 20, 18, 0, 0)

        # 1. Invalid date (e.g. 31st of February)
        val, s_dt, e_dt, msg = DateRangeEngine.validate_date_range("31-02-2023", "15-03-2023", min_dt, max_dt)
        assert val is False
        assert "Invalid Start Date" in msg

        # 2. Inverted dates (end before start)
        val, s_dt, e_dt, msg = DateRangeEngine.validate_date_range("20-01-2023", "10-01-2023", min_dt, max_dt)
        assert val is False
        assert "cannot be earlier" in msg

        # 3. Valid inclusive range
        val, s_dt, e_dt, msg = DateRangeEngine.validate_date_range("12-01-2023", "18-01-2023", min_dt, max_dt)
        assert val is True
        assert s_dt == datetime(2023, 1, 12, 0, 0, 0)
        assert e_dt == datetime(2023, 1, 18, 23, 59, 59, 999999)

        # 4. Message filtering
        conv = Conversation(
            conversation_id="test@s.whatsapp.net",
            display_name="Test Chat",
            messages=[
                ReconstructedMessage(message_id="1", conversation_id="test@s.whatsapp.net", sender_id="", timestamp=1673395200000, text_content="Jan 11"),  # 2023-01-11
                ReconstructedMessage(message_id="2", conversation_id="test@s.whatsapp.net", sender_id="", timestamp=1673654400000, text_content="Jan 14"),  # 2023-01-14
                ReconstructedMessage(message_id="3", conversation_id="test@s.whatsapp.net", sender_id="", timestamp=1674172800000, text_content="Jan 20"),  # 2023-01-20
            ],
        )

        # Filter strictly 12-01-2023 to 18-01-2023
        filtered, excl = DateRangeEngine.filter_conversations_by_date([conv], s_dt, e_dt)
        assert len(filtered) == 1
        assert len(filtered[0].messages) == 1
        assert filtered[0].messages[0].text_content == "Jan 14"

    def test_12_original_source_files_remain_unchanged(self, tmp_path: Path) -> None:
        """12. Original source files remain unchanged and accessed in read-only mode."""
        db_file = tmp_path / "readonly_msgstore.db"
        create_sample_sqlite_whatsapp_db(
            db_file,
            [(1, "target@s.whatsapp.net", 1675000000000, "Original Content")],
        )

        initial_hash = hashlib.sha256(db_file.read_bytes()).hexdigest()
        initial_mtime = db_file.stat().st_mtime

        # Run SQLite inspection and message extraction
        ok, cnt, _, _, _, _, _ = inspect_sqlite_chat_dates(db_file)
        assert ok is True
        raw = WhatsAppDatabaseAnalyzer.extract_raw_messages(db_file)
        assert len(raw) == 1

        final_hash = hashlib.sha256(db_file.read_bytes()).hexdigest()
        final_mtime = db_file.stat().st_mtime

        assert initial_hash == final_hash
        assert initial_mtime == final_mtime

    def test_13_existing_wrs_functionality_and_cli_args(self) -> None:
        """13. Existing WRS functionality, backwards compatibility, and CLI arguments continue working."""
        # 1. Test CLI argument parser flags
        with patch("sys.argv", ["wrs", "--unattended", "--no-color", "--dry-run", "--device", "TEST_SERIAL"]):
            args = parse_args()
        assert args.unattended is True
        assert args.no_color is True
        assert args.dry_run is True
        assert args.device == "TEST_SERIAL"

        # 2. Test find_chat_database_candidates backwards compatibility
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            f1 = p / "msgstore.db"
            f1.touch()
            f2 = p / "msgstore.db.crypt14"
            f2.touch()
            f3 = p / "ignore.tmp"
            f3.touch()

            cands = find_chat_database_candidates(p)
            assert len(cands) == 2
            cand_names = [c.name for c in cands]
            assert "msgstore.db" in cand_names
            assert "msgstore.db.crypt14" in cand_names
            assert "ignore.tmp" not in cand_names
