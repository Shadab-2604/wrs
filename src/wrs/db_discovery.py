"""Automatic chat database discovery, candidate registry, and date discovery service for WRS.

Provides:
- Multi-source database discovery across registry, recovery output, configured paths, and ADB device storage.
- Non-destructive candidate identification (SQLite schema inspection, Crypt14/15 detection).
- Persistent candidate registry with stale entry tracking and integrity tracking.
- Automatic selection flow (single readable, multi-candidate menu, encrypted-only handling, and no-candidate guidance).
- True message timestamp extraction and date-range exploration.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .database import DatabaseMetadata, WhatsAppDatabaseAnalyzer
from .device import AdbExecutor, DeviceInfo
from .hashing import hash_local_file
from .utils import format_bytes, format_timestamp, load_settings
from .wizard import DateRangeEngine, message_to_datetime

logger = logging.getLogger("wrs.db_discovery")


@dataclass
class ChatDatabaseCandidate:
    """Forensic candidate metadata for a discovered WhatsApp database or backup."""

    path: str
    filename: str
    size_bytes: int
    source: str  # "REGISTRY", "ACQUISITION_DIRECTORY", "CONFIGURED_SCAN_DIR", "DEVICE_STORAGE", "MANUAL_IMPORT"
    format_type: str  # "SQLITE", "CRYPT15", "CRYPT14", "CRYPT12", "UNKNOWN"
    is_sqlite: bool = False
    is_encrypted: bool = False
    is_readable: bool = False
    is_accessible: bool = True
    has_key: bool = False
    decrypted_path: Optional[str] = None
    message_count: int = 0
    oldest_timestamp: Optional[str] = None
    newest_timestamp: Optional[str] = None
    oldest_dt: Optional[datetime] = None
    newest_dt: Optional[datetime] = None
    modified_timestamp: str = ""
    mtime_epoch: float = 0.0
    sha256: str = ""
    validation_notes: str = ""
    is_stale: bool = False
    last_discovered: str = field(default_factory=format_timestamp)

    @property
    def size_human(self) -> str:
        return format_bytes(self.size_bytes)

    def to_dict(self) -> Dict[str, Any]:
        """Convert candidate to serializable dictionary for registry storage."""
        d = asdict(self)
        if self.oldest_dt:
            d["oldest_dt"] = self.oldest_dt.isoformat()
        if self.newest_dt:
            d["newest_dt"] = self.newest_dt.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ChatDatabaseCandidate:
        """Construct candidate from registry dictionary."""
        d = dict(data)
        old_dt_str = d.get("oldest_dt")
        if old_dt_str and isinstance(old_dt_str, str):
            try:
                d["oldest_dt"] = datetime.fromisoformat(old_dt_str)
            except ValueError:
                d["oldest_dt"] = None
        else:
            d["oldest_dt"] = None

        new_dt_str = d.get("newest_dt")
        if new_dt_str and isinstance(new_dt_str, str):
            try:
                d["newest_dt"] = datetime.fromisoformat(new_dt_str)
            except ValueError:
                d["newest_dt"] = None
        if "mtime_epoch" not in d:
            d["mtime_epoch"] = 0.0

        return cls(**d)


class ChatDatabaseRegistry:
    """Persistent catalog of discovered chat databases with stale entry tracking."""

    def __init__(self, registry_file: Optional[Path | str] = None) -> None:
        if registry_file:
            self.registry_file = Path(registry_file).resolve()
        else:
            # Default to recovery/database_registry.json
            self.registry_file = Path("recovery/database_registry.json").resolve()

    def load(self) -> List[ChatDatabaseCandidate]:
        """Load registered candidates and validate their presence on disk."""
        if not self.registry_file.exists():
            return []

        candidates: List[ChatDatabaseCandidate] = []
        try:
            with open(self.registry_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, list):
                    return []
                for item in data:
                    if isinstance(item, dict):
                        cand = ChatDatabaseCandidate.from_dict(item)
                        # Detect stale local paths
                        if cand.source != "DEVICE_STORAGE":
                            p = Path(cand.path)
                            if not p.exists():
                                cand.is_stale = True
                                cand.is_accessible = False
                                cand.validation_notes = "File was deleted, moved, or is inaccessible on disk."
                            else:
                                # Revalidate size on disk
                                try:
                                    cur_size = p.stat().st_size
                                    if cur_size != cand.size_bytes:
                                        cand.is_stale = True
                                        cand.validation_notes = f"Size changed on disk ({cand.size_bytes} -> {cur_size})."
                                except OSError:
                                    cand.is_stale = True
                        candidates.append(cand)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Failed to load candidate registry from %s: %s", self.registry_file, e)
            return []

        return candidates

    def save(self, candidates: List[ChatDatabaseCandidate]) -> bool:
        """Persist candidates to registry file, creating parent directories as needed."""
        try:
            self.registry_file.parent.mkdir(parents=True, exist_ok=True)
            serializable = [c.to_dict() for c in candidates if not c.is_stale]
            with open(self.registry_file, "w", encoding="utf-8") as f:
                json.dump(serializable, f, indent=2)
            return True
        except OSError as e:
            logger.warning("Failed to save candidate registry to %s: %s", self.registry_file, e)
            return False

    def register(self, candidate: ChatDatabaseCandidate) -> None:
        """Register or update a candidate in the persistent catalog."""
        current = self.load()
        updated = False
        for idx, existing in enumerate(current):
            if existing.path == candidate.path:
                current[idx] = candidate
                updated = True
                break
        if not updated:
            current.append(candidate)
        self.save(current)


def inspect_sqlite_chat_dates(db_path: Path | str) -> Tuple[bool, int, Optional[str], Optional[str], Optional[datetime], Optional[datetime], str]:
    """Inspect accessible SQLite database schema and extract actual message date range in read-only mode.

    Returns:
        (is_readable, message_count, oldest_formatted, newest_formatted, oldest_dt, newest_dt, notes)
    """
    p = Path(db_path).resolve()
    if not p.is_file():
        return False, 0, None, None, None, None, "File does not exist or is not a regular file."

    uri = f"file:{p}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        cur = conn.cursor()

        # Integrity check
        cur.execute("PRAGMA integrity_check(5);")
        rows = cur.fetchall()
        integrity_ok = any(str(r[0]).strip().lower() == "ok" for r in rows if r)
        if not integrity_ok:
            conn.close()
            return False, 0, None, None, None, None, "SQLite integrity check failed."

        # Discover message tables
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {r[0] for r in cur.fetchall() if r[0]}

        msg_table: Optional[str] = None

        if "message" in tables:
            msg_table = "message"
        elif "messages" in tables:
            msg_table = "messages"

        if not msg_table:
            conn.close()
            return False, 0, None, None, None, None, "Database has no WhatsApp 'message' or 'messages' table."

        # Verify timestamp column existence
        cur.execute(f"PRAGMA table_info({msg_table});")
        cols = {r[1] for r in cur.fetchall() if len(r) > 1}
        if "timestamp" not in cols:
            conn.close()
            return False, 0, None, None, None, None, f"Table '{msg_table}' missing timestamp column."

        # Query counts and boundary timestamps
        cur.execute(f"SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM {msg_table} WHERE timestamp > 0;")
        row = cur.fetchone()
        conn.close()

        if not row:
            return True, 0, None, None, None, None, "Table exists but contains no message records."

        cnt = row[0] or 0
        min_ts = row[1]
        max_ts = row[2]

        if cnt == 0 or min_ts is None or max_ts is None:
            return True, cnt, None, None, None, None, "Valid database with message table, but zero timestamped messages."

        def parse_epoch(val: Any) -> Optional[datetime]:
            try:
                num = float(val)
                if num <= 0:
                    return None
                if num > 1e11:  # Millisecond epoch
                    num /= 1000.0
                dt = datetime.fromtimestamp(num, timezone.utc).astimezone()
                return dt.replace(tzinfo=None)
            except (ValueError, OSError, OverflowError):
                return None

        oldest_dt = parse_epoch(min_ts)
        newest_dt = parse_epoch(max_ts)

        oldest_str = oldest_dt.strftime("%d-%m-%Y %H:%M") if oldest_dt else "Unknown"
        newest_str = newest_dt.strftime("%d-%m-%Y %H:%M") if newest_dt else "Unknown"

        notes = f"Readable SQLite database ({msg_table}) with {cnt} messages."
        return True, cnt, oldest_str, newest_str, oldest_dt, newest_dt, notes

    except sqlite3.Error as e:
        return False, 0, None, None, None, None, f"SQLite query error: {e}"


@dataclass
class DatabaseDiscoveryResult:
    """Consolidated result of a multi-stage database discovery pass."""

    candidates: List[ChatDatabaseCandidate]
    readable_candidates: List[ChatDatabaseCandidate]
    encrypted_candidates: List[ChatDatabaseCandidate]
    unsupported_candidates: List[ChatDatabaseCandidate]
    stale_candidates: List[ChatDatabaseCandidate]
    adb_available: bool
    adb_status_str: str
    device_status_str: str
    locations_searched: List[str]
    message: str


class DatabaseDiscoveryService:
    """Shared database discovery service operating across local files, registry, and ADB."""

    STANDARD_DEVICE_DB_PATHS = [
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
        "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Databases",
        "/sdcard/WhatsApp/Databases",
        "/storage/emulated/0/WhatsApp/Databases",
    ]

    W4B_DEVICE_DB_PATHS = [
        "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp/Databases",
        "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases",
        "/storage/emulated/0/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases",
    ]

    def __init__(
        self,
        executor: Optional[AdbExecutor] = None,
        settings: Optional[dict[str, Any]] = None,
        registry: Optional[ChatDatabaseRegistry] = None,
    ) -> None:
        self.executor = executor or AdbExecutor()
        self.settings = settings or load_settings()
        self.registry = registry or ChatDatabaseRegistry()

    def discover_all(
        self,
        device: Optional[DeviceInfo] = None,
        force_refresh: bool = False,
    ) -> DatabaseDiscoveryResult:
        """Execute comprehensive 6-stage search for WhatsApp chat databases in priority order."""
        locations_searched: List[str] = []
        candidates_by_path: Dict[str, ChatDatabaseCandidate] = {}
        stale_candidates: List[ChatDatabaseCandidate] = []

        # Stage 1: Previously discovered database candidates in Registry
        locations_searched.append(str(self.registry.registry_file))
        reg_candidates = self.registry.load()
        for cand in reg_candidates:
            if cand.is_stale:
                stale_candidates.append(cand)
            else:
                candidates_by_path[cand.path] = cand

        # Stage 2: WRS acquisition and recovery output directories
        rec_dir_name = self.settings.get("acquisition", {}).get("default_recovery_dir", "recovery")
        rec_base = Path(rec_dir_name).resolve()
        locations_searched.append(str(rec_base))
        if rec_base.exists() and rec_base.is_dir():
            self._scan_local_directory(rec_base, "ACQUISITION_DIRECTORY", candidates_by_path)

        # Stage 3: Existing project-configured scan directories & local working directory
        cfg_paths = self.settings.get("storage", {}).get("local_search_paths", [])
        for p_str in cfg_paths:
            p = Path(p_str).resolve()
            locations_searched.append(str(p))
            if p.exists() and p.is_dir():
                self._scan_local_directory(p, "CONFIGURED_SCAN_DIR", candidates_by_path)

        # Stage 4 & 5 & 6: Check ADB status and accessible Android storage
        adb_status = self.executor.check_device_status(selected_serial=device.serial if device else None)
        adb_avail = adb_status.adb_available
        adb_status_str = adb_status.adb_status_display
        dev_status_str = adb_status.device_status_display

        target_dev = device or adb_status.selected_device
        if target_dev and target_dev.is_accessible and adb_avail:
            all_device_paths = self.STANDARD_DEVICE_DB_PATHS + self.W4B_DEVICE_DB_PATHS
            for dev_path in all_device_paths:
                locations_searched.append(f"adb://{target_dev.serial}{dev_path}")
                self._scan_device_location(target_dev.serial, dev_path, candidates_by_path)

        # Re-evaluate all candidate classifications and dates
        all_candidates = list(candidates_by_path.values())
        for cand in all_candidates:
            if cand.source != "DEVICE_STORAGE":
                self._evaluate_local_candidate(cand)

        # Sort candidates: Readable first (newest message first), then encrypted, then others
        def sort_key(c: ChatDatabaseCandidate) -> Tuple[int, float, int]:
            prio = 0
            if c.is_readable and c.message_count > 0:
                prio = 4
            elif c.is_readable:
                prio = 3
            elif c.is_encrypted:
                prio = 2
            elif c.format_type != "UNKNOWN":
                prio = 1

            mtime_epoch = c.mtime_epoch
            if mtime_epoch == 0.0 and c.source != "DEVICE_STORAGE":
                try:
                    mtime_epoch = Path(c.path).stat().st_mtime
                except OSError:
                    mtime_epoch = 0.0

            return (prio, mtime_epoch, c.size_bytes)

        all_candidates.sort(key=sort_key, reverse=True)

        # Save freshly validated candidates to registry
        self.registry.save(all_candidates)

        readable = [c for c in all_candidates if c.is_readable and c.is_accessible]
        encrypted = [c for c in all_candidates if c.is_encrypted and c.is_accessible]
        unsupported = [c for c in all_candidates if not c.is_readable and not c.is_encrypted]

        msg = f"Discovered {len(all_candidates)} candidate(s) ({len(readable)} readable, {len(encrypted)} encrypted)."

        return DatabaseDiscoveryResult(
            candidates=all_candidates,
            readable_candidates=readable,
            encrypted_candidates=encrypted,
            unsupported_candidates=unsupported,
            stale_candidates=stale_candidates,
            adb_available=adb_avail,
            adb_status_str=adb_status_str,
            device_status_str=dev_status_str,
            locations_searched=locations_searched,
            message=msg,
        )

    def _scan_local_directory(
        self,
        directory: Path,
        source_label: str,
        results_map: Dict[str, ChatDatabaseCandidate],
    ) -> None:
        """Recursively scan local directory for database and crypt backup files."""
        for root, _, files in os.walk(directory):
            for fn in files:
                fn_lower = fn.lower()
                if fn_lower.endswith(("-wal", "-shm", "-journal", ".lock", ".tmp", ".json")):
                    continue

                if ".db" in fn_lower or "msgstore" in fn_lower or fn_lower.endswith((".crypt15", ".crypt14", ".crypt12")):
                    p = Path(root) / fn
                    path_str = str(p.resolve())
                    if path_str in results_map:
                        continue

                    try:
                        sz = p.stat().st_size
                        st_mtime = p.stat().st_mtime
                        mtime = datetime.fromtimestamp(st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        sha_hash, _, _ = hash_local_file(p)

                        cand = ChatDatabaseCandidate(
                            path=path_str,
                            filename=fn,
                            size_bytes=sz,
                            source=source_label,
                            format_type="UNKNOWN",
                            modified_timestamp=mtime,
                            mtime_epoch=st_mtime,
                            sha256=sha_hash or "",
                            validation_notes="",
                        )
                        results_map[path_str] = cand
                    except (OSError, PermissionError) as e:
                        logger.debug("Skipping unreadable local candidate %s: %s", p, e)

    def _scan_device_location(
        self,
        serial: str,
        dev_dir: str,
        results_map: Dict[str, ChatDatabaseCandidate],
    ) -> None:
        """Scan specified Android directory over ADB for candidate databases."""
        res = self.executor.run_cmd(["shell", f"ls -l '{dev_dir}' 2>/dev/null"], serial=serial, timeout=10)
        if res.returncode == 0 and res.stdout.strip():
            for line in res.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 8:
                    fn = parts[-1]
                    fn_lower = fn.lower()
                    if fn_lower.endswith(("-wal", "-shm", "-journal", ".lock")):
                        continue

                    if ".db" in fn_lower or "msgstore" in fn_lower or fn_lower.endswith((".crypt15", ".crypt14", ".crypt12")):
                        try:
                            sz = int(parts[4])
                        except (ValueError, IndexError):
                            sz = 0
                        dev_path = f"{dev_dir}/{fn}"
                        if dev_path in results_map:
                            continue

                        is_enc = fn_lower.endswith((".crypt15", ".crypt14", ".crypt12"))
                        fmt = "CRYPT15" if ".crypt15" in fn_lower else ("CRYPT14" if ".crypt14" in fn_lower else ("CRYPT12" if ".crypt12" in fn_lower else "SQLITE"))

                        cand = ChatDatabaseCandidate(
                            path=dev_path,
                            filename=fn,
                            size_bytes=sz,
                            source="DEVICE_STORAGE",
                            format_type=fmt,
                            is_sqlite=(fmt == "SQLITE"),
                            is_encrypted=is_enc,
                            is_readable=False,  # Remote device databases must be acquired before direct SQLite queries
                            is_accessible=True,
                            modified_timestamp=format_timestamp(),
                            validation_notes=f"Discovered on Android device external storage ({dev_dir}).",
                        )
                        results_map[dev_path] = cand

    def _evaluate_local_candidate(self, cand: ChatDatabaseCandidate) -> None:
        """Evaluate local candidate format, schema, encryption, and date range."""
        p = Path(cand.path)
        if not p.is_file():
            cand.is_accessible = False
            cand.is_readable = False
            cand.validation_notes = "File does not exist or is not a regular file."
            return

        header = b""
        try:
            with open(p, "rb") as f:
                header = f.read(128)
        except OSError as e:
            cand.is_accessible = False
            cand.validation_notes = f"Permission or read error: {e}"
            return

        if cand.size_bytes == 0:
            cand.format_type = "EMPTY"
            cand.is_readable = False
            cand.validation_notes = "Zero-byte file. Corrupt or unallocated artifact."
            return

        # Check for plain SQLite
        if header.startswith(b"SQLite format 3\x00"):
            cand.is_sqlite = True
            cand.is_encrypted = False
            cand.format_type = "SQLITE"
            ok, cnt, old_s, new_s, old_dt, new_dt, notes = inspect_sqlite_chat_dates(p)
            cand.is_readable = ok
            cand.message_count = cnt
            cand.oldest_timestamp = old_s
            cand.newest_timestamp = new_s
            cand.oldest_dt = old_dt
            cand.newest_dt = new_dt
            cand.validation_notes = notes
            return

        # Check for crypt extensions
        fn_lower = cand.filename.lower()
        crypt_ver = None
        for v in ("crypt15", "crypt14", "crypt12", "crypt10", "crypt8"):
            if fn_lower.endswith(f".{v}"):
                crypt_ver = v.upper()
                break

        if crypt_ver:
            cand.format_type = crypt_ver
            cand.is_encrypted = True
            cand.is_sqlite = False
            cand.is_readable = False

            key_candidate = p.parent / "key"
            cand.has_key = key_candidate.exists()
            cand.validation_notes = (
                f"WhatsApp {crypt_ver} encrypted database. "
                f"Key status: {'Found in directory' if cand.has_key else 'Key file required'}."
            )
            return

        # Arbitrary file
        cand.format_type = "UNKNOWN"
        cand.is_sqlite = False
        cand.is_encrypted = False
        cand.is_readable = False
        cand.validation_notes = "File has no valid SQLite or Crypt container signature."
