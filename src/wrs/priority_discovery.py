"""Priority-Based File Discovery Engine, Scan Animation & Review Workflow for WRS.

Provides:
- Targeted, permission-aware discovery avoiding blind filesystem traversals.
- Priorities 1 through 6:
  1. Existing WRS results (manifests, database registry, recovery directories, reports).
  2. WhatsApp database and backup locations (on connected, authorized Android devices).
  3. WhatsApp media locations (Images, Videos, Audio, Voice Notes, Documents, Stickers).
  4. WhatsApp Business locations (clearly distinguished from WhatsApp Messenger).
  5. User-configured and local search directories.
  6. Optional extended discovery with explicit user confirmation.
- Rich or plain-text progressive loading animation with real operational stages and Ctrl+C safety.
- Discovery results summary, candidate categorization, and next-action choices menu.
- Persistent discovery manifest with stale record detection and file revalidation.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .database import WhatsAppDatabaseAnalyzer
from .db_discovery import (
    ChatDatabaseCandidate,
    ChatDatabaseRegistry,
    DatabaseDiscoveryService,
    inspect_sqlite_chat_dates,
)
from .device import AdbExecutor, DeviceInfo, DeviceStatusResult
from .ui import (
    HAS_RICH,
    get_console,
    is_color_enabled,
    print_error,
    print_info,
    print_success,
    print_warning,
)
from .utils import format_bytes, format_timestamp, load_settings

logger = logging.getLogger("wrs.priority_discovery")

# Location statuses
STATUS_FOUND = "Found"
STATUS_EMPTY = "Empty"
STATUS_INACCESSIBLE = "Inaccessible"
STATUS_NOT_CHECKED = "Not Checked"
STATUS_NOT_APPLICABLE = "Not Applicable"


@dataclass
class DiscoveryLocation:
    """Represents a potential WhatsApp storage or backup location checked during discovery."""

    id: int
    name: str
    path: str
    canonical_path: str
    priority: int  # 1 to 6
    status: str  # Found, Empty, Inaccessible, Not Checked, Not Applicable
    file_count: int = 0
    total_bytes: int = 0
    is_accessible: bool = False
    is_device: bool = False
    is_business: bool = False
    is_selected: bool = True
    subdirectories: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DiscoveryLocation:
        return cls(**data)


@dataclass
class DiscoveryCandidate:
    """Represents an identified candidate file from priority discovery."""

    path: str
    filename: str
    category: str  # DATABASES, IMAGES, VIDEOS, AUDIO / VOICE NOTES, DOCUMENTS, OTHER
    size_bytes: int
    is_device: bool = False
    is_database: bool = False
    db_format: Optional[str] = None  # SQLITE, CRYPT14, CRYPT15, CRYPT12, UNKNOWN
    is_readable: bool = False
    is_encrypted: bool = False
    message_count: int = 0
    date_range: Optional[str] = None
    modified_time: Optional[str] = None
    source_priority: int = 2
    details: str = ""

    @property
    def size_human(self) -> str:
        return format_bytes(self.size_bytes)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DiscoveryCandidate:
        return cls(**data)


@dataclass
class DiscoveryManifest:
    """Persistent structured manifest recording complete priority discovery results."""

    session_id: str
    timestamp: str
    device_serial: Optional[str]
    device_name: str
    adb_status: str
    device_state: str
    duration_seconds: float
    status: str  # "Discovery completed", "Cancelled", "Incomplete"
    locations: List[DiscoveryLocation] = field(default_factory=list)
    candidates: List[DiscoveryCandidate] = field(default_factory=list)
    summary_counts: Dict[str, int] = field(default_factory=dict)
    manifest_file: Optional[str] = None

    @property
    def total_files(self) -> int:
        loc_sum = sum(loc.file_count for loc in self.locations if loc.file_count > 0)
        if loc_sum > 0:
            return loc_sum
        return len(self.candidates)

    @property
    def total_bytes(self) -> int:
        loc_bytes = sum(loc.total_bytes for loc in self.locations if loc.total_bytes > 0)
        if loc_bytes > 0:
            return loc_bytes
        return sum(c.size_bytes for c in self.candidates if c.size_bytes > 0)

    @property
    def total_size_human(self) -> str:
        return format_bytes(self.total_bytes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "device_serial": self.device_serial,
            "device_name": self.device_name,
            "adb_status": self.adb_status,
            "device_state": self.device_state,
            "duration_seconds": self.duration_seconds,
            "status": self.status,
            "locations": [loc.to_dict() for loc in self.locations],
            "candidates": [cand.to_dict() for cand in self.candidates],
            "summary_counts": self.summary_counts,
            "manifest_file": self.manifest_file,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DiscoveryManifest:
        locs = [DiscoveryLocation.from_dict(l) for l in data.get("locations", [])]
        cands = [DiscoveryCandidate.from_dict(c) for c in data.get("candidates", [])]
        return cls(
            session_id=data.get("session_id", ""),
            timestamp=data.get("timestamp", ""),
            device_serial=data.get("device_serial"),
            device_name=data.get("device_name", "Unknown"),
            adb_status=data.get("adb_status", "UNKNOWN"),
            device_state=data.get("device_state", "UNKNOWN"),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            status=data.get("status", "Unknown"),
            locations=locs,
            candidates=cands,
            summary_counts=data.get("summary_counts", {}),
            manifest_file=data.get("manifest_file"),
        )

    def save(self, target_dir: Optional[Path | str] = None) -> Path:
        """Persist discovery manifest to disk in recovery directory."""
        base_dir = Path(target_dir or "recovery").resolve()
        base_dir.mkdir(parents=True, exist_ok=True)
        fname = f"discovery_manifest_{self.session_id}.json"
        dest = base_dir / fname
        self.manifest_file = str(dest)
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        # Also maintain recovery/discovery_manifest.json as the latest reference
        latest_file = base_dir / "discovery_manifest.json"
        try:
            with open(latest_file, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2)
        except OSError:
            pass
        return dest

    @classmethod
    def load_latest(cls, recovery_dir: Optional[Path | str] = None) -> Optional[DiscoveryManifest]:
        """Load the most recent discovery manifest if available."""
        base = Path(recovery_dir or "recovery").resolve()
        latest = base / "discovery_manifest.json"
        if latest.exists():
            try:
                with open(latest, "r", encoding="utf-8") as f:
                    return cls.from_dict(json.load(f))
            except (OSError, json.JSONDecodeError):
                return None
        return None

    def revalidate_candidates(self) -> None:
        """Re-check local candidate files on disk to eliminate stale entries."""
        for cand in self.candidates:
            if not cand.is_device:
                p = Path(cand.path)
                if not p.exists():
                    cand.is_readable = False
                    cand.details = "File no longer exists on disk (stale)"
                else:
                    try:
                        cur_sz = p.stat().st_size
                        if cur_sz != cand.size_bytes:
                            cand.size_bytes = cur_sz
                            cand.details = f"File size changed on disk ({cand.size_bytes} -> {cur_sz})"
                    except OSError:
                        cand.is_readable = False


class PriorityDiscoveryEngine:
    """Priority-based, targeted, permission-aware file discovery engine."""

    # Standard candidate paths on Android storage
    DEVICE_DB_PATHS = [
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases/",
        "/sdcard/WhatsApp/Databases/",
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Backups/",
    ]

    DEVICE_MEDIA_PATHS = [
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Media/",
        "/sdcard/WhatsApp/Media/",
    ]

    DEVICE_W4B_PATHS = [
        "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/",
        "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp/",
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

    def run_priority_discovery(
        self,
        device: Optional[DeviceInfo] = None,
        stage_callback: Optional[Callable[[str, str], None]] = None,
        cancel_requested: Optional[Callable[[], bool]] = None,
    ) -> DiscoveryManifest:
        """Execute complete prioritized discovery across Priorities 1 to 5."""
        start_ts = time.time()
        sid = f"disc_{int(start_ts)}_{device.serial if device else 'local'}"
        timestamp_str = format_timestamp(start_ts)

        def report_stage(stage_code: str, stage_label: str) -> None:
            if stage_callback:
                stage_callback(stage_code, stage_label)

        # 1. State assessment
        report_stage("RUNNING", "Checking ADB and device authorization")
        time.sleep(0.05)  # brief pacing for live UI feedback
        adb_status = self.executor.check_device_status(selected_serial=device.serial if device else None)
        target_dev = device or adb_status.selected_device

        dev_state_str = "No device connected"
        if not adb_status.adb_available:
            dev_state_str = "ADB unavailable"
        elif not adb_status.adb_server_responsive:
            dev_state_str = "ADB server unavailable"
        elif target_dev:
            if target_dev.state == "unauthorized":
                dev_state_str = "Device unauthorized"
            elif target_dev.state == "offline":
                dev_state_str = "Device offline"
            elif target_dev.is_accessible:
                dev_state_str = "Device connected and authorized"
            else:
                dev_state_str = f"Device state: {target_dev.state}"
        elif adb_status.device_count == 0:
            dev_state_str = "No device connected"

        locations: List[DiscoveryLocation] = []
        candidates: List[DiscoveryCandidate] = []
        loc_id = 1

        # Check for cancellation
        if cancel_requested and cancel_requested():
            return self._build_cancelled_manifest(sid, timestamp_str, target_dev, adb_status, dev_state_str, start_ts)

        # -------------------------------------------------------------
        # Priority 1 — Existing WRS Results
        # -------------------------------------------------------------
        report_stage("RUNNING", "Loading existing WRS scan manifests")
        rec_dir_setting = self.settings.get("acquisition", {}).get("default_recovery_dir", "recovery")
        rec_base = Path(rec_dir_setting).resolve()

        p1_files = 0
        p1_bytes = 0
        p1_status = STATUS_NOT_APPLICABLE
        p1_err = None

        if rec_base.exists() and rec_base.is_dir():
            try:
                # Inspect previously discovered database registry
                reg_cands = self.registry.load()
                for rc in reg_cands:
                    if not rc.is_stale and Path(rc.path).exists():
                        p1_files += 1
                        p1_bytes += rc.size_bytes
                        # Add candidate
                        candidates.append(
                            DiscoveryCandidate(
                                path=rc.path,
                                filename=rc.filename,
                                category="DATABASES",
                                size_bytes=rc.size_bytes,
                                is_device=False,
                                is_database=True,
                                db_format=rc.format_type,
                                is_readable=rc.is_readable,
                                is_encrypted=rc.is_encrypted,
                                message_count=rc.message_count,
                                date_range=(
                                    f"{rc.oldest_timestamp} to {rc.newest_timestamp}"
                                    if rc.oldest_timestamp and rc.newest_timestamp
                                    else None
                                ),
                                modified_time=rc.modified_timestamp,
                                source_priority=1,
                                details="From existing WRS database registry",
                            )
                        )

                # Inspect existing recovery directories for chat or media files
                for item in rec_base.rglob("*"):
                    if item.is_file():
                        # Exclude registry and manifest JSONs from the raw artifact count
                        if item.suffix.lower() in (".json", ".tmp") and ("manifest" in item.name or "registry" in item.name):
                            continue
                        try:
                            sz = item.stat().st_size
                            p1_files += 1
                            p1_bytes += sz
                        except OSError:
                            pass

                p1_status = STATUS_FOUND if p1_files > 0 else STATUS_EMPTY
            except OSError as e:
                p1_status = STATUS_INACCESSIBLE
                p1_err = str(e)
        else:
            p1_status = STATUS_EMPTY

        locations.append(
            DiscoveryLocation(
                id=loc_id,
                name="WRS recovery directory",
                path=str(rec_base),
                canonical_path=str(rec_base),
                priority=1,
                status=p1_status,
                file_count=p1_files,
                total_bytes=p1_bytes,
                is_accessible=(p1_status != STATUS_INACCESSIBLE),
                is_device=False,
                error_message=p1_err,
                notes="Verified local WRS directory and scan registry records",
            )
        )
        loc_id += 1

        if cancel_requested and cancel_requested():
            return self._build_cancelled_manifest(sid, timestamp_str, target_dev, adb_status, dev_state_str, start_ts, locations, candidates)

        # -------------------------------------------------------------
        # Priority 2 — WhatsApp Database and Backup Locations
        # -------------------------------------------------------------
        report_stage("RUNNING", "Checking known WhatsApp database locations")
        time.sleep(0.05)

        p2_status = STATUS_NOT_APPLICABLE
        p2_files = 0
        p2_bytes = 0
        p2_err = None
        p2_path = self.DEVICE_DB_PATHS[0]
        canonical_p2 = p2_path

        if target_dev and target_dev.is_accessible:
            checked_canonicals: Set[str] = set()
            found_db_loc = False

            for cand_path in self.DEVICE_DB_PATHS:
                c_clean = cand_path.rstrip("/") + "/"
                # Test directory existence with timeout
                chk = self.executor.run_cmd(
                    ["shell", "test", "-d", f'"{c_clean}"', "&&", "echo", "EXISTS"],
                    serial=target_dev.serial,
                    timeout=5,
                )
                if "EXISTS" not in chk.stdout:
                    continue

                # Resolve canonical to prevent symlink duplicates (/sdcard vs /storage/emulated/0)
                canon_chk = self.executor.run_cmd(
                    ["shell", f'readlink -f "{c_clean}" || realpath "{c_clean}" 2>/dev/null'],
                    serial=target_dev.serial,
                    timeout=5,
                )
                canon_path = c_clean
                if canon_chk.returncode == 0 and canon_chk.stdout.strip():
                    canon_res = canon_chk.stdout.strip().splitlines()[-1].strip()
                    if canon_res and canon_res.startswith("/"):
                        canon_path = canon_res.rstrip("/") + "/"

                if canon_path in checked_canonicals:
                    continue
                checked_canonicals.add(canon_path)
                p2_path = c_clean
                canonical_p2 = canon_path
                found_db_loc = True

                # Inspect directory contents for databases (limit to relevant patterns)
                ls_cmd = self.executor.run_cmd(
                    ["shell", f'ls -l "{c_clean}" 2>/dev/null'],
                    serial=target_dev.serial,
                    timeout=8,
                )
                if ls_cmd.returncode != 0 and not ls_cmd.stdout:
                    p2_status = STATUS_INACCESSIBLE
                    p2_err = ls_cmd.stderr.strip() or "Access restricted by Android permissions"
                    break

                lines = ls_cmd.stdout.splitlines()
                dir_matched_files = 0
                for line in lines:
                    line_clean = line.strip()
                    if not line_clean or line_clean.startswith("total"):
                        continue
                    parts = line_clean.split()
                    if len(parts) >= 8:
                        fname = parts[-1]
                        # WhatsApp database pattern matching
                        if (
                            fname.startswith("msgstore")
                            or fname.startswith("chatsearch")
                            or fname.startswith("wa.db")
                            or fname.endswith(".db")
                            or ".crypt" in fname
                        ):
                            try:
                                sz = int(parts[4])
                            except (ValueError, IndexError):
                                sz = 0
                            full_dp = f"{c_clean}{fname}"

                            # Determine format
                            fmt = "UNKNOWN"
                            is_enc = False
                            is_sql = False
                            if "crypt15" in fname:
                                fmt = "CRYPT15"
                                is_enc = True
                            elif "crypt14" in fname:
                                fmt = "CRYPT14"
                                is_enc = True
                            elif "crypt12" in fname:
                                fmt = "CRYPT12"
                                is_enc = True
                            elif ".crypt" in fname:
                                fmt = "CRYPT_UNKNOWN"
                                is_enc = True
                            elif fname.endswith(".db"):
                                fmt = "SQLITE"
                                is_sql = True

                            dir_matched_files += 1
                            p2_bytes += sz
                            candidates.append(
                                DiscoveryCandidate(
                                    path=full_dp,
                                    filename=fname,
                                    category="DATABASES",
                                    size_bytes=sz,
                                    is_device=True,
                                    is_database=True,
                                    db_format=fmt,
                                    is_readable=False,  # On device until acquired or inspected
                                    is_encrypted=is_enc,
                                    source_priority=2,
                                    details=(
                                        f"Encrypted Candidate ({fmt})"
                                        if is_enc
                                        else ("SQLite Database Candidate" if is_sql else "Database Backup")
                                    ),
                                )
                            )

                p2_files += dir_matched_files

            if found_db_loc:
                p2_status = STATUS_FOUND if p2_files > 0 else STATUS_EMPTY
            elif p2_status != STATUS_INACCESSIBLE:
                p2_status = STATUS_EMPTY
        elif target_dev:
            p2_status = STATUS_INACCESSIBLE
            p2_err = f"Device is {target_dev.status_display}"
        else:
            p2_status = STATUS_NOT_APPLICABLE
            p2_err = "No Android device connected"

        locations.append(
            DiscoveryLocation(
                id=loc_id,
                name="WhatsApp database directory",
                path=p2_path,
                canonical_path=canonical_p2,
                priority=2,
                status=p2_status,
                file_count=p2_files,
                total_bytes=p2_bytes,
                is_accessible=(p2_status == STATUS_FOUND or p2_status == STATUS_EMPTY),
                is_device=True,
                error_message=p2_err,
                notes="Targeted WhatsApp Databases and Backups path",
            )
        )
        loc_id += 1

        if cancel_requested and cancel_requested():
            return self._build_cancelled_manifest(sid, timestamp_str, target_dev, adb_status, dev_state_str, start_ts, locations, candidates)

        # -------------------------------------------------------------
        # Priority 3 — WhatsApp Media Locations
        # -------------------------------------------------------------
        report_stage("RUNNING", "Discovering WhatsApp media files")
        time.sleep(0.05)

        p3_status = STATUS_NOT_APPLICABLE
        p3_files = 0
        p3_bytes = 0
        p3_err = None
        p3_path = self.DEVICE_MEDIA_PATHS[0]
        canonical_p3 = p3_path
        media_subdirs: List[str] = []

        if target_dev and target_dev.is_accessible:
            found_media_loc = False
            for m_cand in self.DEVICE_MEDIA_PATHS:
                m_clean = m_cand.rstrip("/") + "/"
                chk = self.executor.run_cmd(
                    ["shell", "test", "-d", f'"{m_clean}"', "&&", "echo", "EXISTS"],
                    serial=target_dev.serial,
                    timeout=5,
                )
                if "EXISTS" not in chk.stdout:
                    continue

                found_media_loc = True
                p3_path = m_clean

                # Check readability and list actual subdirectories
                sub_chk = self.executor.run_cmd(
                    ["shell", f'ls -F "{m_clean}" 2>/dev/null | grep "/"'],
                    serial=target_dev.serial,
                    timeout=6,
                )
                if sub_chk.returncode != 0:
                    p3_status = STATUS_INACCESSIBLE
                    p3_err = "Media directory exists but read access restricted"
                    break

                subdirs = [s.strip().rstrip("/") for s in sub_chk.stdout.splitlines() if s.strip()]
                media_subdirs = subdirs

                # Count files per relevant category subdirectory without blind enumeration
                for s_dir in subdirs:
                    cat_name = self._map_subdir_to_category(s_dir)
                    sub_path = f"{m_clean}{s_dir}/"
                    cnt_cmd = self.executor.run_cmd(
                        ["shell", f'ls -f "{sub_path}" 2>/dev/null | wc -l'],
                        serial=target_dev.serial,
                        timeout=12,
                    )
                    count_val = 0
                    if cnt_cmd.returncode == 0 and cnt_cmd.stdout.strip().isdigit():
                        count_val = int(cnt_cmd.stdout.strip())

                    p3_files += count_val
                    if count_val > 0:
                        # Record aggregated candidate record per category for clear reporting
                        candidates.append(
                            DiscoveryCandidate(
                                path=sub_path,
                                filename=s_dir,
                                category=cat_name,
                                size_bytes=0,
                                is_device=True,
                                is_database=False,
                                is_readable=True,
                                message_count=count_val,
                                source_priority=3,
                                details=f"{count_val} matching files in {s_dir}",
                            )
                        )
                break

            if found_media_loc:
                p3_status = STATUS_FOUND if p3_files > 0 else STATUS_EMPTY
            elif p3_status != STATUS_INACCESSIBLE:
                p3_status = STATUS_EMPTY
        elif target_dev:
            p3_status = STATUS_INACCESSIBLE
            p3_err = f"Device is {target_dev.status_display}"
        else:
            p3_status = STATUS_NOT_APPLICABLE
            p3_err = "No Android device connected"

        locations.append(
            DiscoveryLocation(
                id=loc_id,
                name="WhatsApp media directory",
                path=p3_path,
                canonical_path=canonical_p3,
                priority=3,
                status=p3_status,
                file_count=p3_files,
                total_bytes=p3_bytes,
                is_accessible=(p3_status == STATUS_FOUND or p3_status == STATUS_EMPTY),
                is_device=True,
                subdirectories=media_subdirs,
                error_message=p3_err,
                notes="WhatsApp Media storage subdirectories",
            )
        )
        loc_id += 1

        if cancel_requested and cancel_requested():
            return self._build_cancelled_manifest(sid, timestamp_str, target_dev, adb_status, dev_state_str, start_ts, locations, candidates)

        # -------------------------------------------------------------
        # Priority 4 — WhatsApp Business, If Applicable
        # -------------------------------------------------------------
        report_stage("RUNNING", "Checking WhatsApp Business locations")
        time.sleep(0.05)

        p4_status = STATUS_NOT_APPLICABLE
        p4_files = 0
        p4_bytes = 0
        p4_err = None
        p4_path = self.DEVICE_W4B_PATHS[0]
        canonical_p4 = p4_path
        w4b_subdirs: List[str] = []

        if target_dev and target_dev.is_accessible:
            found_w4b = False
            for b_cand in self.DEVICE_W4B_PATHS:
                b_clean = b_cand.rstrip("/") + "/"
                chk = self.executor.run_cmd(
                    ["shell", "test", "-d", f'"{b_clean}"', "&&", "echo", "EXISTS"],
                    serial=target_dev.serial,
                    timeout=5,
                )
                if "EXISTS" in chk.stdout:
                    found_w4b = True
                    p4_path = b_clean

                    # 1. Targeted check for WhatsApp Business Databases & Backups
                    for db_sub in ["Databases/", "Backups/"]:
                        w4b_db_path = f"{b_clean}{db_sub}"
                        chk_db = self.executor.run_cmd(
                            ["shell", "test", "-d", f'"{w4b_db_path}"', "&&", "echo", "EXISTS"],
                            serial=target_dev.serial,
                            timeout=5,
                        )
                        if "EXISTS" in chk_db.stdout:
                            w4b_subdirs.append(db_sub.rstrip("/"))
                            ls_cmd = self.executor.run_cmd(
                                ["shell", f'ls -l "{w4b_db_path}" 2>/dev/null'],
                                serial=target_dev.serial,
                                timeout=8,
                            )
                            if ls_cmd.returncode == 0:
                                for line in ls_cmd.stdout.splitlines():
                                    line_clean = line.strip()
                                    if not line_clean or line_clean.startswith("total"):
                                        continue
                                    parts = line_clean.split()
                                    if len(parts) >= 8:
                                        fname = parts[-1]
                                        if (
                                            fname.startswith("msgstore")
                                            or fname.startswith("chatsearch")
                                            or fname.startswith("wa.db")
                                            or fname.endswith(".db")
                                            or ".crypt" in fname
                                        ):
                                            try:
                                                sz = int(parts[4])
                                            except (ValueError, IndexError):
                                                sz = 0
                                            full_dp = f"{w4b_db_path}{fname}"
                                            fmt = "UNKNOWN"
                                            is_enc = False
                                            is_sql = False
                                            if "crypt15" in fname:
                                                fmt = "CRYPT15"
                                                is_enc = True
                                            elif "crypt14" in fname:
                                                fmt = "CRYPT14"
                                                is_enc = True
                                            elif "crypt12" in fname:
                                                fmt = "CRYPT12"
                                                is_enc = True
                                            elif fname.endswith(".db") and not is_enc:
                                                fmt = "SQLITE"
                                                is_sql = True

                                            candidates.append(
                                                DiscoveryCandidate(
                                                    path=full_dp,
                                                    filename=fname,
                                                    category="DATABASES",
                                                    size_bytes=sz,
                                                    is_device=True,
                                                    is_database=True,
                                                    db_format=fmt,
                                                    is_readable=is_sql,
                                                    is_encrypted=is_enc,
                                                    source_priority=4,
                                                    details="WhatsApp Business database candidate",
                                                )
                                            )
                                            p4_files += 1
                                            p4_bytes += sz
                                            try:
                                                self.registry.register(
                                                    ChatDatabaseCandidate(
                                                        path=full_dp,
                                                        filename=fname,
                                                        size_bytes=sz,
                                                        source="DEVICE_STORAGE",
                                                        format_type=fmt,
                                                        is_sqlite=is_sql,
                                                        is_encrypted=is_enc,
                                                        is_readable=is_sql,
                                                        validation_notes="WhatsApp Business candidate",
                                                    )
                                                )
                                            except Exception:
                                                pass

                    # 2. Targeted check for WhatsApp Business Media subdirectories
                    w4b_media_path = f"{b_clean}Media/"
                    chk_m = self.executor.run_cmd(
                        ["shell", "test", "-d", f'"{w4b_media_path}"', "&&", "echo", "EXISTS"],
                        serial=target_dev.serial,
                        timeout=5,
                    )
                    if "EXISTS" in chk_m.stdout:
                        w4b_subdirs.append("Media")
                        sub_chk = self.executor.run_cmd(
                            ["shell", f'ls -F "{w4b_media_path}" 2>/dev/null | grep "/"'],
                            serial=target_dev.serial,
                            timeout=6,
                        )
                        if sub_chk.returncode == 0:
                            subdirs = [s.strip().rstrip("/") for s in sub_chk.stdout.splitlines() if s.strip()]
                            for s_dir in subdirs:
                                cat_name = self._map_subdir_to_category(s_dir)
                                sub_path = f"{w4b_media_path}{s_dir}/"
                                cnt_cmd = self.executor.run_cmd(
                                    ["shell", f'ls -f "{sub_path}" 2>/dev/null | wc -l'],
                                    serial=target_dev.serial,
                                    timeout=12,
                                )
                                count_val = 0
                                if cnt_cmd.returncode == 0 and cnt_cmd.stdout.strip().isdigit():
                                    count_val = int(cnt_cmd.stdout.strip())
                                p4_files += count_val
                                if count_val > 0:
                                    candidates.append(
                                        DiscoveryCandidate(
                                            path=sub_path,
                                            filename=s_dir,
                                            category=cat_name,
                                            size_bytes=0,
                                            is_device=True,
                                            is_database=False,
                                            source_priority=4,
                                            details=f"WhatsApp Business: {count_val} matching files in {s_dir}",
                                        )
                                    )
                    break

            if found_w4b:
                p4_status = STATUS_FOUND if p4_files > 0 else STATUS_EMPTY
            else:
                p4_status = STATUS_NOT_APPLICABLE
                p4_err = "WhatsApp Business not installed or directory not present"
        elif target_dev:
            p4_status = STATUS_INACCESSIBLE
            p4_err = f"Device is {target_dev.status_display}"
        else:
            p4_status = STATUS_NOT_APPLICABLE
            p4_err = "No Android device connected"

        locations.append(
            DiscoveryLocation(
                id=loc_id,
                name="WhatsApp Business directory",
                path=p4_path,
                canonical_path=canonical_p4,
                priority=4,
                status=p4_status,
                file_count=p4_files,
                total_bytes=p4_bytes,
                is_accessible=(p4_status == STATUS_FOUND or p4_status == STATUS_EMPTY),
                is_device=True,
                is_business=True,
                subdirectories=w4b_subdirs,
                error_message=p4_err,
                notes="WhatsApp Business (com.whatsapp.w4b) directory",
            )
        )
        loc_id += 1

        # -------------------------------------------------------------
        # Priority 5 — User-Configured / Local Locations
        # -------------------------------------------------------------
        cfg_paths = self.settings.get("storage", {}).get("local_search_paths", [])
        for c_idx, c_path in enumerate(cfg_paths, start=1):
            p = Path(c_path).resolve()
            p5_status = STATUS_EMPTY
            p5_cnt = 0
            p5_sz = 0
            p5_err = None
            if p.exists() and p.is_dir():
                try:
                    for f in p.rglob("*"):
                        if f.is_file():
                            p5_cnt += 1
                            p5_sz += f.stat().st_size
                    p5_status = STATUS_FOUND if p5_cnt > 0 else STATUS_EMPTY
                except OSError as e:
                    p5_status = STATUS_INACCESSIBLE
                    p5_err = str(e)
            else:
                p5_status = STATUS_INACCESSIBLE
                p5_err = "Path does not exist"

            locations.append(
                DiscoveryLocation(
                    id=loc_id,
                    name=f"Configured search path [{c_idx}]",
                    path=str(p),
                    canonical_path=str(p),
                    priority=5,
                    status=p5_status,
                    file_count=p5_cnt,
                    total_bytes=p5_sz,
                    is_accessible=(p5_status == STATUS_FOUND or p5_status == STATUS_EMPTY),
                    is_device=False,
                    error_message=p5_err,
                    notes="User-configured storage path in settings.json",
                )
            )
            loc_id += 1

        # -------------------------------------------------------------
        # Database Validation & Summary Computation
        # -------------------------------------------------------------
        report_stage("RUNNING", "Validating database candidates")
        time.sleep(0.05)

        # Revalidate local SQLite databases
        for cand in candidates:
            if cand.is_database and not cand.is_device and not cand.is_encrypted:
                is_ok, cnt, old_ts, new_ts, _, _, notes = inspect_sqlite_chat_dates(cand.path)
                cand.is_readable = is_ok
                cand.message_count = cnt
                if old_ts and new_ts:
                    cand.date_range = f"{old_ts} to {new_ts}"
                if notes:
                    cand.details = notes

        report_stage("RUNNING", "Preparing discovery summary")
        time.sleep(0.05)

        # Compute summary metrics
        db_candidates_count = sum(1 for c in candidates if c.is_database)
        media_files_count = sum(c.message_count for c in candidates if c.category in ("IMAGES", "VIDEOS", "AUDIO / VOICE NOTES", "DOCUMENTS", "OTHER") and not c.is_database)
        unreadable_candidates = sum(1 for c in candidates if c.is_database and not c.is_readable)
        inaccessible_locations = sum(1 for l in locations if l.status == STATUS_INACCESSIBLE)

        summary_counts = {
            "discovered_database_candidates": db_candidates_count,
            "discovered_media_files": media_files_count,
            "unreadable_candidates": unreadable_candidates,
            "inaccessible_locations": inaccessible_locations,
        }

        report_stage("SUCCESS", "Discovery completed")

        duration = time.time() - start_ts
        manifest = DiscoveryManifest(
            session_id=sid,
            timestamp=timestamp_str,
            device_serial=target_dev.serial if target_dev else None,
            device_name=target_dev.display_name if target_dev else "None Connected",
            adb_status=adb_status.adb_status_display,
            device_state=dev_state_str,
            duration_seconds=duration,
            status="Discovery completed",
            locations=locations,
            candidates=candidates,
            summary_counts=summary_counts,
        )
        manifest.save()
        return manifest

    def run_extended_discovery(
        self,
        base_manifest: DiscoveryManifest,
        device: Optional[DeviceInfo],
        additional_paths: List[str],
        stage_callback: Optional[Callable[[str, str], None]] = None,
    ) -> DiscoveryManifest:
        """Priority 6: Inspect explicit, user-approved extended candidate locations."""
        if not device or not device.is_accessible:
            return base_manifest

        start_ts = time.time()
        if stage_callback:
            stage_callback("RUNNING", "Inspecting extended accessible storage locations")

        loc_id = len(base_manifest.locations) + 1
        new_locs: List[DiscoveryLocation] = []

        for p in additional_paths:
            p_clean = p.rstrip("/") + "/"
            chk = self.executor.run_cmd(
                ["shell", "test", "-d", f'"{p_clean}"', "&&", "echo", "EXISTS"],
                serial=device.serial,
                timeout=6,
            )
            st = STATUS_NOT_APPLICABLE
            err = None
            cnt = 0
            if "EXISTS" in chk.stdout:
                cnt_cmd = self.executor.run_cmd(
                    ["shell", f'ls -1 "{p_clean}" 2>/dev/null | wc -l'],
                    serial=device.serial,
                    timeout=6,
                )
                if cnt_cmd.returncode == 0 and cnt_cmd.stdout.strip().isdigit():
                    cnt = int(cnt_cmd.stdout.strip())
                    st = STATUS_FOUND if cnt > 0 else STATUS_EMPTY
                else:
                    st = STATUS_INACCESSIBLE
                    err = "Extended path exists but reading contents timed out or restricted"
            else:
                st = STATUS_EMPTY
                err = "Directory not present on device"

            new_locs.append(
                DiscoveryLocation(
                    id=loc_id,
                    name=f"Extended storage location ({p_clean.split('/')[-2] or 'root'})",
                    path=p_clean,
                    canonical_path=p_clean,
                    priority=6,
                    status=st,
                    file_count=cnt,
                    is_accessible=(st == STATUS_FOUND or st == STATUS_EMPTY),
                    is_device=True,
                    error_message=err,
                    notes="User-approved extended discovery path",
                )
            )
            loc_id += 1

        base_manifest.locations.extend(new_locs)
        base_manifest.duration_seconds += time.time() - start_ts
        base_manifest.save()
        if stage_callback:
            stage_callback("SUCCESS", "Extended discovery completed")
        return base_manifest

    def _map_subdir_to_category(self, subdir_name: str) -> str:
        """Map WhatsApp Media folder names to standard categories."""
        lower = subdir_name.lower()
        if "image" in lower or "photo" in lower or "wall" in lower:
            return "IMAGES"
        if "video" in lower or "gif" in lower:
            return "VIDEOS"
        if "audio" in lower or "voice" in lower:
            return "AUDIO / VOICE NOTES"
        if "document" in lower:
            return "DOCUMENTS"
        return "OTHER"

    def _build_cancelled_manifest(
        self,
        session_id: str,
        timestamp_str: str,
        target_dev: Optional[DeviceInfo],
        adb_status: DeviceStatusResult,
        dev_state_str: str,
        start_ts: float,
        locations: Optional[List[DiscoveryLocation]] = None,
        candidates: Optional[List[DiscoveryCandidate]] = None,
    ) -> DiscoveryManifest:
        """Construct cleanly formatted manifest when scan is cancelled by user."""
        return DiscoveryManifest(
            session_id=session_id,
            timestamp=timestamp_str,
            device_serial=target_dev.serial if target_dev else None,
            device_name=target_dev.display_name if target_dev else "None Connected",
            adb_status=adb_status.adb_status_display,
            device_state=dev_state_str,
            duration_seconds=time.time() - start_ts,
            status="Cancelled",
            locations=locations or [],
            candidates=candidates or [],
            summary_counts={"discovered_database_candidates": 0, "discovered_media_files": 0, "unreadable_candidates": 0, "inaccessible_locations": 0},
        )


# ============================================================================
# Loading Animation & Screen Presentation
# ============================================================================

def run_animated_priority_discovery(
    executor: AdbExecutor,
    selected_device: Optional[DeviceInfo],
    settings: Optional[dict[str, Any]] = None,
) -> DiscoveryManifest:
    """Execute priority discovery with real-time, professional terminal animation."""
    engine = PriorityDiscoveryEngine(executor=executor, settings=settings)
    c = get_console()
    color_on = is_color_enabled() and c is not None

    print("\n" + "=" * 56)
    print("       WRS — PRIORITY-BASED FILE DISCOVERY")
    print("=" * 56)
    dev_title = selected_device.display_name if selected_device else "Offline Local Environment"
    print(f"Target Scope : {dev_title}")
    print("Strategy     : Targeted & Priority-Based (Zero Blind Full-Disk Traversal)\n")

    stages_seen: List[Tuple[str, str]] = []
    active_stage = ["RUNNING", "Initializing priority discovery engine"]

    def stage_cb(code: str, label: str) -> None:
        active_stage[0] = code
        active_stage[1] = label
        if color_on and c:
            if code == "SUCCESS":
                c.print(f"  [bold green][SUCCESS][/bold green] [white]{label}[/white]")
            elif code == "WARNING":
                c.print(f"  [bold yellow][WARNING][/bold yellow] [white]{label}[/white]")
            elif code == "ERROR":
                c.print(f"  [bold red][ERROR][/bold red]   [white]{label}[/white]")
            else:
                # Stage in progress: print with cyan tag
                c.print(f"  [bold cyan][RUNNING][/bold cyan] [white]{label}[/white]...")
        else:
            if code == "SUCCESS":
                print(f"  [SUCCESS] {label}")
            elif code == "WARNING":
                print(f"  [WARNING] {label}")
            elif code == "ERROR":
                print(f"  [ERROR]   {label}")
            else:
                print(f"  [RUNNING] {label}...")

    try:
        manifest = engine.run_priority_discovery(device=selected_device, stage_callback=stage_cb)
        print("")
        return manifest
    except KeyboardInterrupt:
        print("\n\n[!] Discovery interrupted by user (Ctrl+C).")
        print("    Preserving completed scan records and marking discovery as Cancelled.\n")
        try:
            adb_st = executor.check_device_status()
        except (KeyboardInterrupt, Exception):
            adb_st = DeviceStatusResult(
                adb_installed=False,
                adb_available=False,
                adb_version_raw="",
                adb_version="",
                adb_server_responsive=False,
                adb_status_display="CANCELLED",
                enumeration_success=False,
                enumeration_error="Cancelled",
                devices=[],
                device_count=0,
                device_status_display="CANCELLED",
            )
        manifest = engine._build_cancelled_manifest(
            session_id=f"disc_interrupted_{int(time.time())}",
            timestamp_str=format_timestamp(),
            target_dev=selected_device,
            adb_status=adb_st,
            dev_state_str="Cancelled by user",
            start_ts=time.time(),
        )
        manifest.save()
        return manifest


def display_discovery_results_summary(
    manifest: DiscoveryManifest,
    settings: Optional[dict[str, Any]] = None,
) -> None:
    """Display the structured Discovery Results summary and candidate breakdown."""
    dev_str = manifest.device_name
    if manifest.device_serial:
        dev_str += f" ({manifest.device_serial})"
    status_str = manifest.status
    dur_str = f"{manifest.duration_seconds:.2f}s"

    print("=" * 56)
    print("           WRS — DISCOVERY RESULTS")
    print("=" * 56)
    print(f"Device       : {dev_str}")
    print(f"Scan status  : {status_str}")
    print(f"Duration     : {dur_str}\n")

    print("LOCATIONS")
    print("-" * 56)
    for loc in manifest.locations:
        status_disp = loc.status
        if loc.error_message and loc.status == STATUS_INACCESSIBLE:
            status_disp = f"Inaccessible ({loc.error_message[:28]})"
        elif loc.status == STATUS_NOT_APPLICABLE and loc.error_message:
            status_disp = f"Not Applicable ({loc.error_message[:24]})"

        file_disp = f"{loc.file_count:,}" if loc.file_count > 0 else (
            "0" if loc.status in (STATUS_FOUND, STATUS_EMPTY) else "N/A"
        )
        print(f"[{loc.id}] {loc.name}")
        print(f"    Status : {status_disp}")
        print(f"    Files  : {file_disp}")
        if loc.subdirectories:
            subs_str = ", ".join(loc.subdirectories[:5])
            if len(loc.subdirectories) > 5:
                subs_str += f" (+{len(loc.subdirectories)-5} more)"
            print(f"    Subdirs: {subs_str}")
        print("")

    print("-" * 56)
    counts = manifest.summary_counts
    db_cnt = counts.get("discovered_database_candidates", 0)
    media_cnt = counts.get("discovered_media_files", 0)
    unread_cnt = counts.get("unreadable_candidates", 0)
    inacc_cnt = counts.get("inaccessible_locations", 0)

    print(f"Discovered database candidates : {db_cnt}")
    print(f"Discovered media files         : {media_cnt}")
    print(f"Unreadable candidates          : {unread_cnt}")
    print(f"Inaccessible locations         : {inacc_cnt}")
    print("-" * 56 + "\n")

    # Grouped candidate presentation
    print("DISCOVERED CANDIDATES\n")

    # 1. Databases
    db_cands = [c for c in manifest.candidates if c.is_database]
    print("DATABASES")
    if db_cands:
        for idx, d in enumerate(db_cands, start=1):
            if d.is_readable:
                status_desc = f"SQLite / Readable ({d.message_count:,} msgs)"
                if d.date_range:
                    status_desc += f" [{d.date_range}]"
            elif d.is_encrypted:
                status_desc = f"{d.db_format or 'Crypt'} Encrypted Candidate"
            else:
                status_desc = f"{d.db_format or 'Unknown'} / Unvalidated"
            print(f"  [{idx}] {d.filename} — {status_desc}")
    else:
        print("  None found in checked locations.")
    print("")

    # 2. Media categories
    cats = [
        ("IMAGES", "Images"),
        ("VIDEOS", "Videos"),
        ("AUDIO / VOICE NOTES", "Audio / Voice notes"),
        ("DOCUMENTS", "Documents"),
    ]
    for cat_code, cat_title in cats:
        matched = [c for c in manifest.candidates if c.category == cat_code and not c.is_database]
        tot = sum(c.message_count for c in matched)
        print(f"{cat_code}")
        if tot > 0:
            print(f"  {tot:,} matching files")
        else:
            print("  0 matching files (checked, none found)")
        print("")


# ============================================================================
# Discovery Review Menu Workflow
# ============================================================================

def discovery_review_menu_interactive(
    manifest: DiscoveryManifest,
    executor: AdbExecutor,
    selected_device: Optional[DeviceInfo],
    settings: Optional[dict[str, Any]] = None,
) -> DiscoveryManifest:
    """Prompt user to review discovery findings before presenting the main recovery menu.

    Next-action choices:
    [1] Use discovered locations and continue
    [2] Select or deselect specific locations
    [3] Inspect discovered database candidates
    [4] Scan additional accessible locations
    [5] Rescan selected locations
    [0] Exit
    """
    engine = PriorityDiscoveryEngine(executor=executor, settings=settings)
    current_manifest = manifest

    while True:
        display_discovery_results_summary(current_manifest, settings)

        print("Select Next Action:")
        print("  [1] Use discovered locations and continue")
        print("  [2] Select or deselect specific locations")
        print("  [3] Inspect discovered database candidates")
        print("  [4] Scan additional accessible locations")
        print("  [5] Rescan selected locations")
        print("  [0] Exit\n")

        try:
            choice = input("Select an option [0-5]: ").strip()

            if choice == "1":
                # Continue with discovered locations
                return current_manifest

            elif choice == "2":
                # Select or deselect locations
                current_manifest = _toggle_locations_interactive(current_manifest)

            elif choice == "3":
                # Inspect discovered database candidates
                _inspect_database_candidates_screen(current_manifest)

            elif choice == "4":
                # Scan additional accessible locations (Priority 6)
                current_manifest = _run_extended_discovery_interactive(current_manifest, engine, selected_device)

            elif choice == "5":
                # Rescan selected locations
                print("\n[*] Rescanning selected discovery locations...")
                current_manifest = run_animated_priority_discovery(executor, selected_device, settings)

            elif choice == "0" or choice.lower() in ("exit", "quit", "q"):
                print("\nExiting WRS. Goodbye.")
                sys.exit(0)

            else:
                print("[!] Invalid selection. Please choose an option between 0 and 5.")
                time.sleep(1)

        except (KeyboardInterrupt, EOFError):
            print("\nReturning to review options...")
            time.sleep(0.5)


def _toggle_locations_interactive(manifest: DiscoveryManifest) -> DiscoveryManifest:
    """Allow user to selectively include/exclude discovered locations."""
    print("\n" + "=" * 56)
    print("       WRS — SELECT / DESELECT LOCATIONS")
    print("=" * 56)
    print("Toggle locations to include in subsequent recovery & acquisition:")
    for loc in manifest.locations:
        marker = "[●]" if loc.is_selected else "[○]"
        print(f"  {marker} [{loc.id}] {loc.name} ({loc.status})")

    print("\nEnter location numbers to toggle separated by commas (e.g. 1, 3)")
    print("Or press Enter to keep current selection:")
    sel = input("Selection: ").strip()
    if sel:
        tokens = [t.strip() for t in sel.split(",") if t.strip()]
        for tok in tokens:
            try:
                num = int(tok)
                for loc in manifest.locations:
                    if loc.id == num:
                        loc.is_selected = not loc.is_selected
            except ValueError:
                pass
    manifest.save()
    return manifest


def _inspect_database_candidates_screen(manifest: DiscoveryManifest) -> None:
    """Display detailed forensic properties of all discovered database candidates."""
    db_cands = [c for c in manifest.candidates if c.is_database]
    print("\n" + "=" * 56)
    print("       WRS — DATABASE CANDIDATES")
    print("=" * 56)
    if not db_cands:
        print("[!] No database candidates were discovered.")
    else:
        for idx, d in enumerate(db_cands, start=1):
            stat = "Readable SQLite" if d.is_readable else ("Encrypted" if d.is_encrypted else "Unvalidated")
            print(f"[{idx}] {d.filename}")
            print(f"    Path        : {d.path}")
            print(f"    Format      : {d.db_format or 'UNKNOWN'}")
            print(f"    Size        : {d.size_human}")
            print(f"    Status      : {stat}")
            if d.is_readable:
                print(f"    Messages    : {d.message_count:,}")
            if d.date_range:
                print(f"    Date Range  : {d.date_range}")
            if d.details:
                print(f"    Notes       : {d.details}")
            print("")
    input("\nPress Enter to return to review menu...")


def _run_extended_discovery_interactive(
    manifest: DiscoveryManifest,
    engine: PriorityDiscoveryEngine,
    device: Optional[DeviceInfo],
) -> DiscoveryManifest:
    """Prompt user before scanning additional extended storage locations."""
    print("\n" + "=" * 56)
    print("       WRS — EXTENDED STORAGE DISCOVERY")
    print("=" * 56)
    if not device or not device.is_accessible:
        print("[!] Extended discovery requires an authorized, connected Android device.")
        input("Press Enter to return...")
        return manifest

    ext_paths = [
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Media/.trash/",
        "/sdcard/WhatsApp/Media/.trash/",
        "/sdcard/Download/",
    ]
    if device.removable_mounts:
        for m in device.removable_mounts:
            ext_paths.append(f"{m}/WhatsApp/")
            ext_paths.append(f"{m}/Android/media/com.whatsapp/WhatsApp/")

    print("Extended discovery will examine the following additional locations:")
    for ep in ext_paths:
        print(f"  • {ep}")
    print("\nWhy relevant: May contain archived backups, trash media, or external SD contents.")
    print("Scope       : Targeted read-only check (zero full phone traversal).")
    print("Duration    : Expected 3 to 10 seconds depending on storage read speed.\n")

    ans = input("Proceed with extended discovery? [y/N]: ").strip().lower()
    if ans not in ("y", "yes"):
        print("[*] Extended discovery cancelled.")
        time.sleep(0.5)
        return manifest

    return engine.run_extended_discovery(manifest, device, ext_paths)
