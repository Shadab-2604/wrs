"""Key availability assessment, safe acquisition, and decryption service for WRS.

Provides:
- Automated key-availability checks across authorized, legitimate sources.
- Safe key validation without exposing, logging, or printing secret values.
- Android application sandbox and permission boundary awareness.
- Safe copying/acquisition of encrypted database candidates without requiring decryption.
- Working-copy authenticated AES-GCM decryption and SQLite database validation.
- Interactive Encrypted Database Candidates management wizard.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .acquisition import build_default_recovery_destination
from .database import WhatsAppDatabaseAnalyzer
from .db_discovery import (
    ChatDatabaseCandidate,
    ChatDatabaseRegistry,
    inspect_sqlite_chat_dates,
)
from .device import AdbExecutor, DeviceInfo
from .discovery_wizard import (
    confirm_acquisition,
    prompt_recovery_destination,
    validate_destination_path,
)
from .hashing import VerificationRecord, hash_local_file
from .inventory import InventoryRecord, ScanInventoryDB as ScanInventory
from .ui import get_console, is_color_enabled
from .utils import format_bytes, format_timestamp, load_settings, sanitize_device_name

logger = logging.getLogger("wrs.key_assessment")

# Required standardized key statuses
KEY_STATUS_NOT_CHECKED = "ENCRYPTED — KEY NOT CHECKED"
KEY_STATUS_NOT_FOUND = "ENCRYPTED — KEY NOT FOUND IN ACCESSIBLE SOURCES"
KEY_STATUS_AVAILABLE = "ENCRYPTED — REQUIRED KEY MATERIAL AVAILABLE"
STATUS_DECRYPTION_READY = "DECRYPTION READY — FORMAT SUPPORTED"
STATUS_DECRYPTION_UNSUPPORTED = "DECRYPTION UNSUPPORTED"
STATUS_DECRYPTION_FAILED = "DECRYPTION FAILED — SEE DETAILS"
STATUS_DECRYPTED = "DECRYPTED — DATABASE VALIDATION PASSED"

# Supported decryption formats
SUPPORTED_DECRYPTION_FORMATS = {"CRYPT14", "CRYPT15"}


@dataclass
class KeyMaterial:
    """Metadata describing discovered or user-supplied encryption key material.

    Note: Secret key bytes are NEVER included in __repr__, __str__, or serialized dicts.
    """

    source_type: str  # "USER_SPECIFIED", "ADJACENT_DIR", "LOCAL_CASE", "CONFIGURED_DIR", "DEVICE_STORAGE"
    source_path: str
    key_format: str   # "WHATSAPP_158_BYTE", "RAW_AES_32_BYTE", "HEX_64_CHAR"
    is_valid: bool
    size_bytes: int
    description: str
    key_identifier: str  # Non-reversible safe token (e.g. "key_32b_...")
    _raw_key: Optional[bytes] = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize metadata excluding secret key material."""
        return {
            "source_type": self.source_type,
            "source_path": self.source_path,
            "key_format": self.key_format,
            "is_valid": self.is_valid,
            "size_bytes": self.size_bytes,
            "description": self.description,
            "key_identifier": self.key_identifier,
        }

    def get_aes_key(self) -> Optional[bytes]:
        """Retrieve in-memory 32-byte AES key."""
        return self._raw_key


@dataclass
class KeyAssessmentResult:
    """Result of key-availability assessment for a candidate database."""

    candidate_path: str
    format_type: str
    key_status: str
    validation_status: str
    key_found: bool
    key_source: Optional[str] = None
    key_material: Optional[KeyMaterial] = None
    notes: str = ""


class KeyAssessmentService:
    """Assesses encryption key availability through legitimate, authorized sources."""

    def __init__(
        self,
        executor: Optional[AdbExecutor] = None,
        settings: Optional[dict[str, Any]] = None,
    ) -> None:
        self.executor = executor or AdbExecutor()
        self.settings = settings or load_settings()

    @staticmethod
    def validate_key_bytes(data: bytes, source_path: str = "") -> Tuple[bool, Optional[KeyMaterial], str]:
        """Validate key material format and size without printing or logging secret values.

        Supports:
        - 158-byte standard WhatsApp key file (32-byte AES key at offset 126..158).
        - 32-byte raw binary AES key.
        - 64-character hexadecimal ASCII key string.
        """
        if not data:
            return False, None, "Key file is empty (0 bytes)."

        sz = len(data)
        raw_aes: Optional[bytes] = None
        key_fmt = "UNKNOWN"

        if sz == 158:
            key_fmt = "WHATSAPP_158_BYTE"
            raw_aes = data[126:158]
        elif sz == 32:
            key_fmt = "RAW_AES_32_BYTE"
            raw_aes = data
        elif sz in (64, 65):
            try:
                hex_str = data.decode("ascii").strip()
                if len(hex_str) == 64:
                    raw_aes = bytes.fromhex(hex_str)
                    key_fmt = "HEX_64_CHAR"
            except Exception:
                pass
        elif sz > 158:
            key_fmt = "WHATSAPP_EXTENDED_HEADER"
            raw_aes = data[126:158]

        if not raw_aes or len(raw_aes) != 32:
            return False, None, f"Invalid key format ({sz} bytes). Expected 158-byte WhatsApp key file or 32-byte AES key."

        # Check for zeroed or corrupt key
        if raw_aes == b"\x00" * 32:
            return False, None, "Invalid key: Key material consists entirely of zero bytes."

        # Compute safe non-reversible identifier (hash of key length + source)
        safe_hash = hashlib.sha256(f"{source_path}:{sz}".encode()).hexdigest()[:8]
        key_id = f"key_{key_fmt.lower()}_{safe_hash}"

        km = KeyMaterial(
            source_type="VALIDATED",
            source_path=source_path,
            key_format=key_fmt,
            is_valid=True,
            size_bytes=sz,
            description=f"Valid {key_fmt} key ({sz} bytes)",
            key_identifier=key_id,
            _raw_key=raw_aes,
        )
        return True, km, f"Valid {key_fmt} key material."

    def validate_key_file(self, path: Path | str) -> Tuple[bool, Optional[KeyMaterial], str]:
        """Inspect and validate a local key file."""
        p = Path(path).resolve()
        if not p.is_file():
            return False, None, f"Key file not found: {p}"

        try:
            data = p.read_bytes()
            ok, km, msg = self.validate_key_bytes(data, source_path=str(p))
            if ok and km:
                km.source_path = str(p)
            return ok, km, msg
        except OSError as e:
            return False, None, f"Failed to read key file {p}: {e}"

    def discover_available_keys(
        self,
        candidate: Optional[ChatDatabaseCandidate] = None,
        device: Optional[DeviceInfo] = None,
        user_key_path: Optional[str | Path] = None,
    ) -> List[KeyMaterial]:
        """Check documented, authorized local and device sources for matching key material.

        Sources checked in priority order:
        1. Explicit user-provided key path.
        2. Candidate parent directory (e.g. key file next to database).
        3. Configured key paths in settings.json.
        4. Standard project recovery directories (recovery/keys/, recovery/key, ./whatsapp.key).
        5. Android device private key path (/data/data/com.whatsapp/files/key) if authorized/accessible.
        """
        valid_keys: List[KeyMaterial] = []
        checked_paths: Set[str] = set()

        # 1. User-supplied key path
        if user_key_path:
            p = Path(user_key_path).resolve()
            if str(p) not in checked_paths and p.is_file():
                checked_paths.add(str(p))
                ok, km, _ = self.validate_key_file(p)
                if ok and km:
                    km.source_type = "USER_SPECIFIED"
                    valid_keys.append(km)

        # 2. Adjacent to candidate
        if candidate and candidate.source != "DEVICE_STORAGE":
            cand_p = Path(candidate.path).resolve()
            search_dir = cand_p.parent
            for candidate_key_name in ("key", "whatsapp.key", f"{cand_p.stem}.key"):
                kp = search_dir / candidate_key_name
                if str(kp) not in checked_paths and kp.is_file():
                    checked_paths.add(str(kp))
                    ok, km, _ = self.validate_key_file(kp)
                    if ok and km:
                        km.source_type = "ADJACENT_DIR"
                        valid_keys.append(km)

        # 3. Project recovery & root search directories
        rec_dir = Path(self.settings.get("acquisition", {}).get("default_recovery_dir", "recovery")).resolve()
        common_key_locations = [
            rec_dir / "key",
            rec_dir / "keys" / "key",
            rec_dir / "keys" / "whatsapp.key",
            Path("whatsapp.key").resolve(),
            Path("key").resolve(),
        ]
        # Also check subdirectories of recovery/ for key files
        if rec_dir.exists():
            for kf in rec_dir.rglob("key"):
                if kf.is_file() and str(kf) not in checked_paths:
                    common_key_locations.append(kf)

        for kp in common_key_locations:
            if str(kp) not in checked_paths and kp.is_file():
                checked_paths.add(str(kp))
                ok, km, _ = self.validate_key_file(kp)
                if ok and km:
                    km.source_type = "LOCAL_CASE"
                    valid_keys.append(km)

        # 4. Configured settings key path
        cfg_key = self.settings.get("decryption", {}).get("key_path")
        if cfg_key:
            kp = Path(cfg_key).resolve()
            if str(kp) not in checked_paths and kp.is_file():
                checked_paths.add(str(kp))
                ok, km, _ = self.validate_key_file(kp)
                if ok and km:
                    km.source_type = "CONFIGURED_DIR"
                    valid_keys.append(km)

        # 5. Connected Android device check (respects sandbox boundaries)
        if device and device.is_accessible:
            dev_key_res = self._check_device_key_accessibility(device)
            if dev_key_res:
                valid_keys.append(dev_key_res)

        return valid_keys

    def _check_device_key_accessibility(self, device: DeviceInfo) -> Optional[KeyMaterial]:
        """Check whether private key on Android device is legitimately accessible (e.g. root shell).

        Never attempts privilege escalation or unauthorized sandbox bypass on standard devices.
        """
        key_remote_path = "/data/data/com.whatsapp/files/key"
        # Test standard non-destructive access
        res = self.executor.run_cmd(["shell", f"ls -l '{key_remote_path}' 2>/dev/null"], serial=device.serial, timeout=5)
        if res.returncode == 0 and "key" in res.stdout:
            # File is accessible (e.g. user running rooted ROM or root shell)
            # Pull to memory safely
            pull_test = self.executor.run_cmd(["shell", f"cat '{key_remote_path}' 2>/dev/null"], serial=device.serial, timeout=5)
            if pull_test.returncode == 0 and len(pull_test.stdout.encode()) in (158, 32):
                ok, km, _ = self.validate_key_bytes(pull_test.stdout.encode(), source_path=f"adb://{device.serial}{key_remote_path}")
                if ok and km:
                    km.source_type = "DEVICE_STORAGE"
                    return km
        return None

    def assess_candidate(
        self,
        candidate: ChatDatabaseCandidate,
        device: Optional[DeviceInfo] = None,
        user_key_path: Optional[str | Path] = None,
    ) -> KeyAssessmentResult:
        """Perform full assessment of key availability and decryption readiness for a candidate."""
        fn = candidate.filename.lower()
        fmt = candidate.format_type.upper()

        # Plain SQLite is not encrypted
        if candidate.is_sqlite and not candidate.is_encrypted:
            return KeyAssessmentResult(
                candidate_path=candidate.path,
                format_type="SQLITE",
                key_status="NOT ENCRYPTED",
                validation_status="READABLE SQLITE DATABASE",
                key_found=False,
                notes="Database is unencrypted SQLite. No decryption required.",
            )

        # Check format support
        if fmt not in SUPPORTED_DECRYPTION_FORMATS and not fn.endswith((".crypt14", ".crypt15")):
            return KeyAssessmentResult(
                candidate_path=candidate.path,
                format_type=fmt,
                key_status=KEY_STATUS_NOT_CHECKED,
                validation_status=STATUS_DECRYPTION_UNSUPPORTED,
                key_found=False,
                notes=f"Container format {fmt} can be identified but is not supported for decryption.",
            )

        # Discover keys across legitimate sources
        available_keys = self.discover_available_keys(candidate=candidate, device=device, user_key_path=user_key_path)

        if available_keys:
            primary_key = available_keys[0]
            candidate.key_status = KEY_STATUS_AVAILABLE
            candidate.has_key = True
            candidate.key_path = primary_key.source_path
            candidate.decryption_status = STATUS_DECRYPTION_READY
            return KeyAssessmentResult(
                candidate_path=candidate.path,
                format_type=fmt,
                key_status=KEY_STATUS_AVAILABLE,
                validation_status=STATUS_DECRYPTION_READY,
                key_found=True,
                key_source=primary_key.source_path,
                key_material=primary_key,
                notes=f"Key material verified ({primary_key.description}) from {primary_key.source_type}.",
            )
        else:
            candidate.key_status = KEY_STATUS_NOT_FOUND
            candidate.has_key = False
            candidate.decryption_status = "Not yet decrypted"
            note = (
                "Key not found in accessible sources. "
                "Protected private app storage (/data/data/com.whatsapp/files/key) "
                "is restricted by Android application sandbox boundaries and "
                "is inaccessible without authorized root permissions on Android."
            )
            return KeyAssessmentResult(
                candidate_path=candidate.path,
                format_type=fmt,
                key_status=KEY_STATUS_NOT_FOUND,
                validation_status="Not yet decrypted",
                key_found=False,
                notes=note,
            )

    def assess_all(
        self,
        candidates: List[ChatDatabaseCandidate],
        device: Optional[DeviceInfo] = None,
        user_key_path: Optional[str | Path] = None,
    ) -> List[KeyAssessmentResult]:
        """Assess all given candidates and update their key and decryption statuses."""
        results: List[KeyAssessmentResult] = []
        for c in candidates:
            res = self.assess_candidate(c, device=device, user_key_path=user_key_path)
            results.append(res)
        return results


class EncryptedDatabaseManager:
    """Orchestrates safe acquisition and working-copy decryption of encrypted WhatsApp databases."""

    def __init__(
        self,
        executor: Optional[AdbExecutor] = None,
        settings: Optional[dict[str, Any]] = None,
        key_service: Optional[KeyAssessmentService] = None,
        registry: Optional[ChatDatabaseRegistry] = None,
    ) -> None:
        self.executor = executor or AdbExecutor()
        self.settings = settings or load_settings()
        self.key_service = key_service or KeyAssessmentService(self.executor, self.settings)
        self.registry = registry or ChatDatabaseRegistry()

    def find_encrypted_candidates(
        self,
        device: Optional[DeviceInfo] = None,
        discovery_manifest: Optional[Any] = None,
        user_key_path: Optional[str | Path] = None,
    ) -> List[ChatDatabaseCandidate]:
        """Locate all encrypted database candidates across manifest, registry, recovery, and device."""
        candidates_by_path: Dict[str, ChatDatabaseCandidate] = {}

        # 1. Check discovery manifest
        if discovery_manifest and hasattr(discovery_manifest, "candidates"):
            for cand in discovery_manifest.candidates:
                if getattr(cand, "is_database", False) and getattr(cand, "is_encrypted", False):
                    src_tag = "DEVICE_STORAGE" if getattr(cand, "is_device", False) else "ACQUISITION_DIRECTORY"
                    c = ChatDatabaseCandidate(
                        path=cand.path,
                        filename=cand.filename,
                        size_bytes=cand.size_bytes,
                        source=src_tag,
                        format_type=getattr(cand, "db_format", "CRYPT14") or "CRYPT14",
                        is_sqlite=False,
                        is_encrypted=True,
                        is_readable=False,
                        is_accessible=True,
                        modified_timestamp=format_timestamp(),
                    )
                    candidates_by_path[c.path] = c

        # 2. Check persistent registry
        reg_candidates = self.registry.load()
        for cand in reg_candidates:
            if cand.is_encrypted and not cand.is_stale:
                candidates_by_path[cand.path] = cand

        # 3. Check local recovery directory
        rec_dir_name = self.settings.get("acquisition", {}).get("default_recovery_dir", "recovery")
        rec_base = Path(rec_dir_name).resolve()
        if rec_base.exists():
            for root, _, files in os.walk(rec_base):
                for f in files:
                    fn_lower = f.lower()
                    if fn_lower.endswith((".crypt15", ".crypt14", ".crypt12")):
                        fp = Path(root) / f
                        if str(fp) not in candidates_by_path:
                            fmt = "CRYPT15" if ".crypt15" in fn_lower else ("CRYPT14" if ".crypt14" in fn_lower else "CRYPT12")
                            st = fp.stat()
                            c = ChatDatabaseCandidate(
                                path=str(fp),
                                filename=f,
                                size_bytes=st.st_size,
                                source="ACQUISITION_DIRECTORY",
                                format_type=fmt,
                                is_sqlite=False,
                                is_encrypted=True,
                                is_readable=False,
                                is_accessible=True,
                                modified_timestamp=datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                                mtime_epoch=st.st_mtime,
                            )
                            candidates_by_path[c.path] = c

        # 4. Check device storage if device is connected
        if device and device.is_accessible:
            device_paths = [
                "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
                "/sdcard/WhatsApp/Databases",
                "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp/Databases",
                "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases",
                "/sdcard/Android/media/com.whatsapp/WhatsApp/Backups",
            ]
            for dp in device_paths:
                res = self.executor.run_cmd(["shell", f"ls -l '{dp}' 2>/dev/null"], serial=device.serial, timeout=8)
                if res.returncode == 0 and res.stdout.strip():
                    for line in res.stdout.strip().splitlines():
                        parts = line.split()
                        if len(parts) >= 8:
                            fn = parts[-1]
                            fn_lower = fn.lower()
                            if fn_lower.endswith((".crypt15", ".crypt14", ".crypt12")):
                                dev_path = f"{dp}/{fn}"
                                if dev_path not in candidates_by_path:
                                    try:
                                        sz = int(parts[4])
                                    except (ValueError, IndexError):
                                        sz = 0
                                    fmt = "CRYPT15" if ".crypt15" in fn_lower else ("CRYPT14" if ".crypt14" in fn_lower else "CRYPT12")
                                    c = ChatDatabaseCandidate(
                                        path=dev_path,
                                        filename=fn,
                                        size_bytes=sz,
                                        source="DEVICE_STORAGE",
                                        format_type=fmt,
                                        is_sqlite=False,
                                        is_encrypted=True,
                                        is_readable=False,
                                        is_accessible=True,
                                        modified_timestamp=format_timestamp(),
                                    )
                                    candidates_by_path[c.path] = c

        all_cands = list(candidates_by_path.values())
        # Run key assessment across all candidates
        self.key_service.assess_all(all_cands, device=device, user_key_path=user_key_path)

        # Sort: files with available keys first, then newest files
        all_cands.sort(key=lambda c: (1 if c.has_key else 0, c.mtime_epoch, c.size_bytes), reverse=True)
        return all_cands

    def acquire_encrypted_files(
        self,
        candidates: List[ChatDatabaseCandidate],
        device: Optional[DeviceInfo],
        destination_dir: Path,
        progress_callback: Optional[Callable[[int, int, str, str], None]] = None,
    ) -> List[VerificationRecord]:
        """Safely copy or acquire encrypted database candidates to destination without modifying originals.

        Operations:
        - Resolves collisions with unique counter suffixes (_1, _2).
        - Computes streaming SHA-256 for every copied file.
        - Records acquisition manifest and updates scan inventory.
        """
        destination_dir.mkdir(parents=True, exist_ok=True)
        session_root = destination_dir.parent if destination_dir.name == "databases" else destination_dir
        manifests_dir = session_root / "manifests"
        manifests_dir.mkdir(parents=True, exist_ok=True)
        metadata_dir = session_root / "metadata"
        metadata_dir.mkdir(parents=True, exist_ok=True)

        inv_db = ScanInventory(metadata_dir / "scan_inventory.db")

        records: List[VerificationRecord] = []
        total = len(candidates)
        sid = f"acq_enc_{int(time.time())}"

        for idx, cand in enumerate(candidates, start=1):
            if progress_callback:
                progress_callback(idx, total, cand.filename, "COPYING")

            # Determine safe destination filename to prevent overwrite
            base_name = cand.filename
            target_p = destination_dir / base_name
            counter = 1
            if ".db.crypt" in base_name.lower():
                stem, crypt_part = base_name.split(".db.crypt", 1)
                full_ext = f".db.crypt{crypt_part}"
                while target_p.exists():
                    target_p = destination_dir / f"{stem}_{counter}{full_ext}"
                    counter += 1
            else:
                name_stem, ext = os.path.splitext(base_name)
                while target_p.exists():
                    target_p = destination_dir / f"{name_stem}_{counter}{ext}"
                    counter += 1

            if cand.source == "DEVICE_STORAGE" and device is not None:
                # ADB Pull
                pull_res = self.executor.run_cmd(["pull", cand.path, str(target_p)], serial=device.serial, timeout=120)
                if pull_res.returncode == 0 and target_p.exists():
                    h, sz, h_err = hash_local_file(target_p)
                    rec = VerificationRecord(
                        source_path=cand.path,
                        destination_path=str(target_p),
                        expected_size=cand.size_bytes,
                        acquired_size=sz,
                        source_sha256=None,
                        destination_sha256=h,
                        status="VERIFIED",
                        timestamp=format_timestamp(),
                        error_message=h_err,
                    )
                    records.append(rec)
                    inv_db.insert_record(
                        InventoryRecord(
                            scan_id=sid,
                            device_id=device.serial,
                            source_path=cand.path,
                            relative_path=cand.filename,
                            filename=target_p.name,
                            extension=ext,
                            category="Databases",
                            size_bytes=sz,
                            acquisition_status="ACQUIRED",
                            destination_sha256=h or "",
                        )
                    )
                    # Register acquired candidate
                    cand.path = str(target_p.resolve())
                    cand.source = "ACQUISITION_DIRECTORY"
                    cand.sha256 = h or ""
                    self.registry.register(cand)
                else:
                    err_msg = pull_res.stderr.strip() or "ADB pull failed"
                    rec = VerificationRecord(
                        source_path=cand.path,
                        destination_path=str(target_p),
                        expected_size=cand.size_bytes,
                        acquired_size=0,
                        source_sha256=None,
                        destination_sha256=None,
                        status="FAILED",
                        timestamp=format_timestamp(),
                        error_message=err_msg,
                    )
                    records.append(rec)
            else:
                # Local file copy
                src_p = Path(cand.path)
                if src_p.is_file():
                    try:
                        shutil.copy2(src_p, target_p)
                        h, sz, h_err = hash_local_file(target_p)
                        rec = VerificationRecord(
                            source_path=str(src_p),
                            destination_path=str(target_p),
                            expected_size=cand.size_bytes,
                            acquired_size=sz,
                            source_sha256=None,
                            destination_sha256=h,
                            status="VERIFIED",
                            timestamp=format_timestamp(),
                            error_message=h_err,
                        )
                        records.append(rec)
                        cand.path = str(target_p.resolve())
                        cand.source = "ACQUISITION_DIRECTORY"
                        cand.sha256 = h or ""
                        self.registry.register(cand)
                    except OSError as e:
                        records.append(
                            VerificationRecord(
                                source_path=str(src_p),
                                destination_path=str(target_p),
                                expected_size=cand.size_bytes,
                                acquired_size=0,
                                source_sha256=None,
                                destination_sha256=None,
                                status="FAILED",
                                timestamp=format_timestamp(),
                                error_message=str(e),
                            )
                        )
                else:
                    records.append(
                        VerificationRecord(
                            source_path=cand.path,
                            destination_path=str(target_p),
                            expected_size=cand.size_bytes,
                            acquired_size=0,
                            source_sha256=None,
                            destination_sha256=None,
                            status="FAILED",
                            timestamp=format_timestamp(),
                            error_message="Local source file does not exist",
                        )
                    )

        # Write acquisition manifest
        manifest_data = [asdict(r) for r in records]
        for folder in (manifests_dir, metadata_dir):
            with open(folder / "acquisition_manifest.json", "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2)

        return records

    def decrypt_working_copy(
        self,
        candidate: ChatDatabaseCandidate,
        key_material: KeyMaterial,
        output_dir: Path,
        device: Optional[DeviceInfo] = None,
    ) -> Tuple[bool, Optional[ChatDatabaseCandidate], str]:
        """Decrypt a working copy of the candidate with database validation.

        Rules:
        - NEVER modifies or writes over the original encrypted file.
        - If remote on device, copies to local staging first.
        - Decrypts under authenticated AES-GCM and decompresses zlib if needed.
        - Validates SQLite header and PRAGMA integrity_check(5).
        - Registers decrypted database in registry.
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # 1. Determine local source working file
        local_work_file: Path
        if candidate.source == "DEVICE_STORAGE":
            if not device or not device.is_accessible:
                return False, None, "Candidate is on remote Android device, but device is not connected or accessible."
            staging_dir = output_dir / "staging"
            staging_dir.mkdir(parents=True, exist_ok=True)
            local_work_file = staging_dir / candidate.filename
            pull_res = self.executor.run_cmd(["pull", candidate.path, str(local_work_file)], serial=device.serial, timeout=120)
            if pull_res.returncode != 0 or not local_work_file.is_file():
                return False, None, f"Failed to acquire remote working copy from device: {pull_res.stderr.strip()}"
        else:
            local_work_file = Path(candidate.path).resolve()
            if not local_work_file.is_file():
                return False, None, f"Local encrypted database file not found on disk: {local_work_file}"

        # 2. Determine target decrypted database path
        stem_name = local_work_file.name
        for ext in (".crypt15", ".crypt14", ".crypt12", ".db"):
            if stem_name.lower().endswith(ext):
                stem_name = stem_name[: -len(ext)]
        decrypted_filename = f"{stem_name}_decrypted.db"
        decrypted_dest = output_dir / decrypted_filename

        # Prevent overwriting
        counter = 1
        while decrypted_dest.exists():
            decrypted_dest = output_dir / f"{stem_name}_decrypted_{counter}.db"
            counter += 1

        if decrypted_dest.resolve() == local_work_file.resolve():
            return False, None, "Refusing operation: Decrypted destination cannot match the encrypted source file."

        # 3. Key material validation
        if not key_material or not key_material.is_valid:
            return False, None, "Invalid or missing encryption key material."

        key_file_path = Path(key_material.source_path)
        if not key_file_path.is_file():
            # If key is in-memory or remote, write temporary working key file
            temp_key_p = output_dir / ".working_key.tmp"
            if key_material.get_aes_key():
                temp_key_p.write_bytes(key_material.get_aes_key())
                key_file_path = temp_key_p
            else:
                return False, None, "Key file is inaccessible on disk."

        try:
            # 4. Decrypt and validate
            ok, msg = WhatsAppDatabaseAnalyzer.decrypt_crypt_database(
                local_work_file, key_file_path, decrypted_dest
            )
            if not ok:
                candidate.decryption_status = STATUS_DECRYPTION_FAILED
                candidate.validation_notes = msg
                return False, None, msg

            # 5. Database structure inspection & date discovery
            is_readable, cnt, old_s, new_s, old_dt, new_dt, notes = inspect_sqlite_chat_dates(decrypted_dest)
            st = decrypted_dest.stat()
            h, _, _ = hash_local_file(decrypted_dest)

            decrypted_candidate = ChatDatabaseCandidate(
                path=str(decrypted_dest.resolve()),
                filename=decrypted_dest.name,
                size_bytes=st.st_size,
                source="DECRYPTED_CANDIDATE",
                format_type="SQLITE",
                is_sqlite=True,
                is_encrypted=False,
                is_readable=is_readable,
                is_accessible=True,
                has_key=True,
                decrypted_path=str(decrypted_dest.resolve()),
                message_count=cnt,
                oldest_timestamp=old_s,
                newest_timestamp=new_s,
                oldest_dt=old_dt,
                newest_dt=new_dt,
                modified_timestamp=datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                mtime_epoch=st.st_mtime,
                sha256=h or "",
                validation_notes=f"Successfully decrypted from {candidate.filename}. {notes}",
                key_status=KEY_STATUS_AVAILABLE,
                decryption_status=STATUS_DECRYPTED,
            )
            self.registry.register(decrypted_candidate)

            candidate.decrypted_path = str(decrypted_dest.resolve())
            candidate.decryption_status = STATUS_DECRYPTED

            return True, decrypted_candidate, "Decryption and database validation passed successfully."

        finally:
            # Clean up temporary in-memory key file
            temp_key_file = output_dir / ".working_key.tmp"
            if temp_key_file.exists():
                try:
                    temp_key_file.unlink()
                except OSError:
                    pass


def display_encrypted_candidates_list(candidates: List[ChatDatabaseCandidate]) -> None:
    """Render the exact requested ENCRYPTED DATABASE CANDIDATES screen."""
    print("\n" + "=" * 56)
    print("       WRS — ENCRYPTED DATABASE CANDIDATES")
    print("=" * 56 + "\n")

    if not candidates:
        print("No encrypted WhatsApp database candidates discovered.\n")
        return

    for idx, c in enumerate(candidates, start=1):
        print(f"[{idx}] {c.filename}")
        print(f"    Format      : {c.format_type}")
        print(f"    Encryption  : Encrypted candidate")
        print(f"    Key status  : {c.key_status.replace('ENCRYPTED — ', '')}")
        print(f"    Validation  : {c.decryption_status}")
        print()

    print("-" * 56)
    print("[1] Inspect selected candidate")
    print("[2] Check key availability")
    print("[3] Download/copy encrypted files")
    print("[4] Decrypt selected candidate (only if ready)")
    print("[5] Select multiple candidates")
    print("[6] Back\n")


def encrypted_database_candidates_menu(
    executor: AdbExecutor,
    device: Optional[DeviceInfo],
    settings: dict[str, Any],
    discovery_manifest: Optional[Any] = None,
    input_func: Callable[[str], str] = input,
) -> Optional[ChatDatabaseCandidate]:
    """Interactive wizard managing encrypted database candidates, key assessment, download, and decryption."""
    manager = EncryptedDatabaseManager(executor, settings)
    candidates = manager.find_encrypted_candidates(device=device, discovery_manifest=discovery_manifest)

    while True:
        display_encrypted_candidates_list(candidates)
        choice = input_func("Select an operation [1-6]: ").strip()

        if choice in ("6", "0", "back", "b"):
            return None

        elif choice == "1":
            # Inspect selected candidate
            if not candidates:
                print("[!] No encrypted candidates available to inspect.")
                continue
            pick = input_func(f"Select candidate to inspect [1-{len(candidates)}]: ").strip()
            if pick.isdigit() and 1 <= int(pick) <= len(candidates):
                cand = candidates[int(pick) - 1]
                print("\n" + "=" * 56)
                print("  ENCRYPTED DATABASE PROVENANCE & DETAILS")
                print("=" * 56)
                print(f"  Filename         : {cand.filename}")
                print(f"  Source Location  : {cand.path}")
                print(f"  Evidence Source  : {cand.source}")
                print(f"  File Size        : {cand.size_human} ({cand.size_bytes:,} bytes)")
                print(f"  Format Standard  : {cand.format_type}")
                print(f"  Cipher Algorithm : AES-GCM-256")
                print(f"  Key Requirement  : 158-byte WhatsApp key file (or 32-byte AES key)")
                print(f"  Key Status       : {cand.key_status}")
                if cand.key_path:
                    print(f"  Verified Key Path: {cand.key_path}")
                print(f"  Validation State : {cand.decryption_status}")
                if cand.validation_notes:
                    print(f"  Diagnostics      : {cand.validation_notes}")
                print("=" * 56)
                input_func("\nPress Enter to return...")

        elif choice == "2":
            # Check key availability
            print("\n[*] Assessing key availability across authorized sources...")
            custom_key = input_func("Enter custom path to key file (or press Enter to search default sources): ").strip()
            user_kp = custom_key if custom_key else None
            manager.key_service.assess_all(candidates, device=device, user_key_path=user_kp)
            print("[+] Key availability assessment completed.")

        elif choice == "3":
            # Download/copy encrypted files
            if not candidates:
                print("[!] No encrypted candidates available to copy.")
                continue
            print("\nSelect candidates to copy:")
            print("  [A] Acquire all encrypted candidates")
            print("  [1-N] Select specific candidate")
            print("  [0] Cancel")
            sel = input_func("Choice: ").strip().lower()

            selected_for_copy: List[ChatDatabaseCandidate] = []
            if sel == "a":
                selected_for_copy = list(candidates)
            elif sel.isdigit() and 1 <= int(sel) <= len(candidates):
                selected_for_copy = [candidates[int(sel) - 1]]
            else:
                continue

            tot_files = len(selected_for_copy)
            tot_bytes = sum(c.size_bytes for c in selected_for_copy)

            # Destination prompt
            dest = prompt_recovery_destination(
                device=device,
                total_files=tot_files,
                total_bytes=tot_bytes,
                settings=settings,
                input_func=input_func,
            )
            if not dest:
                continue

            # Ensure databases subfolder
            db_dest = dest / "databases" if dest.name != "databases" else dest

            # Pre-acquisition confirmation
            print("\n" + "=" * 56)
            print("       WRS — ACQUISITION CONFIRMATION")
            print("=" * 56)
            print(f"Selected files  : {tot_files}")
            print(f"Selected size   : {format_bytes(tot_bytes)}")
            print(f"Destination     : {db_dest}")
            print(f"Operation       : Copy selected accessible files")
            print(f"Source changes  : None intended\n")
            print("[1] Confirm and start acquisition")
            print("[0] Cancel\n")
            c_conf = input_func("Choose an option: ").strip()
            if c_conf != "1":
                print("[*] Copy cancelled.")
                continue

            print(f"\n[*] Acquiring {tot_files} encrypted database(s)...")
            records = manager.acquire_encrypted_files(selected_for_copy, device, db_dest)
            ok_cnt = sum(1 for r in records if r.status == "VERIFIED")
            print(f"[+] Successfully copied {ok_cnt}/{tot_files} encrypted file(s) to:")
            print(f"    {db_dest}")
            input_func("\nPress Enter to continue...")

        elif choice == "4":
            # Decrypt selected candidate (only if ready)
            if not candidates:
                print("[!] No encrypted candidates available.")
                continue
            pick = input_func(f"Select candidate to decrypt [1-{len(candidates)}]: ").strip()
            if not (pick.isdigit() and 1 <= int(pick) <= len(candidates)):
                continue

            cand = candidates[int(pick) - 1]

            # Re-check key status
            res = manager.key_service.assess_candidate(cand, device=device)
            if not res.key_found or not res.key_material:
                print("\n" + "=" * 56)
                print("       DECRYPTION PREREQUISITE MISSING")
                print("=" * 56)
                print(f"Candidate   : {cand.filename}")
                print(f"Format      : {cand.format_type}")
                print(f"Status      : {res.key_status}")
                print(f"Explanation : {res.notes}\n")
                print("Options:")
                print("  [1] Supply a legitimate decryption key file")
                print("  [2] Acquire/copy the encrypted file for safekeeping without decrypting")
                print("  [0] Return\n")
                opt = input_func("Choose option: ").strip()
                if opt == "1":
                    k_in = input_func("Enter path to valid WhatsApp key file: ").strip()
                    if k_in:
                        ok_k, km, k_msg = manager.key_service.validate_key_file(k_in)
                        if not ok_k or not km:
                            print(f"[!] Invalid key file: {k_msg}")
                            input_func("Press Enter...")
                            continue
                        res.key_material = km
                        res.key_found = True
                    else:
                        continue
                elif opt == "2":
                    dest = prompt_recovery_destination(
                        device=device,
                        total_files=1,
                        total_bytes=cand.size_bytes,
                        settings=settings,
                        input_func=input_func,
                    )
                    if dest:
                        db_dest = dest / "databases" if dest.name != "databases" else dest
                        manager.acquire_encrypted_files([cand], device, db_dest)
                        print(f"[+] Encrypted database acquired to {db_dest}")
                        input_func("Press Enter...")
                    continue
                else:
                    continue

            # Key is available: confirm before decrypting working copy
            rec_root = Path(settings.get("acquisition", {}).get("default_recovery_dir", "recovery")).resolve()
            clean_dev = sanitize_device_name(device.display_name if device else "local_import")
            out_work_dir = rec_root / clean_dev / "decrypted"

            print("\n" + "=" * 56)
            print("       WRS — DECRYPTION CONFIRMATION")
            print("=" * 56)
            print(f"Source Database : {cand.filename} ({cand.size_human})")
            print(f"Format          : {cand.format_type}")
            print(f"Verified Key    : {res.key_material.description}")
            print(f"Output Directory: {out_work_dir}")
            print("Operation       : Decrypt working copy (original remains untouched)")
            print("-" * 56)
            proceed = input_func("Confirm and begin decryption? [y/N]: ").strip().lower()
            if proceed not in ("y", "yes"):
                print("[*] Decryption cancelled.")
                continue

            print("\n[*] Decrypting working copy under AES-GCM...")
            ok_dec, new_cand, dec_msg = manager.decrypt_working_copy(
                candidate=cand,
                key_material=res.key_material,
                output_dir=out_work_dir,
                device=device,
            )

            if not ok_dec or not new_cand:
                print(f"\n[!] Decryption failed: {dec_msg}")
                input_func("Press Enter...")
                continue

            print("\n" + "=" * 56)
            print("       DECRYPTION & VALIDATION SUCCESSFUL")
            print("=" * 56)
            print(f"Decrypted Database : {new_cand.filename}")
            print(f"Output Location    : {new_cand.path}")
            print(f"Validated Messages : {new_cand.message_count:,}")
            print(f"Message Date Range : [{new_cand.oldest_timestamp or 'N/A'} to {new_cand.newest_timestamp or 'N/A'}]")
            print(f"Integrity SHA-256  : {new_cand.sha256[:16]}... verified")
            print("=" * 56 + "\n")

            return new_cand

        elif choice == "5":
            # Select multiple candidates
            print("\nEnter candidate numbers to select (e.g. '1, 2' or '1-3'): ")
            sel_str = input_func("Selection: ").strip()
            chosen_indices: List[int] = []
            for part in sel_str.replace(" ", "").split(","):
                if "-" in part:
                    subparts = part.split("-")
                    if len(subparts) == 2 and subparts[0].isdigit() and subparts[1].isdigit():
                        chosen_indices.extend(range(int(subparts[0]), int(subparts[1]) + 1))
                elif part.isdigit():
                    chosen_indices.append(int(part))

            valid_multi = [candidates[i - 1] for i in chosen_indices if 1 <= i <= len(candidates)]
            if not valid_multi:
                print("[!] No valid candidates selected.")
                continue

            tot_files = len(valid_multi)
            tot_bytes = sum(c.size_bytes for c in valid_multi)
            print(f"\nSelected {tot_files} file(s) ({format_bytes(tot_bytes)}).")

            dest = prompt_recovery_destination(
                device=device,
                total_files=tot_files,
                total_bytes=tot_bytes,
                settings=settings,
                input_func=input_func,
            )
            if dest:
                db_dest = dest / "databases" if dest.name != "databases" else dest
                records = manager.acquire_encrypted_files(valid_multi, device, db_dest)
                ok_cnt = sum(1 for r in records if r.status == "VERIFIED")
                print(f"[+] Successfully copied {ok_cnt}/{tot_files} encrypted file(s) to: {db_dest}")
                input_func("\nPress Enter to continue...")
