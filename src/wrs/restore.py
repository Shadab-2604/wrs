"""Recovery & Restore Assistant module for WRS.

Scans, validates, preserves, stages, and guides native WhatsApp restorations
without modifying WhatsApp application data, uninstalling apps, or silently
overwriting device files or backups.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .database import WhatsAppDatabaseAnalyzer
from .device import AdbExecutor
from .hashing import hash_local_file
from .utils import format_bytes, format_timestamp

logger = logging.getLogger("wrs.restore")


class RestoreCandidateStatus(str, Enum):
    """Forensic classification lifecycle of a recovery/restore candidate."""

    DISCOVERED = "DISCOVERED"
    ACQUIRED = "ACQUIRED"
    VALIDATED = "VALIDATED"
    PARSEABLE = "PARSEABLE"
    RESTORABLE = "RESTORABLE"
    UNSUPPORTED = "UNSUPPORTED"


class CandidateSourceType(str, Enum):
    """Categorization of evidence candidate source."""

    LOCAL_BACKUP = "LOCAL_BACKUP"
    SUPPORTED_READABLE_DATABASE = "SUPPORTED_READABLE_DATABASE"
    MEDIA_ONLY_COLLECTION = "MEDIA_ONLY_COLLECTION"
    UNSUPPORTED_ARTIFACT = "UNSUPPORTED_ARTIFACT"


@dataclass
class RestoreCandidate:
    """A preserved WhatsApp database or backup candidate with forensic provenance."""

    source_path: str
    filename: str
    size_bytes: int
    modified_timestamp: str
    sha256_hash: str
    detected_format: str  # 'SQLITE', 'CRYPT15', 'CRYPT14', 'CRYPT12', 'UNKNOWN'
    status: RestoreCandidateStatus
    source_type: CandidateSourceType
    is_sqlite: bool = False
    is_encrypted: bool = False
    is_dated_backup: bool = False
    restorable_target_name: str = ""
    evidence_location: str = "LOCAL_ACQUISITION"  # 'LOCAL_ACQUISITION' or 'DEVICE_STORAGE'
    table_count: int = 0
    validation_notes: str = ""

    @property
    def size_human(self) -> str:
        return format_bytes(self.size_bytes)


class RestoreAssistant:
    """Guided forensic restoration workstation for native WhatsApp recovery."""

    # Standard WhatsApp storage paths on Android for native restore
    STANDARD_DEVICE_BACKUP_PATHS = [
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
        "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Databases",
        "/sdcard/WhatsApp/Databases",
        "/storage/emulated/0/WhatsApp/Databases",
    ]

    # WhatsApp Business paths
    W4B_DEVICE_BACKUP_PATHS = [
        "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp/Databases",
        "/storage/emulated/0/Android/media/com.whatsapp.w4b/WhatsApp/Databases",
    ]

    @classmethod
    def scan_local_recovery_candidates(cls, base_recovery_dir: Path | str = "recovery") -> List[RestoreCandidate]:
        """Scan existing WRS recovery directories for database and backup candidates.

        Preserves every candidate in read-only state and calculates SHA-256 hashes.
        """
        base = Path(base_recovery_dir).resolve()
        if not base.exists() or not base.is_dir():
            return []

        candidates: List[RestoreCandidate] = []
        # Search for .db and .crypt files recursively
        for root, _, files in os.walk(base):
            for fn in files:
                lower_fn = fn.lower()
                # Skip WAL, SHM, journal, and lock files
                if lower_fn.endswith(("-wal", "-shm", "-journal", ".lock", ".tmp")):
                    continue

                if ".db" in lower_fn or "msgstore" in lower_fn or lower_fn.endswith((".crypt12", ".crypt14", ".crypt15")):
                    file_p = Path(root) / fn
                    try:
                        sz = file_p.stat().st_size
                        mtime = datetime.fromtimestamp(file_p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        sha_hash, _, _ = hash_local_file(file_p)
                        sha256 = sha_hash or ""

                        # Non-destructive format assessment
                        meta = WhatsAppDatabaseAnalyzer.identify_database(file_p)
                        cand = cls._evaluate_candidate(
                            path_str=str(file_p),
                            filename=fn,
                            size_bytes=sz,
                            mtime_str=mtime,
                            sha256=sha256,
                            meta=meta,
                            evidence_loc="LOCAL_ACQUISITION",
                        )
                        candidates.append(cand)
                    except (OSError, PermissionError) as err:
                        logger.warning("Could not assess candidate file %s: %s", file_p, err)

        # Sort candidates by size and recency
        candidates.sort(key=lambda c: (c.status == RestoreCandidateStatus.RESTORABLE, c.size_bytes), reverse=True)
        return candidates

    @classmethod
    def scan_device_candidates(cls, executor: AdbExecutor, serial: str) -> List[RestoreCandidate]:
        """Scan accessible Android device storage for existing WhatsApp databases."""
        if not executor.is_adb_installed():
            return []

        candidates: List[RestoreCandidate] = []
        all_targets = cls.STANDARD_DEVICE_BACKUP_PATHS + cls.W4B_DEVICE_BACKUP_PATHS

        for dev_dir in all_targets:
            res = executor.run_cmd(["shell", f"ls -l '{dev_dir}' 2>/dev/null"], serial=serial, timeout=10)
            if res.returncode == 0 and res.stdout.strip():
                for line in res.stdout.strip().splitlines():
                    parts = line.split()
                    if len(parts) >= 8:
                        fn = parts[-1]
                        lower_fn = fn.lower()
                        if lower_fn.endswith(("-wal", "-shm", "-journal")):
                            continue
                        if ".db" in lower_fn or "msgstore" in lower_fn or lower_fn.endswith((".crypt12", ".crypt14", ".crypt15")):
                            try:
                                sz = int(parts[4])
                            except (ValueError, IndexError):
                                sz = 0
                            dev_path = f"{dev_dir}/{fn}"
                            # Format classification based on filename and known extension
                            fmt_type = "UNKNOWN"
                            is_enc = False
                            is_sqlite = False
                            is_dated = bool(re.search(r"msgstore-\d{4}-\d{2}-\d{2}", lower_fn))

                            if ".crypt15" in lower_fn:
                                fmt_type = "CRYPT15"
                                is_enc = True
                            elif ".crypt14" in lower_fn:
                                fmt_type = "CRYPT14"
                                is_enc = True
                            elif ".crypt12" in lower_fn:
                                fmt_type = "CRYPT12"
                                is_enc = True
                            elif lower_fn.endswith(".db"):
                                fmt_type = "SQLITE"
                                is_sqlite = True

                            status = RestoreCandidateStatus.DISCOVERED
                            target_name = "msgstore.db.crypt14" if ".crypt14" in lower_fn else ("msgstore.db.crypt15" if ".crypt15" in lower_fn else "msgstore.db")

                            candidates.append(
                                RestoreCandidate(
                                    source_path=dev_path,
                                    filename=fn,
                                    size_bytes=sz,
                                    modified_timestamp=format_timestamp(),
                                    sha256_hash="",  # Not computed on remote to avoid pulling
                                    detected_format=fmt_type,
                                    status=status,
                                    source_type=CandidateSourceType.LOCAL_BACKUP if is_enc else CandidateSourceType.SUPPORTED_READABLE_DATABASE,
                                    is_sqlite=is_sqlite,
                                    is_encrypted=is_enc,
                                    is_dated_backup=is_dated,
                                    restorable_target_name=target_name,
                                    evidence_location="DEVICE_STORAGE",
                                    validation_notes="Discovered on device external storage.",
                                )
                            )

        return candidates

    @classmethod
    def _evaluate_candidate(
        cls,
        path_str: str,
        filename: str,
        size_bytes: int,
        mtime_str: str,
        sha256: str,
        meta: Any,
        evidence_loc: str,
    ) -> RestoreCandidate:
        """Evaluate candidate against forensic rules. Never classify encrypted DB as restorable solely from filename."""
        fn_lower = filename.lower()
        is_dated = bool(re.search(r"msgstore-\d{4}-\d{2}-\d{2}", fn_lower))

        # Check for zero-byte or corrupt files
        if size_bytes == 0:
            return RestoreCandidate(
                source_path=path_str,
                filename=filename,
                size_bytes=0,
                modified_timestamp=mtime_str,
                sha256_hash=sha256,
                detected_format="EMPTY",
                status=RestoreCandidateStatus.UNSUPPORTED,
                source_type=CandidateSourceType.UNSUPPORTED_ARTIFACT,
                validation_notes="File is 0 bytes. Corrupted or incomplete artifact.",
                evidence_location=evidence_loc,
            )

        # Check for unencrypted SQLite databases
        if meta.is_sqlite:
            # Active readable database
            status = RestoreCandidateStatus.PARSEABLE
            src_type = CandidateSourceType.SUPPORTED_READABLE_DATABASE
            notes = f"SQLite database with {meta.table_count} tables. Supported for chat extraction."
            target_name = "msgstore.db"
            return RestoreCandidate(
                source_path=path_str,
                filename=filename,
                size_bytes=size_bytes,
                modified_timestamp=mtime_str,
                sha256_hash=sha256,
                detected_format="SQLITE",
                status=status,
                source_type=src_type,
                is_sqlite=True,
                is_encrypted=False,
                is_dated_backup=is_dated,
                restorable_target_name=target_name,
                evidence_location=evidence_loc,
                table_count=meta.table_count,
                validation_notes=notes,
            )

        # Encrypted WhatsApp Backup (.crypt14 / .crypt15 / .crypt12)
        if meta.is_encrypted:
            # RULE: Never classify an encrypted database as restorable solely from its filename!
            # Must verify non-zero size, recognized crypt header, and appropriate size.
            is_valid_header = meta.format_type in ("CRYPT14", "CRYPT15", "CRYPT12")
            if is_valid_header and size_bytes > 512:
                # Valid crypt container format suitable for native WhatsApp restoration
                status = RestoreCandidateStatus.RESTORABLE
                src_type = CandidateSourceType.LOCAL_BACKUP
                target_ext = ".crypt14" if meta.format_type == "CRYPT14" else (".crypt15" if meta.format_type == "CRYPT15" else ".crypt12")
                target_name = f"msgstore.db{target_ext}"
                notes = f"Valid {meta.format_type} container ({format_bytes(size_bytes)}). Restorable as active {target_name}."
            else:
                status = RestoreCandidateStatus.UNSUPPORTED
                src_type = CandidateSourceType.UNSUPPORTED_ARTIFACT
                target_name = ""
                notes = f"Corrupted or invalid {meta.format_type} header structure."

            return RestoreCandidate(
                source_path=path_str,
                filename=filename,
                size_bytes=size_bytes,
                modified_timestamp=mtime_str,
                sha256_hash=sha256,
                detected_format=meta.format_type,
                status=status,
                source_type=src_type,
                is_sqlite=False,
                is_encrypted=True,
                is_dated_backup=is_dated,
                restorable_target_name=target_name,
                evidence_location=evidence_loc,
                validation_notes=notes,
            )

        # Unrecognized artifact
        return RestoreCandidate(
            source_path=path_str,
            filename=filename,
            size_bytes=size_bytes,
            modified_timestamp=mtime_str,
            sha256_hash=sha256,
            detected_format="UNKNOWN",
            status=RestoreCandidateStatus.UNSUPPORTED,
            source_type=CandidateSourceType.UNSUPPORTED_ARTIFACT,
            validation_notes="Unrecognized database format or non-database artifact.",
            evidence_location=evidence_loc,
        )

    @classmethod
    def prepare_restoration_bundle(
        cls,
        candidate: RestoreCandidate,
        staging_dir: Path | str,
    ) -> Tuple[bool, str, Optional[Path]]:
        """Stage a validated backup candidate for native WhatsApp restoration.

        Never modifies or overwrites the original candidate.
        Prepares the active restore name (e.g. msgstore.db.crypt14) in staging.
        """
        staging = Path(staging_dir).resolve()
        staging.mkdir(parents=True, exist_ok=True)

        if candidate.status != RestoreCandidateStatus.RESTORABLE and candidate.source_type != CandidateSourceType.LOCAL_BACKUP:
            return False, f"Candidate '{candidate.filename}' is marked as {candidate.status}. Not eligible for native restoration.", None

        src_file = Path(candidate.source_path).resolve()
        if not src_file.exists():
            return False, f"Source candidate file not found at: {src_file}", None

        target_fn = candidate.restorable_target_name or "msgstore.db.crypt14"
        dest_file = staging / target_fn

        # Collision check in local staging
        if dest_file.exists():
            # If destination already exists with same hash, it's already staged
            curr_hash, _, _ = hash_local_file(dest_file)
            if curr_hash == candidate.sha256_hash:
                logger.info("Candidate already staged at %s", dest_file)
                return True, "Candidate already staged with matching hash.", dest_file
            return False, f"Staging collision: destination file '{dest_file.name}' already exists with different contents.", None

        try:
            # Safe copy to preserve original candidate
            shutil.copy2(src_file, dest_file)
            # Write restoration manifest
            manifest = {
                "generator": "WRS Restoration Assistant",
                "prepared_timestamp": format_timestamp(),
                "original_source_path": str(src_file),
                "original_filename": candidate.filename,
                "original_sha256": candidate.sha256_hash,
                "staged_target_filename": target_fn,
                "staged_file_size": dest_file.stat().st_size,
                "detected_format": candidate.detected_format,
                "prerequisites": cls.get_prerequisites_list(),
            }
            manifest_file = staging / "restoration_manifest.json"
            manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            return True, f"Successfully prepared restoration bundle at {dest_file}", dest_file
        except OSError as e:
            return False, f"Failed to stage restoration bundle: {e}", None

    @classmethod
    def push_staged_backup_to_device(
        cls,
        staged_file: Path | str,
        target_device_serial: str,
        executor: AdbExecutor,
        target_device_dir: Optional[str] = None,
        confirmed: bool = False,
    ) -> Tuple[bool, str]:
        """Push a prepared backup file to the target Android device via ADB.

        Mandatory safety rules:
        - Requires affirmative user confirmation before any write.
        - Checks if destination file already exists on device to prevent overwriting!
        """
        if not confirmed:
            return False, "Operation cancelled: affirmative confirmation required before writing to device."

        staged = Path(staged_file).resolve()
        if not staged.exists() or not staged.is_file():
            return False, f"Staged backup file does not exist: {staged}"

        if not executor.is_device_connected(target_device_serial):
            return False, f"Device '{target_device_serial}' is disconnected or offline."

        target_dir = target_device_dir or cls.STANDARD_DEVICE_BACKUP_PATHS[0]
        dest_remote_path = f"{target_dir}/{staged.name}"

        # 1. Collision check on device (NEVER silently overwrite existing backups)
        chk_res = executor.run_cmd(["shell", f"test -f '{dest_remote_path}' && echo 'EXISTS' || echo 'NOT_FOUND'"], serial=target_device_serial, timeout=10)
        if "EXISTS" in (chk_res.stdout or ""):
            return False, (
                f"Destination collision on device: '{dest_remote_path}' already exists! "
                "WRS refuses to overwrite existing device backups to prevent evidence destruction. "
                "Please back up or rename the existing file on the device first."
            )

        # 2. Ensure target directory exists on device
        mkdir_res = executor.run_cmd(["shell", f"mkdir -p '{target_dir}'"], serial=target_device_serial, timeout=10)
        if mkdir_res.returncode != 0:
            return False, f"Failed to create target directory '{target_dir}' on device: {mkdir_res.stderr}"

        # 3. Perform controlled ADB push
        logger.info("Pushing %s to %s:%s", staged, target_device_serial, dest_remote_path)
        push_res = executor.run_cmd(["push", str(staged), dest_remote_path], serial=target_device_serial, timeout=60)
        if push_res.returncode != 0:
            return False, f"ADB push failed: {push_res.stderr}"

        # 4. Verify file was created on device and size matches
        stat_res = executor.run_cmd(["shell", f"ls -l '{dest_remote_path}' 2>/dev/null"], serial=target_device_serial, timeout=10)
        if stat_res.returncode != 0 or not stat_res.stdout.strip():
            return False, f"Verification failed: pushed file was not found at '{dest_remote_path}'."

        parts = stat_res.stdout.strip().split()
        if len(parts) >= 5:
            try:
                remote_size = int(parts[4])
                local_size = staged.stat().st_size
                if remote_size != local_size:
                    return False, f"Size mismatch after push: local {local_size} bytes vs remote {remote_size} bytes."
            except (ValueError, IndexError):
                pass

        return True, f"Successfully deployed '{staged.name}' to device at: {dest_remote_path}"

    @staticmethod
    def get_prerequisites_list() -> List[str]:
        """Detailed prerequisites for a successful native WhatsApp restoration."""
        return [
            "Same Phone Number: The phone must register with the same phone number associated with the backup.",
            "Fresh WhatsApp Setup: WhatsApp must be freshly installed or cleared, and NOT yet registered or verified.",
            "Pre-registration Placement: The backup file ('msgstore.db.crypt14' or 'crypt15') must be placed in the Databases directory BEFORE opening WhatsApp.",
            "Storage Permissions: Android must have granted Storage / All Files Access permissions to WhatsApp.",
            "Skip Google Drive: When WhatsApp prompts for Google Drive backups during setup, skip Google Drive so it falls back to the local database.",
            "Offline Precaution: Keep Airplane mode available if Google Drive insists on overwriting with empty cloud data.",
        ]

    @staticmethod
    def get_verification_checklist() -> List[str]:
        """Post-restoration verification checklist for the user."""
        return [
            "Open WhatsApp and confirm that chat threads and contacts appear in the main chat list.",
            "Check the date of the most recent message to verify the restored backup timestamp matches.",
            "Open a key conversation and scroll up to verify message history and media placeholders.",
            "Verify group memberships and participant identifiers have loaded correctly.",
            "If media files were also acquired, verify photos, voice notes, and documents resolve properly in the WhatsApp media folders.",
        ]

    @staticmethod
    def get_rollback_precautions() -> List[str]:
        """Precautions and rollback safeguards for restoration workflows."""
        return [
            "Forensic Preservation: WRS operates in non-destructive read-only mode during scanning and acquisition.",
            "Destination Protection: WRS never overwrites existing databases, backups, or device files.",
            "Device Collision Refusal: If msgstore.db.crypt14 already exists on device, WRS refuses to push until manually renamed.",
            "Pre-Restoration Backup: Always preserve existing device /sdcard/WhatsApp/ or com.whatsapp folders before reinstalling WhatsApp.",
            "Local Staging Isolation: Staged restoration bundles are written to a dedicated staging directory with a cryptographic manifest.",
            "No Automatic Actions: WRS never uninstalls apps, clears app storage, or registers phone numbers automatically.",
        ]

    @classmethod
    def assess_source(cls, source_path: Path | str) -> Tuple[CandidateSourceType, List[RestoreCandidate], str]:
        """Classify available evidence source into standard types:
        - CandidateSourceType.LOCAL_BACKUP
        - CandidateSourceType.SUPPORTED_READABLE_DATABASE
        - CandidateSourceType.MEDIA_ONLY_COLLECTION
        - CandidateSourceType.UNSUPPORTED_ARTIFACT
        """
        p = Path(source_path).resolve()
        if not p.exists():
            return CandidateSourceType.UNSUPPORTED_ARTIFACT, [], f"Source path does not exist: {p}"

        if p.is_file():
            sz = p.stat().st_size
            mtime = datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            sha_h, _, _ = hash_local_file(p)
            meta = WhatsAppDatabaseAnalyzer.identify_database(p)
            cand = cls._evaluate_candidate(
                path_str=str(p),
                filename=p.name,
                size_bytes=sz,
                mtime_str=mtime,
                sha256=sha_h or "",
                meta=meta,
                evidence_loc="LOCAL_FILE",
            )
            return cand.source_type, [cand], cand.validation_notes

        cands = cls.scan_local_recovery_candidates(p)
        if not cands:
            media_exts = {".jpg", ".jpeg", ".png", ".mp4", ".3gp", ".opus", ".m4a", ".pdf", ".webp", ".enc"}
            media_count = 0
            for root, _, files in os.walk(p):
                for f in files:
                    if Path(f).suffix.lower() in media_exts:
                        media_count += 1
            if media_count > 0:
                return CandidateSourceType.MEDIA_ONLY_COLLECTION, [], f"Found {media_count} media file(s), but no chat databases or backup candidates."
            return CandidateSourceType.UNSUPPORTED_ARTIFACT, [], "No readable databases, backups, or media collections identified in directory."

        has_restorable = any(c.status == RestoreCandidateStatus.RESTORABLE for c in cands)
        has_parseable = any(c.status == RestoreCandidateStatus.PARSEABLE for c in cands)

        if has_restorable:
            return CandidateSourceType.LOCAL_BACKUP, cands, f"Found {len(cands)} candidate(s) including restorable backup container."
        elif has_parseable:
            return CandidateSourceType.SUPPORTED_READABLE_DATABASE, cands, f"Found {len(cands)} candidate(s) including readable SQLite database."
        else:
            return CandidateSourceType.UNSUPPORTED_ARTIFACT, cands, "Found database candidate files, but none have valid or restorable headers."

