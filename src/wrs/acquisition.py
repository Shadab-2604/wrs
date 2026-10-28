"""Safe file acquisition module for WRS.

Provides pre-acquisition preview, explicit confirmation handling,
deterministic collision resolution, streaming SHA-256 integrity checks,
interrupted-scan resuming, and structured forensic output directory creation.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from .categorizer import (
    ALL_CATEGORIES,
    CAT_BACKUPS,
    CAT_DATABASES,
    CATEGORY_DIR_NAMES,
)
from .device import AdbExecutor, DeviceInfo
from .hashing import (
    STATUS_FAILED,
    STATUS_SKIPPED,
    STATUS_VERIFIED,
    VerificationRecord,
    evaluate_acquisition_integrity,
    get_remote_file_hash,
    hash_local_file,
)
from .scanner import ScannedFile, ScanResult
from .utils import (
    check_disk_space,
    format_bytes,
    format_timestamp,
    get_safe_destination_path,
    get_timestamp_slug,
    resolve_unique_filepath,
    sanitize_device_name,
    sanitize_filename,
)

logger = logging.getLogger("wrs.acquisition")


from .case import CaseManager, generate_scan_id
from .duplicate import DuplicateDetector, DuplicateGroup
from .inventory import (
    InventoryRecord,
    ScanInventoryDB,
    STATUS_ACQUIRED,
    STATUS_ACQUISITION_ELIGIBLE,
    STATUS_DISCOVERED,
    STATUS_FAILED as INV_FAILED,
    STATUS_UNREADABLE,
    STATUS_VERIFIED as INV_VERIFIED,
)


@dataclass
class AcquisitionPreview:
    """Pre-acquisition summary displaying file counts, sizes, and requirements."""

    device_name: str
    serial: str
    android_version: str
    scan_date: str
    selected_locations: List[str]
    category_counts: Dict[str, int]
    category_bytes: Dict[str, int]
    total_files: int
    total_bytes: int
    unreadable_files: int
    skipped_files: int
    database_backup_candidates: int
    destination_path: Path
    required_space_with_margin: int
    available_space: int
    has_sufficient_space: bool
    space_message: str
    scan_id: str = ""
    duplicate_candidates: int = 0
    excluded_duplicates_count: int = 0
    excluded_duplicates_bytes: int = 0


AcquisitionProgressCb = Callable[[int, int, int, int, str, str, float], None]


class AcquisitionManager:
    """Manages the forensic acquisition lifecycle."""

    def __init__(
        self,
        executor: AdbExecutor,
        base_recovery_dir: Path | str = "recovery",
        safety_margin_bytes: int = 104857600,
        safety_margin_ratio: float = 0.10,
    ) -> None:
        self.executor = executor
        self.base_recovery_dir = Path(base_recovery_dir).resolve()
        self.safety_margin_bytes = safety_margin_bytes
        self.safety_margin_ratio = safety_margin_ratio

    def generate_preview(
        self,
        device: DeviceInfo,
        scan_result: ScanResult,
        selected_categories: Optional[Set[str]] = None,
        custom_destination: Optional[Path] = None,
        excluded_paths: Optional[Set[str]] = None,
        scan_id: Optional[str] = None,
    ) -> AcquisitionPreview:
        """Calculate and format an accurate pre-acquisition preview."""
        dest_dir = custom_destination or self._build_scan_dir_path(device)
        sid = scan_id or generate_scan_id(device.serial)

        # Detect duplicate size collisions as potential duplicate candidates
        size_counts: Dict[int, int] = {}
        for f in scan_result.files:
            if f.size_bytes > 0:
                size_counts[f.size_bytes] = size_counts.get(f.size_bytes, 0) + 1
        dup_candidate_count = sum(c for sz, c in size_counts.items() if c > 1)

        filtered_files = scan_result.files
        if selected_categories is not None:
            filtered_files = [f for f in filtered_files if f.category in selected_categories]

        excluded_dup_cnt = 0
        excluded_dup_b = 0
        if excluded_paths:
            final_files = []
            for f in filtered_files:
                if f.original_path in excluded_paths:
                    excluded_dup_cnt += 1
                    excluded_dup_b += f.size_bytes
                else:
                    final_files.append(f)
            filtered_files = final_files

        cat_counts: Dict[str, int] = {c: 0 for c in ALL_CATEGORIES}
        cat_bytes: Dict[str, int] = {c: 0 for c in ALL_CATEGORIES}
        total_bytes = 0
        unreadable = 0
        db_candidates = 0

        for f in filtered_files:
            if not f.readability:
                unreadable += 1
                continue
            cat = f.category
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
            cat_bytes[cat] = cat_bytes.get(cat, 0) + f.size_bytes
            total_bytes += f.size_bytes

            if cat in (CAT_DATABASES, CAT_BACKUPS):
                db_candidates += 1

        skipped = len(scan_result.files) - len(filtered_files)

        has_space, free_b, req_margin, space_msg = check_disk_space(
            destination=dest_dir,
            required_bytes=total_bytes,
            safety_margin_bytes=self.safety_margin_bytes,
            safety_margin_ratio=self.safety_margin_ratio,
        )

        return AcquisitionPreview(
            device_name=device.display_name,
            serial=device.serial,
            android_version=device.android_version,
            scan_date=scan_result.start_time,
            selected_locations=[scan_result.location_path],
            category_counts=cat_counts,
            category_bytes=cat_bytes,
            total_files=len(filtered_files),
            total_bytes=total_bytes,
            unreadable_files=unreadable,
            skipped_files=skipped,
            database_backup_candidates=db_candidates,
            destination_path=dest_dir,
            required_space_with_margin=req_margin,
            available_space=free_b,
            has_sufficient_space=has_space,
            space_message=space_msg,
            scan_id=sid,
            duplicate_candidates=dup_candidate_count,
            excluded_duplicates_count=excluded_dup_cnt,
            excluded_duplicates_bytes=excluded_dup_b,
        )

    def _build_scan_dir_path(self, device: DeviceInfo, timestamp: Optional[datetime] = None) -> Path:
        """Create standard directory path: recovery/DEVICE_NAME_scan_YYYY-MM-DD_HH-MM-SS/."""
        clean_dev = sanitize_device_name(device.display_name)
        if clean_dev in ("", "unknown_device", "Device"):
            suffix = device.serial[-6:] if len(device.serial) > 6 else (device.serial or "dev")
            clean_dev = f"Android_Device_{sanitize_device_name(suffix)}"
        slug = get_timestamp_slug(timestamp)
        candidate_name = f"{clean_dev}_scan_{slug}"
        candidate_path = self.base_recovery_dir / candidate_name

        # Prevent collision if multiple scans execute within same second
        counter = 1
        while candidate_path.exists():
            candidate_path = self.base_recovery_dir / f"{clean_dev}_scan_{slug}_{counter}"
            counter += 1

        return candidate_path

    def setup_recovery_tree(self, destination_dir: Path) -> Dict[str, Path]:
        """Create structured category, metadata, and report directories."""
        dirs: Dict[str, Path] = {
            "root": destination_dir,
            "metadata": destination_dir / "metadata",
            "reports": destination_dir / "reports",
        }

        # Create category directories
        for cat_name, dir_name in CATEGORY_DIR_NAMES.items():
            dirs[cat_name] = destination_dir / dir_name

        for p in dirs.values():
            p.mkdir(parents=True, exist_ok=True)

        return dirs

    def acquire_files(
        self,
        device: DeviceInfo,
        scan_result: ScanResult,
        destination_dir: Path,
        selected_categories: Optional[Set[str]] = None,
        progress_cb: Optional[AcquisitionProgressCb] = None,
        excluded_paths: Optional[Set[str]] = None,
        scan_id: Optional[str] = None,
    ) -> List[VerificationRecord]:
        """Acquire files safely via ADB into structured categories with SHA-256 verification."""
        dir_tree = self.setup_recovery_tree(destination_dir)
        sid = scan_id or generate_scan_id(device.serial)
        case_mgr = CaseManager(destination_dir)
        case_mgr.log_event(sid, "ACQUISITION_INITIALIZED", {
            "device": device.display_name,
            "serial": device.serial,
            "total_files": scan_result.total_files,
            "total_bytes": scan_result.total_bytes,
        })

        # Initialize SQLite scan inventory database
        inv_db_path = dir_tree["metadata"] / "inventory.db"
        inv_db = ScanInventoryDB(inv_db_path)
        init_records = [
            InventoryRecord(
                scan_id=sid,
                device_id=device.device_id or device.serial,
                source_path=f.original_path,
                relative_path=f.relative_path,
                filename=f.filename,
                extension=f.extension,
                category=f.category,
                size_bytes=f.size_bytes,
                modified_time=f.modified_time,
                readability=f.readability,
                acquisition_status=STATUS_ACQUISITION_ELIGIBLE if (
                    (selected_categories is None or f.category in selected_categories)
                    and (not excluded_paths or f.original_path not in excluded_paths)
                ) else STATUS_DISCOVERED,
            )
            for f in scan_result.files
        ]
        inv_db.insert_batch(init_records)

        # Write initial device metadata
        dev_meta_path = dir_tree["metadata"] / "device.json"
        with open(dev_meta_path, "w", encoding="utf-8") as f:
            json.dump(asdict(device), f, indent=2)

        # Save scan summary
        scan_meta_path = dir_tree["metadata"] / "scan_summary.json"
        with open(scan_meta_path, "w", encoding="utf-8") as f:
            summary_dict = {
                "scan_id": sid,
                "serial": scan_result.device_serial,
                "location": scan_result.location_path,
                "start_time": scan_result.start_time,
                "end_time": scan_result.end_time,
                "total_files": scan_result.total_files,
                "total_bytes": scan_result.total_bytes,
                "category_counts": scan_result.category_counts,
                "category_bytes": scan_result.category_bytes,
                "errors": scan_result.errors,
            }
            json.dump(summary_dict, f, indent=2)

        # Filter target files
        target_files = [
            f for f in scan_result.files
            if (selected_categories is None or f.category in selected_categories)
            and (not excluded_paths or f.original_path not in excluded_paths)
        ]

        total_files = len(target_files)
        total_target_bytes = sum(f.size_bytes for f in target_files)
        transferred_bytes = 0
        records: List[VerificationRecord] = []
        errors_log: List[dict] = []
        start_time = time.time()

        # Load existing manifest if resuming an interrupted session
        manifest_path = dir_tree["metadata"] / "acquisition_manifest.json"
        existing_manifest: dict[str, dict] = {}
        if manifest_path.exists():
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    prev_items = json.load(f)
                    for item in prev_items:
                        existing_manifest[item["source_path"]] = item
            except Exception as e:
                logger.warning("Could not read previous manifest: %s", e)

        try:
            for idx, sfile in enumerate(target_files, start=1):
                # 1. Check if already acquired and verified in previous run
                if sfile.original_path in existing_manifest:
                    prev = existing_manifest[sfile.original_path]
                    dest_p = Path(prev["destination_path"])
                    if dest_p.exists() and dest_p.stat().st_size == sfile.size_bytes:
                        # Re-verify local hash quickly
                        h, _, _ = hash_local_file(dest_p)
                        if h and h == prev.get("destination_sha256"):
                            rec = VerificationRecord(
                                source_path=sfile.original_path,
                                destination_path=str(dest_p),
                                expected_size=sfile.size_bytes,
                                acquired_size=dest_p.stat().st_size,
                                source_sha256=prev.get("source_sha256"),
                                destination_sha256=h,
                                status=prev.get("status", STATUS_VERIFIED),
                                timestamp=prev.get("timestamp", format_timestamp()),
                            )
                            records.append(rec)
                            transferred_bytes += sfile.size_bytes
                            if progress_cb:
                                progress_cb(idx, total_files - idx, transferred_bytes, total_target_bytes, sfile.filename, rec.status, time.time() - start_time)
                            continue

                # 2. Determine target destination directory
                cat_dir = dir_tree.get(sfile.category, dir_tree["Other"])

                # Preserve relative directory structure within category folder if safe,
                # otherwise resolve collision-safe path
                safe_rel = sfile.relative_path
                # strip parent directory markers
                safe_dest_path = get_safe_destination_path(cat_dir, safe_rel)

                # Ensure parent directories exist
                safe_dest_path.parent.mkdir(parents=True, exist_ok=True)

                # If file exists and not recorded in manifest, disambiguate
                if safe_dest_path.exists() and safe_dest_path.stat().st_size != sfile.size_bytes:
                    safe_dest_path = resolve_unique_filepath(safe_dest_path.parent, safe_dest_path.name)

                # Check device connection before initiating pull
                if not self.executor.is_device_connected(device.serial):
                    disconn_msg = f"Device {device.display_name} ({device.serial}) disconnected during acquisition."
                    logger.error(disconn_msg)
                    errors_log.append({
                        "file": sfile.original_path,
                        "destination": str(safe_dest_path),
                        "error": disconn_msg,
                        "timestamp": format_timestamp(),
                    })
                    case_mgr.log_event(sid, "DEVICE_DISCONNECTED", {
                        "serial": device.serial,
                        "files_completed": len(records),
                        "files_total": total_files,
                    })
                    interrupted_path = dir_tree["metadata"] / "interrupted.json"
                    with open(interrupted_path, "w", encoding="utf-8") as f:
                        json.dump({
                            "scan_id": sid,
                            "reason": "DEVICE_DISCONNECTED",
                            "serial": device.serial,
                            "interrupted_at": format_timestamp(),
                            "files_completed": len(records),
                            "files_total": total_files,
                        }, f, indent=2)
                    break

                # 3. Pull file via ADB (explicit argument list, no shell=True)
                pull_cmd = ["pull", sfile.original_path, str(safe_dest_path)]
                pull_res = self.executor.run_cmd(pull_cmd, serial=device.serial, timeout=300)

                copy_err = None
                if pull_res.returncode != 0:
                    copy_err = pull_res.stderr.strip() or "ADB pull failed"
                    errors_log.append({
                        "file": sfile.original_path,
                        "destination": str(safe_dest_path),
                        "error": copy_err,
                        "timestamp": format_timestamp(),
                    })
                    # If error indicates disconnection, break loop safely
                    err_lower = copy_err.lower()
                    if "device offline" in err_lower or "device not found" in err_lower or "closed" in err_lower:
                        case_mgr.log_event(sid, "DEVICE_DISCONNECTED", {
                            "serial": device.serial,
                            "files_completed": len(records),
                            "files_total": total_files,
                        })
                        interrupted_path = dir_tree["metadata"] / "interrupted.json"
                        with open(interrupted_path, "w", encoding="utf-8") as f:
                            json.dump({
                                "scan_id": sid,
                                "reason": "DEVICE_DISCONNECTED",
                                "serial": device.serial,
                                "interrupted_at": format_timestamp(),
                                "files_completed": len(records),
                                "files_total": total_files,
                            }, f, indent=2)
                        break

                # 4. Hash acquired file locally
                dest_hash, acquired_sz, hash_err = hash_local_file(safe_dest_path)
                if hash_err and not copy_err:
                    copy_err = hash_err

                # 5. Attempt independent remote source hashing via ADB on device
                source_hash = None
                if not copy_err:
                    source_hash, _ = get_remote_file_hash(self.executor, device.serial, sfile.original_path)

                # 6. Evaluate forensic integrity
                rec = evaluate_acquisition_integrity(
                    source_path=sfile.original_path,
                    dest_path=safe_dest_path,
                    expected_size=sfile.size_bytes,
                    source_hash=source_hash,
                    dest_hash=dest_hash,
                    acquired_size=acquired_sz,
                    copy_error=copy_err,
                )
                records.append(rec)
                transferred_bytes += acquired_sz

                # 7. Update manifest and persistent inventory incrementally
                self._write_manifest(manifest_path, records)
                inv_db.update_acquisition_status(
                    source_path=sfile.original_path,
                    status=rec.status,
                    destination_sha256=rec.destination_sha256,
                    verification_status=rec.status,
                    error_message=rec.error_message,
                )

                # 8. Report progress
                if progress_cb:
                    progress_cb(
                        idx,
                        total_files - idx,
                        transferred_bytes,
                        total_target_bytes,
                        sfile.filename,
                        rec.status,
                        time.time() - start_time,
                    )

        except KeyboardInterrupt:
            logger.warning("Acquisition interrupted by user. Saving state...")
            case_mgr.log_event(sid, "ACQUISITION_INTERRUPTED", {
                "files_completed": len(records),
                "files_total": total_files,
            })
            # Save interruption record
            interrupted_path = dir_tree["metadata"] / "interrupted.json"
            with open(interrupted_path, "w", encoding="utf-8") as f:
                json.dump({
                    "scan_id": sid,
                    "interrupted_at": format_timestamp(),
                    "files_completed": len(records),
                    "files_total": total_files,
                }, f, indent=2)
            raise

        finally:
            # Always save manifest and error log
            self._write_manifest(manifest_path, records)
            err_path = dir_tree["metadata"] / "errors.json"
            with open(err_path, "w", encoding="utf-8") as f:
                json.dump(errors_log, f, indent=2)
            case_mgr.log_event(sid, "ACQUISITION_FINISHED", {
                "total_acquired": len(records),
                "total_errors": len(errors_log),
            })

        return records

    def _write_manifest(self, path: Path, records: List[VerificationRecord]) -> None:
        """Write records to acquisition manifest safely with atomic replace."""
        temp_path = path.with_suffix(".tmp")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump([asdict(r) for r in records], f, indent=2)
            temp_path.replace(path)
        except Exception as e:
            logger.error("Failed to write acquisition manifest: %s", e)
