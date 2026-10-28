"""WRS — Discovery Wizard, Recovery Destination, and Guided Operations Module.

Implements user-controlled scanning, recovery destination selection with blank-default support,
acquisition confirmation, and source-location discovery summaries.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .acquisition import (
    AcquisitionManager,
    build_default_recovery_destination,
)
from .case import CaseManager, generate_scan_id
from .categorizer import (
    ALL_CATEGORIES,
    CAT_AUDIO,
    CAT_BACKUPS,
    CAT_DATABASES,
    CAT_DOCUMENTS,
    CAT_IMAGES,
    CAT_OTHER,
    CAT_STICKERS,
    CAT_VIDEOS,
    CAT_VOICE_NOTES,
    CATEGORY_DIR_NAMES,
)
from .device import AdbExecutor, DeviceInfo
from .hashing import (
    STATUS_FAILED,
    STATUS_SKIPPED,
    STATUS_VERIFIED,
    VerificationRecord,
    evaluate_acquisition_integrity,
    hash_local_file,
)
from .inventory import (
    InventoryRecord,
    ScanInventoryDB,
    STATUS_ACQUIRED,
    STATUS_DISCOVERED,
)
from .priority_discovery import (
    DiscoveryCandidate,
    DiscoveryLocation,
    DiscoveryManifest,
    PriorityDiscoveryEngine,
    run_animated_priority_discovery,
)
from .reporting import ReportGenerator
from .scanner import ScannedFile, ScanResult
from .errors import format_actionable_error
from .ui import (
    get_console,
    is_color_enabled,
    print_confirmation_box,
    print_error,
    print_info,
    print_success,
    print_warning,
)
from .utils import (
    check_disk_space,
    format_bytes,
    format_timestamp,
    get_timestamp_slug,
    is_safe_path,
    sanitize_device_name,
    sanitize_filename,
)

logger = logging.getLogger("wrs.discovery_wizard")


def validate_destination_path(
    dest_input: str | Path,
    total_bytes: int = 0,
    source_paths: Optional[List[str]] = None,
) -> Tuple[bool, Optional[Path], str]:
    """Validate a destination path for file recovery.

    Checks:
    - Path cannot be empty or contain null bytes.
    - Expands ~ to current user's home directory.
    - Resolves to an absolute path.
    - Rejects Android storage paths (/sdcard, /storage, /data).
    - Detects accidental overlap with source locations to protect original files.
    - Verifies writability by testing the directory or nearest existing parent.
    - Verifies sufficient disk space when total_bytes > 0.

    Returns:
        (is_valid, resolved_path, error_message)
    """
    raw_str = str(dest_input).strip()
    if not raw_str:
        return False, None, "Destination path cannot be empty."

    if "\x00" in raw_str:
        return False, None, "Destination path contains illegal null bytes."

    # Expand user home directory and resolve absolute path
    try:
        resolved = Path(os.path.expanduser(raw_str)).resolve()
    except Exception as e:
        return False, None, f"Invalid destination path format: {e}"

    resolved_str_lower = str(resolved).lower()

    # Reject Android device filesystems (ADB device paths)
    android_roots = ["/sdcard", "/storage", "/data"]
    if any(resolved_str_lower.startswith(p) for p in android_roots):
        return (
            False,
            None,
            "Destination path cannot be on the Android device filesystem (/sdcard, /storage, /data). "
            "Recovery must be saved to a local directory on your host computer.",
        )

    # Detect accidental overlap with local source locations
    if source_paths:
        for src in source_paths:
            s_clean = src.strip()
            if not s_clean:
                continue
            # Skip remote device paths
            if any(s_clean.startswith(p) for p in android_roots):
                continue
            try:
                s_resolved = Path(os.path.expanduser(s_clean)).resolve()
                if resolved == s_resolved or resolved in s_resolved.parents or s_resolved in resolved.parents:
                    return (
                        False,
                        None,
                        f"Destination path overlaps with original source location ({s_resolved}). "
                        "Original source files must never be modified or overwritten.",
                    )
            except Exception:
                pass

    # Writability check: verify parent exists and has write permission
    check_parent = resolved
    while not check_parent.exists() and check_parent.parent != check_parent:
        check_parent = check_parent.parent

    if check_parent.exists():
        if not os.access(check_parent, os.W_OK):
            return False, None, f"Permission denied: Directory '{check_parent}' is not writable."
    else:
        return False, None, f"Cannot locate valid parent directory for '{resolved}'."

    # Test creating directory or writing a test file if directory exists
    try:
        resolved.mkdir(parents=True, exist_ok=True)
        test_file = resolved / f".wrs_write_test_{int(time.time())}"
        try:
            with open(test_file, "w", encoding="utf-8") as f:
                f.write("wrs_test")
            test_file.unlink(missing_ok=True)
        except OSError as e:
            return False, None, f"Cannot write to destination directory '{resolved}': {e}"
    except OSError as e:
        return False, None, f"Cannot create destination directory '{resolved}': {e}"

    # Disk space check
    if total_bytes > 0:
        has_space, free_b, req_b, space_msg = check_disk_space(resolved, required_bytes=total_bytes)
        if not has_space:
            return False, resolved, space_msg

    return True, resolved, ""


def prompt_recovery_destination(
    device: Optional[DeviceInfo],
    total_files: int,
    total_bytes: int,
    settings: Optional[dict[str, Any]] = None,
    source_paths: Optional[List[str]] = None,
    input_func: Callable[[str], str] = input,
) -> Optional[Path]:
    """Prompt user for recovery destination path with blank-default support.

    Pressing Enter without input selects the default recovery directory:
        <project_root>/recovery/<clean_device_name>/scan_<timestamp>/

    If custom path entered:
    - Expands ~ to home directory.
    - Resolves and validates absolute path.
    - Rejects unsafe paths or overlaps.
    - Never silently falls back to default on error; offers retry or default.
    """
    settings = settings or {}
    base_rec = settings.get("acquisition", {}).get("default_recovery_dir", "recovery")
    default_dest = build_default_recovery_destination(base_rec, device)

    dev_name = device.display_name if device else "Local Import / Offline"
    files_str = f"{total_files:,} files" if total_files > 0 else "All discovered candidates"
    size_str = format_bytes(total_bytes)

    while True:
        print("\n" + "=" * 56)
        print("       WRS — RECOVERY DESTINATION")
        print("=" * 56)
        print(f"Selected device : {dev_name}")
        print(f"Selected files  : {files_str}")
        print(f"Selected size   : {size_str}\n")
        print("Default recovery destination:")
        print(f"{default_dest}\n")
        print("Enter destination path, or press Enter for the default:")

        try:
            user_in = input_func("> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nDestination selection cancelled.")
            return None

        # Blank input means default
        if not user_in:
            print(f"\n[*] Using default recovery destination:\n    {default_dest}")
            return default_dest

        # Validate custom path
        valid, resolved, err_msg = validate_destination_path(
            user_in,
            total_bytes=total_bytes,
            source_paths=source_paths,
        )

        if valid and resolved is not None:
            print(f"\n[+] Custom destination confirmed:\n    {resolved}")
            return resolved

        # Invalid custom destination: explain problem and offer retry, default, or cancel
        print(f"\n[!] Invalid destination path: {err_msg}\n")
        print("Options:")
        print("  [1] Retry custom destination")
        print("  [2] Use default recovery destination")
        print("  [0] Cancel\n")

        try:
            retry_choice = input_func("Choice [1/2/0]: ").strip()
            if retry_choice == "2":
                print(f"\n[*] Selected default recovery destination:\n    {default_dest}")
                return default_dest
            elif retry_choice == "0" or retry_choice.lower() == "cancel":
                return None
            else:
                continue
        except (KeyboardInterrupt, EOFError):
            return None


def confirm_acquisition(
    device: Optional[DeviceInfo],
    total_files: int,
    total_bytes: int,
    destination: Path,
    input_func: Callable[[str], str] = input,
) -> str:
    """Prompt user with mandatory confirmation before acquiring files.

    Returns:
        'confirm'          - proceed with acquisition
        'change_dest'      - change recovery destination
        'change_selection' - modify file/category selection
        'cancel'           - cancel operation completely
    """
    dev_name = device.display_name if device else "Local Import / Offline"
    files_str = f"{total_files:,} files" if total_files > 0 else "All discovered candidates"
    size_str = format_bytes(total_bytes)

    while True:
        print("\n" + "=" * 56)
        print("       WRS — ACQUISITION CONFIRMATION")
        print("=" * 56)
        print(f"Device          : {dev_name}")
        print(f"Selected files  : {files_str}")
        print(f"Selected size   : {size_str}")
        print(f"Destination     : {destination}")
        print("Operation       : Copy selected accessible files\n")
        print("Source changes  : None intended\n")
        print("[1] Confirm and start acquisition")
        print("[2] Change destination")
        print("[3] Change file selection")
        print("[0] Cancel\n")

        try:
            opt = input_func("Choose an option: ").strip()
            if opt == "1":
                return "confirm"
            elif opt == "2":
                return "change_dest"
            elif opt == "3":
                return "change_selection"
            elif opt == "0" or opt.lower() == "cancel":
                return "cancel"
            else:
                print("Invalid choice. Please select an option between 0 and 3.")
        except (KeyboardInterrupt, EOFError):
            print("\nAcquisition confirmation cancelled.")
            return "cancel"


def display_discovery_summary(
    manifest: DiscoveryManifest,
    device: Optional[DeviceInfo] = None,
) -> None:
    """Display the structured DISCOVERY SUMMARY screen showing actual discovered locations and files."""
    dev_name = device.display_name if device else (manifest.device_name or "Local Discovery")
    status_str = manifest.status.capitalize() if manifest.status else "Discovery completed"
    dur_str = f"{manifest.duration_seconds:.2f}s"

    print("\n" + "=" * 56)
    print("       WRS — DISCOVERY SUMMARY")
    print("=" * 56)
    print(f"Device       : {dev_name}")
    print(f"Scan status  : {status_str}")
    print(f"Duration     : {dur_str}\n")
    print("DISCOVERED LOCATIONS")
    print("-" * 56)

    active_locs = [loc for loc in manifest.locations if loc.is_selected]
    if not active_locs:
        active_locs = manifest.locations

    displayed_count = 0
    for idx, loc in enumerate(active_locs, start=1):
        if loc.status in ("Not Checked", "Not Applicable") and loc.file_count == 0:
            continue
        displayed_count += 1
        cat_label = loc.name
        if loc.is_business:
            cat_label = f"{loc.name} (WhatsApp Business)"
        print(f"[{idx}] {loc.path}")
        print(f"    Category : {cat_label}")
        print(f"    Files    : {loc.file_count:,}")
        print(f"    Size     : {format_bytes(loc.total_bytes)}")
        if loc.status == "Inaccessible":
            print(f"    Status   : Inaccessible ({loc.error_message or 'Permission restricted'})")
        print()

    if displayed_count == 0:
        print("No matching WhatsApp locations were found in checked paths.\n")

    print("-" * 56)
    print(f"Total matching files : {manifest.total_files:,}")
    print(f"Total discovered size: {manifest.total_size_human}")
    print("-" * 56 + "\n")


def execute_manifest_acquisition(
    executor: AdbExecutor,
    device: Optional[DeviceInfo],
    manifest: DiscoveryManifest,
    destination_dir: Path,
    selected_categories: Optional[Set[str]] = None,
    progress_enabled: bool = True,
) -> List[VerificationRecord]:
    """Execute forensic acquisition of candidate files from DiscoveryManifest into structured recovery tree.

    Calculates SHA-256 integrity hashes, records SQLite inventory, and creates manifests and reports.
    Source files on phone or host are NEVER modified, moved, or deleted.
    """
    acq_mgr = AcquisitionManager(executor, base_recovery_dir=destination_dir.parent)
    dir_tree = acq_mgr.setup_recovery_tree(destination_dir)

    sid = manifest.session_id or generate_scan_id(device.serial if device else "local")
    case_mgr = CaseManager(destination_dir)
    case_mgr.log_event(sid, "ACQUISITION_INITIALIZED", {
        "device": device.display_name if device else "Local Discovery",
        "total_files": manifest.total_files,
        "total_bytes": manifest.total_bytes,
        "destination": str(destination_dir),
    })

    # Prepare SQLite inventory database
    inv_db = ScanInventoryDB(dir_tree["metadata"] / "inventory.db")

    # Filter target candidates
    target_cands = manifest.candidates
    if selected_categories is not None:
        target_cands = [
            c for c in manifest.candidates
            if c.category in selected_categories
            or any(cat.upper() in c.category.upper() for cat in selected_categories)
        ]

    records: List[VerificationRecord] = []
    print("\n" + "=" * 56)
    print("  ACQUISITION IN PROGRESS")
    print("=" * 56)
    print(f"  Target Destination : {destination_dir}")
    print(f"  Candidate Scope    : {len(target_cands)} item(s)")
    print("-" * 56)

    success_cnt = 0
    fail_cnt = 0
    skip_cnt = 0

    for idx, cand in enumerate(target_cands, start=1):
        # Resolve target subdirectory based on category
        cat_lower = cand.category.lower()
        if "data" in cat_lower or "back" in cat_lower:
            dest_folder = dir_tree["databases"]
        elif "image" in cat_lower or "photo" in cat_lower:
            dest_folder = dir_tree["images"]
        elif "video" in cat_lower or "gif" in cat_lower:
            dest_folder = dir_tree["videos"]
        elif "audio" in cat_lower or "voice" in cat_lower:
            dest_folder = dir_tree["audio"]
        elif "doc" in cat_lower:
            dest_folder = dir_tree["documents"]
        else:
            dest_folder = dir_tree["root"] / sanitize_filename(cand.category)
            dest_folder.mkdir(parents=True, exist_ok=True)

        target_file_path = dest_folder / sanitize_filename(cand.filename)

        print(f"[{idx}/{len(target_cands)}] Acquiring: {cand.filename} ({cand.size_human})...")

        if cand.is_device and device is not None:
            # ADB Pull from Android device
            pull_res = executor.run_cmd(["pull", cand.path, str(target_file_path)], serial=device.serial, timeout=120)
            if pull_res.returncode == 0 and target_file_path.exists():
                local_h, local_size, hash_err = hash_local_file(target_file_path)
                rec = VerificationRecord(
                    source_path=cand.path,
                    destination_path=str(target_file_path),
                    expected_size=cand.size_bytes,
                    acquired_size=local_size,
                    source_sha256=None,
                    destination_sha256=local_h,
                    status=STATUS_VERIFIED,
                    timestamp=format_timestamp(time.time()),
                    error_message=hash_err,
                )
                records.append(rec)
                success_cnt += 1
                inv_db.insert_record(
                    InventoryRecord(
                        scan_id=sid,
                        device_id=device.serial,
                        source_path=cand.path,
                        relative_path=cand.filename,
                        filename=cand.filename,
                        extension=os.path.splitext(cand.filename)[1],
                        category=cand.category,
                        size_bytes=local_size,
                        acquisition_status=STATUS_ACQUIRED,
                        sha256=local_h,
                        destination_path=str(target_file_path),
                    )
                )
            else:
                err_msg = pull_res.stderr.strip() or "ADB pull failed"
                records.append(
                    VerificationRecord(
                        source_path=cand.path,
                        destination_path=str(target_file_path),
                        expected_size=cand.size_bytes,
                        acquired_size=0,
                        source_sha256=None,
                        destination_sha256=None,
                        status=STATUS_FAILED,
                        timestamp=format_timestamp(time.time()),
                        error_message=err_msg,
                    )
                )
                fail_cnt += 1
        else:
            # Local file copy
            src_p = Path(cand.path)
            if src_p.exists() and src_p.is_file():
                try:
                    shutil.copy2(src_p, target_file_path)
                    local_h, local_size, hash_err = hash_local_file(target_file_path)
                    rec = VerificationRecord(
                        source_path=str(src_p),
                        destination_path=str(target_file_path),
                        expected_size=cand.size_bytes,
                        acquired_size=local_size,
                        source_sha256=None,
                        destination_sha256=local_h,
                        status=STATUS_VERIFIED,
                        timestamp=format_timestamp(time.time()),
                        error_message=hash_err,
                    )
                    records.append(rec)
                    success_cnt += 1
                except Exception as e:
                    records.append(
                        VerificationRecord(
                            source_path=str(src_p),
                            destination_path=str(target_file_path),
                            expected_size=cand.size_bytes,
                            acquired_size=0,
                            source_sha256=None,
                            destination_sha256=None,
                            status=STATUS_FAILED,
                            timestamp=format_timestamp(time.time()),
                            error_message=str(e),
                        )
                    )
                    fail_cnt += 1
            else:
                skip_cnt += 1

    # Save acquisition manifest JSON in manifests/ and metadata/
    manifest_data = [asdict(r) for r in records]
    for folder in [dir_tree["manifests"], dir_tree["metadata"]]:
        with open(folder / "acquisition_manifest.json", "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)

    print("\n" + "=" * 56)
    print("  ACQUISITION COMPLETED")
    print("=" * 56)
    print(f"  Successfully Acquired : {success_cnt} files")
    print(f"  Failed Acquisitions   : {fail_cnt} files")
    print(f"  Skipped Items         : {skip_cnt} files")
    print(f"  Destination Root      : {destination_dir}")
    print(f"  Manifest Path         : {dir_tree['manifests'] / 'acquisition_manifest.json'}")
    print("=" * 56 + "\n")
    return records


def discovery_summary_workflow(
    manifest: DiscoveryManifest,
    executor: AdbExecutor,
    device: Optional[DeviceInfo],
    settings: dict[str, Any],
    active_categories: List[str],
    input_func: Callable[[str], str] = input,
) -> Optional[DiscoveryManifest]:
    """Interactive Discovery Summary workflow presenting review, selection, and acquisition options."""
    current_categories = list(active_categories)

    while True:
        display_discovery_summary(manifest, device)
        print("[1] Review discovered files")
        print("[2] Select files or categories to acquire")
        print("[3] Acquire selected files")
        print("[4] Return to main menu\n")

        try:
            choice = input_func("Select an option [1-4]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nReturning to main menu.")
            return manifest

        if choice == "1":
            # Review discovered files
            print("\n" + "=" * 56)
            print("       REVIEW DISCOVERED FILES")
            print("=" * 56)
            dbs = [c for c in manifest.candidates if c.category == "DATABASES"]
            print(f"\nDATABASES IDENTIFIED ({len(dbs)}):")
            for idx, d in enumerate(dbs, start=1):
                enc_tag = "[ENCRYPTED]" if d.is_encrypted else "[READABLE]"
                print(f"  [{idx}] {d.filename:<40} {d.size_human:>10}  {enc_tag} ({d.db_format})")
                print(f"      Path: {d.path}")

            other_cands = [c for c in manifest.candidates if c.category != "DATABASES"]
            print(f"\nMEDIA & ATTACHMENT CATEGORIES ({len(other_cands)}):")
            for idx, m in enumerate(other_cands, start=1):
                print(f"  [{idx}] [{m.category}] {m.filename} -> {m.details or m.path}")

            try:
                input_func("\nPress Enter to return to Discovery Summary...")
            except (KeyboardInterrupt, EOFError):
                pass

        elif choice == "2":
            # Select files or categories to acquire
            print("\nCurrent Active Categories:")
            print(f"  {', '.join(current_categories) if current_categories else 'All Supported Data'}\n")
            print("Select categories to filter acquisition:")
            print("  [1] All Supported Data")
            print("  [2] Chat Databases & Backups")
            print("  [3] Pictures & Photos")
            print("  [4] Videos")
            print("  [5] Audio & Voice Notes")
            print("  [6] Documents")
            print("  [0] Keep current selection\n")

            try:
                cat_pick = input_func("Choice [1-6 / 0]: ").strip()
                if cat_pick == "1":
                    current_categories = ["All Supported Data"]
                elif cat_pick == "2":
                    current_categories = ["Databases", "Backups"]
                elif cat_pick == "3":
                    current_categories = ["Images"]
                elif cat_pick == "4":
                    current_categories = ["Videos"]
                elif cat_pick == "5":
                    current_categories = ["Audio", "Voice Notes"]
                elif cat_pick == "6":
                    current_categories = ["Documents"]
                print(f"[+] Acquisition filter set to: {', '.join(current_categories)}")
            except (KeyboardInterrupt, EOFError):
                pass

        elif choice == "3":
            # Acquire selected files
            if manifest.total_files == 0 and not manifest.candidates:
                print("\n[!] No matching files discovered to acquire.")
                print("    Please run a Full Scan or select a location with files.\n")
                continue

            cats_set = set(current_categories) if current_categories and "All Supported Data" not in current_categories else None
            source_paths = [loc.path for loc in manifest.locations]

            while True:
                dest_dir = prompt_recovery_destination(
                    device=device,
                    total_files=manifest.total_files,
                    total_bytes=manifest.total_bytes,
                    settings=settings,
                    source_paths=source_paths,
                    input_func=input_func,
                )

                if not dest_dir:
                    print("[*] Acquisition cancelled.")
                    break

                decision = confirm_acquisition(
                    device=device,
                    total_files=manifest.total_files,
                    total_bytes=manifest.total_bytes,
                    destination=dest_dir,
                    input_func=input_func,
                )

                if decision == "confirm":
                    execute_manifest_acquisition(
                        executor=executor,
                        device=device,
                        manifest=manifest,
                        destination_dir=dest_dir,
                        selected_categories=cats_set,
                    )
                    break
                elif decision == "change_dest":
                    continue
                elif decision == "change_selection":
                    break
                else:
                    print("[*] Acquisition cancelled by user. Zero files were copied.")
                    break

        elif choice == "4" or choice.lower() == "back" or choice == "0":
            return manifest
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")


def scan_and_recovery_wizard_menu(
    executor: AdbExecutor,
    selected_dev: Optional[DeviceInfo],
    settings: dict[str, Any],
    active_categories: List[str],
    discovery_manifest: Optional[DiscoveryManifest] = None,
    input_func: Callable[[str], str] = input,
) -> Optional[DiscoveryManifest]:
    """Main menu Option [1] wizard — Scan and Recovery Wizard.

    Provides user-controlled scanning choices:
    [1] Full Scan
    [2] Targeted Scan
    [3] Scan Known WhatsApp Locations
    [4] Scan Existing WRS Recovery Directories
    [5] Inspect Previous Scan Results
    [0] Back
    """
    dev_name = selected_dev.display_name if selected_dev else "None Connected"
    scan_status = "Ready" if (selected_dev and selected_dev.is_accessible) else "Offline Mode"

    while True:
        print("\n" + "=" * 56)
        print("       WRS — SCAN AND RECOVERY WIZARD")
        print("=" * 56)
        print(f"Device       : {dev_name}")
        print(f"Scan status  : {scan_status}\n")
        print("SELECT AN OPERATION\n")
        print("[1] Full Scan")
        print("    Scan prioritized, relevant accessible locations for")
        print("    all supported WhatsApp data categories.\n")
        print("[2] Targeted Scan")
        print("    Scan only selected locations or data categories.\n")
        print("[3] Scan Known WhatsApp Locations")
        print("    Inspect standard WhatsApp database and media paths.\n")
        print("[4] Scan Existing WRS Recovery Directories")
        print("    Find previously acquired data and database candidates.\n")
        print("[5] Inspect Previous Scan Results")
        print("    Review saved discovery results without rescanning.\n")
        print("[0] Back\n")

        try:
            choice = input_func("Select an operation [0-5]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nReturning to main menu.")
            return discovery_manifest

        if choice == "0" or choice.lower() == "back":
            return discovery_manifest

        elif choice == "1":
            # [1] Full Scan
            print("\n" + "=" * 56)
            print("       WRS — FULL SCAN SCOPE SUMMARY")
            print("=" * 56)
            print(f"Device      : {dev_name}")
            print("Priority 1  : WRS recovery directory & previous manifests")
            print("Priority 2  : WhatsApp database and backup locations")
            print("Priority 3  : WhatsApp media storage (Images, Video, Audio, Docs)")
            print("Priority 4  : WhatsApp Business locations (if applicable)")
            print("Priority 5  : User-configured local search paths")
            print("Priority 6  : Extended accessible storage paths (with consent)\n")
            print("This scan inspects relevant accessible locations.")
            print("Zero files will be modified, moved, or deleted on the device.\n")

            try:
                proceed = input_func("Proceed with Full Scan? [y/N]: ").strip().lower()
                if proceed not in ("y", "yes"):
                    print("[*] Full scan cancelled.")
                    continue
            except (KeyboardInterrupt, EOFError):
                print("\nFull scan cancelled.")
                continue

            engine = PriorityDiscoveryEngine(executor=executor, settings=settings)
            manifest = run_animated_priority_discovery(executor, selected_dev, settings)
            discovery_manifest = discovery_summary_workflow(
                manifest=manifest,
                executor=executor,
                device=selected_dev,
                settings=settings,
                active_categories=active_categories,
                input_func=input_func,
            )

        elif choice == "2":
            # [2] Targeted Scan
            print("\n" + "=" * 56)
            print("       WRS — TARGETED SCAN CONFIGURATION")
            print("=" * 56)
            print("Select target locations to inspect:")
            print("  [1] WhatsApp Messenger only (/sdcard/Android/media/com.whatsapp/...)")
            print("  [2] WhatsApp Business only (/sdcard/Android/media/com.whatsapp.w4b/...)")
            print("  [3] Custom local or Android path")
            print("  [0] Cancel\n")

            try:
                tgt_loc = input_func("Select location [1-3 / 0]: ").strip()
                if tgt_loc == "0" or not tgt_loc:
                    continue

                custom_paths: List[str] = []
                if tgt_loc == "1":
                    custom_paths = ["/sdcard/Android/media/com.whatsapp/WhatsApp/"]
                elif tgt_loc == "2":
                    custom_paths = ["/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/"]
                elif tgt_loc == "3":
                    p_in = input_func("Enter custom path to inspect: ").strip()
                    if p_in:
                        custom_paths = [p_in]
                    else:
                        continue

                manifest = run_animated_priority_discovery(executor, selected_dev, settings)
                discovery_manifest = discovery_summary_workflow(
                    manifest=manifest,
                    executor=executor,
                    device=selected_dev,
                    settings=settings,
                    active_categories=active_categories,
                    input_func=input_func,
                )
            except (KeyboardInterrupt, EOFError):
                continue

        elif choice == "3":
            # [3] Scan Known WhatsApp Locations
            if not selected_dev or not selected_dev.is_accessible:
                print("\n[!] Scanning known WhatsApp locations requires an accessible Android device.")
                print("    Please connect and authorize a device, then retry.\n")
                continue

            manifest = run_animated_priority_discovery(executor, selected_dev, settings)
            discovery_manifest = discovery_summary_workflow(
                manifest=manifest,
                executor=executor,
                device=selected_dev,
                settings=settings,
                active_categories=active_categories,
                input_func=input_func,
            )

        elif choice == "4":
            # [4] Scan Existing WRS Recovery Directories
            rec_root = settings.get("acquisition", {}).get("default_recovery_dir", "recovery")
            engine = PriorityDiscoveryEngine(executor=executor, settings=settings)
            # Offline discovery of Priority 1
            manifest = engine.run_priority_discovery(device=None)
            discovery_manifest = discovery_summary_workflow(
                manifest=manifest,
                executor=executor,
                device=selected_dev,
                settings=settings,
                active_categories=active_categories,
                input_func=input_func,
            )

        elif choice == "5":
            # [5] Inspect Previous Scan Results
            rec_root = settings.get("acquisition", {}).get("default_recovery_dir", "recovery")
            prev_manifest = DiscoveryManifest.load_latest(rec_root)
            if prev_manifest:
                prev_manifest.revalidate_candidates()
                print(f"\n[+] Loaded previous scan session '{prev_manifest.session_id}' from {rec_root}.")
                discovery_manifest = discovery_summary_workflow(
                    manifest=prev_manifest,
                    executor=executor,
                    device=selected_dev,
                    settings=settings,
                    active_categories=active_categories,
                    input_func=input_func,
                )
            else:
                print("\n[!] No previous scan manifest found in recovery directory.")
                print("    Please run a Full Scan or Targeted Scan first.\n")

        else:
            print("Invalid choice. Please enter a number between 0 and 5.")
