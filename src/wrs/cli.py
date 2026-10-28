"""Interactive CLI interface and command-line argument dispatcher for WRS.

Provides rich terminal presentation, device selection menus, pre-acquisition
previews, explicit confirmation safeguards, and headless automation.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set

from . import __version__
from .acquisition import AcquisitionManager, AcquisitionPreview
from .case import CaseManager, generate_scan_id
from .categorizer import ALL_CATEGORIES, CATEGORY_DIR_NAMES
from .chat import ChatReconstructionEngine, Conversation
from .database import WhatsAppDatabaseAnalyzer
from .device import AdbExecutor, DeviceInfo
from .discovery import DiscoveredLocation, StorageDiscovery
from .duplicate import DuplicateDetector
from .exporter import ChatExporter, ZipPackager
from .hashing import STATUS_VERIFIED
from .inventory import ScanInventoryDB
from .media import MediaAssociator
from .reporting import ReportGenerator, verify_recovery_directory
from .scanner import FileScanner, ScanResult
from .utils import (
    check_disk_space,
    format_bytes,
    format_timestamp,
    load_settings,
    sanitize_device_name,
    sanitize_filename,
)

logger = logging.getLogger("wrs.cli")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None  # type: ignore


def print_banner(executor: AdbExecutor) -> None:
    """Display professional terminal banner."""
    adb_ok, adb_msg = executor.get_adb_version()
    adb_status = f"Connected ({adb_msg})" if adb_ok else f"Unavailable ({adb_msg})"
    now_str = format_timestamp()

    if HAS_RICH and console:
        title = Text("WRS — WhatsApp Recovery Scanner", style="bold cyan")
        subtitle = Text("Forensic Acquisition & Preservation Utility\n", style="dim")
        body = (
            f"[bold green]●[/bold green] Processing Mode: [bold]100% Local Execution (Zero Network / Cloud)[/bold]\n"
            f"[bold blue]●[/bold blue] ADB Status: [white]{adb_status}[/white]\n"
            f"[bold magenta]●[/bold magenta] Version: [white]v{__version__}[/white] | Timestamp: [white]{now_str}[/white]"
        )
        panel = Panel(body, title=title, subtitle=subtitle, border_style="cyan")
        console.print(panel)
    else:
        print("=" * 72)
        print(f"  WRS — WhatsApp Recovery Scanner (v{__version__})")
        print("  Forensic Acquisition & Preservation Utility")
        print("  Processing: 100% Local Execution — Zero Network / Cloud Telemetry")
        print(f"  ADB Status: {adb_status}")
        print(f"  Timestamp : {now_str}")
        print("=" * 72)


def select_device_interactive(executor: AdbExecutor) -> Optional[DeviceInfo]:
    """Present a numbered list of connected devices for explicit user selection."""
    devices = executor.list_devices()

    if not devices:
        print("\n[!] No connected Android devices detected via ADB.")
        print("    Troubleshooting steps:")
        print("    1. Connect device via USB and ensure Developer Options is enabled.")
        print("    2. Enable 'USB Debugging' in Developer Options.")
        print("    3. If prompted on device, check 'Always allow' and tap OK.")
        print("    4. Run 'adb devices' in terminal to verify connection.\n")
        return None

    if len(devices) == 1:
        dev = devices[0]
        details = executor.get_device_details(dev.serial)
        print(f"\n[+] Detected single device: {details.display_name} ({details.serial}) - State: {details.state}")
        if details.error_message:
            print(f"[!] Warning: {details.error_message}")
        return details

    print("\n--- Connected Android Devices ---")
    for idx, d in enumerate(devices, start=1):
        status_str = f"[{d.state.upper()}]"
        print(f"  [{idx}] {d.serial} — {d.display_name} {status_str}")

    while True:
        try:
            choice = input(f"\nSelect device [1-{len(devices)}] or 'c' to cancel: ").strip().lower()
            if choice == "c":
                return None
            idx = int(choice)
            if 1 <= idx <= len(devices):
                selected = devices[idx - 1]
                return executor.get_device_details(selected.serial)
            print("Invalid selection. Please choose a valid number.")
        except (ValueError, KeyboardInterrupt):
            print("\nSelection cancelled.")
            return None


def select_location_interactive(locations: List[DiscoveredLocation]) -> Optional[List[DiscoveredLocation]]:
    """Prompt user to choose which discovered WhatsApp locations to scan."""
    if not locations:
        print("\n[!] No accessible WhatsApp storage locations discovered on device.")
        return None

    print("\n--- Discovered WhatsApp Storage Locations ---")
    for idx, loc in enumerate(locations, start=1):
        print(f"  [{idx}] {loc.display_label}")
        if loc.aliases:
            for alias in loc.aliases:
                print(f"       ↳ Alias normalized: {alias}")

    print("\nSelection options:")
    print("  [1] Scan all unique accessible locations")
    print("  [2] Select specific location")
    print("  [3] Cancel")

    while True:
        try:
            choice = input("\nEnter choice [1-3]: ").strip()
            if choice == "1":
                return [loc for loc in locations if loc.is_readable]
            elif choice == "2":
                loc_idx = int(input(f"Enter location number [1-{len(locations)}]: ").strip())
                if 1 <= loc_idx <= len(locations):
                    target = locations[loc_idx - 1]
                    if not target.is_readable:
                        print(f"[!] Selected location is marked unreadable: {target.error_message}")
                        return None
                    return [target]
            elif choice == "3" or choice.lower() == "c":
                return None
            print("Invalid option.")
        except (ValueError, KeyboardInterrupt):
            return None


def display_preview(preview: AcquisitionPreview) -> None:
    """Display the pre-acquisition preview table."""
    print("\n" + "=" * 72)
    print("  WRS — ACQUISITION PREVIEW")
    print("=" * 72)
    print(f"  Scan ID          : {preview.scan_id}")
    print(f"  Device           : {preview.device_name}")
    print(f"  Serial           : {preview.serial}")
    print(f"  Android Version  : {preview.android_version}")
    print(f"  Scan Date        : {preview.scan_date}")
    print(f"  Selected Location: {', '.join(preview.selected_locations)}")
    print("-" * 72)

    if HAS_RICH and console:
        tbl = Table(title="Categorized File Inventory", show_header=True, header_style="bold magenta")
        tbl.add_column("Category", style="cyan", width=20)
        tbl.add_column("Files", justify="right", style="green", width=12)
        tbl.add_column("Total Size", justify="right", style="yellow", width=16)

        for cat in ALL_CATEGORIES:
            cnt = preview.category_counts.get(cat, 0)
            sz = preview.category_bytes.get(cat, 0)
            if cnt > 0:
                tbl.add_row(cat, str(cnt), format_bytes(sz))

        tbl.add_row("TOTAL", str(preview.total_files), format_bytes(preview.total_bytes), style="bold white")
        console.print(tbl)
    else:
        print(f"  {'CATEGORY':<20} {'FILES':>10}   {'TOTAL SIZE':>15}")
        print("  " + "-" * 50)
        for cat in ALL_CATEGORIES:
            cnt = preview.category_counts.get(cat, 0)
            sz = preview.category_bytes.get(cat, 0)
            if cnt > 0:
                print(f"  {cat:<20} {cnt:>10}   {format_bytes(sz):>15}")
        print("  " + "-" * 50)
        print(f"  {'TOTAL':<20} {preview.total_files:>10}   {format_bytes(preview.total_bytes):>15}\n")

    print(f"  Unreadable Files       : {preview.unreadable_files}")
    print(f"  Skipped Files          : {preview.skipped_files}")
    print(f"  Database/Backup Assets : {preview.database_backup_candidates}")
    print(f"  Duplicate Candidates   : {preview.duplicate_candidates}")
    if preview.excluded_duplicates_count > 0:
        print(f"  Excluded Duplicates    : {preview.excluded_duplicates_count} ({format_bytes(preview.excluded_duplicates_bytes)} saved)")
    print(f"  Destination Directory  : {preview.destination_path}")
    print(f"  Storage Assessment     : {preview.space_message}")
    print("=" * 72 + "\n")


def ask_acquisition_confirmation(dest_path: Path) -> bool:
    """Prompt user with mandatory confirmation before acquiring files."""
    print("The scanner is ready to copy the selected files to:")
    print(f"  {dest_path}")
    print("\nNo source files will be deleted or modified on the Android device.\n")

    try:
        ans = input("Proceed with acquisition? [y/N]: ").strip().lower()
        return ans in ("y", "yes")
    except KeyboardInterrupt:
        print("\nAcquisition aborted by user.")
        return False


def select_acquisition_scope_interactive(
    preview: AcquisitionPreview,
    acq_manager: AcquisitionManager,
    dev: DeviceInfo,
    scan_result: ScanResult,
    override_output: Optional[Path],
) -> Tuple[Optional[AcquisitionPreview], Optional[Set[str]], Optional[Set[str]], bool]:
    """Provide interactive selection options and dynamically recalculate preview.

    Returns (updated_preview, selected_categories, excluded_paths, continue_acquisition).
    """
    cur_preview = preview
    selected_cats: Optional[Set[str]] = None
    excluded_paths: Optional[Set[str]] = None

    while True:
        display_preview(cur_preview)
        print("Acquisition Selection Options:")
        print("  [1] Proceed with current selection")
        print("  [2] Select specific categories")
        print("  [3] Exclude duplicate candidate files")
        print("  [4] Export inventory catalog only")
        print("  [5] Cancel")

        try:
            opt = input("\nEnter option [1-5]: ").strip()
            if opt == "1":
                return cur_preview, selected_cats, excluded_paths, True
            elif opt == "2":
                print("\nAvailable Categories:")
                for idx, c in enumerate(ALL_CATEGORIES, start=1):
                    print(f"  [{idx}] {c} ({cur_preview.category_counts.get(c, 0)} files)")
                cat_input = input("\nEnter category numbers separated by commas (e.g. 1, 2, 3): ").strip()
                if cat_input:
                    chosen: Set[str] = set()
                    for token in cat_input.split(","):
                        try:
                            n = int(token.strip())
                            if 1 <= n <= len(ALL_CATEGORIES):
                                chosen.add(ALL_CATEGORIES[n - 1])
                        except ValueError:
                            pass
                    if chosen:
                        selected_cats = chosen
                        cur_preview = acq_manager.generate_preview(
                            device=dev,
                            scan_result=scan_result,
                            selected_categories=selected_cats,
                            custom_destination=override_output,
                            excluded_paths=excluded_paths,
                            scan_id=cur_preview.scan_id,
                        )
            elif opt == "3":
                print("\n[*] Analyzing duplicate content candidates across inventory...")
                dup_groups = DuplicateDetector.identify_duplicates_from_records(scan_result.files)
                new_excluded: Set[str] = set()
                for g in dup_groups.values():
                    new_excluded.update(g.duplicate_paths)
                excluded_paths = new_excluded
                print(f"[+] Identified {len(dup_groups)} duplicate groups with {len(excluded_paths)} redundant copies.")
                cur_preview = acq_manager.generate_preview(
                    device=dev,
                    scan_result=scan_result,
                    selected_categories=selected_cats,
                    custom_destination=override_output,
                    excluded_paths=excluded_paths,
                    scan_id=cur_preview.scan_id,
                )
            elif opt == "4":
                return cur_preview, selected_cats, excluded_paths, False
            elif opt in ("5", "c"):
                return None, None, None, False
        except (ValueError, KeyboardInterrupt):
            return None, None, None, False


def run_interactive_workflow(
    executor: AdbExecutor,
    acquire_mode: bool = False,
    override_serial: Optional[str] = None,
    override_output: Optional[Path] = None,
    unattended: bool = False,
    selected_cats: Optional[Set[str]] = None,
    exclude_duplicates: bool = False,
    key_path: Optional[Path] = None,
) -> None:
    """Execute complete workflow: Discovery -> Inventory -> Preview -> Confirmation -> Acquisition -> Report."""
    print_banner(executor)

    # 1. Device Selection
    if override_serial:
        dev = executor.get_device_details(override_serial)
    else:
        dev = select_device_interactive(executor)

    if not dev:
        return

    if not dev.is_accessible:
        print(f"\n[!] Cannot proceed: Device state is '{dev.state}'.")
        if dev.error_message:
            print(f"    {dev.error_message}")
        return

    # 2. Storage Discovery
    print(f"\n[*] Discovering WhatsApp storage on {dev.display_name} ({dev.serial})...")
    discovery = StorageDiscovery(executor)
    locations = discovery.discover_locations(dev)

    if not locations:
        print("[!] No accessible WhatsApp storage locations discovered.")
        return

    selected_locs = [loc for loc in locations if loc.is_readable] if unattended else select_location_interactive(locations)
    if not selected_locs:
        print("[*] Operation cancelled.")
        return

    # 3. Scanning & Inventory
    scanner = FileScanner(executor)
    acq_manager = AcquisitionManager(executor, base_recovery_dir=override_output or "recovery")

    for loc in selected_locs:
        print(f"\n[*] Scanning location: {loc.path}")
        print("    Enumerating files without modification...")

        def scan_progress(phase: str, count: int, total: int, elapsed: float) -> None:
            sys.stdout.write(f"\r    ↳ {phase}: {count} files found ({elapsed:.1f}s)")
            sys.stdout.flush()

        scan_result = scanner.scan_location(dev.serial, loc, progress_cb=scan_progress)
        print(f"\n[+] Scan completed: {scan_result.total_files} files ({format_bytes(scan_result.total_bytes)})")

        # 4. Mandatory Pre-Acquisition Preview
        preview = acq_manager.generate_preview(
            device=dev,
            scan_result=scan_result,
            selected_categories=selected_cats,
            custom_destination=override_output,
        )

        excluded_paths: Optional[Set[str]] = None
        if exclude_duplicates:
            dup_groups = DuplicateDetector.identify_duplicates_from_records(scan_result.files)
            excluded_paths = set()
            for g in dup_groups.values():
                excluded_paths.update(g.duplicate_paths)
            preview = acq_manager.generate_preview(
                device=dev,
                scan_result=scan_result,
                selected_categories=selected_cats,
                custom_destination=override_output,
                excluded_paths=excluded_paths,
                scan_id=preview.scan_id,
            )

        if acquire_mode and not unattended:
            scope_preview, updated_cats, updated_excluded, proceed = select_acquisition_scope_interactive(
                preview, acq_manager, dev, scan_result, override_output
            )
            if not proceed or not scope_preview:
                if scope_preview and not proceed:
                    acquire_mode = False
                else:
                    print("[*] Operation cancelled.")
                    return
            else:
                preview = scope_preview
                selected_cats = updated_cats
                excluded_paths = updated_excluded
        else:
            display_preview(preview)

        # 5. Check Disk Space
        if not preview.has_sufficient_space:
            print("[!] HALTING: Target destination does not have sufficient free disk space.")
            print(f"    {preview.space_message}")
            return

        if not acquire_mode:
            # Inventory-only mode: save inventory metadata and generate report
            print("[*] Inventory-only scan requested. Saving scan catalog...")
            dest_tree = acq_manager.setup_recovery_tree(preview.destination_path)
            rep_gen = ReportGenerator(dev, scan_result, output_dir=dest_tree["reports"])
            h, c, j = rep_gen.generate_all()
            print(f"[+] Reports generated:\n    HTML: {h}\n    CSV : {c}\n    JSON: {j}")
            continue

        # 6. Explicit Acquisition Confirmation
        confirmed = unattended
        if not confirmed:
            confirmed = ask_acquisition_confirmation(preview.destination_path)

        if not confirmed:
            print("[*] Acquisition cancelled by user. No files were copied.")
            return

        # 7. Safe File Acquisition
        print(f"\n[*] Starting forensic acquisition into: {preview.destination_path}")
        last_print = [0.0]

        def acq_progress(
            completed: int,
            remaining: int,
            trans_b: int,
            tot_b: int,
            cur_fn: str,
            stat: str,
            elapsed: float,
        ) -> None:
            now = time.time()
            if now - last_print[0] > 0.1 or remaining == 0:
                last_print[0] = now
                speed = trans_b / elapsed if elapsed > 0 else 0
                pct = (trans_b / tot_b * 100) if tot_b > 0 else 0
                fn_trunc = cur_fn[:25] + "..." if len(cur_fn) > 28 else cur_fn
                sys.stdout.write(
                    f"\r    [{pct:5.1f}%] Completed: {completed} | Remaining: {remaining} | "
                    f"Speed: {format_bytes(int(speed))}/s | Status: {stat:<8} | File: {fn_trunc:<28}"
                )
                sys.stdout.flush()

        try:
            records = acq_manager.acquire_files(
                device=dev,
                scan_result=scan_result,
                destination_dir=preview.destination_path,
                selected_categories=selected_cats,
                progress_cb=acq_progress,
                excluded_paths=excluded_paths,
                scan_id=preview.scan_id,
            )
            print("\n[+] Acquisition phase finished.")
        except KeyboardInterrupt:
            print("\n[!] Acquisition interrupted! Partial progress and manifest preserved safely.")
            return

        # 8. Post-Acquisition Analysis & Chat Reconstruction
        dest_tree = acq_manager.setup_recovery_tree(preview.destination_path)
        analyzed_dbs = []
        conversations = []

        # Check for acquired databases
        db_dir = dest_tree.get("Databases", preview.destination_path / "Databases")
        if db_dir.exists():
            for db_file in db_dir.glob("*"):
                if db_file.is_file():
                    db_meta = WhatsAppDatabaseAnalyzer.identify_database(db_file)
                    analyzed_dbs.append(db_meta)

                    # If SQLite, attempt chat extraction
                    if db_meta.is_sqlite and db_meta.table_count > 0:
                        raw_msgs = WhatsAppDatabaseAnalyzer.extract_raw_messages(db_file)
                        if raw_msgs:
                            convs = ChatReconstructionEngine.reconstruct_conversations(raw_msgs)
                            # Associate media
                            all_acquired = [
                                p for root, _, files in os.walk(preview.destination_path)
                                for p in [Path(root) / fn for fn in files]
                            ]
                            MediaAssociator.associate_media(convs, all_acquired)
                            conversations.extend(convs)

                            # Export chats automatically
                            chats_dir = preview.destination_path / "chats"
                            for c in convs:
                                safe_conv_name = sanitize_filename(c.display_name)[:30]
                                ChatExporter.export_conversation_txt(c, chats_dir / f"{safe_conv_name}.txt")
                                ChatExporter.export_conversation_html(c, chats_dir / f"{safe_conv_name}.html")
                                ChatExporter.export_conversation_json(c, chats_dir / f"{safe_conv_name}.json")
                                ChatExporter.export_conversation_csv(c, chats_dir / f"{safe_conv_name}.csv")

        # 9. Report Generation
        rep_gen = ReportGenerator(
            device=dev,
            scan_result=scan_result,
            records=records,
            output_dir=dest_tree["reports"],
            conversations=conversations,
            database_metadata=analyzed_dbs,
        )
        h, c, j = rep_gen.generate_all()

        # 10. Summary
        verified_cnt = sum(1 for r in records if r.status == STATUS_VERIFIED)
        print("\n" + "=" * 72)
        print("  ACQUISITION SUMMARY")
        print("=" * 72)
        print(f"  Target Destination : {preview.destination_path}")
        print(f"  Total Acquired     : {len(records)} files")
        print(f"  SHA-256 Verified   : {verified_cnt} files")
        if conversations:
            print(f"  Chats Reconstructed: {len(conversations)} conversations")
        print(f"  HTML Report        : {h}")
        print(f"  CSV Report         : {c}")
        print(f"  JSON Report        : {j}")
        print("=" * 72 + "\n")


def show_recovery_info() -> None:
    """Display information about supported storage locations and forensic boundaries."""
    print("\n" + "=" * 72)
    print("  WRS — SUPPORTED RECOVERY LOCATIONS & FORENSIC BOUNDARIES")
    print("=" * 72)
    print("""
  1. Accessible WhatsApp Storage Locations (Standard Android):
     • /sdcard/Android/media/com.whatsapp/WhatsApp/
     • /storage/emulated/0/Android/media/com.whatsapp/WhatsApp/
     • /sdcard/WhatsApp/
     • /storage/emulated/0/WhatsApp/

  2. Accessible WhatsApp Business Storage Locations:
     • /sdcard/Android/media/com.whatsapp.w4b/WhatsApp/
     • /storage/emulated/0/Android/media/com.whatsapp.w4b/WhatsApp/

  3. Removable / External MicroSD Volumes:
     • /storage/XXXX-XXXX/Android/media/com.whatsapp/WhatsApp/
     • /storage/XXXX-XXXX/WhatsApp/

  4. WhatsApp Cryptographic Boundaries:
     • Encrypted databases (.crypt14 / .crypt15) require the AES-GCM
       decryption key located at: /data/data/com.whatsapp/files/key
     • Unrooted ADB cannot access /data/data/ due to Android UID sandboxing.
     • WRS preserves encrypted databases with raw byte accuracy so that
       they can be decrypted if keys are legally obtained through
       physical/root extractions.

  5. Chat Deletion Notice:
     • WRS extracts surviving databases, dated backups, and media from device storage.
     • Deleted chats that were purged before backup creation cannot be recovered
       by standard storage enumeration.
""")
    print("=" * 72 + "\n")


def inspect_target(target: Path, key_path: Optional[Path] = None) -> None:
    """Inspect an acquired WhatsApp database or recovery folder."""
    target = target.resolve()
    if not target.exists():
        print(f"[!] Target path does not exist: {target}")
        return

    if target.is_dir():
        print("\n" + "=" * 72)
        print(f"  INSPECTING RECOVERY DIRECTORY: {target.name}")
        print("=" * 72)
        manifest_p = target / "metadata" / "acquisition_manifest.json"
        if manifest_p.exists():
            audit = verify_recovery_directory(target)
            print(f"  Manifest Found     : {manifest_p}")
            print(f"  Total Tracked Files: {audit['total']}")
            print(f"  Intact & Verified  : {audit['verified_count']}")
            print(f"  Mismatched / Fail  : {audit['mismatch_count']}")
            print(f"  Missing Files      : {audit['missing_count']}")
            status_msg = "PASSED (Fully Intact)" if audit['is_fully_intact'] else "INTEGRITY WARNINGS DETECTED"
            print(f"  Integrity Status   : {status_msg}")
        else:
            print("  [!] No acquisition_manifest.json found in directory metadata.")

        # Check for databases in Databases/ subfolder or root
        db_candidates = list(target.glob("Databases/*")) + list(target.glob("*.db*"))
        db_files = [f for f in db_candidates if f.is_file() and not f.name.endswith("-journal") and not f.name.endswith("-wal")]
        if db_files:
            print(f"\n  Found {len(db_files)} database candidate(s) in directory:")
            for df in db_files:
                meta = WhatsAppDatabaseAnalyzer.identify_database(df)
                enc_str = f"Encrypted ({meta.crypt_version})" if meta.is_encrypted else ("SQLite" if meta.is_sqlite else "Unknown")
                print(f"   • {df.name:<32} {format_bytes(meta.size_bytes):>10}  Format: {enc_str}")
        print("=" * 72 + "\n")
        return

    # Target is a file
    print("\n" + "=" * 72)
    print(f"  INSPECTING DATABASE FILE: {target.name}")
    print("=" * 72)
    meta = WhatsAppDatabaseAnalyzer.identify_database(target)
    print(f"  File Name          : {meta.file_path.name}")
    print(f"  Path               : {meta.file_path}")
    print(f"  Size               : {format_bytes(meta.size_bytes)}")
    print(f"  Format Description : {meta.format_description}")
    print(f"  SQLite Compatible  : {'Yes' if meta.is_sqlite else 'No'}")
    print(f"  Encrypted Backup   : {'Yes' if meta.is_encrypted else 'No'}")
    if meta.crypt_version:
        print(f"  Crypt Version      : {meta.crypt_version}")
        print(f"  Cipher Algorithm   : {meta.cipher_algorithm}")
        print(f"  Decryption Material: {meta.required_key_type}")

    if meta.is_sqlite:
        print(f"  SQLite Tables      : {meta.table_count} tables detected")
        if meta.messages_table_name:
            print(f"  Messages Table     : '{meta.messages_table_name}'")
        if meta.schema_features:
            print(f"  Detected Schema    : {', '.join(meta.schema_features)}")
        raw_msgs = WhatsAppDatabaseAnalyzer.extract_raw_messages(target)
        print(f"  Readable Messages  : {len(raw_msgs)} records found")
        if raw_msgs:
            convs = ChatReconstructionEngine.reconstruct_conversations(raw_msgs)
            print(f"  Conversations      : {len(convs)} reconstructed threads")
            for c in convs[:5]:
                print(f"     ↳ {c.display_name} ({len(c.messages)} msgs, {len(c.participants)} participants)")
            if len(convs) > 5:
                print(f"     ↳ ... and {len(convs) - 5} more conversations.")

    elif meta.is_encrypted and key_path:
        print(f"\n[*] User provided decryption key: {key_path}")
        decrypted_dest = target.parent / f"{target.stem}_decrypted.db"
        ok, msg = WhatsAppDatabaseAnalyzer.decrypt_crypt_database(target, key_path, decrypted_dest)
        if ok:
            print(f"[+] Decryption SUCCESSFUL: {decrypted_dest}")
            dec_meta = WhatsAppDatabaseAnalyzer.identify_database(decrypted_dest)
            raw_msgs = WhatsAppDatabaseAnalyzer.extract_raw_messages(decrypted_dest)
            print(f"    Decrypted Tables  : {dec_meta.table_count}")
            print(f"    Readable Messages : {len(raw_msgs)}")
        else:
            print(f"[!] Decryption failed: {msg}")

    print("=" * 72 + "\n")


def inspect_recovery_folder_interactive() -> None:
    """Inspect and display metadata of an existing recovery folder."""
    target_str = input("Enter path to recovery directory or database file: ").strip()
    if not target_str:
        return
    key_str = input("Enter path to decryption key (optional, press Enter to skip): ").strip()
    key_p = Path(key_str).resolve() if key_str else None
    inspect_target(Path(target_str), key_path=key_p)


def reconstruct_and_export_interactive() -> None:
    """Interactive workflow to reconstruct and export chats from a database."""
    db_path_str = input("Enter path to database file (e.g. recovery/.../Databases/msgstore.db): ").strip()
    if not db_path_str:
        return
    db_p = Path(db_path_str).resolve()
    if not db_p.exists():
        print(f"[!] File not found: {db_p}")
        return

    key_p: Optional[Path] = None
    meta = WhatsAppDatabaseAnalyzer.identify_database(db_p)
    if meta.is_encrypted:
        print(f"[*] Database is encrypted ({meta.crypt_version}). Decryption key required.")
        key_str = input("Enter path to WhatsApp key file (leave blank to cancel): ").strip()
        if not key_str:
            print("[*] Decryption cancelled.")
            return
        key_p = Path(key_str).resolve()

    print("\nSelect export format:")
    print("  [1] All formats (TXT, HTML, JSON, CSV)")
    print("  [2] HTML (Visual forensic transcript)")
    print("  [3] JSON (Machine-readable structured data)")
    print("  [4] CSV (Spreadsheet records)")
    print("  [5] TXT (Plain text)")
    fmt_choice = input("Enter format [1-5, default 1]: ").strip()
    fmt_map = {"1": "all", "2": "html", "3": "json", "4": "csv", "5": "txt"}
    chosen_fmt = fmt_map.get(fmt_choice, "all")

    export_target(db_p, export_format=chosen_fmt, key_path=key_p)


def package_zip_interactive() -> None:
    """Interactive workflow to package a recovery directory into a verified ZIP."""
    dir_str = input("Enter path to recovery directory to package: ").strip()
    if not dir_str:
        return
    rec_dir = Path(dir_str).resolve()
    if not rec_dir.exists() or not rec_dir.is_dir():
        print(f"[!] Directory not found: {rec_dir}")
        return

    preview = ZipPackager.preview_archive(rec_dir)
    print("\n" + "=" * 60)
    print("  ARCHIVE PACKAGING PREVIEW")
    print("=" * 60)
    print(f"  Source Directory    : {rec_dir}")
    print(f"  Eligible Files      : {preview['file_count']}")
    print(f"  Uncompressed Size   : {format_bytes(preview['uncompressed_bytes'])}")
    print(f"  Estimated ZIP Size  : {format_bytes(preview['estimated_zip_bytes'])}")
    print(f"  Available Disk Space: {format_bytes(preview['available_bytes'])}")
    print(f"  Space Sufficient    : {'Yes' if preview['has_sufficient_space'] else 'NO'}")
    print("=" * 60)

    if not preview["has_sufficient_space"]:
        print("[!] Cannot package archive: Insufficient disk space on target partition.")
        return

    out_name = input(f"\nEnter destination ZIP name (default: {rec_dir.name}.zip): ").strip()
    out_zip = rec_dir.parent / (out_name if out_name.endswith(".zip") else (f"{out_name}.zip" if out_name else f"{rec_dir.name}.zip"))

    ans = input(f"Package {preview['file_count']} files into {out_zip.name}? [y/N]: ").strip().lower()
    if ans not in ("y", "yes"):
        print("[*] Packaging cancelled.")
        return

    print("\n[*] Creating and verifying ZIP archive...")
    ok, res_path, err = ZipPackager.package_recovery_archive(rec_dir, out_zip)
    if ok:
        print(f"[+] Archive created successfully: {res_path}")
        print(f"    Size: {format_bytes(res_path.stat().st_size)}")
    else:
        print(f"[!] Archive creation failed: {err}")


def view_case_audit_interactive() -> None:
    """Interactive viewer for local case management and append-only audit events."""
    base_rec = Path("recovery").resolve()
    scans = CaseManager.list_past_scans(base_rec)

    print("\n" + "=" * 72)
    print("  WRS CASE MANAGEMENT & AUDIT LOGS")
    print("=" * 72)

    if not scans:
        print("  No past recovery cases found in recovery directory.")
        print("=" * 72 + "\n")
        return

    print(f"  Found {len(scans)} recovery case(s):\n")
    for idx, s in enumerate(scans, start=1):
        dev = s.get("device_name", "Unknown")
        dt = s.get("timestamp", "Unknown")
        fc = s.get("total_files", 0)
        sz = format_bytes(s.get("total_bytes", 0))
        sid = s.get("scan_id", "N/A")
        print(f"  [{idx}] {sid:<24} | Device: {dev:<18} | Date: {dt} | {fc} files ({sz})")

    print("\nOptions:")
    print("  [1] View audit events for a scan")
    print("  [2] Compare two scans")
    print("  [3] Return to main menu")

    opt = input("\nEnter option [1-3]: ").strip()
    if opt == "1":
        choice = input("Enter case number to view: ").strip()
        try:
            c_idx = int(choice) - 1
            if 0 <= c_idx < len(scans):
                selected = scans[c_idx]
                case_dir = selected["recovery_path"]
                cm = CaseManager(selected.get("scan_id", "unknown"), case_dir)
                events = cm.load_events()
                print(f"\n--- Audit Events for Scan: {selected.get('scan_id')} ---")
                if not events:
                    print("  No audit events recorded for this scan.")
                for ev in events:
                    print(f"  [{ev.timestamp}] {ev.event_type:<24} {ev.details}")
                print("-" * 60)
        except (ValueError, IndexError):
            print("Invalid case number.")
    elif opt == "2":
        if len(scans) < 2:
            print("At least two scans are required to perform a comparison.")
            return
        c1 = input("Enter first case number: ").strip()
        c2 = input("Enter second case number: ").strip()
        try:
            s1 = scans[int(c1) - 1]["recovery_path"]
            s2 = scans[int(c2) - 1]["recovery_path"]
            comp = CaseManager.compare_cases(s1, s2)
            print("\n" + "=" * 60)
            print("  CASE COMPARISON RESULT")
            print("=" * 60)
            print(f"  Case 1 Files       : {comp['case1_total']}")
            print(f"  Case 2 Files       : {comp['case2_total']}")
            print(f"  Common Identical   : {comp['common_identical_count']}")
            print(f"  Files Unique to 1  : {comp['unique_to_case1_count']}")
            print(f"  Files Unique to 2  : {comp['unique_to_case2_count']}")
            print(f"  Content Alterations: {comp['modified_content_count']}")
            print("=" * 60)
        except (ValueError, IndexError):
            print("Invalid case numbers.")


def export_target(
    target: Path,
    export_format: str = "all",
    key_path: Optional[Path] = None,
    output_dir: Optional[Path] = None,
) -> None:
    """Export reconstructed chats or package recovery into ZIP archive."""
    target = target.resolve()
    if not target.exists():
        print(f"[!] Target path does not exist: {target}")
        sys.exit(1)

    export_format = export_format.lower()

    # If ZIP packaging is explicitly chosen and target is a directory
    if export_format == "zip" and target.is_dir():
        out_zip = output_dir if (output_dir and str(output_dir).endswith(".zip")) else (target.parent / f"{target.name}_export.zip")
        print(f"[*] Packaging directory into ZIP archive: {out_zip}")
        ok, res_path, err = ZipPackager.package_recovery_archive(target, out_zip)
        if ok:
            print(f"[+] ZIP packaging completed successfully: {res_path}")
            sys.exit(0)
        else:
            print(f"[!] ZIP packaging failed: {err}")
            sys.exit(1)

    # Database file or directory containing database
    db_file: Optional[Path] = None
    media_dir: Optional[Path] = None

    if target.is_file():
        db_file = target
        media_dir = target.parent
    else:
        # Look for SQLite or crypt DB in Databases/ or root
        candidates = list(target.glob("Databases/*")) + list(target.glob("*.db*"))
        for c in candidates:
            if c.is_file() and not c.name.endswith("-journal") and not c.name.endswith("-wal"):
                db_file = c
                break
        media_dir = target

    if not db_file:
        print(f"[!] No database file found in {target}")
        sys.exit(1)

    meta = WhatsAppDatabaseAnalyzer.identify_database(db_file)
    active_db = db_file
    if meta.is_encrypted:
        if not key_path:
            print(f"[!] Target database '{db_file.name}' is encrypted ({meta.crypt_version}).")
            print("    Please provide decryption key with --key PATH to extract conversations.")
            sys.exit(1)
        dec_dest = db_file.parent / f"{db_file.stem}_decrypted.db"
        ok, msg = WhatsAppDatabaseAnalyzer.decrypt_crypt_database(db_file, key_path, dec_dest)
        if not ok:
            print(f"[!] Decryption failed: {msg}")
            sys.exit(1)
        active_db = dec_dest

    print(f"[*] Extracting messages from database: {active_db.name}...")
    raw_msgs = WhatsAppDatabaseAnalyzer.extract_raw_messages(active_db)
    if not raw_msgs:
        print("[!] No message records could be extracted from database.")
        sys.exit(1)

    convs = ChatReconstructionEngine.reconstruct_conversations(raw_msgs)
    print(f"[+] Reconstructed {len(convs)} conversation threads ({len(raw_msgs)} messages).")

    # Associate media
    if media_dir and media_dir.exists():
        media_files = [p for root, _, files in os.walk(media_dir) for p in [Path(root) / fn for fn in files]]
        MediaAssociator.associate_media(convs, media_files)

    out_base = output_dir or (target / "chats" if target.is_dir() else target.parent / "exported_chats")
    out_base.mkdir(parents=True, exist_ok=True)

    print(f"[*] Exporting conversations to: {out_base} (format: {export_format.upper()})")
    for c in convs:
        safe_name = sanitize_filename(c.display_name)[:30]
        if export_format in ("all", "txt"):
            ChatExporter.export_conversation_txt(c, out_base / f"{safe_name}.txt")
        if export_format in ("all", "html"):
            ChatExporter.export_conversation_html(c, out_base / f"{safe_name}.html")
        if export_format in ("all", "json"):
            ChatExporter.export_conversation_json(c, out_base / f"{safe_name}.json")
        if export_format in ("all", "csv"):
            ChatExporter.export_conversation_csv(c, out_base / f"{safe_name}.csv")

    if export_format == "zip":
        zip_dest = out_base.parent / f"{out_base.name}.zip"
        ZipPackager.package_recovery_archive(out_base, zip_dest)
        print(f"[+] Export archive created: {zip_dest}")

    print(f"[+] Successfully exported {len(convs)} conversations.")


def interactive_menu() -> None:
    """Main terminal menu loop."""
    executor = AdbExecutor()

    while True:
        print_banner(executor)
        print("[1] Scan Android device and discover WhatsApp data (Inventory Only)")
        print("[2] Scan and acquire WhatsApp data")
        print("[3] Inspect recovery folder or SQLite database")
        print("[4] Verify acquired files and hashes")
        print("[5] Reconstruct and export chats from acquired database")
        print("[6] Package recovery directory into ZIP archive")
        print("[7] View case audit log and past scans")
        print("[8] View supported recovery locations and limitations")
        print("[9] Exit")

        try:
            choice = input("\nEnter choice [1-9]: ").strip()
            if choice == "1":
                run_interactive_workflow(executor, acquire_mode=False)
            elif choice == "2":
                run_interactive_workflow(executor, acquire_mode=True)
            elif choice == "3":
                inspect_recovery_folder_interactive()
            elif choice == "4":
                path_input = input("Enter recovery directory path to verify: ").strip()
                if path_input:
                    res = verify_recovery_directory(path_input)
                    print(f"Verification result: {res['verified_count']}/{res['total']} intact.")
            elif choice == "5":
                reconstruct_and_export_interactive()
            elif choice == "6":
                package_zip_interactive()
            elif choice == "7":
                view_case_audit_interactive()
            elif choice == "8":
                show_recovery_info()
            elif choice == "9":
                print("\nExiting WRS. Goodbye.")
                sys.exit(0)
            else:
                print("Invalid choice.")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            sys.exit(0)

        input("\nPress Enter to return to main menu...")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for automated or script-based invocation."""
    parser = argparse.ArgumentParser(
        prog="wrs",
        description="WRS — WhatsApp Recovery Scanner: Advanced Forensic Acquisition & Recovery Workstation",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--list-devices", action="store_true", help="List connected Android devices and exit")
    parser.add_argument("--device", type=str, default=None, help="Target device serial number")
    parser.add_argument("--scan", action="store_true", help="Perform inventory scan without copying files")
    parser.add_argument("--acquire", action="store_true", help="Perform scan and acquire files")
    parser.add_argument("--output", type=str, default=None, help="Custom recovery output directory")
    parser.add_argument("--verify", type=str, default=None, help="Verify integrity of an existing recovery directory")
    parser.add_argument("--inspect", type=str, default=None, help="Inspect an SQLite/Crypt database or recovery directory")
    parser.add_argument("--export", type=str, default=None, help="Export chats from database or package directory to ZIP")
    parser.add_argument(
        "--format",
        type=str,
        default="all",
        choices=["all", "txt", "html", "json", "csv", "zip"],
        help="Export format for chat reconstruction or packaging (default: all)",
    )
    parser.add_argument("--key", type=str, default=None, help="Path to WhatsApp encryption key file for crypt14/15 decryption")
    parser.add_argument("--categories", type=str, default=None, help="Comma-separated category filter (e.g. Images,Videos,Databases)")
    parser.add_argument("--exclude-duplicates", action="store_true", help="Exclude duplicate candidate files from acquisition")
    parser.add_argument("--scan-id", type=str, default=None, help="Specific scan ID for logging or tracking")
    parser.add_argument(
        "--unattended",
        "--yes",
        action="store_true",
        help="Run without interactive confirmation prompts (requires explicit --acquire and scope)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Simulate acquisition without pulling files")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging")

    return parser.parse_args()


def main() -> None:
    """CLI entry point."""
    args = parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    executor = AdbExecutor()
    key_path = Path(args.key).resolve() if args.key else None

    # 1. Standalone verification mode
    if args.verify:
        print_banner(executor)
        print(f"[*] Verifying recovery directory: {args.verify}")
        res = verify_recovery_directory(args.verify)
        if not res.get("success"):
            print(f"[!] Verification failed: {res.get('error')}")
            sys.exit(1)
        print(f"[+] Total checked : {res['total']}")
        print(f"[+] Verified intact: {res['verified_count']}")
        print(f"[!] Mismatches    : {res['mismatch_count']}")
        print(f"[!] Missing files : {res['missing_count']}")
        sys.exit(0 if res.get("is_fully_intact") else 2)

    # 2. Inspect mode
    if args.inspect:
        print_banner(executor)
        inspect_target(Path(args.inspect), key_path=key_path)
        sys.exit(0)

    # 3. Export mode
    if args.export:
        print_banner(executor)
        out_dir = Path(args.output).resolve() if args.output else None
        export_target(Path(args.export), export_format=args.format or "all", key_path=key_path, output_dir=out_dir)
        sys.exit(0)

    # 4. List devices mode
    if args.list_devices:
        devices = executor.list_devices()
        print("\n--- Connected Android Devices ---")
        if not devices:
            print("No devices attached.")
            sys.exit(0)
        for d in devices:
            print(f"Serial: {d.serial:<20} State: {d.state:<12} Model: {d.display_name}")
        sys.exit(0)

    # 5. Headless / CLI scan or acquire mode
    if args.scan or args.acquire:
        out_path = Path(args.output).resolve() if args.output else None
        selected_cats: Optional[Set[str]] = None
        if args.categories:
            selected_cats = {c.strip() for c in args.categories.split(",") if c.strip()}

        run_interactive_workflow(
            executor=executor,
            acquire_mode=args.acquire,
            override_serial=args.device,
            override_output=out_path,
            unattended=args.unattended,
            selected_cats=selected_cats,
            exclude_duplicates=args.exclude_duplicates,
            key_path=key_path,
        )
        sys.exit(0)

    # 6. Interactive menu mode
    interactive_menu()


if __name__ == "__main__":
    main()

