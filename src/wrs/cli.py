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
from .categorizer import ALL_CATEGORIES, CATEGORY_DIR_NAMES
from .device import AdbExecutor, DeviceInfo
from .discovery import DiscoveredLocation, StorageDiscovery
from .hashing import STATUS_VERIFIED
from .reporting import ReportGenerator, verify_recovery_directory
from .scanner import FileScanner, ScanResult
from .utils import (
    format_bytes,
    format_timestamp,
    load_settings,
    sanitize_device_name,
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


def run_interactive_workflow(
    executor: AdbExecutor,
    acquire_mode: bool = False,
    override_serial: Optional[str] = None,
    override_output: Optional[Path] = None,
    unattended: bool = False,
    selected_cats: Optional[Set[str]] = None,
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
            )
            print("\n[+] Acquisition phase finished.")
        except KeyboardInterrupt:
            print("\n[!] Acquisition interrupted! Partial progress and manifest preserved safely.")
            return

        # 8. Report Generation
        dest_tree = acq_manager.setup_recovery_tree(preview.destination_path)
        rep_gen = ReportGenerator(dev, scan_result, records=records, output_dir=dest_tree["reports"])
        h, c, j = rep_gen.generate_all()

        # 9. Summary
        verified_cnt = sum(1 for r in records if r.status == STATUS_VERIFIED)
        print("\n" + "=" * 72)
        print("  ACQUISITION SUMMARY")
        print("=" * 72)
        print(f"  Target Destination : {preview.destination_path}")
        print(f"  Total Acquired     : {len(records)} files")
        print(f"  SHA-256 Verified   : {verified_cnt} files")
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


def inspect_recovery_folder_interactive() -> None:
    """Inspect and display metadata of an existing recovery folder."""
    target_dir_str = input("Enter path to recovery directory (e.g. ./recovery/DEVICE_scan_...): ").strip()
    if not target_dir_str:
        return

    target_dir = Path(target_dir_str).resolve()
    manifest_p = target_dir / "metadata" / "acquisition_manifest.json"

    if not target_dir.exists() or not manifest_p.exists():
        print(f"[!] Directory {target_dir} is not a valid WRS recovery directory (manifest missing).")
        return

    audit = verify_recovery_directory(target_dir)
    print(f"\n--- Recovery Directory Audit: {target_dir.name} ---")
    print(f"  Total Tracked Files : {audit['total']}")
    print(f"  Intact & Verified   : {audit['verified_count']}")
    print(f"  Mismatched / Altered: {audit['mismatch_count']}")
    print(f"  Missing Files       : {audit['missing_count']}")
    status_msg = "PASSED (Fully Intact)" if audit['is_fully_intact'] else "INTEGRITY WARNINGS DETECTED"
    print(f"  Audit Status        : {status_msg}\n")


def interactive_menu() -> None:
    """Main terminal menu loop."""
    executor = AdbExecutor()

    while True:
        print_banner(executor)
        print("[1] Scan Android device and discover WhatsApp data (Inventory Only)")
        print("[2] Scan and acquire WhatsApp data")
        print("[3] Inspect an existing recovery folder")
        print("[4] Verify acquired files and hashes")
        print("[5] Generate or regenerate reports")
        print("[6] View supported recovery locations and limitations")
        print("[7] Exit")

        try:
            choice = input("\nEnter choice [1-7]: ").strip()
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
                print("To regenerate reports, point WRS to an existing scan directory or perform a new scan.")
            elif choice == "6":
                show_recovery_info()
            elif choice == "7":
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
        description="WRS — WhatsApp Recovery Scanner: Local Forensic Acquisition Utility",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--list-devices", action="store_true", help="List connected Android devices and exit")
    parser.add_argument("--device", type=str, default=None, help="Target device serial number")
    parser.add_argument("--scan", action="store_true", help="Perform inventory scan without copying files")
    parser.add_argument("--acquire", action="store_true", help="Perform scan and acquire files")
    parser.add_argument("--output", type=str, default=None, help="Custom recovery output directory")
    parser.add_argument("--verify", type=str, default=None, help="Verify integrity of an existing recovery directory")
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

    # 2. List devices mode
    if args.list_devices:
        devices = executor.list_devices()
        print("\n--- Connected Android Devices ---")
        if not devices:
            print("No devices attached.")
            sys.exit(0)
        for d in devices:
            print(f"Serial: {d.serial:<20} State: {d.state:<12} Model: {d.display_name}")
        sys.exit(0)

    # 3. Headless / CLI invocation
    if args.scan or args.acquire:
        out_path = Path(args.output).resolve() if args.output else None
        run_interactive_workflow(
            executor=executor,
            acquire_mode=args.acquire,
            override_serial=args.device,
            override_output=out_path,
            unattended=args.unattended,
        )
        sys.exit(0)

    # 4. Interactive menu mode
    interactive_menu()


if __name__ == "__main__":
    main()
