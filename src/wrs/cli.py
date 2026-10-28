"""Interactive CLI interface and command-line argument dispatcher for WRS.

Provides rich terminal presentation, device detection and selection, pre-acquisition
previews, explicit confirmation safeguards, professional progress displays,
structured error handling, persistent configuration, and headless automation.
"""

from __future__ import annotations

import argparse
import logging
import os
import platform
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, List, Optional, Set, Tuple

from . import __version__
from .acquisition import AcquisitionManager, AcquisitionPreview
from .case import CaseManager, generate_scan_id
from .categorizer import ALL_CATEGORIES, CATEGORY_DIR_NAMES
from .chat import ChatReconstructionEngine, Conversation
from .database import WhatsAppDatabaseAnalyzer
from .device import AdbExecutor, DeviceInfo
from .discovery import DiscoveredLocation, StorageDiscovery
from .duplicate import DuplicateDetector
from .errors import (
    ERR_ADB_NOT_FOUND,
    ERR_DEVICE_DISCONNECTED,
    ERR_DEVICE_OFFLINE,
    ERR_DEVICE_UNAUTHORIZED,
    ERR_INSUFFICIENT_SPACE,
    ERR_NO_DEVICE_CONNECTED,
    ERR_NO_WHATSAPP_STORAGE,
    ERR_STORAGE_PERMISSION_DENIED,
    ERR_TRANSFER_INTERRUPTED,
    format_actionable_error,
)
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
    mask_serial,
    sanitize_device_name,
    sanitize_filename,
    save_settings,
    validate_settings,
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


def get_environment_name() -> str:
    """Detect local OS environment, preferring distribution name on Linux."""
    try:
        os_rel = Path("/etc/os-release")
        if os_rel.exists():
            with open(os_rel, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return f"{platform.system()} {platform.release()}"


def print_banner(
    executor: AdbExecutor,
    device: Optional[DeviceInfo] = None,
    settings: Optional[dict[str, Any]] = None,
) -> None:
    """Display professional terminal banner."""
    adb_ok, adb_msg = executor.get_adb_version()
    adb_status = f"Available ({adb_msg})" if adb_ok else f"Unavailable ({adb_msg})"
    now_str = format_timestamp()
    env_str = get_environment_name()

    mask = False
    if settings and settings.get("ui", {}).get("mask_device_serial"):
        mask = True

    dev_str = "None"
    if device:
        s_disp = device.get_display_serial(masked=mask)
        dev_str = f"{device.display_name} ({s_disp})" if s_disp else device.display_name

    if HAS_RICH and console:
        title = Text("WRS — WhatsApp Recovery Scanner", style="bold cyan")
        subtitle = Text("Forensic Acquisition & Preservation Utility\n", style="dim")
        body = (
            f"[bold green]●[/bold green] Environment    : [white]{env_str}[/white]\n"
            f"[bold blue]●[/bold blue] Processing Mode: [bold]100% Local Execution (Zero Network / Cloud)[/bold]\n"
            f"[bold cyan]●[/bold cyan] ADB Status      : [white]{adb_status}[/white]\n"
            f"[bold yellow]●[/bold yellow] Selected Device : [bold white]{dev_str}[/bold white]\n"
            f"[bold magenta]●[/bold magenta] Version        : [white]v{__version__}[/white] | Timestamp: [white]{now_str}[/white]"
        )
        panel = Panel(body, title=title, subtitle=subtitle, border_style="cyan")
        console.print(panel)
    else:
        print("=" * 72)
        print(f"  WRS — WHATSAPP RECOVERY SCANNER (v{__version__})")
        print("  Forensic Acquisition & Preservation Utility")
        print(f"  Environment    : {env_str}")
        print("  Processing     : 100% Local Execution — Zero Network / Cloud Telemetry")
        print(f"  ADB Status     : {adb_status}")
        print(f"  Selected Device: {dev_str}")
        print(f"  Timestamp      : {now_str}")
        print("=" * 72)


def print_screen_header(
    title: str,
    device: Optional[DeviceInfo] = None,
    settings: Optional[dict[str, Any]] = None,
) -> None:
    """Print consistent screen header ensuring selected device remains visible."""
    mask = False
    if settings and settings.get("ui", {}).get("mask_device_serial"):
        mask = True

    dev_label = device.display_name if device else "No Device Selected"
    if device and device.serial:
        s_disp = device.get_display_serial(masked=mask)
        dev_label = f"{device.display_name} ({s_disp})"

    print("\n" + "=" * 65)
    print(f"  WRS — {title.upper()}")
    print("=" * 65)
    print(f"  Selected Device : {dev_label}")
    print("-" * 65)


def detect_and_display_startup_devices(
    executor: AdbExecutor,
    settings: Optional[dict[str, Any]] = None,
) -> Tuple[List[DeviceInfo], Optional[DeviceInfo]]:
    """Perform preflight checks and query ADB.

    Displays environment, ADB status, connected devices count, current time,
    and a structured device table before returning (all_devices, selected_device).
    """
    adb_ok, adb_msg = executor.get_adb_version()
    adb_status = f"Available" if adb_ok else f"Unavailable ({adb_msg})"
    env_str = get_environment_name()
    now_str = format_timestamp()

    mask = False
    if settings and settings.get("ui", {}).get("mask_device_serial"):
        mask = True

    if not adb_ok:
        print("\n" + "=" * 62)
        print("          WRS — WHATSAPP RECOVERY SCANNER")
        print("=" * 62)
        print(f"Environment       : {env_str}")
        print(f"ADB Status        : {adb_status}")
        print(f"Connected Devices : 0")
        print(f"Current Time      : {now_str}")
        print(format_actionable_error(ERR_ADB_NOT_FOUND, context=adb_msg))
        return [], None

    # Enumerate devices
    raw_devices = executor.list_devices()
    devices: List[DeviceInfo] = []
    for d in raw_devices:
        details = executor.get_device_details(d.serial)
        devices.append(details)

    print("\n" + "=" * 62)
    print("          WRS — WHATSAPP RECOVERY SCANNER")
    print("=" * 62)
    print(f"Environment       : {env_str}")
    print(f"ADB Status        : {adb_status}")
    print(f"Connected Devices : {len(devices)}")
    print(f"Current Time      : {now_str}")
    print("\nCONNECTED ANDROID DEVICES")
    print("-" * 62)

    # 1. Zero devices connected
    if not devices:
        print("[!] No authorized Android device detected.\n")
        print("1. Connect the Android phone using USB.")
        print("2. Enable USB debugging.")
        print("3. Unlock the phone.")
        print("4. Approve the USB debugging authorization prompt.")
        print("5. Run the device detection command again.\n")
        print("[R] Retry")
        print("[Q] Exit")
        print("-" * 62)
        print("Selected Device  : None")
        print("=" * 62 + "\n")
        return [], None

    # 2. Exactly one device connected
    if len(devices) == 1:
        dev = devices[0]
        s_id = dev.get_display_serial(masked=mask)
        mfg = dev.manufacturer if dev.manufacturer != "Unknown" else "Unavailable"
        mdl = dev.model if dev.model != "Unknown" else "Unavailable"
        av = dev.android_version if dev.android_version != "Unknown" else "Unavailable"

        print(f"[1] Device Name : {dev.display_name}")
        print(f"    Model       : {mdl}")
        print(f"    Manufacturer: {mfg}")
        print(f"    Android     : {av}")
        print(f"    Device ID   : {s_id}")
        print(f"    Status      : {dev.status_display}")
        print("-" * 62)

        if dev.is_accessible:
            print(f"Selected Device  : {dev.display_name}")
            print("=" * 62 + "\n")
            return devices, dev
        else:
            print(f"Selected Device  : {dev.display_name} ({dev.status_display})")
            print("=" * 62 + "\n")
            if dev.state == "unauthorized":
                print(format_actionable_error(ERR_DEVICE_UNAUTHORIZED, device_name=dev.display_name))
            elif dev.state == "offline":
                print(format_actionable_error(ERR_DEVICE_OFFLINE, device_name=dev.display_name))
            return devices, dev

    # 3. Multiple devices connected
    for idx, d in enumerate(devices, start=1):
        s_id = d.get_display_serial(masked=mask)
        mfg = d.manufacturer if d.manufacturer != "Unknown" else "Unavailable"
        mdl = d.model if d.model != "Unknown" else "Unavailable"
        av = d.android_version if d.android_version != "Unknown" else "Unavailable"

        print(f"[{idx}] Device Name : {d.display_name}")
        print(f"    Model       : {mdl}")
        print(f"    Manufacturer: {mfg}")
        print(f"    Android     : {av}")
        print(f"    Device ID   : {s_id}")
        print(f"    Status      : {d.status_display}")

    print("-" * 62)
    print("CONNECTED DEVICES\n")
    for idx, d in enumerate(devices, start=1):
        mdl_str = d.model if d.model != "Unknown" else "Model Unavailable"
        st_compact = "AUTHORIZED" if d.is_authorized else d.status_display
        print(f"[{idx}] {d.display_name} | {mdl_str} | {st_compact}")
    print("-" * 62)

    while True:
        try:
            choice = input(f"\nSelect device [1-{len(devices)}] or 'q' to exit: ").strip().lower()
            if choice == "q":
                sys.exit(0)
            c_idx = int(choice)
            if 1 <= c_idx <= len(devices):
                selected = devices[c_idx - 1]
                print(f"Selected Device  : {selected.display_name}")
                print("=" * 62 + "\n")
                if not selected.is_accessible:
                    if selected.state == "unauthorized":
                        print(format_actionable_error(ERR_DEVICE_UNAUTHORIZED, device_name=selected.display_name))
                    elif selected.state == "offline":
                        print(format_actionable_error(ERR_DEVICE_OFFLINE, device_name=selected.display_name))
                return devices, selected
            print(f"Invalid selection. Please choose a number between 1 and {len(devices)}.")
        except (ValueError, KeyboardInterrupt):
            print("\nSelection cancelled.")
            return devices, None


def select_device_interactive(
    executor: AdbExecutor,
    settings: Optional[dict[str, Any]] = None,
) -> Optional[DeviceInfo]:
    """Present a numbered table of connected devices for explicit user selection."""
    mask = False
    if settings and settings.get("ui", {}).get("mask_device_serial"):
        mask = True

    devices = executor.list_devices()
    if not devices:
        print(format_actionable_error(ERR_NO_DEVICE_CONNECTED))
        return None

    if len(devices) == 1:
        dev = devices[0]
        details = executor.get_device_details(dev.serial)
        print(f"\n[+] Selected Device: {details.display_name} ({details.get_display_serial(masked=mask)}) — [{details.status_display}]")
        if not details.is_accessible:
            if details.state == "unauthorized":
                print(format_actionable_error(ERR_DEVICE_UNAUTHORIZED, device_name=details.display_name))
            elif details.state == "offline":
                print(format_actionable_error(ERR_DEVICE_OFFLINE, device_name=details.display_name))
        return details

    print("\nCONNECTED DEVICES")
    print("-" * 62)
    detailed_list: List[DeviceInfo] = []
    for idx, d in enumerate(devices, start=1):
        det = executor.get_device_details(d.serial)
        detailed_list.append(det)
        mdl = det.model if det.model != "Unknown" else "Model Unavailable"
        print(f"[{idx}] {det.display_name} | {mdl} | {det.status_display}")
    print("-" * 62)

    while True:
        try:
            choice = input(f"\nSelect device [1-{len(detailed_list)}] or 'c' to cancel: ").strip().lower()
            if choice == "c":
                return None
            idx = int(choice)
            if 1 <= idx <= len(detailed_list):
                selected = detailed_list[idx - 1]
                if not selected.is_accessible:
                    if selected.state == "unauthorized":
                        print(format_actionable_error(ERR_DEVICE_UNAUTHORIZED, device_name=selected.display_name))
                    elif selected.state == "offline":
                        print(format_actionable_error(ERR_DEVICE_OFFLINE, device_name=selected.display_name))
                return selected
            print("Invalid selection. Please choose a valid number.")
        except (ValueError, KeyboardInterrupt):
            print("\nSelection cancelled.")
            return None


def select_location_interactive(locations: List[DiscoveredLocation], device_name: str) -> Optional[List[DiscoveredLocation]]:
    """Prompt user to choose which discovered WhatsApp locations to scan."""
    if not locations:
        print(format_actionable_error(ERR_NO_WHATSAPP_STORAGE, device_name=device_name))
        return None

    print(f"\n--- Discovered WhatsApp Storage Locations on {device_name} ---")
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


def display_preview(
    preview: AcquisitionPreview,
    settings: Optional[dict[str, Any]] = None,
) -> None:
    """Display comprehensive pre-acquisition preview table."""
    mask = False
    if settings and settings.get("ui", {}).get("mask_device_serial"):
        mask = True

    disp_serial = mask_serial(preview.serial) if mask else preview.serial
    margin_b = 104857600
    margin_ratio = 0.10
    if settings and "acquisition" in settings:
        margin_b = settings["acquisition"].get("safety_margin_bytes", margin_b)
        margin_ratio = settings["acquisition"].get("safety_margin_ratio", margin_ratio)

    print("\n" + "=" * 72)
    print("  WRS — ACQUISITION PREVIEW")
    print("=" * 72)
    print(f"  Scan ID                 : {preview.scan_id}")
    print(f"  Device Name & Model     : {preview.device_name}")
    print(f"  Device Serial / ID      : {disp_serial}")
    print(f"  Android OS Version      : {preview.android_version}")
    print(f"  Scan Timestamp          : {preview.scan_date}")
    print(f"  Selected Source Scope   : {', '.join(preview.selected_locations)}")
    print(f"  Eligible Files Selected : {preview.total_files}")
    avail_b = getattr(preview, "available_space", getattr(preview, "available_bytes", 0))
    req_b = getattr(preview, "required_space_with_margin", getattr(preview, "required_bytes", 0))
    print(f"  Available Disk Space    : {format_bytes(avail_b)}")
    print(f"  Estimated Required Space: {format_bytes(req_b)}")
    print(f"  Configured Safety Margin: {format_bytes(margin_b)} ({int(margin_ratio * 100)}% dynamic)")
    print(f"  Target Destination Path : {preview.destination_path}")
    print("-" * 72)

    if HAS_RICH and console:
        tbl = Table(title="Categorized Acquisition Scope", show_header=True, header_style="bold magenta")
        tbl.add_column("Category", style="cyan", width=22)
        tbl.add_column("Files", justify="right", style="green", width=12)
        tbl.add_column("Total Size", justify="right", style="yellow", width=18)

        for cat in ALL_CATEGORIES:
            cnt = preview.category_counts.get(cat, 0)
            sz = preview.category_bytes.get(cat, 0)
            if cnt > 0:
                tbl.add_row(cat, str(cnt), format_bytes(sz))

        tbl.add_row("TOTAL", str(preview.total_files), format_bytes(preview.total_bytes), style="bold white")
        console.print(tbl)
    else:
        print(f"  {'CATEGORY':<22} {'FILES':>10}   {'TOTAL SIZE':>18}")
        print("  " + "-" * 56)
        for cat in ALL_CATEGORIES:
            cnt = preview.category_counts.get(cat, 0)
            sz = preview.category_bytes.get(cat, 0)
            if cnt > 0:
                print(f"  {cat:<22} {cnt:>10}   {format_bytes(sz):>18}")
        print("  " + "-" * 56)
        print(f"  {'TOTAL':<22} {preview.total_files:>10}   {format_bytes(preview.total_bytes):>18}\n")

    if preview.unreadable_files > 0:
        print(f"  [!] Inaccessible / Unreadable Files : {preview.unreadable_files}")
    if preview.skipped_files > 0:
        print(f"  [*] Filtered / Skipped Files        : {preview.skipped_files}")
    print(f"  Database / Backup Candidates        : {preview.database_backup_candidates}")
    print(f"  Duplicate Content Candidates        : {preview.duplicate_candidates}")
    if preview.excluded_duplicates_count > 0:
        print(f"  Excluded Duplicate Copies           : {preview.excluded_duplicates_count} ({format_bytes(preview.excluded_duplicates_bytes)} saved)")
    print(f"  Storage Assessment                  : {preview.space_message}")
    print("=" * 72 + "\n")


def ask_acquisition_confirmation(
    target: Any,
    dest_path: Optional[Path] = None,
    device_name: Optional[str] = None,
) -> bool:
    """Prompt user with mandatory confirmation before acquiring files.

    Defaults safely to No.
    """
    if isinstance(target, AcquisitionPreview):
        dev = target.device_name
        files_cnt = str(target.total_files)
        total_sz = format_bytes(target.total_bytes)
        dst = str(dest_path or target.destination_path)
    else:
        dev = device_name or "Android Device"
        files_cnt = "Selected scope"
        total_sz = "As calculated in preview"
        dst = str(target)

    print("\n" + "=" * 65)
    print("  ACQUISITION PREVIEW & CONFIRMATION")
    print("=" * 65)
    print(f"  Device       : {dev}")
    print(f"  Files        : {files_cnt}")
    print(f"  Total Size   : {total_sz}")
    print(f"  Destination  : {dst}")
    print("=" * 65)
    print("The scanner is ready to copy the selected files to the destination above.")
    print("No source files will be deleted or modified on the Android device.\n")

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
    settings: Optional[dict[str, Any]] = None,
) -> Tuple[Optional[AcquisitionPreview], Optional[Set[str]], Optional[Set[str]], bool]:
    """Provide interactive selection options and dynamically recalculate preview.

    Returns (updated_preview, selected_categories, excluded_paths, continue_acquisition).
    """
    cur_preview = preview
    selected_cats: Optional[Set[str]] = None
    excluded_paths: Optional[Set[str]] = None

    while True:
        display_preview(cur_preview, settings)
        print("Acquisition Selection Options:")
        print("  [1] Proceed with current selection")
        print("  [2] Select specific categories")
        print("  [3] Exclude duplicate candidate files")
        print("  [4] Export inventory catalog only (No file copy)")
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


def make_discovery_progress_callback(
    device_name: str,
    location_path: str,
    progress_enabled: bool = True,
) -> Callable[[str, int, int, float], None]:
    """Create discovery progress callback with plain-text fallback."""
    last_print = [0.0]

    def disc_progress(phase: str, count: int, total: int, elapsed: float) -> None:
        now = time.time()
        if not progress_enabled:
            if count % 250 == 0 or count < 10:
                print(f"[*] Scope: Accessible paths | Discovered: {count} files ({elapsed:.1f}s)")
            return

        if now - last_print[0] > 0.1 or count < 10:
            last_print[0] = now
            sys.stdout.write(
                f"\r[*] DEVICE: {device_name[:16]} | {phase}: {count} accessible files | Elapsed: {elapsed:.1f}s"
            )
            sys.stdout.flush()

    return disc_progress


def make_acquisition_progress_callback(
    device_name: str,
    total_files: int,
    progress_enabled: bool = True,
) -> Callable[[int, int, int, int, str, str, float], None]:
    """Create acquisition progress callback with real-time ETA and plain-text fallback."""
    last_print = [0.0]
    failure_count = [0]

    def acq_progress(
        completed: int,
        remaining: int,
        trans_b: int,
        tot_b: int,
        cur_fn: str,
        stat: str,
        elapsed: float,
    ) -> None:
        if stat in ("FAILED", "MISMATCH"):
            failure_count[0] += 1

        now = time.time()
        if not progress_enabled:
            if completed % 25 == 0 or remaining == 0:
                print(
                    f"[{completed}/{total_files}] Device: {device_name} | "
                    f"Transferred: {format_bytes(trans_b)} | File: {cur_fn} | Status: {stat}"
                )
            return

        if now - last_print[0] > 0.12 or remaining == 0:
            last_print[0] = now
            pct = (trans_b / tot_b * 100) if tot_b > 0 else 0
            speed = trans_b / elapsed if elapsed > 0 else 0
            eta_str = ""
            if speed > 0 and tot_b > trans_b:
                eta_sec = int((tot_b - trans_b) / speed)
                eta_str = f" | ETA: {eta_sec}s"

            fn_disp = cur_fn[:22] + "..." if len(cur_fn) > 25 else cur_fn
            sys.stdout.write(
                f"\rDEVICE: {device_name[:14]} | PROGRESS: {completed}/{total_files} ({pct:4.1f}%) | "
                f"BYTES: {format_bytes(trans_b)} | FILE: {fn_disp:<25} | STAT: {stat:<8} | FAILS: {failure_count[0]}{eta_str}"
            )
            sys.stdout.flush()

    return acq_progress


def display_scan_completed_summary(
    device: DeviceInfo,
    scan_result: ScanResult,
    report_dir: Path,
) -> None:
    """Present concise summary screen after discovery scan (Requirement 9.C)."""
    db_cnt = scan_result.category_counts.get("Databases", 0) + scan_result.category_counts.get("Backups", 0)
    media_cats = ["Images", "Videos", "Audio", "Voice_Notes", "Stickers", "Animated_GIFs"]
    media_cnt = sum(scan_result.category_counts.get(c, 0) for c in media_cats)

    print("\n" + "=" * 65)
    print("  SCAN COMPLETED")
    print("=" * 65)
    print(f"  Device             : {device.display_name}")
    print(f"  Files discovered   : {scan_result.total_files}")
    print(f"  Total data         : {format_bytes(scan_result.total_bytes)}")
    print(f"  Database candidates: {db_cnt}")
    print(f"  Media files        : {media_cnt}")
    print(f"  Inaccessible paths : {len(scan_result.errors)}")
    print(f"  Reports            : {report_dir}")
    print("=" * 65 + "\n")


def run_interactive_workflow(
    executor: AdbExecutor,
    acquire_mode: bool = False,
    override_serial: Optional[str] = None,
    override_output: Optional[Path] = None,
    unattended: bool = False,
    selected_cats: Optional[Set[str]] = None,
    exclude_duplicates: bool = False,
    key_path: Optional[Path] = None,
    dry_run: bool = False,
    settings: Optional[dict[str, Any]] = None,
) -> None:
    """Execute complete workflow: Discovery -> Inventory -> Preview -> Confirmation -> Acquisition -> Report."""
    cfg = settings or load_settings()
    progress_enabled = bool(cfg.get("ui", {}).get("progress_display_enabled", True))

    # 1. Device Selection & Pre-verification
    if override_serial:
        dev = executor.get_device_details(override_serial)
    else:
        dev = select_device_interactive(executor, cfg)

    if not dev:
        return

    # Check connection stability
    if not executor.is_device_connected(dev.serial):
        print(format_actionable_error(ERR_DEVICE_DISCONNECTED, device_name=dev.display_name))
        return

    if not dev.is_accessible:
        if dev.state == "unauthorized":
            print(format_actionable_error(ERR_DEVICE_UNAUTHORIZED, device_name=dev.display_name))
        elif dev.state == "offline":
            print(format_actionable_error(ERR_DEVICE_OFFLINE, device_name=dev.display_name))
        else:
            print(format_actionable_error(f"ERR_STATE_{dev.state.upper()}", context=dev.error_message, device_name=dev.display_name))
        return

    # 2. Storage Discovery
    print_screen_header("STORAGE DISCOVERY", dev, cfg)
    print(f"[*] Discovering WhatsApp storage on {dev.display_name} ({dev.get_display_serial()})...")
    discovery = StorageDiscovery(executor)
    locations = discovery.discover_locations(dev)

    if not locations:
        print(format_actionable_error(ERR_NO_WHATSAPP_STORAGE, device_name=dev.display_name))
        return

    selected_locs = [loc for loc in locations if loc.is_readable] if unattended else select_location_interactive(locations, dev.display_name)
    if not selected_locs:
        print("[*] Operation cancelled.")
        return

    # 3. Scanning & Inventory
    scanner = FileScanner(executor)
    base_rec = override_output or Path(cfg.get("acquisition", {}).get("default_recovery_dir", "recovery"))
    acq_manager = AcquisitionManager(executor, base_recovery_dir=base_rec)

    for loc in selected_locs:
        # Verify device remains attached
        if not executor.is_device_connected(dev.serial):
            print(format_actionable_error(ERR_DEVICE_DISCONNECTED, device_name=dev.display_name))
            return

        print_screen_header("SCAN & INVENTORY", dev, cfg)
        print(f"[*] Scanning location: {loc.path}")
        print("    Enumerating files without modification (Scope: Accessible selected locations)...")

        scan_cb = make_discovery_progress_callback(dev.display_name, loc.path, progress_enabled)
        scan_result = scanner.scan_location(dev.serial, loc, progress_cb=scan_cb)
        print(f"\n[+] Scan completed: {scan_result.total_files} accessible files ({format_bytes(scan_result.total_bytes)})")

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

        # Handle Dry-Run Mode
        if dry_run:
            display_preview(preview, cfg)
            print("\n" + "=" * 65)
            print("  DRY RUN SIMULATION RESULT")
            print("=" * 65)
            print(f"  Device              : {dev.display_name}")
            print(f"  Simulated Mode      : DRY-RUN (Zero Files Copied or Modified)")
            print(f"  Target Scope        : {preview.total_files} files ({format_bytes(preview.total_bytes)})")
            print(f"  Database Candidates : {preview.database_backup_candidates}")
            req_b = getattr(preview, "required_space_with_margin", getattr(preview, "required_bytes", 0))
            avail_b = getattr(preview, "available_space", getattr(preview, "available_bytes", 0))
            print(f"  Required Space      : {format_bytes(req_b)}")
            print(f"  Available Space     : {format_bytes(avail_b)}")
            print(f"  Storage Assessment  : {preview.space_message}")
            print("=" * 65 + "\n")
            return

        if acquire_mode and not unattended:
            scope_preview, updated_cats, updated_excluded, proceed = select_acquisition_scope_interactive(
                preview, acq_manager, dev, scan_result, override_output, cfg
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
            display_preview(preview, cfg)

        # 5. Check Disk Space
        if not preview.has_sufficient_space:
            print(format_actionable_error(ERR_INSUFFICIENT_SPACE, context=preview.space_message, device_name=dev.display_name))
            return

        if not acquire_mode:
            # Inventory-only mode: save catalog and generate reports
            print("[*] Inventory-only scan requested. Saving scan catalog...")
            dest_tree = acq_manager.setup_recovery_tree(preview.destination_path)
            rep_gen = ReportGenerator(dev, scan_result, output_dir=dest_tree["reports"])
            h, c, j = rep_gen.generate_all()
            display_scan_completed_summary(dev, scan_result, dest_tree["reports"])
            continue

        # 6. Explicit Acquisition Confirmation
        confirmed = unattended
        if not confirmed:
            confirmed = ask_acquisition_confirmation(preview, preview.destination_path, device_name=dev.display_name)

        if not confirmed:
            print("[*] Acquisition cancelled by user. No files were copied.")
            return

        # 7. Safe File Acquisition
        # Verify connection right before acquisition starts
        if not executor.is_device_connected(dev.serial):
            print(format_actionable_error(ERR_DEVICE_DISCONNECTED, device_name=dev.display_name))
            return

        print_screen_header("FILE ACQUISITION IN PROGRESS", dev, cfg)
        print(f"DEVICE       : {dev.display_name}")
        print(f"PHASE        : FILE ACQUISITION")
        print(f"TOTAL FILES  : {preview.total_files}")
        print(f"TOTAL BYTES  : {format_bytes(preview.total_bytes)}")
        print(f"DESTINATION  : {preview.destination_path}")
        print("-" * 65)

        acq_cb = make_acquisition_progress_callback(dev.display_name, preview.total_files, progress_enabled)

        try:
            records = acq_manager.acquire_files(
                device=dev,
                scan_result=scan_result,
                destination_dir=preview.destination_path,
                selected_categories=selected_cats,
                progress_cb=acq_cb,
                excluded_paths=excluded_paths,
                scan_id=preview.scan_id,
            )
            print("\n[+] Acquisition phase finished.")
        except KeyboardInterrupt:
            print(format_actionable_error(ERR_TRANSFER_INTERRUPTED, device_name=dev.display_name))
            return

        # Check if disconnected during acquisition
        interrupted_file = preview.destination_path / "metadata" / "interrupted.json"
        if interrupted_file.exists():
            print(format_actionable_error(ERR_DEVICE_DISCONNECTED, context="Acquisition session was interrupted due to device disconnection.", device_name=dev.display_name))

        # 8. Post-Acquisition Analysis & Chat Reconstruction
        dest_tree = acq_manager.setup_recovery_tree(preview.destination_path)
        analyzed_dbs = []
        conversations = []

        db_dir = dest_tree.get("Databases", preview.destination_path / "Databases")
        if db_dir.exists():
            for db_file in db_dir.glob("*"):
                if db_file.is_file():
                    db_meta = WhatsAppDatabaseAnalyzer.identify_database(db_file)
                    analyzed_dbs.append(db_meta)

                    if db_meta.is_sqlite and db_meta.table_count > 0:
                        raw_msgs = WhatsAppDatabaseAnalyzer.extract_raw_messages(db_file)
                        if raw_msgs:
                            convs = ChatReconstructionEngine.reconstruct_conversations(raw_msgs)
                            all_acquired = [
                                p for root, _, files in os.walk(preview.destination_path)
                                for p in [Path(root) / fn for fn in files]
                            ]
                            MediaAssociator.associate_media(convs, all_acquired)
                            conversations.extend(convs)

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
        print("\n" + "=" * 65)
        print("  ACQUISITION SUMMARY")
        print("=" * 65)
        print(f"  Device              : {dev.display_name}")
        print(f"  Target Destination  : {preview.destination_path}")
        print(f"  Total Acquired      : {len(records)} files")
        print(f"  SHA-256 Verified    : {verified_cnt} files")
        if conversations:
            print(f"  Chats Reconstructed : {len(conversations)} conversations")
        print(f"  HTML Report         : {h}")
        print(f"  CSV Report          : {c}")
        print(f"  JSON Report         : {j}")
        print("=" * 65 + "\n")


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


def inspect_target(
    target: Path,
    key_path: Optional[Path] = None,
    device_name: Optional[str] = None,
) -> None:
    """Inspect an acquired WhatsApp database or recovery folder."""
    target = target.resolve()
    if not target.exists():
        print(f"[!] Target path does not exist: {target}")
        return

    dev_label = device_name or "Recovery Case"

    if target.is_dir():
        print("\n" + "=" * 65)
        print(f"  INSPECTING RECOVERY DIRECTORY: {target.name}")
        print("=" * 65)
        print(f"  Selected Device    : {dev_label}")
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

        db_candidates = list(target.glob("Databases/*")) + list(target.glob("*.db*"))
        db_files = [f for f in db_candidates if f.is_file() and not f.name.endswith("-journal") and not f.name.endswith("-wal")]
        if db_files:
            print(f"\n  Found {len(db_files)} database candidate(s) in directory:")
            for df in db_files:
                meta = WhatsAppDatabaseAnalyzer.identify_database(df)
                enc_str = f"Encrypted ({meta.crypt_version})" if meta.is_encrypted else ("SQLite" if meta.is_sqlite else "Unknown")
                print(f"   • {df.name:<32} {format_bytes(meta.size_bytes):>10}  Format: {enc_str}")
        print("=" * 65 + "\n")
        return

    # Target is a file
    print("\n" + "=" * 65)
    print(f"  INSPECTING DATABASE FILE: {target.name}")
    print("=" * 65)
    print(f"  Selected Device    : {dev_label}")
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

    print("=" * 65 + "\n")


def inspect_recovery_folder_interactive(device: Optional[DeviceInfo] = None) -> None:
    """Inspect and display metadata of an existing recovery folder."""
    target_str = input("Enter path to recovery directory or database file: ").strip()
    if not target_str:
        return
    key_str = input("Enter path to decryption key (optional, press Enter to skip): ").strip()
    key_p = Path(key_str).resolve() if key_str else None
    dev_name = device.display_name if device else None
    inspect_target(Path(target_str), key_path=key_p, device_name=dev_name)


def verify_acquired_files_interactive(
    device: Optional[DeviceInfo] = None,
    settings: Optional[dict[str, Any]] = None,
) -> None:
    """Interactive integrity verification screen for acquired files (Option 4)."""
    print_screen_header("INTEGRITY VERIFICATION", device, settings)
    path_input = input("Enter recovery directory path to verify: ").strip()
    if not path_input:
        return

    rec_path = Path(path_input).resolve()
    if not rec_path.exists():
        print(f"[!] Path does not exist: {rec_path}")
        return

    print(f"\n[*] Verifying cryptographic SHA-256 hashes against manifest: {rec_path.name}...")
    res = verify_recovery_directory(rec_path)
    if not res.get("success"):
        print(f"[!] Verification could not be completed: {res.get('error')}")
        return

    # Check device recorded in manifest if available
    dev_recorded = res.get("device_name") or (device.display_name if device else "Recorded Device")

    print("\n" + "=" * 65)
    print("  INTEGRITY VERIFICATION RESULT")
    print("=" * 65)
    print(f"  Device              : {dev_recorded}")
    print(f"  Recovery Path       : {rec_path}")
    print(f"  Total Checked Files : {res['total']}")
    print(f"  Cryptographically OK: {res['verified_count']}")
    print(f"  Hash Mismatches     : {res['mismatch_count']}")
    print(f"  Missing Acquired    : {res['missing_count']}")
    status_label = "PASSED — FULLY INTACT" if res["is_fully_intact"] else "FAILED — INTEGRITY WARNINGS DETECTED"
    print(f"  Status Assessment   : {status_label}")
    print("=" * 65 + "\n")


def review_database_candidates_interactive(
    device: Optional[DeviceInfo] = None,
    settings: Optional[dict[str, Any]] = None,
) -> None:
    """Interactive database candidate reviewer and inspector (Option 6)."""
    print_screen_header("REVIEW DATABASE CANDIDATES", device, settings)
    base_dir_input = input("Enter recovery folder path to inspect (default: ./recovery): ").strip()
    base_dir = Path(base_dir_input).resolve() if base_dir_input else Path("recovery").resolve()

    if not base_dir.exists():
        print(f"[!] Directory not found: {base_dir}")
        return

    # Find database candidates (*.db, *.db.crypt*)
    db_files: List[Path] = []
    for root, _, files in os.walk(base_dir):
        for f in files:
            if (f.endswith(".db") or ".crypt" in f) and not f.endswith("-journal") and not f.endswith("-wal"):
                db_files.append(Path(root) / f)

    if not db_files:
        print(f"[*] No database candidate files found in: {base_dir}")
        return

    print(f"\nFound {len(db_files)} database candidate(s):\n")
    print(f"  {'#':<4} {'FILE NAME':<34} {'SIZE':>10}  {'FORMAT / CRYPT':<22}")
    print("  " + "-" * 72)

    metas = []
    for idx, df in enumerate(db_files, start=1):
        meta = WhatsAppDatabaseAnalyzer.identify_database(df)
        metas.append(meta)
        enc_str = f"Encrypted ({meta.crypt_version})" if meta.is_encrypted else ("SQLite Database" if meta.is_sqlite else "Unknown")
        print(f"  [{idx:<2}] {df.name:<34} {format_bytes(meta.size_bytes):>10}  {enc_str:<22}")

    print("\nOptions:")
    print("  [1-N] Inspect specific database file")
    print("  [c]   Return to main menu")

    choice = input("\nEnter choice: ").strip().lower()
    if choice == "c" or not choice:
        return

    try:
        idx = int(choice)
        if 1 <= idx <= len(db_files):
            chosen_file = db_files[idx - 1]
            key_in = input("Enter path to decryption key (leave blank if unencrypted or unavailable): ").strip()
            key_p = Path(key_in).resolve() if key_in else None
            inspect_target(chosen_file, key_path=key_p, device_name=device.display_name if device else None)
    except ValueError:
        print("Invalid choice.")


def export_and_package_menu_interactive(device: Optional[DeviceInfo] = None) -> None:
    """Submenu for chat export and ZIP archive packaging (Option 5)."""
    print_screen_header("EXPORT REPORTS & ARCHIVE", device)
    print("  [1] Reconstruct and export conversations from database (HTML, JSON, CSV, TXT)")
    print("  [2] Package recovery directory into verified ZIP archive")
    print("  [3] Return to main menu")

    choice = input("\nEnter choice [1-3]: ").strip()
    if choice == "1":
        reconstruct_and_export_interactive()
    elif choice == "2":
        package_zip_interactive()


def settings_menu_interactive(settings: dict[str, Any]) -> None:
    """Interactive persistent configuration editor (Option 7)."""
    while True:
        ui = settings.setdefault("ui", {})
        acq = settings.setdefault("acquisition", {})

        mask_enabled = ui.get("mask_device_serial", False)
        prog_enabled = ui.get("progress_display_enabled", True)
        rec_dir = acq.get("default_recovery_dir", "recovery")
        margin_b = acq.get("safety_margin_bytes", 104857600)
        margin_r = acq.get("safety_margin_ratio", 0.10)

        print("\n" + "=" * 65)
        print("  WRS — SETTINGS & PERSISTENT CONFIGURATION")
        print("=" * 65)
        print(f"  [1] Device Serial Masking       : {'ENABLED' if mask_enabled else 'DISABLED'}")
        print(f"  [2] Scan Progress Display       : {'ENABLED' if prog_enabled else 'DISABLED'}")
        print(f"  [3] Default Recovery Directory  : {rec_dir}")
        print(f"  [4] Safety Margin Bytes         : {format_bytes(margin_b)} ({margin_b} bytes)")
        print(f"  [5] Safety Margin Ratio         : {int(margin_r * 100)}%")
        print("  [6] Reset Settings to Safe Defaults")
        print("  [7] Return to Main Menu")
        print("-" * 65)

        opt = input("\nEnter option [1-7]: ").strip()
        if opt == "1":
            ui["mask_device_serial"] = not mask_enabled
            save_settings(settings)
            print(f"[+] Device serial masking is now: {'ENABLED' if ui['mask_device_serial'] else 'DISABLED'}")
        elif opt == "2":
            ui["progress_display_enabled"] = not prog_enabled
            save_settings(settings)
            print(f"[+] Progress display is now: {'ENABLED' if ui['progress_display_enabled'] else 'DISABLED'}")
        elif opt == "3":
            new_dir = input(f"Enter new default recovery directory [{rec_dir}]: ").strip()
            if new_dir:
                acq["default_recovery_dir"] = new_dir
                save_settings(settings)
                print(f"[+] Default recovery directory set to: {new_dir}")
        elif opt == "4":
            new_mb = input(f"Enter safety margin in megabytes (MB) [{margin_b // 1048576}]: ").strip()
            if new_mb.isdigit() and int(new_mb) >= 0:
                acq["safety_margin_bytes"] = int(new_mb) * 1048576
                save_settings(settings)
                print(f"[+] Safety margin set to: {format_bytes(acq['safety_margin_bytes'])}")
        elif opt == "5":
            new_ratio = input(f"Enter safety margin percentage (0-50) [{int(margin_r * 100)}]: ").strip()
            if new_ratio.isdigit() and 0 <= int(new_ratio) <= 50:
                acq["safety_margin_ratio"] = int(new_ratio) / 100.0
                save_settings(settings)
                print(f"[+] Safety margin ratio set to: {int(acq['safety_margin_ratio'] * 100)}%")
        elif opt == "6":
            ui["mask_device_serial"] = False
            ui["progress_display_enabled"] = True
            acq["default_recovery_dir"] = "recovery"
            acq["safety_margin_bytes"] = 104857600
            acq["safety_margin_ratio"] = 0.10
            save_settings(settings)
            print("[+] Settings reset to factory defaults.")
        elif opt == "7" or opt.lower() == "c":
            return
        else:
            print("Invalid option.")


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

    db_file: Optional[Path] = None
    media_dir: Optional[Path] = None

    if target.is_file():
        db_file = target
        media_dir = target.parent
    else:
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
    """Main terminal menu loop with startup preflight and 9-option dispatcher."""
    executor = AdbExecutor()
    settings = load_settings()

    # Preflight Check & Device Detection
    all_devs, selected_dev = detect_and_display_startup_devices(executor, settings)

    # If 0 devices connected, offer retry or continue
    if not all_devs:
        while not all_devs:
            try:
                prompt_act = input("Select [R] to Retry device detection, or [Q] to Exit: ").strip().lower()
                if prompt_act == "q":
                    print("\nExiting WRS. Goodbye.")
                    sys.exit(0)
                elif prompt_act == "r":
                    executor.clear_cache()
                    all_devs, selected_dev = detect_and_display_startup_devices(executor, settings)
                else:
                    print("Invalid choice. Press 'R' to retry detection or 'Q' to exit.")
            except (KeyboardInterrupt, EOFError):
                print("\nExiting WRS.")
                sys.exit(0)

    while True:
        # Keep selected device name visible at top of main menu
        mask = settings.get("ui", {}).get("mask_device_serial", False)
        dev_title = "None"
        if selected_dev:
            s_disp = selected_dev.get_display_serial(masked=mask)
            dev_title = f"{selected_dev.display_name} ({s_disp})" if s_disp else selected_dev.display_name

        print("\n" + "=" * 65)
        print("          WRS — WHATSAPP RECOVERY SCANNER")
        print("=" * 65)
        print(f"Selected Device: {dev_title}\n")
        print("[1] Scan and discover WhatsApp data")
        print("[2] Scan and acquire data")
        print("[3] Inspect an existing recovery case")
        print("[4] Verify acquired files")
        print("[5] Export reports and ZIP archive")
        print("[6] Review database candidates")
        print("[7] Settings and configuration")
        print("[8] Refresh connected devices")
        print("[9] Exit")
        print("=" * 65)

        try:
            choice = input("\nEnter choice [1-9]: ").strip()
            if choice == "1":
                if not selected_dev or not selected_dev.is_accessible:
                    print("[!] No accessible Android device selected. Attempting device detection...")
                    _, selected_dev = detect_and_display_startup_devices(executor, settings)
                    if not selected_dev or not selected_dev.is_accessible:
                        print("[!] Cannot start scan: Device is not authorized or offline.")
                        continue
                run_interactive_workflow(executor, acquire_mode=False, override_serial=selected_dev.serial, settings=settings)

            elif choice == "2":
                if not selected_dev or not selected_dev.is_accessible:
                    print("[!] No accessible Android device selected. Attempting device detection...")
                    _, selected_dev = detect_and_display_startup_devices(executor, settings)
                    if not selected_dev or not selected_dev.is_accessible:
                        print("[!] Cannot start acquisition: Device is not authorized or offline.")
                        continue
                run_interactive_workflow(executor, acquire_mode=True, override_serial=selected_dev.serial, settings=settings)

            elif choice == "3":
                inspect_recovery_folder_interactive(selected_dev)

            elif choice == "4":
                verify_acquired_files_interactive(selected_dev, settings)

            elif choice == "5":
                export_and_package_menu_interactive(selected_dev)

            elif choice == "6":
                review_database_candidates_interactive(selected_dev, settings)

            elif choice == "7":
                settings_menu_interactive(settings)

            elif choice == "8":
                print("\n[*] Refreshing connected Android devices...")
                executor.clear_cache()
                all_devs, selected_dev = detect_and_display_startup_devices(executor, settings)

            elif choice == "9":
                print("\nExiting WRS. Goodbye.")
                sys.exit(0)

            else:
                print("Invalid choice. Please select a number from 1 to 9.")

        except KeyboardInterrupt:
            print("\nOperation cancelled. Returning to main menu...")
        except EOFError:
            print("\nExiting WRS. Goodbye.")
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
    parser.add_argument("--dry-run", action="store_true", help="Simulate acquisition inventory without copying files")
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
    settings = load_settings()
    key_path = Path(args.key).resolve() if args.key else None

    # 1. Standalone verification mode
    if args.verify:
        print_banner(executor, settings=settings)
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
        print_banner(executor, settings=settings)
        inspect_target(Path(args.inspect), key_path=key_path)
        sys.exit(0)

    # 3. Export mode
    if args.export:
        print_banner(executor, settings=settings)
        out_dir = Path(args.output).resolve() if args.output else None
        export_target(Path(args.export), export_format=args.format or "all", key_path=key_path, output_dir=out_dir)
        sys.exit(0)

    # 4. List devices mode
    if args.list_devices:
        detect_and_display_startup_devices(executor, settings)
        sys.exit(0)

    # 5. Headless / CLI scan, acquire, or dry-run mode
    if args.scan or args.acquire or args.dry_run:
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
            dry_run=args.dry_run,
            settings=settings,
        )
        sys.exit(0)

    # 6. Interactive menu mode
    interactive_menu()


if __name__ == "__main__":
    main()
