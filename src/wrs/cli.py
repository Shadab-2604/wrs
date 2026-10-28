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
from .device import AdbExecutor, DeviceInfo, DeviceStatusResult
from .discovery import DiscoveredLocation, StorageDiscovery
from .duplicate import DuplicateDetector
from .state import RuntimeStateManager
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
from .wizard import (
    CATEGORY_MENU_MAP,
    DateRangeEngine,
    RecoverySelectionPreview,
    parse_category_selection,
    resolve_storage_categories,
    parse_date_dd_mm_yyyy,
)
from .restore import (
    CandidateSourceType,
    RestoreAssistant,
    RestoreCandidate,
    RestoreCandidateStatus,
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
    device_status: Optional[DeviceStatusResult] = None,
) -> None:
    """Display authentic terminal banner with independent ADB and Android device statuses."""
    now_str = format_timestamp()

    mask = False
    if settings and settings.get("ui", {}).get("mask_device_serial"):
        mask = True

    # 1. Obtain authentic status if not provided
    status = device_status
    if status is None:
        status = executor.check_device_status(selected_serial=device.serial if device else None)

    # 2. Determine ADB Status string
    adb_status_str = status.adb_status_display

    # 3. Determine Android Device string
    if device:
        if device.is_authorized:
            device_status_str = f"{device.display_name} (CONNECTED AND AUTHORIZED)"
        elif device.state == "unauthorized":
            device_status_str = f"UNAUTHORIZED ({device.get_display_serial(masked=mask)})"
        elif device.state == "offline":
            device_status_str = f"OFFLINE ({device.get_display_serial(masked=mask)})"
        elif device.state in ("disconnected", "unavailable"):
            device_status_str = f"DISCONNECTED ({device.get_display_serial(masked=mask)})"
        else:
            device_status_str = f"{device.state.upper()} ({device.get_display_serial(masked=mask)})"
    else:
        device_status_str = status.device_status_display

    top_border = f"╭{'─' * 18} WRS — WhatsApp Recovery Scanner {'─' * 18}╮"
    bot_border = f"╰{'─' * 12} Forensic Acquisition & Preservation Utility {'─' * 12}╯"

    if HAS_RICH and console and hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
        from rich import box
        content = (
            f"[bold cyan]Processing Mode[/bold cyan] : [bold]100% Local Execution[/bold]\n"
            f"[bold cyan]ADB Status     [/bold cyan] : [bold green]{adb_status_str}[/bold green]\n"
            f"[bold cyan]Android Device [/bold cyan] : [bold yellow]{device_status_str}[/bold yellow]\n"
            f"[bold cyan]Version        [/bold cyan] : v{__version__}\n"
            f"[bold cyan]Timestamp      [/bold cyan] : {now_str}"
        )
        panel = Panel(
            content,
            title="[bold white]WRS — WhatsApp Recovery Scanner[/bold white]",
            subtitle="[dim]Forensic Acquisition & Preservation Utility[/dim]",
            box=box.ROUNDED,
            border_style="cyan",
            width=72,
        )
        console.print(panel)
    else:
        print(top_border)
        print(f"│ {'Processing Mode : 100% Local Execution':<68} │")
        print(f"│ {f'ADB Status      : {adb_status_str}':<68} │")
        print(f"│ {f'Android Device  : {device_status_str}':<68} │")
        print(f"│ {f'Version         : v{__version__}':<68} │")
        print(f"│ {f'Timestamp       : {now_str}':<68} │")
        print(bot_border)


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

    Displays environment, independent ADB and device statuses, connected devices count,
    current time, and structured device details before returning (all_devices, selected_device).
    """
    status = executor.check_device_status()
    RuntimeStateManager.get_instance().sync_device_status(status)

    env_str = get_environment_name()
    now_str = status.timestamp or format_timestamp()

    mask = False
    if settings and settings.get("ui", {}).get("mask_device_serial"):
        mask = True

    # 1. ADB Missing or Command Error
    if not status.adb_available:
        print_banner(executor, settings=settings, device_status=status)
        print("\n" + "=" * 62)
        print("          WRS — WHATSAPP RECOVERY SCANNER")
        print("=" * 62)
        print(f"Environment       : {env_str}")
        print(f"ADB Status        : {status.adb_status_display}")
        print(f"Connected Devices : 0")
        print(f"Current Time      : {now_str}")
        print(format_actionable_error(ERR_ADB_NOT_FOUND, context=status.adb_version_raw or status.enumeration_error))
        return [], None

    # 2. Enumeration Failed
    if not status.enumeration_success:
        print_banner(executor, settings=settings, device_status=status)
        print("\n" + "=" * 62)
        print("          WRS — WHATSAPP RECOVERY SCANNER")
        print("=" * 62)
        print(f"Environment       : {env_str}")
        print(f"ADB Status        : {status.adb_status_display}")
        print(f"Device Listing    : FAILED")
        print(f"Reason            : {status.enumeration_error}")
        print(f"Current Time      : {now_str}")
        print("-" * 62)
        print("[!] Device enumeration failed. Check ADB daemon or permissions.")
        print("=" * 62 + "\n")
        return [], None

    # 3. Successful enumeration
    devices = status.devices

    # 3A. Zero devices connected
    if not devices:
        print_banner(executor, settings=settings, device_status=status)
        print("\n" + "=" * 62)
        print("          WRS — WHATSAPP RECOVERY SCANNER")
        print("=" * 62)
        print(f"Environment       : {env_str}")
        print(f"ADB Status        : {status.adb_status_display}")
        print(f"Connected Devices : 0")
        print(f"Current Time      : {now_str}")
        print("\nCONNECTED ANDROID DEVICES")
        print("-" * 62)
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

    # 3B. Exactly one device connected
    if len(devices) == 1:
        dev = devices[0]
        # Query full properties only for authorized device
        if dev.is_authorized and dev.serial not in executor._device_cache:
            dev = executor.get_device_details(dev.serial)
            devices[0] = dev

        print_banner(executor, device=dev, settings=settings, device_status=status)
        print("\n" + "=" * 62)
        print("          WRS — WHATSAPP RECOVERY SCANNER")
        print("=" * 62)
        print(f"Environment       : {env_str}")
        print(f"ADB Status        : {status.adb_status_display}")
        print(f"Connected Devices : 1")
        print(f"Current Time      : {now_str}")
        print("\nCONNECTED ANDROID DEVICES")
        print("-" * 62)

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

    # 3C. Multiple devices connected
    print_banner(executor, settings=settings, device_status=status)
    print("\n" + "=" * 62)
    print("          WRS — WHATSAPP RECOVERY SCANNER")
    print("=" * 62)
    print(f"Environment       : {env_str}")
    print(f"ADB Status        : {status.adb_status_display}")
    print(f"Connected Devices : {len(devices)}")
    print(f"Current Time      : {now_str}")
    print("\nCONNECTED ANDROID DEVICES")
    print("-" * 62)

    for idx, d in enumerate(devices, start=1):
        if d.is_authorized and d.serial not in executor._device_cache:
            d = executor.get_device_details(d.serial)
            devices[idx - 1] = d

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

    # Check connection stability and revalidate device
    val_ok, reval_dev, val_msg = executor.revalidate_selected_device(dev.serial)
    if not val_ok:
        if not executor.is_device_connected(dev.serial):
            print(format_actionable_error(ERR_DEVICE_DISCONNECTED, context=val_msg, device_name=dev.display_name))
        elif dev.state == "unauthorized":
            print(format_actionable_error(ERR_DEVICE_UNAUTHORIZED, device_name=dev.display_name))
        elif dev.state == "offline":
            print(format_actionable_error(ERR_DEVICE_OFFLINE, device_name=dev.display_name))
        else:
            print(f"[!] Device validation failed: {val_msg}")
        return
    dev = reval_dev or dev

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
        # Verify connection and authorization right before acquisition starts
        acq_ok, acq_dev, acq_msg = executor.revalidate_selected_device(dev.serial)
        if not acq_ok:
            print(format_actionable_error(ERR_DEVICE_DISCONNECTED, context=acq_msg, device_name=dev.display_name))
            return
        dev = acq_dev or dev

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


def find_chat_database_candidates(base_dir: Path | str = "recovery") -> List[Path]:
    """Find all potential database candidates in local recovery directory."""
    base = Path(base_dir).resolve()
    if not base.exists():
        return []
    candidates: List[Path] = []
    for root, _, files in os.walk(base):
        for f in files:
            lower_f = f.lower()
            if lower_f.endswith(("-wal", "-shm", "-journal", ".lock", ".tmp")):
                continue
            if lower_f.endswith(".db") or ".crypt" in lower_f or "msgstore" in lower_f:
                candidates.append(Path(root) / f)
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates


def category_selection_interactive(current_selection: Optional[List[str]] = None) -> List[str]:
    """Interactive category selection screen (Phase 4, Option [2])."""
    curr = current_selection or ["All Supported Data"]
    curr_str = ", ".join(curr)

    print("\n" + "=" * 56)
    print("       WRS — SELECT DATA CATEGORIES")
    print("=" * 56)
    print(f"Current Selection : {curr_str}\n")
    print("[1] All Supported Data")
    print("[2] Chat History")
    print("[3] Photos and Images")
    print("[4] Videos")
    print("[5] Audio Files")
    print("[6] Voice Notes")
    print("[7] Documents and Files")
    print("[8] Stickers")
    print("[9] GIFs and Animated Media")
    print("[10] Thumbnails")
    print("[11] Databases and Backups")
    print("[12] Other Supported Files\n")
    print("Enter multiple options separated by commas.")
    print("Example: 2,4,7\n")
    print("[A] Select All")
    print("[C] Clear Selection")
    print("[0] Back\n")

    user_in = input("Your selection: ").strip()
    valid, selected, includes_chats, msg = parse_category_selection(user_in)
    if not valid:
        print(f"[!] {msg}")
        return current_selection or ["All Supported Data"]

    if msg == "BACK":
        return current_selection or ["All Supported Data"]

    if msg == "Selection cleared.":
        print("[*] Category selection cleared.")
        return []

    print(f"[+] {msg}")
    print(f"    Active Categories: {', '.join(selected)}")
    return selected


def recovery_wizard_flow(
    executor: AdbExecutor,
    selected_dev: Optional[DeviceInfo],
    settings: dict[str, Any],
    active_categories: List[str],
) -> None:
    """Recovery Operation Selection (Phase 4, Option [1])."""
    dev_name = selected_dev.display_name if selected_dev else "NONE DETECTED"
    cats_str = ", ".join(active_categories) if active_categories else "All Supported Data"

    while True:
        print("\n" + "=" * 56)
        print("       WRS — RECOVERY OPERATION SELECTION")
        print("=" * 56)
        print(f"Selected Device : {dev_name}")
        print(f"Categories      : {cats_str}\n")
        print("SELECT OPERATION\n")
        print("[1] Scan Only")
        print("    Discover data and calculate counts and sizes.\n")
        print("[2] Acquire Files")
        print("    Copy selected accessible files to the recovery directory.\n")
        print("[3] Analyze Chat Databases")
        print("    Inspect supported readable databases and backup candidates.\n")
        print("[4] Export Readable Chats")
        print("    Export supported, actually available chat records.\n")
        print("[5] Export Selected Media")
        print("    Export selected media files and their metadata.\n")
        print("[6] Prepare Native WhatsApp Restore")
        print("    Validate supported backup candidates and guide the user")
        print("    through an applicable native WhatsApp restoration process.\n")
        print("[7] Verify Acquired Data")
        print("    Verify existing acquired files and their integrity.\n")
        print("[0] Back\n")

        op = input("Select an operation [0-7]: ").strip()
        if op == "0" or op.lower() == "back":
            return
        elif op == "1":
            if not selected_dev or not selected_dev.is_accessible:
                print("[!] Scan Only requires an accessible, authorized Android device.")
                print("    Please connect and authorize a device, then retry.")
                return
            cats_set = resolve_storage_categories(active_categories) if active_categories else None
            run_interactive_workflow(executor, acquire_mode=False, override_serial=selected_dev.serial, selected_categories=cats_set, settings=settings)
            return
        elif op == "2":
            if not selected_dev or not selected_dev.is_accessible:
                print("[!] File Acquisition requires an accessible, authorized Android device.")
                print("    Please connect and authorize a device, then retry.")
                return
            cats_set = resolve_storage_categories(active_categories) if active_categories else None
            run_interactive_workflow(executor, acquire_mode=True, override_serial=selected_dev.serial, selected_categories=cats_set, settings=settings)
            return
        elif op == "3":
            inspect_backups_and_databases_interactive(executor, selected_dev, settings)
            return
        elif op == "4":
            recover_chat_history_interactive(selected_dev, settings)
            return
        elif op == "5":
            recover_media_interactive(selected_dev, settings, active_categories)
            return
        elif op == "6":
            guided_native_restore_flow(executor, selected_dev, settings)
            return
        elif op == "7":
            verify_acquired_files_interactive(selected_dev, settings)
            return
        else:
            print("[!] Invalid operation choice. Enter a number between 0 and 7.")


def recover_chat_history_interactive(
    device: Optional[DeviceInfo],
    settings: dict[str, Any],
) -> None:
    """Chat History Availability Discovery & Date-Range Recovery (Phase 4, Option [3])."""
    dev_name = device.display_name if device else "NONE DETECTED"

    print("\n" + "=" * 56)
    print("       WRS — RECOVER CHAT HISTORY")
    print("=" * 56)

    # 1. Look for existing databases in recovery folder or prompt user
    candidates = find_chat_database_candidates("recovery")
    chosen_db: Optional[Path] = None

    if candidates:
        print(f"[*] Found {len(candidates)} database candidate(s) in local recovery:")
        for idx, c in enumerate(candidates[:5], start=1):
            meta = WhatsAppDatabaseAnalyzer.identify_database(c)
            fmt_lbl = f"Encrypted ({meta.crypt_version})" if meta.is_encrypted else ("SQLite" if meta.is_sqlite else "Unknown")
            print(f"  [{idx}] {c.name} ({format_bytes(meta.size_bytes)}) - {fmt_lbl}")
        if len(candidates) > 5:
            print(f"  ... and {len(candidates) - 5} more.")
        print("  [C] Custom path to database")
        print("  [0] Back")

        pick = input("\nSelect candidate [1-N / C / 0]: ").strip().lower()
        if pick == "0":
            return
        elif pick == "c":
            p_in = input("Enter path to database file: ").strip()
            if p_in:
                chosen_db = Path(p_in).resolve()
        elif pick.isdigit() and 1 <= int(pick) <= min(len(candidates), 5):
            chosen_db = candidates[int(pick) - 1]

    if not chosen_db:
        if not candidates:
            p_in = input("Enter path to database file (or press Enter to view chat status): ").strip()
            if p_in:
                chosen_db = Path(p_in).resolve()

    # 2. If no readable database established, show CHAT HISTORY STATUS screen (Section 6)
    if not chosen_db or not chosen_db.exists():
        print("\n" + "=" * 56)
        print("       CHAT HISTORY STATUS")
        print("=" * 56)
        print("No readable chat source has been established.\n")
        print("Possible reasons:")
        print("- No database or backup was found in accessible locations.")
        print("- The available database is encrypted and cannot currently be processed.")
        print("- The source format is unsupported.")
        print("- The available files contain media but no readable messages.\n")
        print("No chat records have been reconstructed.\n")
        print("Next actions:")
        print("[1] Scan additional accessible locations")
        print("[2] Inspect discovered database candidates")
        print("[3] Import an existing supported chat export")
        print("[0] Back\n")

        act = input("Select an action [0-3]: ").strip()
        if act == "2":
            inspect_backups_and_databases_interactive(AdbExecutor(), device, settings)
        return

    # 3. Check encryption and extract messages
    meta = WhatsAppDatabaseAnalyzer.identify_database(chosen_db)
    active_db = chosen_db
    if meta.is_encrypted:
        print(f"\n[*] Selected database is encrypted ({meta.crypt_version}). Decryption key required.")
        key_str = input("Enter path to WhatsApp key file (leave blank to cancel): ").strip()
        if not key_str:
            print("[*] Operation cancelled: cannot parse encrypted database without key.")
            return
        key_p = Path(key_str).resolve()
        dec_dest = chosen_db.parent / f"{chosen_db.stem}_decrypted.db"
        ok, msg = WhatsAppDatabaseAnalyzer.decrypt_crypt_database(chosen_db, key_p, dec_dest)
        if not ok:
            print(f"[!] Decryption failed: {msg}")
            return
        active_db = dec_dest

    raw_msgs = WhatsAppDatabaseAnalyzer.extract_raw_messages(active_db)
    if not raw_msgs:
        print("[!] No readable message records could be extracted from database.")
        return

    conversations = ChatReconstructionEngine.reconstruct_conversations(raw_msgs)
    if not conversations:
        print("[!] No conversation threads could be reconstructed from raw messages.")
        return

    # 4. Extract Oldest-to-Most-Recent Chat Timeline (Section 7)
    timeline = DateRangeEngine.extract_timeline(conversations)

    while True:
        print("\n" + "=" * 56)
        print("       AVAILABLE CHAT HISTORY")
        print("=" * 56)
        print(f"Oldest Available Message : {timeline.oldest_formatted}")
        print(f"Most Recent Message      : {timeline.newest_formatted}\n")
        print(f"Readable Messages        : {timeline.total_messages}")
        print(f"Conversations            : {timeline.total_conversations}")
        print(f"Missing Timestamps       : {timeline.missing_timestamps_count}\n")
        print("Choose History Range\n")
        print("[1] All Available History")
        print("[2] Custom Date Range")
        print("[3] Select One Conversation")
        print("[4] Select Multiple Conversations")
        print("[0] Back\n")

        range_choice = input("Select an option [0-4]: ").strip()
        if range_choice == "0":
            return

        selected_convs: List[Conversation] = conversations
        requested_range_str = "All Available History"
        excluded_missing = 0

        if range_choice == "1":
            selected_convs = conversations
            requested_range_str = "All Available History"

        elif range_choice == "2":
            # Custom date range (DD-MM-YYYY)
            print(f"\nAvailable boundaries: {timeline.oldest_formatted} to {timeline.newest_formatted}")
            start_in = input("Start Date (DD-MM-YYYY): ").strip()
            end_in = input("End Date   (DD-MM-YYYY): ").strip()

            valid, s_dt, e_dt, val_msg = DateRangeEngine.validate_date_range(
                start_in, end_in, timeline.oldest_dt, timeline.newest_dt
            )
            if not valid or s_dt is None or e_dt is None:
                print(f"[!] Date range rejected: {val_msg}")
                continue

            if "Partial overlap" in val_msg:
                print(f"[*] {val_msg}")
                proceed_adj = input("Accept adjusted range? [y/N]: ").strip().lower()
                if proceed_adj not in ("y", "yes"):
                    continue

            selected_convs, excluded_missing = DateRangeEngine.filter_conversations_by_date(conversations, s_dt, e_dt)
            requested_range_str = f"{s_dt.strftime('%d-%m-%Y')} to {e_dt.strftime('%d-%m-%Y')}"
            if not selected_convs:
                print(f"[!] No chat records found within range {requested_range_str}.")
                continue

        elif range_choice in ("3", "4"):
            # Conversation Selection (Section 10)
            print("\n" + "=" * 56)
            print("       SELECT CONVERSATIONS")
            print("=" * 56)
            for idx, c in enumerate(conversations[:20], start=1):
                print(f"[{idx:<2}] {c.display_name:<30} | {len(c.messages)} messages")
            if len(conversations) > 20:
                print(f"... and {len(conversations) - 20} more conversations.")
            print("[A]  All Conversations")
            print("[0]  Back\n")

            conv_in = input("Your selection: ").strip()
            if conv_in == "0":
                continue
            elif conv_in.upper() == "A":
                selected_convs = conversations
            else:
                tokens = [t.strip() for t in conv_in.replace(" ", ",").split(",") if t.strip()]
                picked_indices = []
                for tok in tokens:
                    if tok.isdigit() and 1 <= int(tok) <= len(conversations):
                        picked_indices.append(int(tok) - 1)
                if not picked_indices:
                    print("[!] No valid conversation indices selected.")
                    continue
                selected_convs = [conversations[i] for i in picked_indices]
                requested_range_str = f"Specific conversations ({len(selected_convs)} selected)"

        # Ask Section 5: Include media referenced by selected chats?
        inc_media = input("\nInclude media referenced by selected chats? [y/N]: ").strip().lower() in ("y", "yes")
        matched_media_files = []
        if inc_media:
            # Search for media in database parent directory or recovery folder
            search_base = chosen_db.parent.parent if chosen_db.parent.name == "Databases" else chosen_db.parent
            media_files = [p for root, _, files in os.walk(search_base) for p in [Path(root) / fn for fn in files]]
            MediaAssociator.associate_media(selected_convs, media_files)
            for c in selected_convs:
                for m in c.messages:
                    if m.media_reference and m.media_reference.resolved_path:
                        p = Path(m.media_reference.resolved_path)
                        if p.exists() and p not in matched_media_files:
                            matched_media_files.append(p)

        # 5. Acquisition and Export Preview (Section 12)
        total_msgs = sum(len(c.messages) for c in selected_convs)
        media_size = sum(f.stat().st_size for f in matched_media_files)
        # Approximate size of exported chat text
        chat_text_size = sum(len(m.body or "") for c in selected_convs for m in c.messages)

        dest_export_dir = Path("recovery") / f"chat_export_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"

        print("\n" + "=" * 56)
        print("       RECOVERY SELECTION PREVIEW")
        print("=" * 56)
        print(f"Device               : {dev_name}")
        print("Operation            : Export Readable Chats")
        print(f"Categories           : Chat History{' + Associated Media' if inc_media else ''}\n")
        print(f"Chat Source           : {chosen_db.name} (Reconstructed)")
        print(f"Oldest Available Date : {timeline.oldest_formatted}")
        print(f"Newest Available Date : {timeline.newest_formatted}\n")
        print(f"Requested Range       : {requested_range_str}")
        print(f"Selected Conversations: {len(selected_convs)}")
        print(f"Selected Messages     : {total_msgs}")
        print(f"Selected Files        : {len(matched_media_files)} media files")
        print(f"Total Selected Size   : {format_bytes(media_size + chat_text_size)}\n")
        print(f"Unreadable Records    : 0")
        print(f"Missing Timestamps    : {excluded_missing}")
        print(f"Unmatched Media       : 0\n")
        print(f"Destination           : {dest_export_dir}")
        print("=" * 56 + "\n")

        # 6. Explicit Confirmation (Section 13)
        print("You are about to export selected chat records.\n")
        print(f"Conversations : {len(selected_convs)}")
        print(f"Messages      : {total_msgs}")
        print(f"Date Range    : {requested_range_str}")
        print("Output Format : TXT, HTML, JSON, and ZIP archive")
        print(f"Destination   : {dest_export_dir}\n")

        proceed = input("Proceed? [y/N]: ").strip().lower()
        if proceed not in ("y", "yes"):
            print("[*] Operation cancelled. Returning to menu.")
            return

        # 7. Execute Export (Section 14)
        dest_export_dir.mkdir(parents=True, exist_ok=True)
        chats_sub = dest_export_dir / "chats"
        chats_sub.mkdir(parents=True, exist_ok=True)

        for c in selected_convs:
            safe_cname = sanitize_filename(c.display_name)[:30]
            ChatExporter.export_conversation_txt(c, chats_sub / f"{safe_cname}.txt")
            ChatExporter.export_conversation_html(c, chats_sub / f"{safe_cname}.html")
            ChatExporter.export_conversation_json(c, chats_sub / f"{safe_cname}.json")
            ChatExporter.export_conversation_csv(c, chats_sub / f"{safe_cname}.csv")

        # Copy associated media if selected
        if matched_media_files:
            media_sub = dest_export_dir / "media"
            media_sub.mkdir(parents=True, exist_ok=True)
            for mf in matched_media_files:
                try:
                    shutil.copy2(mf, media_sub / mf.name)
                except OSError:
                    pass

        # Manifest
        manifest = {
            "generator": "WRS Chat Recovery Engine",
            "export_timestamp": format_timestamp(),
            "source_database": str(chosen_db),
            "requested_date_range": requested_range_str,
            "selected_conversations_count": len(selected_convs),
            "selected_messages_count": total_msgs,
            "excluded_records_missing_timestamps": excluded_missing,
            "associated_media_count": len(matched_media_files),
        }
        (dest_export_dir / "export_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        # Create ZIP package
        zip_path = dest_export_dir.parent / f"{dest_export_dir.name}.zip"
        ZipPackager.package_recovery_archive(dest_export_dir, zip_path)

        print("\n[+] Chat export completed successfully!")
        print(f"    Export directory : {dest_export_dir}")
        print(f"    Archive package  : {zip_path}")
        print("    Note: Exported archives do NOT restore WhatsApp chats into the WhatsApp app.")
        return


def view_available_chat_dates_interactive(
    device: Optional[DeviceInfo],
    settings: dict[str, Any],
) -> None:
    """Chronological Available-Date Calendar (Phase 4, Option [6])."""
    print("\n" + "=" * 56)
    print("       WRS — VIEW AVAILABLE CHAT DATES")
    print("=" * 56)

    candidates = find_chat_database_candidates("recovery")
    chosen_db: Optional[Path] = None
    if candidates:
        chosen_db = candidates[0]
    else:
        p_in = input("Enter path to readable database file: ").strip()
        if p_in:
            chosen_db = Path(p_in).resolve()

    if not chosen_db or not chosen_db.exists():
        print("[!] No readable chat database found. Please acquire or inspect a database first.")
        return

    meta = WhatsAppDatabaseAnalyzer.identify_database(chosen_db)
    active_db = chosen_db
    if meta.is_encrypted:
        key_str = input("Database is encrypted. Enter path to key file (leave blank to cancel): ").strip()
        if not key_str:
            return
        dec_dest = chosen_db.parent / f"{chosen_db.stem}_decrypted.db"
        ok, msg = WhatsAppDatabaseAnalyzer.decrypt_crypt_database(chosen_db, Path(key_str).resolve(), dec_dest)
        if not ok:
            print(f"[!] Decryption failed: {msg}")
            return
        active_db = dec_dest

    raw_msgs = WhatsAppDatabaseAnalyzer.extract_raw_messages(active_db)
    convs = ChatReconstructionEngine.reconstruct_conversations(raw_msgs)
    timeline = DateRangeEngine.extract_timeline(convs)

    if not timeline.dates_calendar:
        print("[!] No readable messages with valid timestamps found in this database.")
        return

    print("\nAVAILABLE MESSAGE DATES\n")
    sorted_dates = list(timeline.dates_calendar.keys())
    for idx, d_str in enumerate(sorted_dates[:40], start=1):
        cnt = timeline.dates_calendar[d_str]
        print(f"[{idx:<2}] {d_str}  | {cnt} messages")
    if len(sorted_dates) > 40:
        print(f"... and {len(sorted_dates) - 40} more dates.")

    print("\nDate Selection Options:")
    print("  [A]     Select All Available Dates")
    print("  [1-N]   Specific Date(s) (comma-separated, e.g. 1,3,5)")
    print("  [0]     Back\n")

    sel = input("Your choice: ").strip()
    if sel == "0" or not sel:
        return

    target_dates: Set[str] = set()
    if sel.upper() == "A":
        target_dates = set(sorted_dates)
    else:
        tokens = [t.strip() for t in sel.replace(" ", ",").split(",") if t.strip()]
        for tok in tokens:
            if tok.isdigit() and 1 <= int(tok) <= len(sorted_dates):
                target_dates.add(sorted_dates[int(tok) - 1])

    if not target_dates:
        print("[!] No valid dates selected.")
        return

    filtered_convs, excluded_missing = DateRangeEngine.filter_conversations_by_specific_dates(convs, target_dates)
    total_msgs = sum(len(c.messages) for c in filtered_convs)
    print(f"\n[+] Selected {len(target_dates)} date(s), matching {total_msgs} messages across {len(filtered_convs)} conversations.")

    export_ans = input("Export these selected records? [y/N]: ").strip().lower()
    if export_ans in ("y", "yes"):
        out_d = Path("recovery") / f"dates_export_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
        out_d.mkdir(parents=True, exist_ok=True)
        for c in filtered_convs:
            s_name = sanitize_filename(c.display_name)[:30]
            ChatExporter.export_conversation_html(c, out_d / f"{s_name}.html")
            ChatExporter.export_conversation_json(c, out_d / f"{s_name}.json")
            ChatExporter.export_conversation_txt(c, out_d / f"{s_name}.txt")
        print(f"[+] Export saved to: {out_d}")


def recover_media_interactive(
    device: Optional[DeviceInfo],
    settings: dict[str, Any],
    active_categories: List[str],
) -> None:
    """Recover Media and Attachments Workflow (Phase 4, Option [4])."""
    dev_name = device.display_name if device else "NONE DETECTED"
    print("\n" + "=" * 56)
    print("       WRS — RECOVER MEDIA AND ATTACHMENTS")
    print("=" * 56)
    print(f"Selected Device : {dev_name}\n")
    print("Supported Media Categories:")
    print("  • Photos and Images")
    print("  • Videos")
    print("  • Audio Files")
    print("  • Voice Notes")
    print("  • Documents and Files")
    print("  • Stickers")
    print("  • GIFs and Animated Media\n")

    if not device or not device.is_accessible:
        print("[!] No accessible Android device connected for media acquisition.")
        print("    To export media from existing acquisitions, use Option [7].")
        return

    print("Media recovery will acquire accessible photos, videos, audio, voice notes, and documents.")
    ans = input("Proceed with media acquisition from connected device? [y/N]: ").strip().lower()
    if ans not in ("y", "yes"):
        print("[*] Media recovery cancelled.")
        return

    media_cats = {
        "Photos and Images",
        "Videos",
        "Audio Files",
        "Voice Notes",
        "Documents and Files",
        "Stickers",
        "GIFs and Animated Media",
    }
    storage_cats = resolve_storage_categories(list(media_cats))
    run_interactive_workflow(
        AdbExecutor(),
        acquire_mode=True,
        override_serial=device.serial,
        selected_categories=storage_cats,
        settings=settings,
    )


def inspect_backups_and_databases_interactive(
    executor: AdbExecutor,
    device: Optional[DeviceInfo],
    settings: dict[str, Any],
) -> None:
    """Inspect Backups and Databases with RestoreAssistant (Option [5])."""
    print_screen_header("INSPECT BACKUPS & DATABASES", device, settings)
    print("[*] Scanning local recovery folders and connected device storage...\n")

    local_candidates = RestoreAssistant.scan_local_recovery_candidates("recovery")
    dev_candidates: List[RestoreCandidate] = []
    if device and device.is_accessible:
        dev_candidates = RestoreAssistant.scan_device_candidates(executor, device.serial)

    all_candidates = local_candidates + dev_candidates

    if not all_candidates:
        print("[*] No database or backup candidates found in local recovery or device external storage.")
        p_in = input("Enter custom database or backup file path to inspect (or press Enter to return): ").strip()
        if p_in:
            inspect_target(Path(p_in).resolve(), device_name=device.display_name if device else None)
        return

    print(f"Found {len(all_candidates)} candidate artifact(s):\n")
    print(f"  {'#':<4} {'FILENAME':<32} {'SIZE':>10}  {'FORMAT':<10} {'STATUS':<12} {'LOCATION':<16}")
    print("  " + "-" * 88)

    for idx, c in enumerate(all_candidates, start=1):
        print(f"  [{idx:<2}] {c.filename:<32} {c.size_human:>10}  {c.detected_format:<10} {c.status.value:<12} {c.evidence_location:<16}")

    print("\nOptions:")
    print("  [1-N] Inspect candidate details")
    print("  [0]   Back to Main Menu\n")

    pick = input("Enter choice: ").strip()
    if pick == "0" or not pick:
        return

    if pick.isdigit() and 1 <= int(pick) <= len(all_candidates):
        cand = all_candidates[int(pick) - 1]
        print("\n" + "=" * 65)
        print("  CANDIDATE FORENSIC PROVENANCE")
        print("=" * 65)
        print(f"  Source Path        : {cand.source_path}")
        print(f"  File Name          : {cand.filename}")
        print(f"  Size               : {cand.size_human} ({cand.size_bytes} bytes)")
        print(f"  Modified Timestamp : {cand.modified_timestamp}")
        print(f"  SHA-256 Hash       : {cand.sha256_hash or 'Not calculated on remote device'}")
        print(f"  Detected Format    : {cand.detected_format}")
        print(f"  Classification     : {cand.status.value}")
        print(f"  Evidence Source    : {cand.source_type.value}")
        print(f"  Validation Notes   : {cand.validation_notes}")
        if cand.is_sqlite:
            print(f"  Table Count        : {cand.table_count}")
        print("=" * 65 + "\n")

        if cand.status == RestoreCandidateStatus.RESTORABLE:
            print("This candidate is a validated WhatsApp backup eligible for native restoration.")
            stg = input("Stage this backup for native WhatsApp restoration? [y/N]: ").strip().lower()
            if stg in ("y", "yes"):
                guided_native_restore_flow(executor, device, settings, selected_candidate=cand)
        elif cand.is_sqlite and cand.evidence_location == "LOCAL_ACQUISITION":
            exp = input("Extract and export readable chats from this SQLite database? [y/N]: ").strip().lower()
            if exp in ("y", "yes"):
                reconstruct_and_export_interactive()


def guided_native_restore_flow(
    executor: AdbExecutor,
    device: Optional[DeviceInfo],
    settings: dict[str, Any],
    selected_candidate: Optional[RestoreCandidate] = None,
) -> None:
    """Guided Native WhatsApp Restore Workstation (Recovery Assistant)."""
    dev_name = device.display_name if device else "NONE DETECTED"

    print("\n" + "=" * 65)
    print("       WRS — NATIVE WHATSAPP RESTORE ASSISTANT")
    print("=" * 65)
    print(f"Selected Device : {dev_name}\n")

    cand = selected_candidate
    if not cand:
        local_cands = RestoreAssistant.scan_local_recovery_candidates("recovery")
        restorable = [c for c in local_cands if c.status == RestoreCandidateStatus.RESTORABLE]
        if not restorable:
            print("[!] No restorable backup candidates found in local recovery directory.")
            print("    Native restoration requires an encrypted local backup (.crypt14 or .crypt15)")
            print("    with valid container headers (not just filename match).")
            print("    Restoration is unsupported with the current evidence.")
            return

        print(f"Found {len(restorable)} restorable backup candidate(s):")
        for idx, rc in enumerate(restorable, start=1):
            print(f"  [{idx}] {rc.filename} ({rc.size_human}) - {rc.detected_format}")
        print("  [0] Back")

        pick = input("\nSelect candidate to restore [1-N / 0]: ").strip()
        if pick == "0" or not pick.isdigit() or not (1 <= int(pick) <= len(restorable)):
            return
        cand = restorable[int(pick) - 1]

    # Explain Consequences & Prerequisites
    print("\n" + "=" * 65)
    print("  RESTORATION PREREQUISITES & SAFETY NOTICE")
    print("=" * 65)
    for idx, prereq in enumerate(RestoreAssistant.get_prerequisites_list(), start=1):
        print(f"  {idx}. {prereq}")

    print("\nConsequences & Critical Safeguards:")
    print("  • Native restoration requires reinstalling WhatsApp or clearing app storage.")
    print("  • WRS will NEVER automatically uninstall WhatsApp, clear app data,")
    print("    or register phone numbers without explicit user action.")
    print("  • Never overwrite existing backups. WRS verifies destination collision.")
    print("  • Staging does NOT modify original evidence files.\n")

    conf_stage = input("Have you reviewed these prerequisites and wish to stage the restore bundle? [y/N]: ").strip().lower()
    if conf_stage not in ("y", "yes"):
        print("[*] Restoration staging cancelled.")
        return

    # Stage the restoration bundle
    staging_base = Path("recovery") / f"staged_restore_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
    ok, msg, dest_file = RestoreAssistant.prepare_restoration_bundle(cand, staging_base)
    if not ok or not dest_file:
        print(f"[!] Staging failed: {msg}")
        return

    print(f"\n[+] Restoration bundle staged successfully!")
    print(f"    Staged File     : {dest_file}")
    print(f"    Restore Target  : {dest_file.name}")
    print(f"    File Size       : {format_bytes(dest_file.stat().st_size)}")
    print(f"    Original SHA-256: {cand.sha256_hash}")

    # Check device deployment
    if device and device.is_accessible:
        print("\n" + "-" * 65)
        print(f"Ready to deploy staged backup to Android device: {device.display_name}")
        print(f"Target location: /sdcard/Android/media/com.whatsapp/WhatsApp/Databases/{dest_file.name}")
        push_conf = input("\nProceed with ADB push to device? [y/N]: ").strip().lower()
        if push_conf in ("y", "yes"):
            push_ok, push_msg = RestoreAssistant.push_staged_backup_to_device(
                dest_file, device.serial, executor, confirmed=True
            )
            if push_ok:
                print(f"\n[+] {push_msg}")
            else:
                print(f"\n[!] Deployment halted: {push_msg}")
        else:
            print("\n[*] Deployment to device skipped. You may copy the staged file manually.")
    else:
        print("\n[*] No accessible Android device connected. You may copy the staged file manually")
        print(f"    to: /sdcard/Android/media/com.whatsapp/WhatsApp/Databases/{dest_file.name}")

    # Post-Restoration Verification Checklist (Section 13)
    print("\n" + "=" * 65)
    print("  POST-RESTORATION VERIFICATION CHECKLIST")
    print("=" * 65)
    for idx, item in enumerate(RestoreAssistant.get_verification_checklist(), start=1):
        print(f"  [ ] {idx}. {item}")
    print("=" * 65 + "\n")


def view_previous_scans_interactive(settings: dict[str, Any]) -> None:
    """Inspect previous scan acquisition directories (Option [9])."""
    print_screen_header("VIEW PREVIOUS SCANS", None, settings)
    rec_base = Path("recovery").resolve()
    if not rec_base.exists():
        print("[*] No recovery directory found at ./recovery")
        return

    subdirs = [d for d in rec_base.iterdir() if d.is_dir() and not d.name.startswith(".")]
    subdirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)

    if not subdirs:
        print("[*] No previous scan directories found in ./recovery")
        return

    print(f"Found {len(subdirs)} previous scan directory/directories:\n")
    print(f"  {'#':<4} {'DIRECTORY NAME':<38} {'MODIFIED':<20}")
    print("  " + "-" * 66)

    for idx, d in enumerate(subdirs[:15], start=1):
        mtime_str = datetime.fromtimestamp(d.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  [{idx:<2}] {d.name:<38} {mtime_str:<20}")

    print("\nOptions:")
    print("  [1-N] Inspect scan directory")
    print("  [0]   Back to Main Menu\n")

    pick = input("Select scan [1-N / 0]: ").strip()
    if pick == "0" or not pick or not pick.isdigit() or not (1 <= int(pick) <= len(subdirs)):
        return

    chosen_dir = subdirs[int(pick) - 1]
    inspect_target(chosen_dir)


def settings_and_help_interactive(settings: dict[str, Any]) -> None:
    """Settings, Forensic Boundaries & Restore Help (Option [10])."""
    while True:
        ui = settings.setdefault("ui", {})
        acq = settings.setdefault("acquisition", {})

        mask_enabled = ui.get("mask_device_serial", False)
        prog_enabled = ui.get("progress_display_enabled", True)
        rec_dir = acq.get("default_recovery_dir", "recovery")
        margin_b = acq.get("safety_margin_bytes", 104857600)
        margin_r = acq.get("safety_margin_ratio", 0.10)

        print("\n" + "=" * 65)
        print("  WRS — SETTINGS, BOUNDARIES & RESTORE HELP")
        print("=" * 65)
        print(f"  [1] Device Serial Masking       : {'ENABLED' if mask_enabled else 'DISABLED'}")
        print(f"  [2] Scan Progress Display       : {'ENABLED' if prog_enabled else 'DISABLED'}")
        print(f"  [3] Default Recovery Directory  : {rec_dir}")
        print(f"  [4] Safety Margin Bytes         : {format_bytes(margin_b)} ({margin_b} bytes)")
        print(f"  [5] Safety Margin Ratio         : {int(margin_r * 100)}%")
        print("  [6] Reset Settings to Safe Defaults")
        print("  [7] Supported Recovery Locations & Boundaries")
        print("  [8] Restoration Prerequisites & Rollback Safeguards")
        print("  [0] Return to Main Menu")
        print("-" * 65)

        opt = input("\nEnter option [0-8]: ").strip()
        if opt == "0" or opt.lower() == "c":
            return
        elif opt == "1":
            ui["mask_device_serial"] = not mask_enabled
            save_settings(settings)
            print(f"[+] Device serial masking: {'ENABLED' if ui['mask_device_serial'] else 'DISABLED'}")
        elif opt == "2":
            ui["progress_display_enabled"] = not prog_enabled
            save_settings(settings)
            print(f"[+] Progress display: {'ENABLED' if ui['progress_display_enabled'] else 'DISABLED'}")
        elif opt == "3":
            new_dir = input(f"Enter new default recovery directory [{rec_dir}]: ").strip()
            if new_dir:
                acq["default_recovery_dir"] = new_dir
                save_settings(settings)
                print(f"[+] Default recovery directory set to: {new_dir}")
        elif opt == "4":
            new_mb = input(f"Enter safety margin in MB [{margin_b // 1048576}]: ").strip()
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
            print("[+] Settings reset to safe factory defaults.")
        elif opt == "7":
            show_recovery_info()
        elif opt == "8":
            print("\n" + "=" * 65)
            print("  WRS RESTORATION PREREQUISITES & ROLLBACK PRECAUTIONS")
            print("=" * 65)
            print("\nPREREQUISITES:")
            for p in RestoreAssistant.get_prerequisites_list():
                print(f"  • {p}")
            print("\nROLLBACK SAFEGUARDS:")
            for r in RestoreAssistant.get_rollback_precautions():
                print(f"  • {r}")
            print("=" * 65 + "\n")


def interactive_menu() -> None:
    """Main terminal menu loop (Phase 4, 10-Option Menu + Exit)."""
    executor = AdbExecutor()
    settings = load_settings()
    active_categories: List[str] = ["All Supported Data"]

    # Preflight Check & Device Detection
    all_devs, selected_dev = detect_and_display_startup_devices(executor, settings)

    if not all_devs:
        print("[*] No active Android device connected. WRS remains available for offline case inspection,")
        print("    report export, file verification, and settings.")
        print("    Press [Enter] to navigate Main Menu, [R] to retry device detection, or [Q] to exit.")
        try:
            prompt_act = input("Selection [Enter/R/Q]: ").strip().lower()
            if prompt_act == "q":
                print("\nExiting WRS. Goodbye.")
                sys.exit(0)
            elif prompt_act == "r":
                executor.clear_cache()
                all_devs, selected_dev = detect_and_display_startup_devices(executor, settings)
        except (KeyboardInterrupt, EOFError):
            print("\nExiting WRS.")
            sys.exit(0)

    while True:
        # Runtime device & status check
        status = executor.check_device_status(selected_serial=selected_dev.serial if selected_dev else None)
        mask = settings.get("ui", {}).get("mask_device_serial", False)

        if selected_dev:
            s_disp = selected_dev.get_display_serial(masked=mask)
            dev_title = f"{selected_dev.display_name} ({s_disp})" if s_disp else selected_dev.display_name
        else:
            dev_title = "NONE DETECTED"

        adb_status_str = status.adb_status_display
        scan_status_str = "READY" if (selected_dev and selected_dev.is_accessible) else "IDLE"

        print("\n" + "=" * 56)
        print("       WRS — WHATSAPP RECOVERY SCANNER")
        print("=" * 56)
        print(f"Selected Device : {dev_title}")
        print(f"ADB Status      : {adb_status_str}")
        print(f"Scan Status     : {scan_status_str}\n")
        print("MAIN MENU\n")
        print("[1] Scan and Recover Data")
        print("[2] Select Specific Data Categories")
        print("[3] Recover Chat History")
        print("[4] Recover Media and Attachments")
        print("[5] Inspect Backups and Databases")
        print("[6] View Available Chat Dates")
        print("[7] Export Recovered Data")
        print("[8] Verify Existing Recovery Files")
        print("[9] View Previous Scans")
        print("[10] Settings and Help")
        print("[0] Exit\n")

        try:
            choice = input("Select an option: ").strip()

            if choice == "1":
                recovery_wizard_flow(executor, selected_dev, settings, active_categories)

            elif choice == "2":
                active_categories = category_selection_interactive(active_categories)

            elif choice == "3":
                recover_chat_history_interactive(selected_dev, settings)

            elif choice == "4":
                recover_media_interactive(selected_dev, settings, active_categories)

            elif choice == "5":
                inspect_backups_and_databases_interactive(executor, selected_dev, settings)

            elif choice == "6":
                view_available_chat_dates_interactive(selected_dev, settings)

            elif choice == "7":
                export_and_package_menu_interactive(selected_dev)

            elif choice == "8":
                verify_acquired_files_interactive(selected_dev, settings)

            elif choice == "9":
                view_previous_scans_interactive(settings)

            elif choice == "10":
                settings_and_help_interactive(settings)

            elif choice == "0" or choice.lower() in ("exit", "quit", "q"):
                print("\nExiting WRS. Goodbye.")
                sys.exit(0)

            elif choice == "refresh" or choice.lower() == "r":
                print("\n[*] Refreshing connected Android devices...")
                executor.clear_cache()
                all_devs, selected_dev = detect_and_display_startup_devices(executor, settings)

            else:
                print("Invalid choice. Please select an option between 0 and 10.")

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
