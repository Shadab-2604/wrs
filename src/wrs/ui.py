"""Terminal UI styling, themes, status helpers, and Rich rendering engine for WRS.

Provides a clean, professional cybersecurity utility aesthetic tailored for Kali Linux:
- Color palette: Cyan/Blue (headings/options), Green (success/authorized),
  Yellow (warnings/encrypted), Red (errors/failures), Magenta (special modules),
  Bright White (values), Dim Gray (secondary).
- Reusable status tag helpers: [SUCCESS], [INFO], [WARNING], [ERROR], [SCAN], [ACQUIRE].
- Graceful degradation: respects NO_COLOR, TERM=dumb, non-tty pipes, and --no-color flag.
- Rich-powered panels, structured tables, and progress indicators with plain-text fallback.
"""

from __future__ import annotations

import os
import platform
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .utils import format_bytes

# Attempt Rich import with graceful fallback
try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    Console = None  # type: ignore
    Panel = None  # type: ignore
    Table = None  # type: ignore
    Text = None  # type: ignore
    box = None  # type: ignore


# Global UI configuration
_FORCE_NO_COLOR: bool = False
_RICH_CONSOLE: Optional[Any] = None


def set_force_no_color(disabled: bool) -> None:
    """Explicitly enable or disable color and styling globally."""
    global _FORCE_NO_COLOR, _RICH_CONSOLE
    _FORCE_NO_COLOR = disabled
    _RICH_CONSOLE = None  # Reset console cache


def is_color_enabled() -> bool:
    """Determine whether color output is active and supported."""
    if _FORCE_NO_COLOR:
        return False
    # Respect standard NO_COLOR specification (https://no-color.org)
    if os.environ.get("NO_COLOR", "").strip():
        return False
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    # Respect non-tty redirection (e.g. pipes, log files)
    if not (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()):
        return False
    return HAS_RICH


def get_console() -> Optional[Any]:
    """Obtain or initialize the cached Rich console instance."""
    global _RICH_CONSOLE
    if not HAS_RICH:
        return None
    if _RICH_CONSOLE is None:
        color_sys = "auto" if is_color_enabled() else None
        _RICH_CONSOLE = Console(
            color_system=color_sys,
            highlight=False,
            force_terminal=is_color_enabled(),
        )
    return _RICH_CONSOLE


# ============================================================================
# Reusable Status Message Helpers (Requirement 5)
# ============================================================================

def print_success(msg: str) -> None:
    """Print operation completion message with green tag."""
    c = get_console()
    if is_color_enabled() and c:
        c.print(f"[bold green][SUCCESS][/bold green] {msg}")
    else:
        print(f"[SUCCESS] {msg}")


def print_info(msg: str) -> None:
    """Print informational operational message with cyan tag."""
    c = get_console()
    if is_color_enabled() and c:
        c.print(f"[bold cyan][INFO][/bold cyan]    {msg}")
    else:
        print(f"[INFO]    {msg}")


def print_warning(msg: str) -> None:
    """Print cautionary warning message with yellow tag."""
    c = get_console()
    if is_color_enabled() and c:
        c.print(f"[bold yellow][WARNING][/bold yellow] {msg}")
    else:
        print(f"[WARNING] {msg}")


def print_error(msg: str) -> None:
    """Print failure message with red tag."""
    c = get_console()
    if is_color_enabled() and c:
        c.print(f"[bold red][ERROR][/bold red]   {msg}")
    else:
        print(f"[ERROR]   {msg}")


def print_scan(msg: str) -> None:
    """Print discovery or inventory scan activity with magenta tag."""
    c = get_console()
    if is_color_enabled() and c:
        c.print(f"[bold magenta][SCAN][/bold magenta]    {msg}")
    else:
        print(f"[SCAN]    {msg}")


def print_acquire(msg: str) -> None:
    """Print evidence acquisition activity with blue tag."""
    c = get_console()
    if is_color_enabled() and c:
        c.print(f"[bold blue][ACQUIRE][/bold blue] {msg}")
    else:
        print(f"[ACQUIRE] {msg}")


# ============================================================================
# Section Headers and Frame Rendering (Requirements 1, 3, 7)
# ============================================================================

def print_header(title: str, device_label: Optional[str] = None) -> None:
    """Print consistent screen header ensuring title and selected device remain clear."""
    c = get_console()
    dev_str = device_label or "No Device Selected"

    if is_color_enabled() and c:
        hdr_text = f"  [bold cyan]WRS — {title.upper()}[/bold cyan]\n"
        hdr_text += f"  [dim]Selected Device :[/dim] [bold yellow]{dev_str}[/bold yellow]"
        pnl = Panel(
            hdr_text,
            box=box.ROUNDED,
            border_style="cyan",
            expand=False,
            padding=(0, 2),
        )
        c.print("")
        c.print(pnl)
    else:
        print("\n" + "=" * 65)
        print(f"  WRS — {title.upper()}")
        print("=" * 65)
        print(f"  Selected Device : {dev_str}")
        print("-" * 65)


def print_rich_missing_advisory() -> None:
    """Print helpful installation instructions when Rich is unavailable."""
    print("[INFO] Rich library is not installed. Running in standard terminal mode.")
    print("       To enable styled panels, tables, and colors, install Rich:")
    print("       pip install rich>=13.0.0\n")


def print_app_banner(
    version: str,
    adb_status_str: str,
    device_status_str: str,
    scan_status_str: str = "IDLE",
    timestamp_str: Optional[str] = None,
) -> None:
    """Display startup banner with independent ADB, device, and scan statuses."""
    now_str = timestamp_str or time.strftime("%Y-%m-%d %H:%M:%S")
    c = get_console()

    # Determine status colors
    adb_style = "bold green" if "available" in adb_status_str.lower() or "connected" in adb_status_str.lower() else "bold red"
    dev_style = "bold green" if "authorized" in device_status_str.lower() else ("bold yellow" if "unauthorized" in device_status_str.lower() or "none" in device_status_str.lower() else "bold red")
    scan_style = "bold green" if scan_status_str == "READY" else ("bold magenta" if scan_status_str == "RUNNING" else "dim")

    if is_color_enabled() and c:
        top_content = (
            "[bold white]WRS — WhatsApp Recovery Scanner[/bold white]\n"
            "[dim]Local Android Data Discovery & Recovery Assistance[/dim]"
        )
        c.print("")
        c.print(
            Panel(
                top_content,
                box=box.ROUNDED,
                border_style="cyan",
                width=66,
                padding=(0, 2),
            )
        )
        c.print(f"  [bold cyan]DEVICE[/bold cyan]       : [{dev_style}]{device_status_str}[/{dev_style}]")
        c.print(f"  [bold cyan]ADB[/bold cyan]          : [{adb_style}]{adb_status_str}[/{adb_style}]")
        c.print(f"  [bold cyan]SCAN[/bold cyan]         : [{scan_style}]{scan_status_str}[/{scan_style}]")
        c.print(f"  [dim]MODE[/dim]         : [bold]100% Local Execution[/bold]")
        c.print(f"  [dim]VERSION[/dim]      : v{version}  |  {now_str}")
        c.print("")
    else:
        top_border = f"╭{'─' * 18} WRS — WhatsApp Recovery Scanner {'─' * 18}╮"
        bot_border = f"╰{'─' * 12} Forensic Acquisition & Preservation Utility {'─' * 12}╯"
        print(top_border)
        print(f"│ {'Processing Mode : 100% Local Execution':<68} │")
        print(f"│ {f'ADB Status      : {adb_status_str}':<68} │")
        print(f"│ {f'Android Device  : {device_status_str}':<68} │")
        print(f"│ {f'Version         : v{version}':<68} │")
        print(f"│ {f'Timestamp       : {now_str}':<68} │")
        print(bot_border)


# ============================================================================
# Menu and Selection Formatting (Requirement 4)
# ============================================================================

def print_category_selection_screen(
    categories_map: Dict[int, str],
    selected_labels: Set[str],
) -> None:
    """Format dedicated category selection screen with clear selection indicators."""
    c = get_console()
    curr_summary = ", ".join(sorted(selected_labels)) if selected_labels else "None"

    if is_color_enabled() and c:
        c.print("\n[bold cyan]SELECT DATA CATEGORIES[/bold cyan]\n")
        for num in range(1, 13):
            label = categories_map.get(num, "")
            is_sel = (label in selected_labels) or ("All Supported Data" in selected_labels)
            tag = "[bold green][●][/bold green]" if is_sel else "[dim][○][/dim]"
            style = "bold white" if is_sel else "dim"
            c.print(f"  {tag} [{style}][{num:<2}][/{style}] {label}")

        c.print("\n  [bold cyan][A][/bold cyan]  Select All Categories")
        c.print("  [bold yellow][C][/bold yellow]  Clear Selection")
        c.print("  [dim][0] / [B][/dim]  Back\n")
        c.print("  [dim]Enter multiple options separated by commas (e.g. 2,4,7).[/dim]")
        c.print(f"  [bold]Selected:[/bold] [bold cyan]{curr_summary}[/bold cyan]\n")
    else:
        print("\n" + "=" * 56)
        print("       WRS — SELECT DATA CATEGORIES")
        print("=" * 56)
        print(f"Current Selection : {curr_summary}\n")
        for num in range(1, 13):
            label = categories_map.get(num, "")
            is_sel = (label in selected_labels) or ("All Supported Data" in selected_labels)
            marker = "[●]" if is_sel else "[○]"
            print(f"  {marker} [{num:<2}] {label}")
        print("\n  [A] Select All Categories")
        print("  [C] Clear Selection")
        print("  [0] / [B] Back\n")
        print("  Enter multiple options separated by commas (e.g. 2,4,7).")
        print(f"  Selected: {curr_summary}\n")


# ============================================================================
# Tables & Panels (Requirements 2, 7)
# ============================================================================

def print_table_data(
    title: str,
    headers: List[str],
    rows: List[List[str]],
    alignments: Optional[List[str]] = None,
    header_style: str = "bold cyan",
) -> None:
    """Render a structured table with Rich styling or clean plain-text fallback."""
    c = get_console()
    if is_color_enabled() and c:
        tbl = Table(title=title, box=box.ROUNDED, header_style=header_style, show_header=True)
        for idx, h in enumerate(headers):
            justify = "right" if (alignments and idx < len(alignments) and alignments[idx] == "right") else "left"
            tbl.add_column(h, justify=justify)
        for r in rows:
            tbl.add_row(*r)
        c.print(tbl)
    else:
        print(f"\n{title}")
        print("-" * 65)
        header_line = "  ".join(f"{h:<16}" for h in headers)
        print(header_line)
        print("-" * 65)
        for r in rows:
            row_line = "  ".join(f"{col:<16}" for col in r)
            print(row_line)
        print("-" * 65)


def print_confirmation_box(
    action_description: str,
    details: Dict[str, str],
) -> None:
    """Display an explicit, warning-accented confirmation panel."""
    c = get_console()
    if is_color_enabled() and c:
        content = f"[bold yellow]{action_description}[/bold yellow]\n\n"
        for k, v in details.items():
            content += f"[dim]{k:<16}:[/dim] [bold white]{v}[/bold white]\n"
        content += "\n[dim]No source files will be deleted or modified on the Android device.[/dim]"
        c.print(
            Panel(
                content,
                title="[bold red]ACQUISITION CONFIRMATION[/bold red]",
                box=box.ROUNDED,
                border_style="yellow",
                width=68,
            )
        )
    else:
        print("\n" + "=" * 65)
        print("  ACQUISITION PREVIEW & CONFIRMATION")
        print("=" * 65)
        print(action_description)
        for k, v in details.items():
            print(f"  {k:<14} : {v}")
        print("=" * 65)
        print("No source files will be deleted or modified on the Android device.\n")


# ============================================================================
# Progress Callback Handlers (Requirement 6)
# ============================================================================

def make_rich_discovery_progress_callback(
    device_name: str,
    location_path: str,
    progress_enabled: bool = True,
) -> Callable[[str, int, int, float], None]:
    """Create a terminal discovery callback with accurate live counts and clean fallback."""
    last_print = [0.0]
    c = get_console()

    def disc_progress(phase: str, count: int, total: int, elapsed: float) -> None:
        now = time.time()
        if not progress_enabled or not (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()):
            if count % 250 == 0 or count < 10:
                print(f"[*] Scope: Accessible paths | Discovered: {count} files ({elapsed:.1f}s)")
            return

        if now - last_print[0] > 0.08 or count < 10:
            last_print[0] = now
            if is_color_enabled() and c:
                dev_disp = device_name[:14]
                sys.stdout.write(
                    f"\r\033[K[SCAN] Device: \033[1;37m{dev_disp}\033[0m | Scope: Accessible paths | "
                    f"Discovered: \033[1;32m{count}\033[0m files | Elapsed: \033[2m{elapsed:.1f}s\033[0m"
                )
                sys.stdout.flush()
            else:
                sys.stdout.write(
                    f"\r[*] DEVICE: {device_name[:16]} | {phase}: {count} accessible files | Elapsed: {elapsed:.1f}s"
                )
                sys.stdout.flush()

    return disc_progress


def make_rich_acquisition_progress_callback(
    device_name: str,
    total_files: int,
    progress_enabled: bool = True,
) -> Callable[[int, int, int, int, str, str, float], None]:
    """Create acquisition progress callback with real byte counters, rate, and status."""
    last_print = [0.0]
    failure_count = [0]
    c = get_console()

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
        # Fallback when progress is disabled or non-tty
        if not progress_enabled or not (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()):
            if completed % 25 == 0 or remaining == 0:
                print(
                    f"[{completed}/{total_files}] Device: {device_name} | "
                    f"Transferred: {format_bytes(trans_b)} | File: {cur_fn} | Status: {stat}"
                )
            return

        if now - last_print[0] > 0.1 or remaining == 0:
            last_print[0] = now
            pct = (completed / total_files * 100) if total_files > 0 else 0
            fn_disp = cur_fn[:22] + "..." if len(cur_fn) > 25 else cur_fn

            stat_color = "\033[1;32m" if stat == "VERIFIED" else ("\033[1;33m" if "UNAVAILABLE" in stat else "\033[1;31m")

            if is_color_enabled() and c:
                sys.stdout.write(
                    f"\r\033[K[ACQUIRE] [{completed}/{total_files}] (\033[1;36m{pct:4.1f}%\033[0m) | "
                    f"Bytes: \033[1;33m{format_bytes(trans_b)}\033[0m | "
                    f"File: \033[1;37m{fn_disp:<24}\033[0m | Status: {stat_color}{stat:<8}\033[0m | Fails: {failure_count[0]}"
                )
                sys.stdout.flush()
            else:
                sys.stdout.write(
                    f"\rDEVICE: {device_name[:14]} | PROGRESS: {completed}/{total_files} ({pct:4.1f}%) | "
                    f"BYTES: {format_bytes(trans_b)} | FILE: {fn_disp:<25} | STAT: {stat:<8} | FAILS: {failure_count[0]}"
                )
                sys.stdout.flush()

    return acq_progress
