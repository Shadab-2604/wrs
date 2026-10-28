"""Recursive file scanner module for WRS.

Enumerates WhatsApp files on Android storage via ADB, extracting file sizes,
timestamps, and paths while handling Unicode, spaces, and edge cases.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Callable, List, Optional

from .categorizer import Categorizer, CAT_OTHER
from .device import AdbExecutor
from .discovery import DiscoveredLocation
from .utils import format_bytes, format_timestamp

logger = logging.getLogger("wrs.scanner")


@dataclass
class ScannedFile:
    """Detailed metadata for an enumerated file on device."""

    original_path: str
    relative_path: str
    filename: str
    extension: str
    category: str
    size_bytes: int
    size_human: str
    modified_time: Optional[str] = None
    identification_method: str = "path_and_extension"
    readability: bool = True
    error: Optional[str] = None


@dataclass
class ScanResult:
    """Aggregated scan inventory for a device location."""

    device_serial: str
    location_path: str
    start_time: str
    end_time: str
    files: List[ScannedFile] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    category_counts: dict[str, int] = field(default_factory=dict)
    category_bytes: dict[str, int] = field(default_factory=dict)
    total_files: int = 0
    total_bytes: int = 0


ProgressCallback = Callable[[str, int, int, float], None]


class FileScanner:
    """Recursive file scanner for Android storage over ADB."""

    def __init__(self, executor: AdbExecutor, categorizer: Optional[Categorizer] = None) -> None:
        self.executor = executor
        self.categorizer = categorizer or Categorizer()

    def scan_location(
        self,
        serial: str,
        location: DiscoveredLocation,
        progress_cb: Optional[ProgressCallback] = None,
    ) -> ScanResult:
        """Scan a discovered WhatsApp location and return complete inventory."""
        start_ts = time.time()
        start_time_str = format_timestamp(start_ts)
        root_path = location.path.rstrip("/")

        scanned_files: List[ScannedFile] = []
        errors: List[str] = []

        # Attempt high-performance find + stat batch enumeration
        raw_entries, scan_err = self._scan_with_find_stat(serial, root_path, progress_cb, start_ts)

        if scan_err:
            errors.append(scan_err)

        if not raw_entries and not scan_err:
            # Fallback to recursive directory listing
            raw_entries, fallback_err = self._scan_with_walk(serial, root_path, progress_cb, start_ts)
            if fallback_err:
                errors.append(fallback_err)

        # Categorize and build ScannedFile records
        cat_counts: dict[str, int] = {}
        cat_bytes: dict[str, int] = {}
        total_bytes = 0

        for original_path, size_b, mtime_str in raw_entries:
            try:
                # Compute relative path
                if original_path.startswith(root_path):
                    rel = original_path[len(root_path):].lstrip("/")
                else:
                    rel = PurePosixPath(original_path).name

                filename = PurePosixPath(original_path).name
                ext = os.path.splitext(filename)[1].lower()

                cat, method = self.categorizer.categorize(
                    filename=filename,
                    relative_path=rel,
                    size_bytes=size_b,
                )

                sfile = ScannedFile(
                    original_path=original_path,
                    relative_path=rel,
                    filename=filename,
                    extension=ext,
                    category=cat,
                    size_bytes=size_b,
                    size_human=format_bytes(size_b),
                    modified_time=mtime_str,
                    identification_method=method,
                    readability=True,
                )
                scanned_files.append(sfile)

                cat_counts[cat] = cat_counts.get(cat, 0) + 1
                cat_bytes[cat] = cat_bytes.get(cat, 0) + size_b
                total_bytes += size_b

            except Exception as e:
                err_msg = f"Failed to process file entry {original_path}: {e}"
                errors.append(err_msg)
                logger.warning(err_msg)

        end_ts = time.time()
        end_time_str = format_timestamp(end_ts)

        return ScanResult(
            device_serial=serial,
            location_path=root_path,
            start_time=start_time_str,
            end_time=end_time_str,
            files=scanned_files,
            errors=errors,
            category_counts=cat_counts,
            category_bytes=cat_bytes,
            total_files=len(scanned_files),
            total_bytes=total_bytes,
        )

    def _scan_with_find_stat(
        self,
        serial: str,
        root_path: str,
        progress_cb: Optional[ProgressCallback],
        start_ts: float,
    ) -> tuple[List[tuple[str, int, str]], Optional[str]]:
        """Run find and stat via ADB for rapid enumeration."""
        # Find all files and print: %s|%Y|%n (size, timestamp in seconds, filename)
        cmd = [
            "shell",
            f'find "{root_path}" -type f -exec stat -c "%s|%Y|%n" {{}} + 2>/dev/null',
        ]
        res = self.executor.run_cmd(cmd, serial=serial, timeout=120)

        if res.returncode != 0 or not res.stdout.strip():
            return [], None

        entries: List[tuple[str, int, str]] = []
        lines = res.stdout.strip().splitlines()

        for idx, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or "|" not in line:
                continue

            parts = line.split("|", 2)
            if len(parts) != 3:
                continue

            try:
                size_b = int(parts[0])
                mtime_epoch = int(parts[1])
                filepath = parts[2].strip()

                mtime_dt = datetime.fromtimestamp(mtime_epoch, timezone.utc).astimezone()
                mtime_str = mtime_dt.strftime("%Y-%m-%d %H:%M:%S")

                entries.append((filepath, size_b, mtime_str))

                if progress_cb and (idx % 100 == 0 or idx == len(lines)):
                    progress_cb("Enumerating files", idx, 0, time.time() - start_ts)
            except (ValueError, OSError):
                continue

        return entries, None

    def _scan_with_walk(
        self,
        serial: str,
        root_path: str,
        progress_cb: Optional[ProgressCallback],
        start_ts: float,
    ) -> tuple[List[tuple[str, int, str]], Optional[str]]:
        """Fallback recursive traversal using 'ls -la' if find/stat fails."""
        entries: List[tuple[str, int, str]] = []
        stack: List[str] = [root_path]
        seen_dirs: set[str] = set()

        while stack:
            curr_dir = stack.pop()
            if curr_dir in seen_dirs:
                continue
            seen_dirs.add(curr_dir)

            res = self.executor.run_cmd(["shell", "ls", "-la", f'"{curr_dir}"'], serial=serial, timeout=30)
            if res.returncode != 0:
                continue

            for line in res.stdout.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("total"):
                    continue

                parts = line.split(maxsplit=7)
                if len(parts) < 8:
                    continue

                permissions = parts[0]
                entry_name = parts[7]

                if entry_name in (".", ".."):
                    continue

                full_entry_path = f"{curr_dir}/{entry_name}"

                # If directory and not a symlink
                if permissions.startswith("d"):
                    stack.append(full_entry_path)
                elif permissions.startswith("-"):
                    try:
                        size_b = int(parts[4])
                    except ValueError:
                        size_b = 0

                    entries.append((full_entry_path, size_b, format_timestamp()))

                    if progress_cb and len(entries) % 50 == 0:
                        progress_cb("Enumerating files (fallback)", len(entries), 0, time.time() - start_ts)

        return entries, None
