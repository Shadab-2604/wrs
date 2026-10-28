"""Storage discovery module for WRS.

Discovers accessible WhatsApp and WhatsApp Business storage locations
across internal shared storage and external/removable storage mounts.
Normalizes filesystem aliases/symlinks to prevent duplicate traversal.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from .device import AdbExecutor, DeviceInfo

logger = logging.getLogger("wrs.discovery")

STANDARD_CANDIDATES: list[str] = [
    "/sdcard/Android/media/com.whatsapp/WhatsApp/",
    "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/",
    "/sdcard/WhatsApp/",
    "/storage/emulated/0/WhatsApp/",
    "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp/",
    "/storage/emulated/0/Android/media/com.whatsapp.w4b/WhatsApp/",
]


@dataclass
class DiscoveredLocation:
    """Represents a discovered WhatsApp directory on an Android device."""

    path: str
    canonical_path: str
    app_type: str  # 'WhatsApp Standard', 'WhatsApp Business', 'Unknown'
    parent_root: str = ""
    exists: bool = False
    is_readable: bool = False
    is_removable: bool = False
    subdirectories: List[str] = field(default_factory=list)
    file_count: int = 0
    logical_size: int = 0
    categories_found: List[str] = field(default_factory=list)
    scan_duration: float = 0.0
    aliases: List[str] = field(default_factory=list)
    error_message: Optional[str] = None

    @property
    def display_label(self) -> str:
        """Formatted summary label for CLI presentation."""
        type_str = f"[{self.app_type}]"
        removable_str = " (Removable SD)" if self.is_removable else ""
        readable_str = "Readable" if self.is_readable else "Access Restricted"
        subs = f" ({len(self.subdirectories)} subdirs)" if self.subdirectories else ""
        return f"{self.path} {type_str}{removable_str} — {readable_str}{subs}"


class StorageDiscovery:
    """Discovers and normalizes accessible WhatsApp storage locations."""

    def __init__(self, executor: AdbExecutor) -> None:
        self.executor = executor

    def discover_locations(
        self,
        device: DeviceInfo,
        custom_candidates: Optional[List[str]] = None,
    ) -> List[DiscoveredLocation]:
        """Discover all unique accessible WhatsApp locations on the selected device.

        Normalizes symlinks and aliases to guarantee no duplicate directory traversal.
        """
        candidates: List[str] = list(custom_candidates or STANDARD_CANDIDATES)

        # Check removable mounts if discovered
        for mount in device.removable_mounts:
            candidates.extend([
                f"{mount}/Android/media/com.whatsapp/WhatsApp/",
                f"{mount}/WhatsApp/",
                f"{mount}/Android/media/com.whatsapp.w4b/WhatsApp/",
            ])

        canonical_map: dict[str, DiscoveredLocation] = {}

        for cand in candidates:
            cand_clean = cand.rstrip("/") + "/"
            loc = self._inspect_candidate(device.serial, cand_clean)

            if not loc.exists:
                continue

            # Group by canonical path to eliminate symlink duplicates (/sdcard vs /storage/emulated/0)
            canonical_key = loc.canonical_path or loc.path

            if canonical_key in canonical_map:
                existing = canonical_map[canonical_key]
                if cand_clean not in existing.aliases and cand_clean != existing.path:
                    existing.aliases.append(cand_clean)
            else:
                canonical_map[canonical_key] = loc

        return list(canonical_map.values())

    def _inspect_candidate(self, serial: str, path: str) -> DiscoveredLocation:
        """Check existence, canonical path, readability, and app type of a path."""
        app_type = "WhatsApp Standard"
        if "com.whatsapp.w4b" in path:
            app_type = "WhatsApp Business"

        is_removable = not (path.startswith("/sdcard") or path.startswith("/storage/emulated"))

        # Test if directory exists
        chk = self.executor.run_cmd(
            ["shell", "test", "-d", f'"{path}"', "&&", "echo", "EXISTS"],
            serial=serial,
            timeout=5,
        )
        exists = "EXISTS" in chk.stdout

        if not exists:
            return DiscoveredLocation(
                path=path,
                canonical_path=path,
                app_type=app_type,
                exists=False,
                is_readable=False,
                is_removable=is_removable,
            )

        # Resolve canonical path / symlink target using readlink -f or realpath
        canonical = path
        canon_chk = self.executor.run_cmd(
            ["shell", f'readlink -f "{path}" || realpath "{path}" 2>/dev/null'],
            serial=serial,
            timeout=5,
        )
        if canon_chk.returncode == 0 and canon_chk.stdout.strip():
            resolved = canon_chk.stdout.strip().splitlines()[-1].strip()
            if resolved and resolved.startswith("/"):
                canonical = resolved.rstrip("/") + "/"

        # Determine parent root
        p_clean = path.rstrip("/")
        parent_root = p_clean.rsplit("/", 1)[0] if "/" in p_clean else p_clean

        # Test readability by listing directory contents
        read_chk = self.executor.run_cmd(
            ["shell", "ls", "-d", f'"{path}"*'],
            serial=serial,
            timeout=10,
        )
        is_readable = read_chk.returncode == 0
        error_msg = None
        subdirs: List[str] = []
        if not is_readable:
            error_msg = read_chk.stderr.strip() or "Permission denied or directory unreadable"
        else:
            # Check for standard subfolders
            sub_chk = self.executor.run_cmd(
                ["shell", f'ls -F "{path}" 2>/dev/null | grep "/"'],
                serial=serial,
                timeout=5,
            )
            if sub_chk.returncode == 0 and sub_chk.stdout:
                subdirs = [s.strip().rstrip("/") for s in sub_chk.stdout.splitlines() if s.strip()]

        return DiscoveredLocation(
            path=path,
            canonical_path=canonical,
            app_type=app_type,
            parent_root=parent_root,
            exists=True,
            is_readable=is_readable,
            is_removable=is_removable,
            subdirectories=subdirs,
            error_message=error_msg,
        )
