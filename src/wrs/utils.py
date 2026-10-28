"""Utility functions for WRS (WhatsApp Recovery Scanner).

Provides formatting, path validation, disk checks, sanitization,
and configuration loading.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
from datetime import datetime, timezone
from typing import Any, Optional, Tuple


def format_bytes(size_bytes: int) -> str:
    """Format bytes into binary units (B, KiB, MiB, GiB, TiB).

    Binary prefixes (1024) are used consistently across WRS.
    """
    if size_bytes < 0:
        return "0 B"
    if size_bytes < 1024:
        return f"{size_bytes} B"

    units = ["KiB", "MiB", "GiB", "TiB", "PiB"]
    value = float(size_bytes)
    unit = units[0]

    for u in units:
        value /= 1024.0
        unit = u
        if value < 1024.0:
            break

    return f"{value:.2f} {unit}"


def format_timestamp(dt: Optional[datetime | float | int | str] = None) -> str:
    """Format a datetime or epoch timestamp into ISO-8601 string."""
    if dt is None:
        return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")

    if isinstance(dt, (int, float)):
        try:
            return datetime.fromtimestamp(dt, timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError):
            return str(dt)

    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    return str(dt)


def get_timestamp_slug(dt: Optional[datetime] = None) -> str:
    """Get a safe timestamp string for directory names: YYYY-MM-DD_HH-MM-SS."""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d_%H-%M-%S")


def sanitize_filename(name: str) -> str:
    """Sanitize a filename to prevent path traversal and illegal filesystem characters.

    Removes null bytes, path separators, control characters, and keeps safe chars.
    """
    if not name:
        return "unnamed_file"

    # Remove null bytes and control chars
    clean = "".join(c for c in name if ord(c) >= 32 and c != "\x7f")

    # Replace path separators and reserved characters across Linux/Windows/FAT
    clean = re.sub(r'[\\/*?:"<>|]', "_", clean)

    # Remove dangerous leading/trailing dots or spaces
    clean = clean.strip(". ")

    # Prevent directory traversal aliases
    if clean in ("", ".", ".."):
        return "unnamed_file"

    return clean


def sanitize_device_name(name: str) -> str:
    """Sanitize device manufacturer and model strings for directory naming."""
    if not name or name.strip() == "":
        return "unknown_device"

    clean = re.sub(r"[^\w\-_.]", "_", name.strip())
    clean = re.sub(r"_+", "_", clean).strip("_")
    return clean or "unknown_device"


def is_safe_path(base_dir: Path, target_path: Path) -> bool:
    """Verify that target_path is strictly contained within base_dir.

    Prevents directory traversal vulnerabilities.
    """
    try:
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        # Ensure target is relative to base
        resolved_target.relative_to(resolved_base)
        return True
    except (ValueError, RuntimeError):
        return False


def get_safe_destination_path(base_dir: Path, relative_path: str | Path) -> Path:
    """Safely resolve relative_path within base_dir.

    Raises ValueError if relative_path attempts to escape base_dir or contains
    directory traversal segments ('..').
    """
    rel_p = Path(relative_path)
    
    # Check for path traversal components
    for part in rel_p.parts:
        if part == ".." or part.startswith("../") or part.startswith("..\\"):
            raise ValueError(f"Path traversal detected: {relative_path} attempts to escape {base_dir}")

    clean_parts: list[str] = []
    for part in rel_p.parts:
        if part in ("/", "\\", ""):
            continue
        sanitized = sanitize_filename(part)
        if sanitized:
            clean_parts.append(sanitized)

    if not clean_parts:
        destination = base_dir.resolve()
    else:
        destination = base_dir.joinpath(*clean_parts).resolve()

    if not is_safe_path(base_dir, destination):
        raise ValueError(f"Path traversal detected: {relative_path} attempts to escape {base_dir}")

    return destination


def resolve_unique_filepath(dest_dir: Path, filename: str) -> Path:
    """Return a unique path within dest_dir.

    If a file with the given name already exists, appends _1, _2, etc.
    before the suffix to prevent overwriting existing files.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    sanitized = sanitize_filename(filename)
    candidate = dest_dir / sanitized

    if not candidate.exists():
        return candidate

    stem = candidate.stem
    suffix = candidate.suffix
    counter = 1

    while True:
        unique_name = f"{stem}_{counter}{suffix}"
        candidate = dest_dir / unique_name
        if not candidate.exists():
            return candidate
        counter += 1


def check_disk_space(
    destination: Path | str,
    required_bytes: int,
    safety_margin_bytes: int = 104857600,
    safety_margin_ratio: float = 0.10,
) -> Tuple[bool, int, int, str]:
    """Check whether sufficient disk space exists at destination.

    Computes: total_required = required_bytes + max(safety_margin_bytes, int(required_bytes * safety_margin_ratio))
    Returns (has_enough, free_bytes, total_required, message).
    """
    dest_path = Path(destination).resolve()
    # Find existing parent directory if destination does not exist yet
    check_dir = dest_path
    while not check_dir.exists() and check_dir.parent != check_dir:
        check_dir = check_dir.parent

    try:
        usage = shutil.disk_usage(str(check_dir))
        free_bytes = usage.free
    except OSError as e:
        return False, 0, required_bytes, f"Unable to query disk space at {check_dir}: {e}"

    margin = max(safety_margin_bytes, int(required_bytes * safety_margin_ratio))
    total_required = required_bytes + margin

    if free_bytes >= total_required:
        msg = (
            f"Disk space OK: {format_bytes(free_bytes)} available. "
            f"Required: {format_bytes(required_bytes)} + {format_bytes(margin)} safety margin."
        )
        return True, free_bytes, total_required, msg
    else:
        shortfall = total_required - free_bytes
        msg = (
            f"Insufficient disk space at {check_dir}: {format_bytes(free_bytes)} free, "
            f"but {format_bytes(total_required)} required ({format_bytes(required_bytes)} data + "
            f"{format_bytes(margin)} margin). Shortfall: {format_bytes(shortfall)}."
        )
        return False, free_bytes, total_required, msg


def mask_serial(serial: str) -> str:
    """Mask serial identifier for privacy in ordinary terminal displays.

    Example: '28241FDH2006G7' -> '2824****06G7'
    """
    if not serial:
        return ""
    clean = serial.strip()
    if len(clean) <= 6:
        return "****" + clean[-2:]
    return f"{clean[:4]}****{clean[-4:]}"


def validate_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Validate configuration settings, sanitizing invalid types and falling back to safe defaults.

    Never permits storing passwords, private keys, or authentication material.
    """
    validated = dict(settings)

    # 1. Strip prohibited sensitive fields if present
    prohibited_keys = {"password", "token", "secret", "private_key", "key", "auth"}
    for k in list(validated.keys()):
        if any(p in k.lower() for p in prohibited_keys):
            del validated[k]

    # 2. UI section
    ui = validated.setdefault("ui", {})
    if not isinstance(ui.get("mask_device_serial"), bool):
        ui["mask_device_serial"] = False
    if not isinstance(ui.get("progress_display_enabled"), bool):
        ui["progress_display_enabled"] = True
    if not isinstance(ui.get("use_rich_formatting"), bool):
        ui["use_rich_formatting"] = True

    # 3. Acquisition section
    acq = validated.setdefault("acquisition", {})
    if not isinstance(acq.get("default_recovery_dir"), str) or not acq["default_recovery_dir"].strip():
        acq["default_recovery_dir"] = "recovery"
    if not isinstance(acq.get("safety_margin_bytes"), int) or acq["safety_margin_bytes"] < 0:
        acq["safety_margin_bytes"] = 104857600  # 100 MiB
    if not isinstance(acq.get("safety_margin_ratio"), (int, float)) or acq["safety_margin_ratio"] < 0:
        acq["safety_margin_ratio"] = 0.10

    # 4. Reporting section
    rep = validated.setdefault("reporting", {})
    if not isinstance(rep.get("preferred_report_formats"), list):
        rep["preferred_report_formats"] = ["html", "json", "csv"]

    return validated


def load_settings(config_path: Optional[Path] = None) -> dict[str, Any]:
    """Load settings from config/settings.json or fallback defaults."""
    default_settings: dict[str, Any] = {
        "app_name": "WRS — WhatsApp Recovery Scanner",
        "version": "2.0.0",
        "ui": {
            "mask_device_serial": False,
            "progress_display_enabled": True,
            "use_rich_formatting": True,
        },
        "storage": {
            "target_paths": [
                "/sdcard/Android/media/com.whatsapp/WhatsApp/",
                "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/",
                "/sdcard/WhatsApp/",
                "/storage/emulated/0/WhatsApp/",
                "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp/",
                "/storage/emulated/0/Android/media/com.whatsapp.w4b/WhatsApp/",
            ],
            "removable_search_roots": ["/storage/", "/mnt/media_rw/"],
        },
        "acquisition": {
            "default_recovery_dir": "recovery",
            "safety_margin_bytes": 104857600,
            "safety_margin_ratio": 0.10,
            "chunk_size_bytes": 65536,
            "hash_algorithm": "sha256",
            "adb_command_timeout_seconds": 30,
            "adb_pull_timeout_seconds": 300,
        },
        "reporting": {
            "preferred_report_formats": ["html", "json", "csv"],
        },
    }

    if config_path is None:
        # Check standard config relative to repository
        repo_root = Path(__file__).resolve().parent.parent.parent
        config_path = repo_root / "config" / "settings.json"

    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                # Merge top-level keys
                for k, v in loaded.items():
                    if isinstance(v, dict) and k in default_settings and isinstance(default_settings[k], dict):
                        default_settings[k].update(v)
                    else:
                        default_settings[k] = v
        except Exception:
            pass

    return validate_settings(default_settings)


def save_settings(settings: dict[str, Any], config_path: Optional[Path] = None) -> bool:
    """Save validated settings dictionary to config/settings.json."""
    if config_path is None:
        repo_root = Path(__file__).resolve().parent.parent.parent
        config_path = repo_root / "config" / "settings.json"

    validated = validate_settings(settings)
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(validated, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False
