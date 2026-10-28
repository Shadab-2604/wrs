"""Device detection, inspection, and ADB communication module for WRS.

Executes controlled ADB commands without shell=True, handles authorization
states, inspects device properties, storage access, screen lock status,
and root indicator status.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

logger = logging.getLogger("wrs.device")


def get_device_salt() -> bytes:
    """Load or generate a local persistent 32-byte salt for non-secret device identifier hashing."""
    salt_dir = Path(__file__).resolve().parent.parent.parent / "config"
    salt_file = salt_dir / "device_salt.bin"
    if salt_file.exists():
        try:
            val = salt_file.read_bytes()
            if len(val) >= 16:
                return val
        except OSError:
            pass
    salt_dir.mkdir(parents=True, exist_ok=True)
    new_salt = os.urandom(32)
    try:
        salt_file.write_bytes(new_salt)
    except OSError:
        pass
    return new_salt


def generate_device_identifier(
    manufacturer: str, model: str, serial: str, salt: Optional[bytes] = None
) -> str:
    """Create a stable internal device identifier using non-secret metadata and local salt.

    Never hashes or stores sensitive user identifiers like IMEI or phone numbers.
    """
    if not serial:
        return "dev_unknown"
    s = salt if salt is not None else get_device_salt()
    token = f"{s.hex()}:{manufacturer.strip().lower()}:{model.strip().lower()}:{serial.strip()}".encode("utf-8")
    return f"dev_{hashlib.sha256(token).hexdigest()[:16]}"


@dataclass
class DeviceInfo:
    """Comprehensive details of an Android device inspected via ADB."""

    serial: str
    state: str  # 'device', 'unauthorized', 'offline', 'unavailable', etc.
    device_id: str = ""
    manufacturer: str = "Unknown"
    model: str = "Unknown"
    android_version: str = "Unknown"
    sdk_version: str = "Unknown"
    screen_unlocked: Optional[bool] = None
    root_status: str = "UNKNOWN"  # 'DETECTED', 'NOT_DETECTED', 'UNKNOWN'
    internal_storage_accessible: bool = False
    removable_storage_accessible: bool = False
    removable_mounts: List[str] = field(default_factory=list)
    product_name: str = ""
    device_codename: str = ""
    error_message: Optional[str] = None

    @property
    def display_name(self) -> str:
        """Formatted human-readable device name based on priority:
        1. Manufacturer and model.
        2. Product or device model if reported model is unavailable.
        3. Neutral fallback: Android Device (<serial suffix>).
        """
        mfg = self.manufacturer.strip() if self.manufacturer else ""
        mdl = self.model.strip() if self.model else ""
        prod = self.product_name.strip() if self.product_name else ""
        code = self.device_codename.strip() if self.device_codename else ""

        if mfg and mfg.lower() != "unknown" and mdl and mdl.lower() != "unknown":
            if mdl.lower().startswith(mfg.lower()):
                return mdl
            return f"{mfg} {mdl}"
        if mdl and mdl.lower() != "unknown":
            return mdl
        if prod and prod.lower() != "unknown":
            return prod
        if code and code.lower() != "unknown":
            return code

        suffix = self.serial[-6:] if len(self.serial) > 6 else self.serial
        return f"Android Device ({suffix})"

    @property
    def is_authorized(self) -> bool:
        """Whether the device has granted USB debugging authorization."""
        return self.state.lower() in ("device", "authorized")

    @property
    def status_display(self) -> str:
        """Human-readable connection status indicator."""
        st = self.state.lower()
        if st in ("device", "authorized"):
            return "CONNECTED / AUTHORIZED"
        if st == "unauthorized":
            return "UNAUTHORIZED"
        if st == "offline":
            return "OFFLINE"
        if st in ("disconnected", "unavailable"):
            return "DISCONNECTED"
        return "UNKNOWN"

    def get_display_serial(self, masked: bool = False) -> str:
        """Return raw or masked serial string for display."""
        if not masked or not self.serial:
            return self.serial
        clean = self.serial.strip()
        if len(clean) <= 6:
            return "****" + clean[-2:]
        return f"{clean[:4]}****{clean[-4:]}"

    @property
    def is_accessible(self) -> bool:
        """Whether the device is in ready state for scanning."""
        if not self.is_authorized:
            return False
        if self.state in ("unauthorized", "offline", "unavailable"):
            return False
        return True


class AdbExecutor:
    """Safely executes ADB commands with argument lists and strict timeouts."""

    def __init__(
        self,
        adb_path: Optional[str] = None,
        runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
    ) -> None:
        self.adb_path = adb_path or shutil.which("adb") or "/usr/bin/adb"
        self._runner = runner or subprocess.run
        self._device_cache: dict[str, DeviceInfo] = {}

    def is_adb_installed(self) -> bool:
        """Check if ADB executable exists on system."""
        return bool(shutil.which(self.adb_path) or os.path.isfile(self.adb_path))

    def get_adb_version(self) -> Tuple[bool, str]:
        """Query ADB version."""
        if not self.is_adb_installed():
            return False, "ADB executable not found. Install android-tools-adb or android-sdk-platform-tools."

        try:
            res = self._runner(
                [self.adb_path, "version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if res.returncode == 0:
                first_line = res.stdout.strip().split("\n")[0] if res.stdout else "ADB installed"
                return True, first_line
            return False, f"ADB version check failed: {res.stderr.strip()}"
        except (subprocess.TimeoutExpired, OSError) as e:
            return False, f"Failed to execute ADB: {e}"

    def run_cmd(
        self,
        args: List[str],
        serial: Optional[str] = None,
        timeout: int = 30,
        text: bool = True,
    ) -> subprocess.CompletedProcess:
        """Execute ADB command using argument list (never shell=True)."""
        cmd = [self.adb_path]
        if serial:
            cmd.extend(["-s", serial])
        cmd.extend(args)

        try:
            return self._runner(
                cmd,
                capture_output=True,
                text=text,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            logger.warning("ADB command timed out after %ds: %s", timeout, " ".join(cmd))
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=-1,
                stdout="" if text else b"",
                stderr=f"Command timed out after {timeout} seconds: {exc}" if text else b"Command timed out",
            )
        except OSError as exc:
            logger.error("OS error executing ADB command: %s", exc)
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=-2,
                stdout="" if text else b"",
                stderr=str(exc) if text else str(exc).encode(),
            )

    def list_devices(self) -> List[DeviceInfo]:
        """Enumerate connected Android devices using 'adb devices -l'."""
        if not self.is_adb_installed():
            return []

        res = self.run_cmd(["devices", "-l"], timeout=10)
        if res.returncode != 0:
            logger.error("adb devices -l failed: %s", res.stderr)
            return []

        devices: List[DeviceInfo] = []
        lines = res.stdout.strip().splitlines()

        for line in lines[1:]:  # skip 'List of devices attached'
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if not parts:
                continue

            serial = parts[0]
            state = parts[1] if len(parts) > 1 else "unknown"

            # Parse optional key-value descriptors (e.g. product:cheetah model:Pixel_7 device:cheetah)
            extra_props: dict[str, str] = {}
            for token in parts[2:]:
                if ":" in token:
                    k, v = token.split(":", 1)
                    extra_props[k] = v

            dev = DeviceInfo(
                serial=serial,
                state=state,
                product_name=extra_props.get("product", ""),
                model=extra_props.get("model", "Unknown").replace("_", " "),
                device_codename=extra_props.get("device", ""),
            )

            # If unauthorized or offline, record appropriate advisory
            if state == "unauthorized":
                dev.error_message = (
                    "Device is unauthorized. Please unlock your phone screen, "
                    "look for the 'Allow USB debugging?' dialog, check 'Always allow from this computer', "
                    "and tap OK."
                )
            elif state == "offline":
                dev.error_message = (
                    "Device is offline. Disconnect and reconnect the USB cable, "
                    "or toggle USB Debugging in Developer Options."
                )

            devices.append(dev)

        return devices

    def clear_cache(self) -> None:
        """Clear cached session device metadata."""
        self._device_cache.clear()

    def get_device_details(self, serial: str, refresh: bool = False) -> DeviceInfo:
        """Inspect detailed hardware, OS, root, storage, and screen lock properties."""
        if not refresh and serial in self._device_cache:
            cached = self._device_cache[serial]
            if self.is_device_connected(serial):
                return cached

        # First query device list to get baseline state
        devices = self.list_devices()
        dev: Optional[DeviceInfo] = next((d for d in devices if d.serial == serial), None)

        if not dev:
            return DeviceInfo(
                serial=serial,
                state="unavailable",
                error_message=f"Device {serial} was not found in connected ADB devices.",
            )

        if dev.state != "device":
            self._device_cache[serial] = dev
            return dev

        # 1. Hardware & OS properties
        props_cmd = self.run_cmd(
            ["shell", "getprop"],
            serial=serial,
            timeout=15,
        )
        props = {}
        if props_cmd.returncode == 0:
            props = self._parse_getprop(props_cmd.stdout)
            dev.manufacturer = props.get("ro.product.manufacturer", dev.manufacturer).strip().title()
            dev.model = props.get("ro.product.model", dev.model).strip()
            dev.android_version = props.get("ro.build.version.release", dev.android_version).strip()
            dev.sdk_version = props.get("ro.build.version.sdk", dev.sdk_version).strip()
            dev.product_name = props.get("ro.product.name", dev.product_name).strip()
            dev.device_codename = props.get("ro.product.device", dev.device_codename).strip()

        # Query individual getprop properties if core attributes remain Unknown
        if dev.manufacturer == "Unknown":
            res_m = self.run_cmd(["shell", "getprop", "ro.product.manufacturer"], serial=serial, timeout=5)
            if res_m.returncode == 0 and res_m.stdout.strip():
                dev.manufacturer = res_m.stdout.strip().title()
        if dev.model == "Unknown":
            res_mdl = self.run_cmd(["shell", "getprop", "ro.product.model"], serial=serial, timeout=5)
            if res_mdl.returncode == 0 and res_mdl.stdout.strip():
                dev.model = res_mdl.stdout.strip()
        if dev.android_version == "Unknown":
            res_av = self.run_cmd(["shell", "getprop", "ro.build.version.release"], serial=serial, timeout=5)
            if res_av.returncode == 0 and res_av.stdout.strip():
                dev.android_version = res_av.stdout.strip()
        if dev.sdk_version == "Unknown":
            res_sdk = self.run_cmd(["shell", "getprop", "ro.build.version.sdk"], serial=serial, timeout=5)
            if res_sdk.returncode == 0 and res_sdk.stdout.strip():
                dev.sdk_version = res_sdk.stdout.strip()

        # 2. Storage Accessibility
        # Test internal shared storage
        int_res = self.run_cmd(
            ["shell", "ls", "-d", "/sdcard", "/storage/emulated/0"],
            serial=serial,
            timeout=10,
        )
        dev.internal_storage_accessible = int_res.returncode == 0 and bool(int_res.stdout.strip())

        # Test removable storage mounts
        mounts_res = self.run_cmd(
            ["shell", "ls", "/storage/"],
            serial=serial,
            timeout=10,
        )
        if mounts_res.returncode == 0 and mounts_res.stdout:
            removable: List[str] = []
            for entry in mounts_res.stdout.strip().split():
                clean_entry = entry.strip()
                # Secondary volumes on Android are usually formatted as XXXX-XXXX (hex volume ID)
                if clean_entry and clean_entry not in ("emulated", "self", "knox-emulated") and not clean_entry.startswith("."):
                    path = f"/storage/{clean_entry}"
                    # test if readable
                    chk = self.run_cmd(["shell", "ls", path], serial=serial, timeout=5)
                    if chk.returncode == 0:
                        removable.append(path)
            if removable:
                dev.removable_storage_accessible = True
                dev.removable_mounts = removable

        # 3. Screen Lock Status (safely queried without erroring if permission restricted)
        dev.screen_unlocked = self._check_screen_unlocked(serial)

        # 4. Root Status Check
        # Note: Do not treat failed root check as proof of non-root.
        dev.root_status = self._check_root_status(serial)

        # 5. Stable non-secret device identifier
        dev.device_id = generate_device_identifier(dev.manufacturer, dev.model, dev.serial)

        self._device_cache[serial] = dev
        return dev

    def is_device_connected(self, serial: str) -> bool:
        """Verify whether the device remains attached and responsive."""
        res = self.run_cmd(["get-state"], serial=serial, timeout=5)
        if res.returncode != 0:
            return False
        err_lower = (res.stderr or "").lower()
        out_lower = (res.stdout or "").lower()
        if any(term in err_lower or term in out_lower for term in ["offline", "not found", "disconnected", "unauthorized", "closed"]):
            return False
        if out_lower:
            return "device" in out_lower
        return True

    def _parse_getprop(self, output: str) -> dict[str, str]:
        """Parse getprop bracketed format: [key]: [value]."""
        props: dict[str, str] = {}
        pattern = re.compile(r"^\[(.*?)\]:\s*\[(.*?)\]$", re.MULTILINE)
        for match in pattern.finditer(output):
            props[match.group(1)] = match.group(2)
        return props

    def _check_screen_unlocked(self, serial: str) -> Optional[bool]:
        """Check if screen is on and unlocked. Returns None if unknown."""
        # Try dumpsys window or dumpsys power safely
        res = self.run_cmd(["shell", "dumpsys", "window"], serial=serial, timeout=10)
        if res.returncode == 0 and res.stdout:
            out = res.stdout.lower()
            # Check keyguard showing
            if "mkeyguardshowing=true" in out or "mshowingdream=true" in out:
                return False
            if "mkeyguardshowing=false" in out:
                return True

        # Fallback to dumpsys power
        pwr = self.run_cmd(["shell", "dumpsys", "power"], serial=serial, timeout=10)
        if pwr.returncode == 0 and pwr.stdout:
            out = pwr.stdout.lower()
            if "mholdingdisplaysuspendblocker=false" in out or "display power: state=off" in out:
                return False

        return None

    def _check_root_status(self, serial: str) -> str:
        """Check root indicators without modifying the device.

        Returns:
            'DETECTED': SU binary or root UID confirmed.
            'NOT_DETECTED': Root indicators not found in standard paths.
            'UNKNOWN': Check inconclusive or command restricted.
        """
        # Test 1: id command
        id_res = self.run_cmd(["shell", "id"], serial=serial, timeout=5)
        if id_res.returncode == 0 and "uid=0(root)" in id_res.stdout:
            return "DETECTED"

        # Test 2: which su or presence of su binary in common locations
        su_test = self.run_cmd(
            ["shell", "which su || ls /system/bin/su /system/xbin/su /sbin/su /vendor/bin/su 2>/dev/null"],
            serial=serial,
            timeout=5,
        )
        if su_test.returncode == 0 and "su" in su_test.stdout.lower():
            return "DETECTED"

        # If tests executed normally without root indicators
        if id_res.returncode == 0:
            return "NOT_DETECTED"

        return "UNKNOWN"
