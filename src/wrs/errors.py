"""Structured forensic error codes and actionable user guidance for WRS.

Provides unambiguous machine-readable error codes and human-friendly,
actionable remediation instructions.
"""

from __future__ import annotations

from typing import Optional

# Structured Error Codes
ERR_ADB_NOT_FOUND = "ERR_ADB_NOT_FOUND"
ERR_NO_DEVICE_CONNECTED = "ERR_NO_DEVICE_CONNECTED"
ERR_DEVICE_UNAUTHORIZED = "ERR_DEVICE_UNAUTHORIZED"
ERR_DEVICE_OFFLINE = "ERR_DEVICE_OFFLINE"
ERR_DEVICE_DISCONNECTED = "ERR_DEVICE_DISCONNECTED"
ERR_STORAGE_PERMISSION_DENIED = "ERR_STORAGE_PERMISSION_DENIED"
ERR_INSUFFICIENT_SPACE = "ERR_INSUFFICIENT_SPACE"
ERR_TRANSFER_INTERRUPTED = "ERR_TRANSFER_INTERRUPTED"
ERR_NO_WHATSAPP_STORAGE = "ERR_NO_WHATSAPP_STORAGE"
ERR_DATABASE_UNREADABLE = "ERR_DATABASE_UNREADABLE"
ERR_ENCRYPTION_KEY_REQUIRED = "ERR_ENCRYPTION_KEY_REQUIRED"
ERR_INVALID_CONFIGURATION = "ERR_INVALID_CONFIGURATION"


def format_actionable_error(
    error_code: str,
    context: Optional[str] = None,
    device_name: Optional[str] = None,
) -> str:
    """Format an error code into a structured, actionable terminal message."""
    dev_str = f"Device: {device_name}\n" if device_name else ""
    ctx_str = f"Details: {context}\n" if context else ""

    if error_code == ERR_ADB_NOT_FOUND:
        return (
            "\n" + "=" * 65 + "\n"
            "  ERROR [ERR_ADB_NOT_FOUND]: Android Debug Bridge (ADB) Not Found\n"
            "=" * 65 + "\n"
            f"{ctx_str}"
            "Explanation:\n"
            "  The 'adb' executable could not be located in your system PATH.\n\n"
            "Recommended Action:\n"
            "  1. Install ADB using your distribution's package manager:\n"
            "     sudo apt update && sudo apt install -y adb\n"
            "  2. Verify installation: adb version\n"
            "  3. Restart WRS.\n"
            + "=" * 65 + "\n"
        )

    if error_code == ERR_NO_DEVICE_CONNECTED:
        return (
            "\n" + "=" * 65 + "\n"
            "  ERROR [ERR_NO_DEVICE_CONNECTED]: No Android Device Detected\n"
            "=" * 65 + "\n"
            f"{ctx_str}"
            "Explanation:\n"
            "  ADB reported no attached Android devices over USB or Wi-Fi.\n\n"
            "Recommended Action:\n"
            "  1. Ensure your phone is connected to this computer with a USB data cable.\n"
            "  2. Enable Developer Options: Settings > About Phone > Tap 'Build Number' 7 times.\n"
            "  3. Enable USB Debugging: Settings > Developer Options > USB Debugging.\n"
            "  4. Unlock your phone screen.\n"
            "  5. Choose 'Refresh Devices' from the menu.\n"
            + "=" * 65 + "\n"
        )

    if error_code == ERR_DEVICE_UNAUTHORIZED:
        return (
            "\n" + "=" * 65 + "\n"
            "  ERROR [ERR_DEVICE_UNAUTHORIZED]: USB Debugging Unauthorized\n"
            "=" * 65 + "\n"
            f"{dev_str}{ctx_str}"
            "Explanation:\n"
            "  The target Android device has not granted USB debugging authorization\n"
            "  to this workstation's RSA key.\n\n"
            "Recommended Action:\n"
            "  1. Unlock the phone screen.\n"
            "  2. Look for the 'Allow USB debugging?' dialog on the phone screen.\n"
            "  3. Check 'Always allow from this computer' and tap 'Allow' or 'OK'.\n"
            "  4. Select 'Refresh Devices' [8] to confirm authorization.\n"
            + "=" * 65 + "\n"
        )

    if error_code == ERR_DEVICE_OFFLINE:
        return (
            "\n" + "=" * 65 + "\n"
            "  ERROR [ERR_DEVICE_OFFLINE]: Device is Offline\n"
            "=" * 65 + "\n"
            f"{dev_str}{ctx_str}"
            "Explanation:\n"
            "  The device is physically connected but ADB daemon cannot establish communication.\n\n"
            "Recommended Action:\n"
            "  1. Disconnect and firmly reconnect the USB cable.\n"
            "  2. Toggle USB Debugging OFF and then ON in Developer Options.\n"
            "  3. Restart ADB server if needed: adb kill-server && adb start-server\n"
            "  4. Select 'Refresh Devices' [8].\n"
            + "=" * 65 + "\n"
        )

    if error_code == ERR_DEVICE_DISCONNECTED:
        return (
            "\n" + "=" * 65 + "\n"
            "  ERROR [ERR_DEVICE_DISCONNECTED]: Device Disconnected During Operation\n"
            "=" * 65 + "\n"
            f"{dev_str}{ctx_str}"
            "Explanation:\n"
            "  The target phone disconnected while an operation was in progress.\n"
            "  All previously acquired files and verification manifests have been preserved safely.\n\n"
            "Recommended Action:\n"
            "  1. Check the USB physical connection.\n"
            "  2. Ensure the phone remains powered on and unlocked.\n"
            "  3. Reconnect the same device and select 'Scan and acquire data' [2] to resume.\n"
            "     WRS will automatically resume from the existing manifest without re-pulling intact files.\n"
            + "=" * 65 + "\n"
        )

    if error_code == ERR_STORAGE_PERMISSION_DENIED:
        return (
            "\n" + "=" * 65 + "\n"
            "  ERROR [ERR_STORAGE_PERMISSION_DENIED]: Storage Access Denied\n"
            "=" * 65 + "\n"
            f"{dev_str}{ctx_str}"
            "Explanation:\n"
            "  Access to the requested storage directory was blocked by Android permissions or SELinux.\n\n"
            "Recommended Action:\n"
            "  1. Unlock the phone.\n"
            "  2. On Android 11+, ensure the USB connection mode is set to 'File Transfer (MTP)'.\n"
            "  3. Check that external/shared storage is mounted and accessible.\n"
            + "=" * 65 + "\n"
        )

    if error_code == ERR_INSUFFICIENT_SPACE:
        return (
            "\n" + "=" * 65 + "\n"
            "  ERROR [ERR_INSUFFICIENT_SPACE]: Insufficient Destination Disk Space\n"
            "=" * 65 + "\n"
            f"{ctx_str}"
            "Explanation:\n"
            "  The destination partition does not have enough free capacity for the selected\n"
            "  acquisition data plus the configured safety margin.\n\n"
            "Recommended Action:\n"
            "  1. Free disk space on your workstation partition.\n"
            "  2. Specify a secondary external storage drive using --output PATH.\n"
            "  3. Alternatively, filter categories in the interactive scope selector.\n"
            + "=" * 65 + "\n"
        )

    if error_code == ERR_TRANSFER_INTERRUPTED:
        return (
            "\n" + "=" * 65 + "\n"
            "  WARNING [ERR_TRANSFER_INTERRUPTED]: Acquisition Session Interrupted\n"
            "=" * 65 + "\n"
            f"{dev_str}{ctx_str}"
            "Explanation:\n"
            "  The acquisition was cancelled or interrupted. All completed files, hashes,\n"
            "  and catalog entries have been saved to the recovery directory.\n\n"
            "Recommended Action:\n"
            "  To resume without re-copying existing files, rerun acquisition pointing to the\n"
            "  same target destination directory.\n"
            + "=" * 65 + "\n"
        )

    if error_code == ERR_NO_WHATSAPP_STORAGE:
        return (
            "\n" + "=" * 65 + "\n"
            "  NOTICE [ERR_NO_WHATSAPP_STORAGE]: No WhatsApp Storage Paths Detected\n"
            "=" * 65 + "\n"
            f"{dev_str}{ctx_str}"
            "Explanation:\n"
            "  No WhatsApp or WhatsApp Business directories were found in searched shared-storage\n"
            "  paths (/sdcard/Android/media/com.whatsapp/WhatsApp/, /sdcard/WhatsApp/, etc.).\n\n"
            "Forensic Note:\n"
            "  This does not claim WhatsApp was never installed. WhatsApp may store data exclusively\n"
            "  inside the app-private sandbox (/data/data/com.whatsapp/), which is isolated by Android OS.\n"
            + "=" * 65 + "\n"
        )

    # Generic fallback
    return (
        f"\n[!] ERROR [{error_code}]: {context or 'An unexpected error occurred.'}\n"
    )
