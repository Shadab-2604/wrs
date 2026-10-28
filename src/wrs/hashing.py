"""SHA-256 calculation and integrity verification module for WRS.

Streams file data for memory-efficient hashing, queries on-device hashes
when supported, compares integrity, and validates acquired datasets.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from .device import AdbExecutor
from .utils import format_timestamp

logger = logging.getLogger("wrs.hashing")

# Verification Status Identifiers
STATUS_VERIFIED = "VERIFIED"
STATUS_SOURCE_HASH_UNAVAILABLE = "SOURCE_HASH_UNAVAILABLE"
STATUS_SIZE_MISMATCH = "SIZE_MISMATCH"
STATUS_HASH_MISMATCH = "HASH_MISMATCH"
STATUS_PARTIAL = "PARTIAL"
STATUS_FAILED = "FAILED"
STATUS_SKIPPED = "SKIPPED"


@dataclass
class VerificationRecord:
    """Integrity verification result for a single acquired file."""

    source_path: str
    destination_path: str
    expected_size: int
    acquired_size: int
    source_sha256: Optional[str]
    destination_sha256: Optional[str]
    status: str
    timestamp: str
    error_message: Optional[str] = None


def hash_local_file(filepath: Path | str, chunk_size: int = 65536) -> Tuple[Optional[str], int, Optional[str]]:
    """Compute SHA-256 hash and size of a local file via streaming.

    Returns (sha256_hex, file_size_bytes, error_message).
    """
    path = Path(filepath)
    if not path.is_file():
        return None, 0, f"File does not exist or is not a regular file: {path}"

    sha256 = hashlib.sha256()
    total_bytes = 0

    try:
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
                total_bytes += len(chunk)
        return sha256.hexdigest(), total_bytes, None
    except OSError as e:
        return None, total_bytes, f"OS error reading {path}: {e}"


def get_remote_file_hash(executor: AdbExecutor, serial: str, remote_path: str) -> Tuple[Optional[str], Optional[str]]:
    """Attempt to compute SHA-256 on the Android device via 'sha256sum'.

    Returns (sha256_hex, error_message).
    If sha256sum is unavailable on the device, returns (None, reason).
    """
    cmd = ["shell", f'sha256sum "{remote_path}" 2>/dev/null']
    res = executor.run_cmd(cmd, serial=serial, timeout=30)

    if res.returncode == 0 and res.stdout.strip():
        parts = res.stdout.strip().split()
        if parts:
            candidate_hash = parts[0].lower()
            if len(candidate_hash) == 64 and all(c in "0123456789abcdef" for c in candidate_hash):
                return candidate_hash, None

    # Fallback check if toybox sha256sum exists
    return None, "Device sha256sum utility was unavailable or permission was restricted."


def evaluate_acquisition_integrity(
    source_path: str,
    dest_path: Path,
    expected_size: int,
    source_hash: Optional[str],
    dest_hash: Optional[str],
    acquired_size: int,
    copy_error: Optional[str] = None,
) -> VerificationRecord:
    """Evaluate and assign precise acquisition status based on forensic criteria."""
    now_str = format_timestamp()

    if copy_error:
        return VerificationRecord(
            source_path=source_path,
            destination_path=str(dest_path),
            expected_size=expected_size,
            acquired_size=acquired_size,
            source_sha256=source_hash,
            destination_sha256=dest_hash,
            status=STATUS_FAILED,
            timestamp=now_str,
            error_message=copy_error,
        )

    if not dest_path.exists():
        return VerificationRecord(
            source_path=source_path,
            destination_path=str(dest_path),
            expected_size=expected_size,
            acquired_size=0,
            source_sha256=source_hash,
            destination_sha256=None,
            status=STATUS_FAILED,
            timestamp=now_str,
            error_message="Destination file was not created.",
        )

    # Size check
    if acquired_size != expected_size and expected_size > 0:
        return VerificationRecord(
            source_path=source_path,
            destination_path=str(dest_path),
            expected_size=expected_size,
            acquired_size=acquired_size,
            source_sha256=source_hash,
            destination_sha256=dest_hash,
            status=STATUS_SIZE_MISMATCH,
            timestamp=now_str,
            error_message=f"Size mismatch: expected {expected_size} bytes, got {acquired_size} bytes.",
        )

    # If destination hash could not be computed
    if not dest_hash:
        return VerificationRecord(
            source_path=source_path,
            destination_path=str(dest_path),
            expected_size=expected_size,
            acquired_size=acquired_size,
            source_sha256=source_hash,
            destination_sha256=None,
            status=STATUS_FAILED,
            timestamp=now_str,
            error_message="Failed to compute destination SHA-256 hash.",
        )

    # If source hash was obtained independently on device
    if source_hash:
        if source_hash.lower() == dest_hash.lower():
            return VerificationRecord(
                source_path=source_path,
                destination_path=str(dest_path),
                expected_size=expected_size,
                acquired_size=acquired_size,
                source_sha256=source_hash,
                destination_sha256=dest_hash,
                status=STATUS_VERIFIED,
                timestamp=now_str,
            )
        else:
            return VerificationRecord(
                source_path=source_path,
                destination_path=str(dest_path),
                expected_size=expected_size,
                acquired_size=acquired_size,
                source_sha256=source_hash,
                destination_sha256=dest_hash,
                status=STATUS_HASH_MISMATCH,
                timestamp=now_str,
                error_message="SHA-256 mismatch between device source and local acquired file.",
            )

    # Source hash was not available independently
    return VerificationRecord(
        source_path=source_path,
        destination_path=str(dest_path),
        expected_size=expected_size,
        acquired_size=acquired_size,
        source_sha256=None,
        destination_sha256=dest_hash,
        status=STATUS_SOURCE_HASH_UNAVAILABLE,
        timestamp=now_str,
        error_message="Destination hash computed; independent device source hash was unavailable.",
    )
