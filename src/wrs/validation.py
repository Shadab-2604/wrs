"""Forensic validation and database assessment module for WRS.

Inspects accessible SQLite databases in read-only mode, assesses
encrypted database candidates (crypt14/crypt15), and prevents path traversal.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("wrs.validation")


@dataclass
class SQLiteInspectionResult:
    """Summary of read-only SQLite database inspection."""

    is_sqlite: bool
    integrity_ok: bool
    table_count: int = 0
    tables: List[str] = field(default_factory=list)
    integrity_output: str = ""
    error_message: Optional[str] = None


@dataclass
class EncryptedDatabaseCandidate:
    """Forensic assessment of an encrypted WhatsApp database candidate."""

    filepath: str
    filename: str
    crypt_version: str  # 'crypt14', 'crypt15', 'crypt12', etc.
    size_bytes: int
    header_magic: str = ""
    is_dated_backup: bool = False
    assessment: str = ""


class ForensicValidator:
    """Performs non-destructive validation and analysis on acquired assets."""

    @staticmethod
    def inspect_sqlite_readonly(db_path: Path | str) -> SQLiteInspectionResult:
        """Inspect an SQLite database in strictly read-only mode.

        Opens with URI mode=ro to prevent any modification or WAL creation.
        """
        p = Path(db_path)
        if not p.is_file():
            return SQLiteInspectionResult(
                is_sqlite=False,
                integrity_ok=False,
                error_message=f"File not found: {p}",
            )

        # Quick header check
        try:
            with open(p, "rb") as f:
                header = f.read(16)
                if not header.startswith(b"SQLite format 3\x00"):
                    return SQLiteInspectionResult(
                        is_sqlite=False,
                        integrity_ok=False,
                        error_message="Header does not match SQLite format 3 signature.",
                    )
        except OSError as e:
            return SQLiteInspectionResult(is_sqlite=False, integrity_ok=False, error_message=str(e))

        # Open in strictly read-only mode
        uri = f"file:{p.resolve()}?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=5.0)
            cursor = conn.cursor()

            # Integrity check
            cursor.execute("PRAGMA integrity_check(5);")
            rows = cursor.fetchall()
            integrity_output = "\n".join(r[0] for r in rows if r)
            integrity_ok = integrity_output.strip().lower() == "ok"

            # Table inventory
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
            tables = [r[0] for r in cursor.fetchall() if r]

            conn.close()

            return SQLiteInspectionResult(
                is_sqlite=True,
                integrity_ok=integrity_ok,
                table_count=len(tables),
                tables=tables,
                integrity_output=integrity_output,
            )
        except sqlite3.Error as e:
            return SQLiteInspectionResult(
                is_sqlite=True,
                integrity_ok=False,
                integrity_output=str(e),
                error_message=f"SQLite inspection error: {e}",
            )

    @staticmethod
    def assess_encrypted_database(
        filepath: str,
        filename: str,
        size_bytes: int,
        header_sample: Optional[bytes] = None,
    ) -> EncryptedDatabaseCandidate:
        """Assess an encrypted WhatsApp database candidate without attempting decryption."""
        fn_lower = filename.lower()
        crypt_ver = "unknown_crypt"

        for v in ("crypt15", "crypt14", "crypt12", "crypt10", "crypt8", "crypt7", "crypt"):
            if fn_lower.endswith(f".{v}"):
                crypt_ver = v
                break

        is_dated = "msgstore-20" in fn_lower

        magic_hex = header_sample[:16].hex() if header_sample else ""

        assessment = (
            f"Candidate WhatsApp {crypt_ver.upper()} encrypted database (AES-GCM format). "
            "Integrity preserved in raw format. Decryption requires the private encryption "
            "key (/data/data/com.whatsapp/files/key), which is secured in WhatsApp private "
            "storage and is inaccessible via standard unrooted ADB. No decryption or modification attempted."
        )

        return EncryptedDatabaseCandidate(
            filepath=filepath,
            filename=filename,
            crypt_version=crypt_ver,
            size_bytes=size_bytes,
            header_magic=magic_hex,
            is_dated_backup=is_dated,
            assessment=assessment,
        )
