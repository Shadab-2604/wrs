"""Persistent SQLite scan inventory engine for WRS.

Tracks every discovered and acquired file with granular forensic statuses,
indexing, duplicate groups, and query support.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("wrs.inventory")

# Forensic inventory statuses
STATUS_DISCOVERED = "DISCOVERED"
STATUS_READABLE = "READABLE"
STATUS_ACQUISITION_ELIGIBLE = "ACQUISITION_ELIGIBLE"
STATUS_ACQUIRED = "ACQUIRED"
STATUS_VERIFIED = "VERIFIED"
STATUS_PARSEABLE = "PARSEABLE"
STATUS_RECOVERY_CANDIDATE = "RECOVERY_CANDIDATE"
STATUS_UNREADABLE = "UNREADABLE"
STATUS_FAILED = "FAILED"

VALID_INVENTORY_STATUSES = {
    STATUS_DISCOVERED,
    STATUS_READABLE,
    STATUS_ACQUISITION_ELIGIBLE,
    STATUS_ACQUIRED,
    STATUS_VERIFIED,
    STATUS_PARSEABLE,
    STATUS_RECOVERY_CANDIDATE,
    STATUS_UNREADABLE,
    STATUS_FAILED,
}


@dataclass
class InventoryRecord:
    """Detailed forensic inventory entry for an inspected device file."""

    scan_id: str
    device_id: str
    source_path: str
    relative_path: str
    filename: str
    extension: str
    category: str
    size_bytes: int
    modified_time: Optional[str] = None
    detected_mime_type: Optional[str] = None
    file_signature: Optional[str] = None
    readability: bool = True
    duplicate_group: Optional[str] = None
    acquisition_status: str = STATUS_DISCOVERED
    source_sha256: Optional[str] = None
    destination_sha256: Optional[str] = None
    verification_status: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None


class ScanInventoryDB:
    """SQLite-backed persistent scan inventory database."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables and performance indexes."""
        with self._get_connection() as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS file_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                source_path TEXT NOT NULL UNIQUE,
                relative_path TEXT NOT NULL,
                filename TEXT NOT NULL,
                extension TEXT NOT NULL,
                category TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                modified_time TEXT,
                detected_mime_type TEXT,
                file_signature TEXT,
                readability INTEGER NOT NULL DEFAULT 1,
                duplicate_group TEXT,
                acquisition_status TEXT NOT NULL DEFAULT 'DISCOVERED',
                source_sha256 TEXT,
                destination_sha256 TEXT,
                verification_status TEXT,
                error_code TEXT,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

            # Required indexes for rapid retrieval
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_scan_id ON file_inventory(scan_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_category ON file_inventory(category);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_source_path ON file_inventory(source_path);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_size_bytes ON file_inventory(size_bytes);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_dup_group ON file_inventory(duplicate_group);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_acq_status ON file_inventory(acquisition_status);")
            conn.commit()

    def insert_record(self, record: InventoryRecord) -> None:
        """Insert or replace a single file record."""
        self.insert_batch([record])

    def insert_batch(self, records: List[InventoryRecord]) -> None:
        """Insert or replace a batch of file inventory records efficiently."""
        if not records:
            return

        query = """
        INSERT INTO file_inventory (
            scan_id, device_id, source_path, relative_path, filename, extension,
            category, size_bytes, modified_time, detected_mime_type, file_signature,
            readability, duplicate_group, acquisition_status, source_sha256,
            destination_sha256, verification_status, error_code, error_message
        ) VALUES (
            :scan_id, :device_id, :source_path, :relative_path, :filename, :extension,
            :category, :size_bytes, :modified_time, :detected_mime_type, :file_signature,
            :readability, :duplicate_group, :acquisition_status, :source_sha256,
            :destination_sha256, :verification_status, :error_code, :error_message
        ) ON CONFLICT(source_path) DO UPDATE SET
            category=excluded.category,
            size_bytes=excluded.size_bytes,
            modified_time=excluded.modified_time,
            readability=excluded.readability,
            acquisition_status=excluded.acquisition_status,
            source_sha256=COALESCE(excluded.source_sha256, file_inventory.source_sha256),
            destination_sha256=COALESCE(excluded.destination_sha256, file_inventory.destination_sha256),
            verification_status=COALESCE(excluded.verification_status, file_inventory.verification_status),
            error_message=COALESCE(excluded.error_message, file_inventory.error_message);
        """
        payloads = []
        for r in records:
            d = asdict(r)
            d["readability"] = 1 if r.readability else 0
            payloads.append(d)

        with self._get_connection() as conn:
            conn.executemany(query, payloads)
            conn.commit()

    def update_acquisition_status(
        self,
        source_path: str,
        status: str,
        destination_sha256: Optional[str] = None,
        verification_status: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Update acquisition outcome for a given file."""
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE file_inventory
                SET acquisition_status = ?,
                    destination_sha256 = COALESCE(?, destination_sha256),
                    verification_status = COALESCE(?, verification_status),
                    error_message = COALESCE(?, error_message)
                WHERE source_path = ?;
                """,
                (status, destination_sha256, verification_status, error_message, source_path),
            )
            conn.commit()

    def update_duplicate_groups(self, groups: Dict[str, List[str]]) -> None:
        """Assign duplicate group identifiers to matching source paths."""
        updates = []
        for group_id, paths in groups.items():
            for p in paths:
                updates.append((group_id, p))

        with self._get_connection() as conn:
            conn.executemany(
                "UPDATE file_inventory SET duplicate_group = ? WHERE source_path = ?;",
                updates,
            )
            conn.commit()

    def get_records(
        self,
        scan_id: Optional[str] = None,
        category: Optional[str] = None,
        acquisition_status: Optional[str] = None,
        duplicate_group: Optional[str] = None,
    ) -> List[InventoryRecord]:
        """Query inventory records matching specified filters."""
        clauses = []
        params: List[Any] = []

        if scan_id:
            clauses.append("scan_id = ?")
            params.append(scan_id)
        if category:
            clauses.append("category = ?")
            params.append(category)
        if acquisition_status:
            clauses.append("acquisition_status = ?")
            params.append(acquisition_status)
        if duplicate_group:
            clauses.append("duplicate_group = ?")
            params.append(duplicate_group)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        query = f"SELECT * FROM file_inventory {where} ORDER BY category, relative_path;"

        records = []
        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            for row in cursor.fetchall():
                records.append(
                    InventoryRecord(
                        scan_id=row["scan_id"],
                        device_id=row["device_id"],
                        source_path=row["source_path"],
                        relative_path=row["relative_path"],
                        filename=row["filename"],
                        extension=row["extension"],
                        category=row["category"],
                        size_bytes=row["size_bytes"],
                        modified_time=row["modified_time"],
                        detected_mime_type=row["detected_mime_type"],
                        file_signature=row["file_signature"],
                        readability=bool(row["readability"]),
                        duplicate_group=row["duplicate_group"],
                        acquisition_status=row["acquisition_status"],
                        source_sha256=row["source_sha256"],
                        destination_sha256=row["destination_sha256"],
                        verification_status=row["verification_status"],
                        error_code=row["error_code"],
                        error_message=row["error_message"],
                    )
                )
        return records

    def get_summary(self, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Aggregate counts and sizes by category and status."""
        where = "WHERE scan_id = ?" if scan_id else ""
        params = [scan_id] if scan_id else []

        with self._get_connection() as conn:
            # Totals
            cur = conn.execute(f"SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM file_inventory {where};", params)
            tot_files, tot_bytes = cur.fetchone()

            # By Category
            cur = conn.execute(
                f"SELECT category, COUNT(*), SUM(size_bytes) FROM file_inventory {where} GROUP BY category;",
                params,
            )
            cat_counts = {}
            cat_bytes = {}
            for row in cur.fetchall():
                cat_counts[row[0]] = row[1]
                cat_bytes[row[0]] = row[2] or 0

            # By Status
            cur = conn.execute(
                f"SELECT acquisition_status, COUNT(*) FROM file_inventory {where} GROUP BY acquisition_status;",
                params,
            )
            status_counts = {row[0]: row[1] for row in cur.fetchall()}

            # Duplicate count
            cur = conn.execute(
                f"SELECT COUNT(*) FROM file_inventory {where} AND duplicate_group IS NOT NULL;"
                if where else "SELECT COUNT(*) FROM file_inventory WHERE duplicate_group IS NOT NULL;",
                params,
            )
            dup_count = cur.fetchone()[0]

        return {
            "total_files": tot_files,
            "total_bytes": tot_bytes,
            "category_counts": cat_counts,
            "category_bytes": cat_bytes,
            "status_counts": status_counts,
            "duplicate_candidates": dup_count,
        }
