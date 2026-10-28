"""Unit tests for SQLite persistent scan inventory (src/wrs/inventory.py)."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from wrs.inventory import (
    STATUS_ACQUISITION_ELIGIBLE,
    STATUS_ACQUIRED,
    STATUS_DISCOVERED,
    STATUS_VERIFIED,
    InventoryRecord,
    ScanInventoryDB,
)


class TestScanInventory(unittest.TestCase):
    """Test ScanInventoryDB database creation, indexing, records upsert, and queries."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_inventory.db"
        self.inv = ScanInventoryDB(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_schema_and_indexes_initialization(self):
        """Verify inventory database tables and indexes are created properly."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='file_inventory'")
            tbl = cursor.fetchone()
            self.assertIsNotNone(tbl)

            # Check indexes
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
            indexes = {row[0] for row in cursor.fetchall()}
            self.assertIn("idx_inv_scan_id", indexes)
            self.assertIn("idx_inv_category", indexes)
            self.assertIn("idx_inv_acq_status", indexes)
            self.assertIn("idx_inv_size_bytes", indexes)

    def test_insert_and_retrieve_record(self):
        """Test inserting and retrieving single record."""
        rec = InventoryRecord(
            scan_id="SCAN_001",
            device_id="DEV_ABC",
            source_path="/sdcard/WhatsApp/Media/WhatsApp Images/photo.jpg",
            relative_path="Media/WhatsApp Images/photo.jpg",
            filename="photo.jpg",
            extension=".jpg",
            category="Images",
            size_bytes=1048576,
            modified_time="2023-07-22 10:00:00",
            detected_mime_type="image/jpeg",
            acquisition_status=STATUS_DISCOVERED,
        )
        self.inv.insert_record(rec)

        records = self.inv.get_records(scan_id="SCAN_001")
        self.assertEqual(len(records), 1)
        retrieved = records[0]
        self.assertEqual(retrieved.scan_id, "SCAN_001")
        self.assertEqual(retrieved.category, "Images")
        self.assertEqual(retrieved.size_bytes, 1048576)
        self.assertEqual(retrieved.acquisition_status, STATUS_DISCOVERED)

    def test_batch_insert_and_summary(self):
        """Test batch insertion and calculation of scan inventory summary."""
        records = [
            InventoryRecord(
                scan_id="SCAN_001",
                device_id="DEV_ABC",
                source_path=f"/sdcard/WhatsApp/img_{i}.jpg",
                relative_path=f"img_{i}.jpg",
                filename=f"img_{i}.jpg",
                extension=".jpg",
                category="Images",
                size_bytes=1000 * (i + 1),
                acquisition_status=STATUS_ACQUISITION_ELIGIBLE,
            )
            for i in range(5)
        ]
        records.append(
            InventoryRecord(
                scan_id="SCAN_001",
                device_id="DEV_ABC",
                source_path="/sdcard/WhatsApp/Databases/msgstore.db.crypt14",
                relative_path="Databases/msgstore.db.crypt14",
                filename="msgstore.db.crypt14",
                extension=".crypt14",
                category="Databases",
                size_bytes=50000,
                acquisition_status=STATUS_DISCOVERED,
            )
        )

        self.inv.insert_batch(records)
        summary = self.inv.get_summary("SCAN_001")

        self.assertEqual(summary["total_files"], 6)
        self.assertEqual(summary["total_bytes"], 1000 + 2000 + 3000 + 4000 + 5000 + 50000)
        self.assertEqual(summary["category_counts"]["Images"], 5)
        self.assertEqual(summary["category_counts"]["Databases"], 1)
        self.assertEqual(summary["status_counts"][STATUS_ACQUISITION_ELIGIBLE], 5)

    def test_update_status_and_hashes(self):
        """Test updating acquisition status and SHA-256 digests."""
        rec = InventoryRecord(
            scan_id="SCAN_001",
            device_id="DEV_ABC",
            source_path="/sdcard/WhatsApp/doc.pdf",
            relative_path="doc.pdf",
            filename="doc.pdf",
            extension=".pdf",
            category="Documents",
            size_bytes=5000,
            acquisition_status=STATUS_DISCOVERED,
        )
        self.inv.insert_record(rec)

        self.inv.update_acquisition_status(
            source_path="/sdcard/WhatsApp/doc.pdf",
            status=STATUS_VERIFIED,
            destination_sha256="aaa111",
            verification_status="VERIFIED",
        )

        records = self.inv.get_records(scan_id="SCAN_001")
        self.assertEqual(len(records), 1)
        updated = records[0]
        self.assertEqual(updated.acquisition_status, STATUS_VERIFIED)
        self.assertEqual(updated.destination_sha256, "aaa111")
        self.assertEqual(updated.verification_status, "VERIFIED")

    def test_duplicate_groups(self):
        """Test assigning duplicate group and retrieving records by duplicate group."""
        rec1 = InventoryRecord(
            scan_id="SCAN_001",
            device_id="DEV_ABC",
            source_path="/sdcard/WhatsApp/dup1.jpg",
            relative_path="dup1.jpg",
            filename="dup1.jpg",
            extension=".jpg",
            category="Images",
            size_bytes=2048,
        )
        rec2 = InventoryRecord(
            scan_id="SCAN_001",
            device_id="DEV_ABC",
            source_path="/sdcard/WhatsApp/dup2.jpg",
            relative_path="dup2.jpg",
            filename="dup2.jpg",
            extension=".jpg",
            category="Images",
            size_bytes=2048,
        )
        self.inv.insert_batch([rec1, rec2])

        self.inv.update_duplicate_groups({"DUP_HASH_XYZ": ["/sdcard/WhatsApp/dup1.jpg", "/sdcard/WhatsApp/dup2.jpg"]})

        group_records = self.inv.get_records(duplicate_group="DUP_HASH_XYZ")
        self.assertEqual(len(group_records), 2)
        paths = {r.source_path for r in group_records}
        self.assertIn("/sdcard/WhatsApp/dup1.jpg", paths)
        self.assertIn("/sdcard/WhatsApp/dup2.jpg", paths)


if __name__ == "__main__":
    unittest.main()
