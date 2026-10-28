"""Report generation and manifest verification module for WRS.

Generates forensic HTML, CSV, and JSON reports from acquisition records,
incorporating SHA-256 verification results, category summaries, and forensic limitations.
Provides standalone post-acquisition verification against the stored manifest.
"""

from __future__ import annotations

import csv
import html
import json
import logging
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .categorizer import ALL_CATEGORIES, CAT_BACKUPS, CAT_DATABASES
from .device import DeviceInfo
from .hashing import (
    STATUS_FAILED,
    STATUS_HASH_MISMATCH,
    STATUS_SIZE_MISMATCH,
    STATUS_SOURCE_HASH_UNAVAILABLE,
    STATUS_VERIFIED,
    VerificationRecord,
    hash_local_file,
)
from .scanner import ScannedFile, ScanResult
from .utils import format_bytes, format_timestamp

logger = logging.getLogger("wrs.reporting")


class ReportGenerator:
    """Generates HTML, CSV, and JSON forensic reports."""

    def __init__(
        self,
        device: DeviceInfo,
        scan_result: ScanResult,
        records: Optional[List[VerificationRecord]] = None,
        output_dir: Optional[Path] = None,
    ) -> None:
        self.device = device
        self.scan_result = scan_result
        self.records = records or []
        self.output_dir = output_dir or Path(".")

        # Index verification records by source path for rapid lookup
        self.records_by_source: Dict[str, VerificationRecord] = {
            r.source_path: r for r in self.records
        }

    def generate_all(self) -> Tuple[Path, Path, Path]:
        """Generate HTML, CSV, and JSON reports in output_dir."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        html_path = self.output_dir / "report.html"
        csv_path = self.output_dir / "report.csv"
        json_path = self.output_dir / "report.json"

        self.generate_html(html_path)
        self.generate_csv(csv_path)
        self.generate_json(json_path)

        return html_path, csv_path, json_path

    def generate_csv(self, target_path: Path) -> None:
        """Generate structured CSV report with one row per discovered file."""
        fieldnames = [
            "original_path",
            "category",
            "filename",
            "size_bytes",
            "size_human",
            "modified_time",
            "relative_path",
            "local_path",
            "acquisition_status",
            "source_sha256",
            "destination_sha256",
            "hash_verified",
            "error",
        ]

        with open(target_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for sfile in self.scan_result.files:
                rec = self.records_by_source.get(sfile.original_path)
                status = rec.status if rec else "NOT_ACQUIRED"
                local_p = rec.destination_path if rec else ""
                src_hash = rec.source_sha256 if rec else ""
                dst_hash = rec.destination_sha256 if rec else ""
                verified_str = "YES" if status == STATUS_VERIFIED else "NO"
                err_str = rec.error_message if (rec and rec.error_message) else (sfile.error or "")

                writer.writerow({
                    "original_path": sfile.original_path,
                    "category": sfile.category,
                    "filename": sfile.filename,
                    "size_bytes": sfile.size_bytes,
                    "size_human": sfile.size_human,
                    "modified_time": sfile.modified_time or "",
                    "relative_path": sfile.relative_path,
                    "local_path": local_p,
                    "acquisition_status": status,
                    "source_sha256": src_hash or "",
                    "destination_sha256": dst_hash or "",
                    "hash_verified": verified_str,
                    "error": err_str,
                })

    def generate_json(self, target_path: Path) -> None:
        """Generate comprehensive forensic JSON report."""
        # Calculate verification counts
        status_counts: Dict[str, int] = {}
        for r in self.records:
            status_counts[r.status] = status_counts.get(r.status, 0) + 1

        file_entries: List[dict] = []
        for sfile in self.scan_result.files:
            rec = self.records_by_source.get(sfile.original_path)
            file_entries.append({
                "original_path": sfile.original_path,
                "relative_path": sfile.relative_path,
                "filename": sfile.filename,
                "extension": sfile.extension,
                "category": sfile.category,
                "size_bytes": sfile.size_bytes,
                "size_human": sfile.size_human,
                "modified_time": sfile.modified_time,
                "identification_method": sfile.identification_method,
                "readability": sfile.readability,
                "acquisition": asdict(rec) if rec else None,
            })

        payload = {
            "generator": "WRS — WhatsApp Recovery Scanner",
            "version": "1.0.0",
            "report_timestamp": format_timestamp(),
            "device": asdict(self.device),
            "scan_metadata": {
                "location": self.scan_result.location_path,
                "start_time": self.scan_result.start_time,
                "end_time": self.scan_result.end_time,
                "total_files": self.scan_result.total_files,
                "total_bytes": self.scan_result.total_bytes,
                "category_counts": self.scan_result.category_counts,
                "category_bytes": self.scan_result.category_bytes,
                "errors": self.scan_result.errors,
            },
            "acquisition_summary": {
                "total_acquired": len(self.records),
                "status_breakdown": status_counts,
            },
            "files": file_entries,
            "forensic_limitations": {
                "private_storage_restriction": (
                    "Standard ADB access inspects shared external storage only. "
                    "WhatsApp's internal application directory (/data/data/com.whatsapp/) "
                    "is protected by Android OS sandbox permissions and cannot be read without root or physical extraction."
                ),
                "encryption_key_notice": (
                    "WhatsApp crypt14 and crypt15 databases are encrypted with AES-GCM. "
                    "Decryption requires the private key (/data/data/com.whatsapp/files/key) "
                    "which resides in protected app storage. WRS acquires and preserves encrypted databases "
                    "in byte-accurate raw form without attempting unauthorized decryption."
                ),
                "deleted_data_notice": (
                    "This tool acquires existing files from device storage. It does not perform flash-memory carving "
                    "or recover unallocated space without specialized low-level physical acquisition."
                ),
            },
        }

        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    def generate_html(self, target_path: Path) -> None:
        """Generate a secure, standalone HTML forensic report."""
        status_counts: Dict[str, int] = {}
        for r in self.records:
            status_counts[r.status] = status_counts.get(r.status, 0) + 1

        verified_count = status_counts.get(STATUS_VERIFIED, 0)
        source_unavail_count = status_counts.get(STATUS_SOURCE_HASH_UNAVAILABLE, 0)
        failed_count = (
            status_counts.get(STATUS_FAILED, 0)
            + status_counts.get(STATUS_HASH_MISMATCH, 0)
            + status_counts.get(STATUS_SIZE_MISMATCH, 0)
        )

        # Database and backup candidate list
        db_candidates = [
            f for f in self.scan_result.files
            if f.category in (CAT_DATABASES, CAT_BACKUPS)
        ]

        # Escape all dynamic data safely
        dev_display = html.escape(self.device.display_name)
        dev_serial = html.escape(self.device.serial)
        dev_os = html.escape(self.device.android_version)
        dev_sdk = html.escape(self.device.sdk_version)
        dev_root = html.escape(self.device.root_status)
        location_path = html.escape(self.scan_result.location_path)
        start_t = html.escape(self.scan_result.start_time)
        end_t = html.escape(self.scan_result.end_time)

        # Build Category Table rows
        cat_rows = []
        for cat in ALL_CATEGORIES:
            cnt = self.scan_result.category_counts.get(cat, 0)
            b = self.scan_result.category_bytes.get(cat, 0)
            if cnt > 0:
                share = (b / self.scan_result.total_bytes * 100) if self.scan_result.total_bytes > 0 else 0
                cat_rows.append(f"""
                <tr>
                    <td><strong>{html.escape(cat)}</strong></td>
                    <td class="num">{cnt}</td>
                    <td class="num">{html.escape(format_bytes(b))}</td>
                    <td class="num">{share:.1f}%</td>
                </tr>
                """)
        cat_table_body = "".join(cat_rows)

        # Build DB Candidates rows
        db_rows = []
        for f in db_candidates:
            rec = self.records_by_source.get(f.original_path)
            st = rec.status if rec else "DISCOVERED_ONLY"
            badge_class = "badge-success" if st == STATUS_VERIFIED else ("badge-warning" if "UNAVAILABLE" in st else "badge-info")
            db_rows.append(f"""
            <tr>
                <td><code>{html.escape(f.filename)}</code></td>
                <td><span class="badge {badge_class}">{html.escape(f.category)}</span></td>
                <td class="num">{html.escape(f.size_human)}</td>
                <td><span class="badge {badge_class}">{html.escape(st)}</span></td>
                <td><small>{html.escape(f.relative_path)}</small></td>
            </tr>
            """)
        db_table_body = "".join(db_rows) if db_rows else "<tr><td colspan='5'>No database or backup candidates found.</td></tr>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WRS Forensic Acquisition Report — {dev_display}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
            --badge-bg: #334155;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        .header h1 {{
            margin: 0 0 0.5rem 0;
            color: var(--accent);
            font-size: 2rem;
        }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-success {{ background: rgba(34, 197, 94, 0.2); color: var(--success); border: 1px solid var(--success); }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid var(--warning); }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }}
        .badge-info {{ background: rgba(56, 189, 248, 0.2); color: var(--accent); border: 1px solid var(--accent); }}
        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
        }}
        .card .label {{
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-bottom: 0.5rem;
        }}
        .card .value {{
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--text);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 2rem;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: rgba(0, 0, 0, 0.2);
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
        }}
        td.num, th.num {{
            text-align: right;
        }}
        code {{
            background: rgba(0,0,0,0.3);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
        }}
        .notice {{
            background: rgba(56, 189, 248, 0.05);
            border-left: 4px solid var(--accent);
            padding: 1rem;
            margin-bottom: 1.5rem;
            border-radius: 0 4px 4px 0;
        }}
        .warning-notice {{
            background: rgba(245, 158, 11, 0.05);
            border-left: 4px solid var(--warning);
            padding: 1rem;
            margin-bottom: 1.5rem;
            border-radius: 0 4px 4px 0;
        }}
        .footer {{
            border-top: 1px solid var(--border);
            padding-top: 1.5rem;
            color: var(--text-muted);
            font-size: 0.85rem;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WRS — WhatsApp Recovery Scanner</h1>
            <p>Forensic Acquisition & Verification Report | 100% Local Processing</p>
        </div>

        <div class="cards">
            <div class="card">
                <div class="label">Total Discovered Files</div>
                <div class="value">{self.scan_result.total_files}</div>
            </div>
            <div class="card">
                <div class="label">Total Logical Size</div>
                <div class="value">{html.escape(format_bytes(self.scan_result.total_bytes))}</div>
            </div>
            <div class="card">
                <div class="label">SHA-256 Verified</div>
                <div class="value" style="color: var(--success);">{verified_count}</div>
            </div>
            <div class="card">
                <div class="label">Acquired (Source Hash Unavail)</div>
                <div class="value" style="color: var(--warning);">{source_unavail_count}</div>
            </div>
        </div>

        <h2>Device & Acquisition Metadata</h2>
        <table>
            <tr><th>Manufacturer & Model</th><td>{dev_display}</td><th>Serial Number</th><td><code>{dev_serial}</code></td></tr>
            <tr><th>Android Version</th><td>{dev_os} (API SDK {dev_sdk})</td><th>Root Indicator Status</th><td>{dev_root}</td></tr>
            <tr><th>Scan Start Time</th><td>{start_t}</td><th>Scan End Time</th><td>{end_t}</td></tr>
            <tr><th>Source Directory</th><td colspan="3"><code>{location_path}</code></td></tr>
        </table>

        <h2>Category Inventory Breakdown</h2>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th class="num">Files</th>
                    <th class="num">Total Size</th>
                    <th class="num">Share</th>
                </tr>
            </thead>
            <tbody>
                {cat_table_body}
            </tbody>
            <tfoot>
                <tr style="font-weight: 700;">
                    <td>TOTAL</td>
                    <td class="num">{self.scan_result.total_files}</td>
                    <td class="num">{html.escape(format_bytes(self.scan_result.total_bytes))}</td>
                    <td class="num">100.0%</td>
                </tr>
            </tfoot>
        </table>

        <h2>Database & Backup Candidates</h2>
        <div class="notice">
            <p><strong>Database Preservation Note:</strong> Databases are preserved byte-for-byte in their raw format.
            Encrypted WhatsApp databases (.crypt14 / .crypt15) require the private encryption key located in
            protected application storage (/data/data/com.whatsapp/files/key) for decryption.</p>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Filename</th>
                    <th>Category</th>
                    <th class="num">Size</th>
                    <th>Status</th>
                    <th>Relative Path</th>
                </tr>
            </thead>
            <tbody>
                {db_table_body}
            </tbody>
        </table>

        <h2>Forensic Limitations & Legal Disclosures</h2>
        <div class="warning-notice">
            <h4>1. Unrooted Android Sandbox Protections</h4>
            <p>Standard unrooted ADB communicates exclusively with accessible external and shared storage volumes.
            The private internal app directory (<code>/data/data/com.whatsapp/</code>) remains protected by Android OS
            SELinux and UID separation. Decryption keys and un-backed active databases stored therein cannot be extracted without root or physical memory acquisition.</p>

            <h4>2. Data Distinction</h4>
            <p>Files listed as <strong>Discovered</strong> exist on the filesystem. Files listed as <strong>Acquired</strong> have been copied to the local recovery repository.
            Files marked <strong>VERIFIED</strong> have matching source and destination SHA-256 hashes. Deleted chats purged prior to backup creation are not restored by file copying.</p>
        </div>

        <div class="footer">
            <p>Generated by WRS (WhatsApp Recovery Scanner) v1.0.0 on {html.escape(format_timestamp())}.</p>
            <p>Forensic Integrity Assured — Local-First Acquisition Protocol.</p>
        </div>
    </div>
</body>
</html>
"""
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(html_content)


def verify_recovery_directory(recovery_dir: Path | str) -> dict:
    """Verify acquired files against stored acquisition manifest without modifying data.

    Returns summary dictionary with counts and per-file audit results.
    """
    rec_path = Path(recovery_dir).resolve()
    manifest_path = rec_path / "metadata" / "acquisition_manifest.json"

    if not manifest_path.exists():
        return {
            "success": False,
            "error": f"Acquisition manifest not found at {manifest_path}",
            "verified_count": 0,
            "mismatch_count": 0,
            "missing_count": 0,
            "total": 0,
        }

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            records = json.load(f)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to parse manifest: {e}",
            "verified_count": 0,
            "mismatch_count": 0,
            "missing_count": 0,
            "total": 0,
        }

    total = len(records)
    verified = 0
    mismatches = 0
    missing = 0
    results: List[dict] = []

    for item in records:
        dest_p = Path(item["destination_path"])
        expected_hash = item.get("destination_sha256")
        expected_size = item.get("acquired_size")

        if not dest_p.exists():
            missing += 1
            results.append({
                "path": str(dest_p),
                "status": "MISSING",
                "message": "File recorded in manifest does not exist locally.",
            })
            continue

        curr_hash, curr_size, err = hash_local_file(dest_p)
        if err or not curr_hash:
            mismatches += 1
            results.append({
                "path": str(dest_p),
                "status": "READ_ERROR",
                "message": str(err),
            })
            continue

        if curr_size != expected_size:
            mismatches += 1
            results.append({
                "path": str(dest_p),
                "status": "SIZE_MISMATCH",
                "message": f"Size changed: expected {expected_size}, got {curr_size}",
            })
            continue

        if expected_hash and curr_hash.lower() != expected_hash.lower():
            mismatches += 1
            results.append({
                "path": str(dest_p),
                "status": "HASH_MISMATCH",
                "message": f"Hash changed! Expected {expected_hash}, computed {curr_hash}",
            })
            continue

        verified += 1
        results.append({
            "path": str(dest_p),
            "status": "INTACT",
            "sha256": curr_hash,
        })

    return {
        "success": True,
        "total": total,
        "verified_count": verified,
        "mismatch_count": mismatches,
        "missing_count": missing,
        "is_fully_intact": (mismatches == 0 and missing == 0 and verified == total),
        "details": results,
    }
