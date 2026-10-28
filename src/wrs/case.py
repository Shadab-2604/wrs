"""Case management and audit logging module for WRS.

Provides append-only event logging, scan ID tracking, case discovery,
historical audit inspection, and cross-scan inventory comparisons.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .utils import format_bytes, format_timestamp

logger = logging.getLogger("wrs.case")

SENSITIVE_KEY_SUBSTRINGS = {"password", "token", "secret", "private_key", "key", "auth"}


def generate_scan_id(device_serial: str) -> str:
    """Generate a unique scan identifier combining device serial, date, and short UUID."""
    slug_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_serial = "".join(c for c in device_serial if c.isalnum())[:8] or "dev"
    unique_suffix = uuid.uuid4().hex[:6]
    return f"scan_{clean_serial}_{slug_time}_{unique_suffix}"


def redact_sensitive_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively redact sensitive tokens or credentials from audit logs."""
    clean: Dict[str, Any] = {}
    for k, v in data.items():
        k_lower = str(k).lower()
        if any(s in k_lower for s in SENSITIVE_KEY_SUBSTRINGS):
            clean[k] = "[REDACTED]"
        elif isinstance(v, dict):
            clean[k] = redact_sensitive_dict(v)
        elif isinstance(v, list):
            clean[k] = [
                redact_sensitive_dict(i) if isinstance(i, dict) else i
                for i in v
            ]
        else:
            clean[k] = v
    return clean


@dataclass
class CaseEvent:
    """An immutable audit event recorded during a forensic acquisition session."""

    timestamp: str
    scan_id: str
    event_type: str
    details: Dict[str, Any]


class CaseManager:
    """Audit logger and forensic case repository manager."""

    def __init__(self, case_dir: Path | str) -> None:
        self.case_dir = Path(case_dir).resolve()
        self.metadata_dir = self.case_dir / "metadata"
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.metadata_dir / "case_events.jsonl"

    def log_event(self, scan_id: str, event_type: str, details: Dict[str, Any]) -> None:
        """Append an event to the append-only JSON Lines audit log."""
        ts = format_timestamp()
        safe_details = redact_sensitive_dict(details)

        event = CaseEvent(
            timestamp=ts,
            scan_id=scan_id,
            event_type=event_type,
            details=safe_details,
        )

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
        except OSError as e:
            logger.error("Failed to append case audit log: %s", e)

    def get_events(self, scan_id: Optional[str] = None) -> List[CaseEvent]:
        """Read all recorded audit events for this case."""
        if not self.log_path.exists():
            return []

        events = []
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                        if scan_id and d.get("scan_id") != scan_id:
                            continue
                        events.append(CaseEvent(
                            timestamp=d.get("timestamp", ""),
                            scan_id=d.get("scan_id", ""),
                            event_type=d.get("event_type", ""),
                            details=d.get("details", {}),
                        ))
                    except json.JSONDecodeError:
                        continue
        except OSError as e:
            logger.error("Failed to read audit log: %s", e)

        return events

    load_events = get_events

    @staticmethod
    def list_past_scans(recovery_root: Path | str = "recovery") -> List[Dict[str, Any]]:
        """Discover and summarize past acquisition cases in the recovery directory."""
        root = Path(recovery_root).resolve()
        if not root.is_dir():
            return []

        scans: List[Dict[str, Any]] = []
        for entry in root.iterdir():
            if not entry.is_dir():
                continue
            meta_dir = entry / "metadata"
            manifest_p = meta_dir / "acquisition_manifest.json"
            dev_p = meta_dir / "device.json"
            summary_p = meta_dir / "scan_summary.json"

            if manifest_p.exists() or dev_p.exists():
                dev_info = {}
                if dev_p.exists():
                    try:
                        dev_info = json.loads(dev_p.read_text(encoding="utf-8"))
                    except Exception:
                        pass

                summary_info = {}
                if summary_p.exists():
                    try:
                        summary_info = json.loads(summary_p.read_text(encoding="utf-8"))
                    except Exception:
                        pass

                manifest_items = 0
                if manifest_p.exists():
                    try:
                        manifest_items = len(json.loads(manifest_p.read_text(encoding="utf-8")))
                    except Exception:
                        pass

                scans.append({
                    "case_name": entry.name,
                    "case_path": str(entry),
                    "device": dev_info.get("model") or dev_info.get("serial") or "Unknown",
                    "serial": dev_info.get("serial", "N/A"),
                    "scan_date": summary_info.get("start_time") or entry.name.split("_scan_")[-1],
                    "total_files": summary_info.get("total_files") or manifest_items,
                    "total_bytes": summary_info.get("total_bytes", 0),
                    "has_manifest": manifest_p.exists(),
                })

        scans.sort(key=lambda x: x["scan_date"], reverse=True)
        return scans

    @staticmethod
    def compare_cases(case_dir_a: Path | str, case_dir_b: Path | str) -> Dict[str, Any]:
        """Compare two acquired cases to detect newly acquired, deleted, or altered assets."""
        path_a = Path(case_dir_a)
        path_b = Path(case_dir_b)

        manifest_a_p = path_a / "metadata" / "acquisition_manifest.json"
        manifest_b_p = path_b / "metadata" / "acquisition_manifest.json"

        def _load_manifest_items(p: Path) -> Dict[str, str]:
            items: Dict[str, str] = {}
            if not p.exists():
                return items
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for row in data:
                        sp = row.get("source_path", row.get("relative_path", ""))
                        if sp:
                            items[sp] = row.get("destination_sha256", row.get("sha256", ""))
                elif isinstance(data, dict):
                    # Could be {"files": {...}} or direct dict
                    file_dict = data.get("files", data)
                    for k, v in file_dict.items():
                        if isinstance(v, dict):
                            items[k] = v.get("destination_sha256", v.get("sha256", ""))
                        else:
                            items[k] = str(v)
            except Exception:
                pass
            return items

        items_a = _load_manifest_items(manifest_a_p)
        items_b = _load_manifest_items(manifest_b_p)

        common_keys = set(items_a.keys()) & set(items_b.keys())
        only_in_a = set(items_a.keys()) - set(items_b.keys())
        only_in_b = set(items_b.keys()) - set(items_a.keys())

        identical_count = sum(1 for k in common_keys if items_a[k] == items_b[k] and items_a[k])
        modified_count = sum(1 for k in common_keys if items_a[k] != items_b[k])

        return {
            "case_a": path_a.name,
            "case_b": path_b.name,
            "total_files_a": len(items_a),
            "total_files_b": len(items_b),
            "case1_total": len(items_a),
            "case2_total": len(items_b),
            "common_files": len(common_keys),
            "common_identical_count": identical_count,
            "identical_hash_files": identical_count,
            "modified_files": modified_count,
            "modified_content_count": modified_count,
            "files_only_in_a": len(only_in_a),
            "unique_to_case1_count": len(only_in_a),
            "files_only_in_b": len(only_in_b),
            "unique_to_case2_count": len(only_in_b),
        }
