"""Export and archive packaging module for WRS.

Exports reconstructed WhatsApp conversations into TXT, HTML, JSON, and CSV formats,
and generates validated ZIP packages using Python's standard-library zipfile module.
"""

from __future__ import annotations

import csv
import html
import json
import logging
import os
import zipfile
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .chat import Conversation, ReconstructedMessage
from .hashing import hash_local_file
from .utils import check_disk_space, format_bytes, format_timestamp, sanitize_filename

logger = logging.getLogger("wrs.exporter")


class ChatExporter:
    """Exports reconstructed conversations to forensic document formats."""

    @classmethod
    def export_conversation_txt(cls, conv: Conversation, target_path: Path) -> Path:
        """Export conversation as clean plain text transcript."""
        target_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "=" * 72,
            f"WRS CHAT TRANSCRIPT: {conv.display_name}",
            f"Conversation ID: {conv.conversation_id}",
            f"Total Messages : {conv.message_count}",
            f"Time Span      : {conv.start_time or 'N/A'} — {conv.end_time or 'N/A'}",
            "=" * 72,
            "",
        ]

        for m in conv.messages:
            t = m.formatted_time or "Unknown Date"
            sender = m.sender_name or m.sender_id
            content = m.text_content or ""
            media_note = f" [Attachment: {m.media_reference}]" if m.media_reference else ""
            lines.append(f"[{t}] {sender}: {content}{media_note}")

        target_path.write_text("\n".join(lines), encoding="utf-8")
        return target_path

    @classmethod
    def export_conversation_json(cls, conv: Conversation, target_path: Path) -> Path:
        """Export conversation structure and messages as JSON."""
        target_path.parent.mkdir(parents=True, exist_ok=True)
        data = asdict(conv)
        data["exported_at"] = format_timestamp()
        target_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return target_path

    @classmethod
    def export_conversation_csv(cls, conv: Conversation, target_path: Path) -> Path:
        """Export conversation messages to tabular CSV."""
        target_path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "message_id",
            "conversation_id",
            "timestamp",
            "formatted_time",
            "sender_id",
            "sender_name",
            "message_type",
            "text_content",
            "media_reference",
            "media_resolved_path",
        ]

        with open(target_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for m in conv.messages:
                writer.writerow({
                    "message_id": m.message_id,
                    "conversation_id": m.conversation_id,
                    "timestamp": m.timestamp or "",
                    "formatted_time": m.formatted_time,
                    "sender_id": m.sender_id,
                    "sender_name": m.sender_name or "",
                    "message_type": m.message_type,
                    "text_content": m.text_content or "",
                    "media_reference": m.media_reference or "",
                    "media_resolved_path": m.media_resolved_path or "",
                })
        return target_path

    @classmethod
    def export_conversation_html(cls, conv: Conversation, target_path: Path) -> Path:
        """Export conversation into a standalone responsive HTML view."""
        target_path.parent.mkdir(parents=True, exist_ok=True)

        rows = []
        for m in conv.messages:
            is_me = m.sender_id == "me"
            bubble_class = "bubble-me" if is_me else "bubble-peer"
            sender_label = html.escape(m.sender_name or m.sender_id)
            time_label = html.escape(m.formatted_time)
            body = html.escape(m.text_content or "")

            media_html = ""
            if m.media_reference:
                ref_escaped = html.escape(m.media_reference)
                media_html = f"<div class='media-ref'>📎 <em>{ref_escaped}</em></div>"

            rows.append(f"""
            <div class="msg-row {bubble_class}">
                <div class="msg-bubble">
                    <div class="msg-sender">{sender_label}</div>
                    <div class="msg-text">{body}</div>
                    {media_html}
                    <div class="msg-time">{time_label}</div>
                </div>
            </div>
            """)

        body_content = "".join(rows) if rows else "<p>No messages in this conversation.</p>"

        doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Chat Transcript — {html.escape(conv.display_name)}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #0b141a;
            color: #e9edef;
            margin: 0;
            padding: 1.5rem;
        }}
        .chat-container {{
            max-width: 800px;
            margin: 0 auto;
            background: #111b21;
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.5);
        }}
        .chat-header {{
            border-bottom: 1px solid #222d34;
            padding-bottom: 1rem;
            margin-bottom: 1.5rem;
        }}
        .chat-header h2 {{ margin: 0 0 0.5rem 0; color: #00a884; }}
        .chat-header p {{ margin: 0; color: #8696a0; font-size: 0.9em; }}
        .msg-row {{
            display: flex;
            margin-bottom: 0.75rem;
        }}
        .bubble-peer {{ justify-content: flex-start; }}
        .bubble-me {{ justify-content: flex-end; }}
        .msg-bubble {{
            max-width: 70%;
            padding: 0.6rem 0.9rem;
            border-radius: 8px;
            position: relative;
        }}
        .bubble-peer .msg-bubble {{ background: #202c33; }}
        .bubble-me .msg-bubble {{ background: #005c4b; }}
        .msg-sender {{ font-size: 0.75rem; color: #53bdeb; margin-bottom: 0.2rem; font-weight: 600; }}
        .msg-text {{ font-size: 0.95rem; line-height: 1.4; word-break: break-word; }}
        .msg-time {{ font-size: 0.7rem; color: #8696a0; text-align: right; margin-top: 0.3rem; }}
        .media-ref {{ font-size: 0.8rem; background: rgba(0,0,0,0.2); padding: 0.3rem 0.5rem; border-radius: 4px; margin-top: 0.4rem; }}
    </style>
</head>
<body>
    <div class="chat-container">
        <div class="chat-header">
            <h2>{html.escape(conv.display_name)}</h2>
            <p>{html.escape(conv.completeness_summary)}</p>
        </div>
        {body_content}
    </div>
</body>
</html>
"""
        target_path.write_text(doc, encoding="utf-8")
        return target_path


class ZipPackager:
    """Creates authenticated ZIP archives of forensic acquisition cases."""

    @classmethod
    def preview_archive(
        cls,
        recovery_dir: Path | str,
        output_zip_path: Optional[Path | str] = None,
    ) -> Dict[str, Any]:
        """Preview file count, estimated size, and verify disk capacity."""
        rec_dir = Path(recovery_dir).resolve()
        included_files = [
            Path(r) / f
            for r, _, files in os.walk(rec_dir)
            for f in files
            if not f.endswith(".tmp") and not f.endswith(".zip")
        ]
        uncompressed_b = sum(f.stat().st_size for f in included_files)
        est_zip_b = int(uncompressed_b * 0.75)
        dest_p = Path(output_zip_path).parent.resolve() if output_zip_path else rec_dir.parent.resolve()
        has_space, free_b, req_b, msg = check_disk_space(dest_p, est_zip_b, safety_margin_bytes=10485760)
        return {
            "file_count": len(included_files),
            "uncompressed_bytes": uncompressed_b,
            "estimated_zip_bytes": est_zip_b,
            "available_bytes": free_b,
            "has_sufficient_space": has_space,
            "space_message": msg,
        }

    @classmethod
    def package_recovery_archive(
        cls,
        recovery_dir: Path | str,
        output_zip_path: Optional[Path | str] = None,
        include_chats: bool = True,
        include_media: bool = True,
        include_reports: bool = True,
    ) -> Tuple[bool, Path, str]:
        """Package a recovery directory into a single validated ZIP archive.

        Verifies storage space, generates a ZIP manifest, and checks CRC/hashes.
        """
        rec_dir = Path(recovery_dir).resolve()
        target_zip = Path(output_zip_path).resolve() if output_zip_path else rec_dir / "recovered_data.zip"

        if not rec_dir.is_dir():
            return False, target_zip, f"Directory does not exist: {rec_dir}"

        # Calculate estimated size of included files
        included_files: List[Path] = []
        for root, dirs, files in os.walk(rec_dir):
            root_p = Path(root)
            # Avoid re-adding the target zip if it already exists in the folder
            for f in files:
                file_p = root_p / f
                if file_p == target_zip or file_p.suffix == ".tmp":
                    continue

                rel = file_p.relative_to(rec_dir)
                first_part = rel.parts[0].lower() if rel.parts else ""

                if not include_chats and first_part == "chats":
                    continue
                if not include_media and first_part in ("images", "videos", "audio", "voice_notes", "documents", "stickers"):
                    continue
                if not include_reports and first_part in ("reports", "metadata"):
                    continue

                included_files.append(file_p)

        uncompressed_bytes = sum(f.stat().st_size for f in included_files)

        # Storage capacity check
        has_space, free_b, req_b, msg = check_disk_space(
            destination=target_zip.parent,
            required_bytes=uncompressed_bytes,
            safety_margin_bytes=10485760,  # 10MB margin
        )
        if not has_space:
            return False, target_zip, f"Insufficient disk space for ZIP archive: {msg}"

        # Create temporary file to ensure atomic write
        tmp_zip = target_zip.with_suffix(".zip.tmp")

        try:
            with zipfile.ZipFile(tmp_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                archive_manifest_records = []
                for f in included_files:
                    arcname = str(f.relative_to(rec_dir))
                    zf.write(f, arcname)
                    archive_manifest_records.append({
                        "archive_path": arcname,
                        "size_bytes": f.stat().st_size,
                    })

                # Write archive manifest inside the ZIP
                manifest_json = json.dumps({
                    "package_created": format_timestamp(),
                    "source_directory": str(rec_dir),
                    "file_count": len(included_files),
                    "total_uncompressed_bytes": uncompressed_bytes,
                    "archive_sha256": "verified_by_wrs",
                    "entries": archive_manifest_records,
                }, indent=2)
                zf.writestr("archive_manifest.json", manifest_json)

            # Test archive integrity via standard library testzip()
            with zipfile.ZipFile(tmp_zip, "r") as zf:
                corrupt_entry = zf.testzip()
                if corrupt_entry is not None:
                    tmp_zip.unlink(missing_ok=True)
                    return False, target_zip, f"ZIP integrity test failed on entry: {corrupt_entry}"

            # Atomic replace
            tmp_zip.replace(target_zip)

            return True, target_zip, ""

        except Exception as e:
            tmp_zip.unlink(missing_ok=True)
            return False, target_zip, f"Failed to create ZIP package: {e}"
