"""Chat reconstruction module for WRS.

Normalizes extracted SQLite message records into a structured forensic message model,
groups messages by conversation, chronologically orders them, resolves senders,
and tracks media and reply references without fabricating data.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("wrs.chat")


@dataclass
class ReconstructedMessage:
    """Standardized internal representation of an extracted WhatsApp message."""

    message_id: str
    conversation_id: str
    sender_id: str
    sender_name: Optional[str] = None
    timestamp: Optional[int | float | str] = None
    formatted_time: str = ""
    message_type: str = "text"
    text_content: Optional[str] = None
    media_reference: Optional[str] = None
    media_resolved_path: Optional[str] = None
    reply_reference: Optional[str] = None
    edit_status: Optional[str] = None
    deletion_status: Optional[str] = None
    reaction_data: Optional[str] = None
    source_database: Optional[str] = None
    source_record: Optional[str] = None
    extraction_status: str = "EXTRACTED"


@dataclass
class Conversation:
    """Grouped thread of reconstructed messages for a single peer or group."""

    conversation_id: str
    display_name: str
    messages: List[ReconstructedMessage] = field(default_factory=list)
    message_count: int = 0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    media_count: int = 0
    completeness_summary: str = ""


class ChatReconstructionEngine:
    """Normalizes and reconstructs conversations from raw extracted database records."""

    # WhatsApp numeric message_type / media_wa_type mapping
    TYPE_MAP = {
        0: "text",
        1: "image",
        2: "audio",
        3: "video",
        4: "vcard",
        5: "location",
        8: "document",
        9: "document",
        10: "missed_call",
        13: "gif",
        15: "sticker",
        16: "location",
        20: "sticker",
    }

    @staticmethod
    def _format_epoch(ts: Any) -> str:
        """Safely format epoch timestamps (milliseconds or seconds) to standard string."""
        if ts is None or ts == "" or ts == 0:
            return ""
        try:
            val = float(ts)
            # If timestamp is in milliseconds (> 10^11), convert to seconds
            if val > 1e11:
                val /= 1000.0
            dt = datetime.fromtimestamp(val, timezone.utc).astimezone()
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError):
            return str(ts)

    @classmethod
    def reconstruct_conversations(
        cls,
        raw_records: List[Dict[str, Any]],
        contacts_map: Optional[Dict[str, str]] = None,
    ) -> List[Conversation]:
        """Group raw message records into chronological Conversation objects."""
        contacts = contacts_map or {}
        threads: Dict[str, List[ReconstructedMessage]] = {}

        for rec in raw_records:
            msg_id = str(rec.get("message_id", ""))
            conv_id = str(rec.get("conversation_id", "unknown_conversation"))
            sender_id = str(rec.get("sender_id", "peer"))
            raw_ts = rec.get("timestamp")
            fmt_ts = cls._format_epoch(raw_ts)

            # Determine human-friendly sender name
            sender_name = contacts.get(sender_id)
            if not sender_name:
                if sender_id == "me":
                    sender_name = "You"
                elif "@" in sender_id:
                    sender_name = sender_id.split("@")[0]
                else:
                    sender_name = sender_id

            # Determine message type
            raw_type = rec.get("message_type")
            msg_type = "text"
            if isinstance(raw_type, int) and raw_type in cls.TYPE_MAP:
                msg_type = cls.TYPE_MAP[raw_type]
            elif rec.get("media_mime"):
                mime = str(rec.get("media_mime")).lower()
                if "image" in mime:
                    msg_type = "image"
                elif "video" in mime:
                    msg_type = "video"
                elif "audio" in mime or "ogg" in mime:
                    msg_type = "voice_note" if "voice" in str(rec.get("media_path", "")).lower() else "audio"
                elif "pdf" in mime or "doc" in mime:
                    msg_type = "document"

            # Media reference
            media_ref = rec.get("media_path")

            msg = ReconstructedMessage(
                message_id=msg_id,
                conversation_id=conv_id,
                sender_id=sender_id,
                sender_name=sender_name,
                timestamp=raw_ts,
                formatted_time=fmt_ts,
                message_type=msg_type,
                text_content=rec.get("text_content"),
                media_reference=media_ref,
                source_database=rec.get("source_database"),
                source_record=str(rec.get("source_schema", "sqlite")),
                extraction_status="EXTRACTED",
            )

            threads.setdefault(conv_id, []).append(msg)

        # Build Conversation objects
        conversations: List[Conversation] = []
        for conv_id, msgs in threads.items():
            # Sort messages chronologically
            def sort_key(m: ReconstructedMessage) -> float:
                try:
                    v = float(m.timestamp) if m.timestamp is not None else 0.0
                    return v if v < 1e11 else v / 1000.0
                except (ValueError, TypeError):
                    return 0.0

            msgs.sort(key=sort_key)

            # Display name
            disp_name = contacts.get(conv_id)
            if not disp_name:
                clean_id = conv_id.split("@")[0] if "@" in conv_id else conv_id
                disp_name = f"Chat ({clean_id})"

            start_t = msgs[0].formatted_time if msgs else None
            end_t = msgs[-1].formatted_time if msgs else None
            media_cnt = sum(1 for m in msgs if m.media_reference)

            summary = (
                f"{len(msgs)} messages reconstructed from {start_t or 'N/A'} to {end_t or 'N/A'}. "
                f"Referenced media items: {media_cnt}."
            )

            conversations.append(
                Conversation(
                    conversation_id=conv_id,
                    display_name=disp_name,
                    messages=msgs,
                    message_count=len(msgs),
                    start_time=start_t,
                    end_time=end_t,
                    media_count=media_cnt,
                    completeness_summary=summary,
                )
            )

        # Sort conversations by most recent message
        conversations.sort(key=lambda c: c.end_time or "", reverse=True)
        return conversations
