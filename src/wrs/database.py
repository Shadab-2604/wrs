"""WhatsApp database and backup analysis module for WRS.

Provides non-destructive format identification, read-only SQLite schema inspection,
table adapter queries across WhatsApp database versions, and authenticated AES-GCM
decryption support when user-provided key material is supplied.
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .hashing import hash_local_file

logger = logging.getLogger("wrs.database")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


@dataclass
class DatabaseMetadata:
    """Forensic assessment and structural metadata of an analyzed database."""

    filepath: str
    filename: str
    format_type: str  # 'SQLITE', 'CRYPT15', 'CRYPT14', 'CRYPT12', 'UNKNOWN'
    confidence: str   # 'CONFIRMED', 'HIGH', 'PROBABLE', 'LOW'
    is_sqlite: bool = False
    is_encrypted: bool = False
    is_dated_backup: bool = False
    size_bytes: int = 0
    sha256: str = ""
    integrity_ok: bool = False
    table_count: int = 0
    tables: List[str] = field(default_factory=list)
    message_count: int = 0
    schema_version: str = "unknown"
    notes: str = ""


class WhatsAppDatabaseAnalyzer:
    """Forensic analyzer for WhatsApp databases and encrypted backups."""

    @staticmethod
    def identify_database(db_path: Path | str) -> DatabaseMetadata:
        """Classify database format, encryption standard, and integrity."""
        p = Path(db_path).resolve()
        if not p.is_file():
            return DatabaseMetadata(
                filepath=str(p),
                filename=p.name,
                format_type="UNKNOWN",
                confidence="LOW",
                notes="File does not exist or is not a regular file.",
            )

        sz = p.stat().st_size
        sha256_hash, _, _ = hash_local_file(p)
        fn_lower = p.name.lower()
        is_dated = bool(re.search(r"msgstore-\d{4}-\d{2}-\d{2}", fn_lower))

        # Read first 128 bytes for magic signature checks
        header = b""
        try:
            with open(p, "rb") as f:
                header = f.read(128)
        except OSError as e:
            return DatabaseMetadata(
                filepath=str(p),
                filename=p.name,
                format_type="UNKNOWN",
                confidence="LOW",
                size_bytes=sz,
                sha256=sha256_hash or "",
                notes=f"Error reading file header: {e}",
            )

        # 1. Plain SQLite database
        if header.startswith(b"SQLite format 3\x00"):
            meta = DatabaseMetadata(
                filepath=str(p),
                filename=p.name,
                format_type="SQLITE",
                confidence="CONFIRMED",
                is_sqlite=True,
                is_encrypted=False,
                is_dated_backup=is_dated,
                size_bytes=sz,
                sha256=sha256_hash or "",
            )
            # Inspect SQLite read-only
            schema_info = WhatsAppDatabaseAnalyzer.inspect_sqlite_schema(p)
            meta.integrity_ok = schema_info.get("integrity_ok", False)
            meta.table_count = schema_info.get("table_count", 0)
            meta.tables = schema_info.get("tables", [])
            meta.message_count = schema_info.get("message_count", 0)
            meta.schema_version = schema_info.get("schema_version", "unknown")
            meta.notes = (
                f"Valid SQLite database. Integrity: {'OK' if meta.integrity_ok else 'FAILED'}. "
                f"Tables: {meta.table_count}, Detected messages: {meta.message_count}."
            )
            return meta

        # 2. Encrypted formats (.crypt15, .crypt14, .crypt12)
        crypt_ver = None
        for v in ("crypt15", "crypt14", "crypt12", "crypt10", "crypt8"):
            if fn_lower.endswith(f".{v}"):
                crypt_ver = v.upper()
                break

        if crypt_ver:
            return DatabaseMetadata(
                filepath=str(p),
                filename=p.name,
                format_type=crypt_ver,
                confidence="HIGH",
                is_sqlite=False,
                is_encrypted=True,
                is_dated_backup=is_dated,
                size_bytes=sz,
                sha256=sha256_hash or "",
                notes=(
                    f"WhatsApp {crypt_ver} encrypted database. AES-GCM encrypted format. "
                    "Decryption requires the private encryption key (/data/data/com.whatsapp/files/key). "
                    "Integrity preserved in raw format."
                ),
            )

        return DatabaseMetadata(
            filepath=str(p),
            filename=p.name,
            format_type="UNKNOWN",
            confidence="PROBABLE",
            is_sqlite=False,
            is_encrypted=False,
            is_dated_backup=is_dated,
            size_bytes=sz,
            sha256=sha256_hash or "",
            notes="Unrecognized database format or arbitrary binary asset.",
        )

    @staticmethod
    def inspect_sqlite_schema(db_path: Path | str) -> Dict[str, Any]:
        """Inspect accessible SQLite database schema in strictly read-only mode."""
        p = Path(db_path).resolve()
        uri = f"file:{p}?mode=ro"

        out: Dict[str, Any] = {
            "is_sqlite": True,
            "integrity_ok": False,
            "table_count": 0,
            "tables": [],
            "schema_version": "unknown",
            "message_count": 0,
            "has_messages_table": False,
            "has_chat_table": False,
            "has_jid_table": False,
            "has_media_table": False,
        }

        try:
            conn = sqlite3.connect(uri, uri=True, timeout=5.0)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # Integrity check
            cur.execute("PRAGMA integrity_check(5);")
            rows = cur.fetchall()
            integrity_str = "\n".join(str(r[0]) for r in rows if r)
            out["integrity_ok"] = integrity_str.strip().lower() == "ok"

            # Table list
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
            tables = [r[0] for r in cur.fetchall() if r[0]]
            out["tables"] = tables
            out["table_count"] = len(tables)

            # Detect schema version
            if "message" in tables:
                out["schema_version"] = "whatsapp_v2_modern"
                out["has_messages_table"] = True
                cur.execute("SELECT COUNT(*) FROM message;")
                out["message_count"] = cur.fetchone()[0]
            elif "messages" in tables:
                out["schema_version"] = "whatsapp_v1_classic"
                out["has_messages_table"] = True
                cur.execute("SELECT COUNT(*) FROM messages;")
                out["message_count"] = cur.fetchone()[0]

            out["has_chat_table"] = "chat" in tables
            out["has_jid_table"] = "jid" in tables
            out["has_media_table"] = "message_media" in tables

            conn.close()
        except sqlite3.Error as e:
            out["error"] = str(e)

        return out

    @staticmethod
    def extract_raw_messages(db_path: Path | str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Extract message records into normalized internal dictionary records.

        Supports both modern schema ('message' + 'chat' + 'jid') and classic schema ('messages').
        """
        p = Path(db_path).resolve()
        uri = f"file:{p}?mode=ro"
        messages: List[Dict[str, Any]] = []

        try:
            conn = sqlite3.connect(uri, uri=True, timeout=5.0)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # Check tables
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tbls = {r[0] for r in cur.fetchall() if r[0]}

            limit_clause = f"LIMIT {int(limit)}" if limit else ""

            if "message" in tbls:
                # Modern schema adapter
                has_media = "message_media" in tbls
                has_chat = "chat" in tbls
                has_jid = "jid" in tbls

                media_select = "media.file_path AS media_path, media.file_size AS media_size, media.mime_type AS media_mime" if has_media else "NULL AS media_path, NULL AS media_size, NULL AS media_mime"
                media_join = "LEFT JOIN message_media media ON m._id = media.message_row_id" if has_media else ""
                chat_join = "LEFT JOIN chat c ON m.chat_row_id = c._id" if has_chat else ""
                jid_join = "LEFT JOIN jid j ON c.jid_row_id = j._id" if (has_chat and has_jid) else ""
                conv_col = "COALESCE(j.raw_string, CAST(m.chat_row_id AS TEXT))" if (has_chat and has_jid) else "CAST(m.chat_row_id AS TEXT)"
                sender_col = f"CASE WHEN m.from_me = 1 THEN 'me' ELSE {conv_col} END"

                query = f"""
                SELECT
                    m._id AS message_id,
                    {conv_col} AS conversation_id,
                    {sender_col} AS sender_id,
                    m.timestamp AS timestamp,
                    m.message_type AS message_type,
                    m.text_data AS text_content,
                    {media_select}
                FROM message m
                {chat_join}
                {jid_join}
                {media_join}
                ORDER BY m.timestamp ASC
                {limit_clause};
                """
                try:
                    cur.execute(query)
                    for r in cur.fetchall():
                        messages.append({
                            "message_id": str(r["message_id"]),
                            "conversation_id": str(r["conversation_id"]),
                            "sender_id": str(r["sender_id"]),
                            "timestamp": r["timestamp"],
                            "message_type": r["message_type"],
                            "text_content": r["text_content"],
                            "media_path": r["media_path"],
                            "media_size": r["media_size"],
                            "media_mime": r["media_mime"],
                            "source_database": str(p),
                            "source_schema": "modern",
                        })
                except sqlite3.OperationalError as e:
                    logger.warning("Modern query fallback: %s", e)
                    try:
                        fallback_q = f"""
                        SELECT
                            _id AS message_id,
                            CAST(chat_row_id AS TEXT) AS conversation_id,
                            CASE WHEN from_me = 1 THEN 'me' ELSE 'peer' END AS sender_id,
                            timestamp,
                            message_type,
                            text_data AS text_content
                        FROM message
                        ORDER BY timestamp ASC
                        {limit_clause};
                        """
                        cur.execute(fallback_q)
                        for r in cur.fetchall():
                            messages.append({
                                "message_id": str(r["message_id"]),
                                "conversation_id": str(r["conversation_id"]),
                                "sender_id": str(r["sender_id"]),
                                "timestamp": r["timestamp"],
                                "message_type": r["message_type"],
                                "text_content": r["text_content"],
                                "media_path": None,
                                "media_size": None,
                                "media_mime": None,
                                "source_database": str(p),
                                "source_schema": "modern_fallback",
                            })
                    except sqlite3.OperationalError as e2:
                        logger.error("Modern fallback also failed: %s", e2)

            elif "messages" in tbls:
                # Classic schema adapter
                # messages table columns: _id, key_remote_jid, key_from_me, data, timestamp, media_url, media_mime_type, media_size, media_name
                query = f"""
                SELECT
                    _id AS message_id,
                    key_remote_jid AS conversation_id,
                    CASE WHEN key_from_me = 1 THEN 'me' ELSE key_remote_jid END AS sender_id,
                    timestamp,
                    media_wa_type AS message_type,
                    data AS text_content,
                    media_name AS media_path,
                    media_size,
                    media_mime_type AS media_mime
                FROM messages
                ORDER BY timestamp ASC
                {limit_clause};
                """
                try:
                    cur.execute(query)
                    for r in cur.fetchall():
                        messages.append({
                            "message_id": str(r["message_id"]),
                            "conversation_id": str(r["conversation_id"]),
                            "sender_id": str(r["sender_id"]),
                            "timestamp": r["timestamp"],
                            "message_type": r["message_type"],
                            "text_content": r["text_content"],
                            "media_path": r["media_path"],
                            "media_size": r["media_size"],
                            "media_mime": r["media_mime"],
                            "source_database": str(p),
                            "source_schema": "classic",
                        })
                except sqlite3.OperationalError as e:
                    logger.warning("Classic query fallback: %s", e)
                    try:
                        fallback_q = f"""
                        SELECT
                            _id AS message_id,
                            key_remote_jid AS conversation_id,
                            CASE WHEN key_from_me = 1 THEN 'me' ELSE key_remote_jid END AS sender_id,
                            timestamp,
                            data AS text_content
                        FROM messages
                        ORDER BY timestamp ASC
                        {limit_clause};
                        """
                        cur.execute(fallback_q)
                        for r in cur.fetchall():
                            messages.append({
                                "message_id": str(r["message_id"]),
                                "conversation_id": str(r["conversation_id"]),
                                "sender_id": str(r["sender_id"]),
                                "timestamp": r["timestamp"],
                                "message_type": "text",
                                "text_content": r["text_content"],
                                "media_path": None,
                                "media_size": None,
                                "media_mime": None,
                                "source_database": str(p),
                                "source_schema": "classic_fallback",
                            })
                    except sqlite3.OperationalError as e2:
                        logger.error("Classic fallback also failed: %s", e2)

            conn.close()
        except sqlite3.Error as e:
            logger.error("Failed to query messages from %s: %s", p, e)

        return messages

    @staticmethod
    def decrypt_crypt_database(
        crypt_path: Path | str,
        key_path: Path | str,
        output_path: Path | str,
    ) -> Tuple[bool, str]:
        """Decrypt a WhatsApp crypt14 / crypt15 database using a valid user-provided key.

        WhatsApp key files are 158 bytes; the 32-byte AES key is at offset 126..158.
        """
        if not HAS_CRYPTOGRAPHY:
            return False, "Python 'cryptography' library is not available in environment."

        c_path = Path(crypt_path).resolve()
        k_path = Path(key_path).resolve()
        out_p = Path(output_path).resolve()

        if not c_path.is_file():
            return False, f"Encrypted database not found: {c_path}"
        if not k_path.is_file():
            return False, f"Key file not found: {k_path}"

        try:
            key_data = k_path.read_bytes()
            if len(key_data) < 158:
                return False, f"Invalid WhatsApp key size ({len(key_data)} bytes). Standard key is 158 bytes."

            # Extract 32-byte AES key
            aes_key = key_data[126:158]

            with open(c_path, "rb") as f:
                crypt_data = f.read()

            fn_lower = c_path.name.lower()

            # Crypt14 / Crypt15 header handling
            if fn_lower.endswith((".crypt14", ".crypt15")):
                # In crypt14/15, IV is 16 bytes. Header is typically 191 bytes (or variable protobuf).
                # IV is located at offset 67:83 in standard crypt14 protobuf header.
                if len(crypt_data) < 191 + 16:
                    return False, "File too small to be a valid crypt14/15 database."

                iv = crypt_data[67:83]
                ciphertext = crypt_data[191:]

                aesgcm = AESGCM(aes_key)
                # In AES-GCM, the last 16 bytes of ciphertext are typically the authentication tag
                decrypted = aesgcm.decrypt(iv[:12], ciphertext, None)

                out_p.parent.mkdir(parents=True, exist_ok=True)
                out_p.write_bytes(decrypted)
                return True, f"Successfully decrypted to {out_p} ({len(decrypted)} bytes)."

            return False, f"Unsupported encryption format for {c_path.name}."

        except Exception as e:
            return False, f"Decryption failed: {e}. Ensure key matches this specific database."
