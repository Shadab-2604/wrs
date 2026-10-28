"""File classification and categorization module for WRS.

Categorizes WhatsApp files into forensically distinct categories:
Databases, Backups, Images, Videos, Audio, Voice Notes, Documents,
Stickers, Animated Media, Thumbnails, and Other.
Uses path context, file naming patterns, extensions, and file signatures.
"""

from __future__ import annotations

import os
import re
from pathlib import PurePosixPath
from typing import Optional, Tuple

try:
    import magic  # type: ignore
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False


# Supported Category Identifiers
CAT_DATABASES = "Databases"
CAT_BACKUPS = "Backups"
CAT_IMAGES = "Images"
CAT_VIDEOS = "Videos"
CAT_AUDIO = "Audio"
CAT_VOICE_NOTES = "Voice Notes"
CAT_DOCUMENTS = "Documents"
CAT_STICKERS = "Stickers"
CAT_ANIMATED_GIFS = "Animated GIFs"
CAT_THUMBNAILS = "Thumbnails"
CAT_OTHER = "Other"

ALL_CATEGORIES = [
    CAT_DATABASES,
    CAT_BACKUPS,
    CAT_IMAGES,
    CAT_VIDEOS,
    CAT_AUDIO,
    CAT_VOICE_NOTES,
    CAT_DOCUMENTS,
    CAT_STICKERS,
    CAT_ANIMATED_GIFS,
    CAT_THUMBNAILS,
    CAT_OTHER,
]

# Standard category directory names for the recovery folder
CATEGORY_DIR_NAMES = {
    CAT_DATABASES: "Databases",
    CAT_BACKUPS: "Backups",
    CAT_IMAGES: "Images",
    CAT_VIDEOS: "Videos",
    CAT_AUDIO: "Audio",
    CAT_VOICE_NOTES: "Voice_Notes",
    CAT_DOCUMENTS: "Documents",
    CAT_STICKERS: "Stickers",
    CAT_ANIMATED_GIFS: "Animated_GIFs",
    CAT_THUMBNAILS: "Thumbnails",
    CAT_OTHER: "Other",
}

# Regex for dated WhatsApp database backups (e.g. msgstore-2026-10-25.1.db.crypt14)
RE_DATED_BACKUP = re.compile(
    r"^msgstore-\d{4}-\d{2}-\d{2}(\.\d+)?\.db\.crypt\d+$",
    re.IGNORECASE,
)

# Regex for WhatsApp active databases (e.g. msgstore.db.crypt14, msgstore.db)
RE_ACTIVE_DATABASE = re.compile(
    r"^(msgstore|wa|chatsettingsbackup|stickers|media)(\.db)?(\.crypt\d+)?$",
    re.IGNORECASE,
)

# Common extensions
EXT_IMAGE = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tiff", ".tif", ".heic", ".heif"}
EXT_VIDEO = {".mp4", ".3gp", ".mov", ".mkv", ".avi", ".webm", ".m4v", ".flv"}
EXT_AUDIO = {".mp3", ".ogg", ".opus", ".m4a", ".wav", ".aac", ".flac", ".amr", ".wma"}
EXT_DOCUMENTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".csv", ".rtf", ".odt", ".ods", ".odp",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".vcf",
}


class Categorizer:
    """Classifies files into forensic categories based on evidence."""

    def __init__(self) -> None:
        self.magic_detector = magic.Magic(mime=True) if HAS_MAGIC else None

    def detect_signature(self, header: bytes) -> Optional[str]:
        """Detect file format using magic byte signatures."""
        if not header or len(header) < 4:
            return None

        if header.startswith(b"\xFF\xD8\xFF"):
            return "image/jpeg"
        if header.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
            return "image/gif"
        if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
            return "image/webp"
        if header.startswith(b"SQLite format 3\x00"):
            return "application/x-sqlite3"
        if header.startswith(b"%PDF-"):
            return "application/pdf"
        if header.startswith(b"PK\x03\x04"):
            return "application/zip"
        if header.startswith(b"OggS"):
            return "audio/ogg"
        if len(header) >= 8 and header[4:8] in (b"ftyp", b"moov"):
            return "video/mp4"

        if self.magic_detector:
            try:
                return self.magic_detector.from_buffer(header)
            except Exception:
                pass

        return None

    def categorize(
        self,
        filename: str,
        relative_path: str,
        size_bytes: int = 0,
        header_bytes: Optional[bytes] = None,
    ) -> Tuple[str, str]:
        """Classify a file into its most specific category.

        Returns (category, identification_method).
        """
        fn_lower = filename.lower()
        path_parts = [p.lower() for p in PurePosixPath(relative_path).parts]
        ext = os.path.splitext(fn_lower)[1]

        # 1. Thumbnails check (path or filename indicator)
        if (
            ".thumbs" in path_parts
            or ".thumbnails" in path_parts
            or fn_lower.startswith(".thumb")
            or ".thumb" in fn_lower
        ):
            return CAT_THUMBNAILS, "path_thumbnail_indicator"

        # 2. Dated Database Backups
        # Rule: Do not classify a file as backup solely because 'backup' is in the name.
        if RE_DATED_BACKUP.match(fn_lower):
            return CAT_BACKUPS, "dated_backup_pattern"

        # Secondary backup pattern: files inside a dedicated 'Backups' folder with crypt extension
        if "backups" in path_parts and (".crypt" in fn_lower or fn_lower.endswith(".db")):
            return CAT_BACKUPS, "backup_directory_context"

        # 3. Active / Undated WhatsApp Databases
        if (
            RE_ACTIVE_DATABASE.match(fn_lower)
            or "databases" in path_parts
            or fn_lower.endswith(".crypt14")
            or fn_lower.endswith(".crypt15")
            or fn_lower.endswith(".crypt12")
            or (ext == ".db" and ("msgstore" in fn_lower or "wa" in fn_lower))
        ):
            if fn_lower.endswith((".crypt14", ".crypt15", ".crypt12")):
                return CAT_DATABASES, "encrypted_database_extension"
            if ext == ".db" or "databases" in path_parts:
                return CAT_DATABASES, "database_directory_or_extension"

        # 4. Stickers
        # Specific check: stickers directory or sticker packs
        if (
            "whatsapp stickers" in path_parts
            or "stickers" in path_parts
            or (fn_lower.startswith("sticker_") and ext == ".webp")
        ):
            return CAT_STICKERS, "sticker_directory_context"

        # 5. Animated GIFs
        if (
            "whatsapp animated gifs" in path_parts
            or "animated gifs" in path_parts
            or (ext == ".gif" and not fn_lower.startswith("."))
        ):
            return CAT_ANIMATED_GIFS, "animated_gif_context"

        # 6. Voice Notes (PTT)
        # Rule: Use the most specific category. Opus in PTT is Voice Notes, not generic audio.
        is_ptt_path = (
            "whatsapp voice notes" in path_parts
            or "voice notes" in path_parts
            or "ptt" in path_parts
            or fn_lower.startswith("ptt-")
        )
        if is_ptt_path and (ext in EXT_AUDIO or ext == ".opus"):
            return CAT_VOICE_NOTES, "voice_notes_ptt_context"

        # 7. Generic Audio
        if ext in EXT_AUDIO or "whatsapp audio" in path_parts:
            return CAT_AUDIO, "audio_extension_or_path"

        # 8. Video Media
        if ext in EXT_VIDEO or "whatsapp video" in path_parts:
            return CAT_VIDEOS, "video_extension_or_path"

        # 9. Image Media
        if ext in EXT_IMAGE or "whatsapp images" in path_parts:
            return CAT_IMAGES, "image_extension_or_path"

        # 10. Documents
        if ext in EXT_DOCUMENTS or "whatsapp documents" in path_parts or "documents" in path_parts:
            return CAT_DOCUMENTS, "document_extension_or_path"

        # 11. Header inspection / signature fallback
        if header_bytes:
            sig = self.detect_signature(header_bytes)
            if sig:
                if sig.startswith("image/"):
                    return CAT_IMAGES, f"signature_{sig}"
                if sig.startswith("video/"):
                    return CAT_VIDEOS, f"signature_{sig}"
                if sig.startswith("audio/"):
                    return CAT_AUDIO, f"signature_{sig}"
                if sig == "application/x-sqlite3":
                    return CAT_DATABASES, "signature_sqlite"
                if sig in ("application/pdf", "application/zip"):
                    return CAT_DOCUMENTS, f"signature_{sig}"

        # 12. Fallback / Other
        return CAT_OTHER, "unclassified_fallback"
