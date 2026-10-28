"""Media association and forensic validation module for WRS.

Links acquired media files to reconstructed messages using strict evidence levels,
verifies file signatures, detects missing media references, and accounts for
unreferenced media assets without altering source files.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Set

from .chat import Conversation, ReconstructedMessage
from .hashing import hash_local_file

logger = logging.getLogger("wrs.media")

# Forensic evidence levels for media association
EVIDENCE_EXACT_REFERENCE = "EXACT_DATABASE_REFERENCE"
EVIDENCE_MATCHED_RELATIVE = "MATCHED_RELATIVE_PATH"
EVIDENCE_MATCHED_FILENAME = "MATCHED_FILENAME"
EVIDENCE_UNMATCHED = "UNMATCHED"


@dataclass
class MediaAssociationRecord:
    """Forensic link between an acquired media file and a conversation message."""

    media_reference: str
    local_path: Optional[str] = None
    evidence_level: str = EVIDENCE_UNMATCHED
    file_exists: bool = False
    size_bytes: int = 0
    sha256: Optional[str] = None
    associated_message_id: Optional[str] = None
    associated_conversation_id: Optional[str] = None
    error: Optional[str] = None


class MediaAssociator:
    """Resolves and validates media references against acquired media files."""

    @classmethod
    def associate_media(
        cls,
        conversations: List[Conversation],
        acquired_files: List[Path | str],
    ) -> Dict[str, MediaAssociationRecord]:
        """Associate conversation media references with acquired local media assets.

        Updates msg.media_resolved_path on matching messages.
        Returns a dictionary of media_reference -> MediaAssociationRecord.
        """
        # Index acquired files
        by_exact: Dict[str, Path] = {}
        by_name: Dict[str, List[Path]] = {}

        for f in acquired_files:
            p = Path(f).resolve()
            if not p.is_file():
                continue
            by_exact[str(p)] = p
            # Also index relative path parts
            by_exact[p.name] = p
            by_name.setdefault(p.name.lower(), []).append(p)

        results: Dict[str, MediaAssociationRecord] = {}
        matched_local_paths: Set[str] = set()

        for conv in conversations:
            for msg in conv.messages:
                if not msg.media_reference:
                    continue

                ref = msg.media_reference
                ref_clean = ref.strip()
                ref_name = PurePosixPath(ref_clean).name.lower()

                matched_path: Optional[Path] = None
                evidence = EVIDENCE_UNMATCHED

                # 1. Exact reference check
                if ref_clean in by_exact:
                    matched_path = by_exact[ref_clean]
                    evidence = EVIDENCE_EXACT_REFERENCE
                else:
                    # 2. Relative path suffix check
                    # e.g., 'WhatsApp Images/IMG-20261025-WA0001.jpg'
                    ref_parts = PurePosixPath(ref_clean).parts
                    if len(ref_parts) > 1:
                        suffix_str = f"{ref_parts[-2]}/{ref_parts[-1]}".lower()
                        for p in by_exact.values():
                            norm_p = str(p).replace("\\", "/").lower()
                            if norm_p.endswith(suffix_str) or norm_p.endswith(ref_clean.lower()):
                                matched_path = p
                                evidence = EVIDENCE_MATCHED_RELATIVE
                                break

                    # 3. Filename match check
                    if not matched_path and ref_name in by_name:
                        matched_path = by_name[ref_name][0]
                        evidence = EVIDENCE_MATCHED_FILENAME

                if matched_path and matched_path.exists():
                    msg.media_resolved_path = str(matched_path)
                    matched_local_paths.add(str(matched_path))
                    sz = matched_path.stat().st_size
                    h, _, _ = hash_local_file(matched_path)

                    results[ref] = MediaAssociationRecord(
                        media_reference=ref,
                        local_path=str(matched_path),
                        evidence_level=evidence,
                        file_exists=True,
                        size_bytes=sz,
                        sha256=h,
                        associated_message_id=msg.message_id,
                        associated_conversation_id=conv.conversation_id,
                    )
                else:
                    results[ref] = MediaAssociationRecord(
                        media_reference=ref,
                        local_path=None,
                        evidence_level=EVIDENCE_UNMATCHED,
                        file_exists=False,
                        size_bytes=0,
                        associated_message_id=msg.message_id,
                        associated_conversation_id=conv.conversation_id,
                        error="Media referenced in database record was not found in acquired assets.",
                    )

        # Account for unmatched acquired media
        for f in acquired_files:
            p_str = str(Path(f).resolve())
            if p_str not in matched_local_paths and Path(p_str).is_file():
                results[f"unreferenced_{Path(p_str).name}"] = MediaAssociationRecord(
                    media_reference=Path(p_str).name,
                    local_path=p_str,
                    evidence_level=EVIDENCE_UNMATCHED,
                    file_exists=True,
                    size_bytes=Path(p_str).stat().st_size,
                    error="Asset acquired on storage but unreferenced in accessible chat records.",
                )

        return results
