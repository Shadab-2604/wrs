"""Staged duplicate detection and management module for WRS.

Identifies identical assets using a staged pipeline:
1. Group files by exact byte size.
2. Eliminate unique-size files from expensive hash calculations.
3. Compute and compare SHA-256 hashes of remaining candidates.
4. Organize confirmed identical files into duplicate groups.
Supports safe, explicit duplicate exclusion during acquisition without data loss.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .hashing import hash_local_file

logger = logging.getLogger("wrs.duplicate")


@dataclass
class DuplicateGroup:
    """Represents a set of confirmed identical files."""

    group_id: str
    sha256_hash: str
    size_bytes: int
    primary_path: str
    duplicate_paths: List[str] = field(default_factory=list)

    @property
    def total_count(self) -> int:
        return 1 + len(self.duplicate_paths)

    @property
    def wasted_bytes(self) -> int:
        return len(self.duplicate_paths) * self.size_bytes


class DuplicateDetector:
    """Staged duplicate detection engine."""

    @staticmethod
    def identify_duplicates_from_local_files(
        filepaths: List[Path | str],
    ) -> Dict[str, DuplicateGroup]:
        """Perform staged duplicate identification across local files."""
        # Stage 1: Group by size
        size_buckets: Dict[int, List[Path]] = {}
        for p in filepaths:
            path_obj = Path(p)
            if not path_obj.is_file():
                continue
            sz = path_obj.stat().st_size
            if sz == 0:
                continue  # Skip 0-byte files from duplicate deduplication
            size_buckets.setdefault(sz, []).append(path_obj)

        # Stage 2: Eliminate unique sizes
        candidate_buckets = {sz: paths for sz, paths in size_buckets.items() if len(paths) > 1}

        # Stage 3: Hash comparison on remaining candidates
        groups: Dict[str, DuplicateGroup] = {}
        for sz, candidates in candidate_buckets.items():
            hash_buckets: Dict[str, List[str]] = {}
            for cand in candidates:
                h, _, err = hash_local_file(cand)
                if h and not err:
                    hash_buckets.setdefault(h, []).append(str(cand))

            # Stage 4: Form duplicate groups
            for h, matching_paths in hash_buckets.items():
                if len(matching_paths) > 1:
                    gid = f"dup_{h[:12]}"
                    groups[gid] = DuplicateGroup(
                        group_id=gid,
                        sha256_hash=h,
                        size_bytes=sz,
                        primary_path=matching_paths[0],
                        duplicate_paths=matching_paths[1:],
                    )

        return groups

    @staticmethod
    def identify_duplicates_from_records(
        records: List[Any],
        get_hash_func: Optional[Callable[[str], Optional[str]]] = None,
    ) -> Dict[str, DuplicateGroup]:
        """Identify duplicates from inventory or scanned records.

        Records can be InventoryRecord or ScannedFile instances.
        """
        # Stage 1: Group by size
        size_buckets: Dict[int, List[Any]] = {}
        for r in records:
            sz = getattr(r, "size_bytes", 0)
            if sz > 0:
                size_buckets.setdefault(sz, []).append(r)

        # Stage 2: Candidates with size collision
        candidate_buckets = {sz: items for sz, items in size_buckets.items() if len(items) > 1}

        groups: Dict[str, DuplicateGroup] = {}
        for sz, candidates in candidate_buckets.items():
            hash_buckets: Dict[str, List[str]] = {}
            for item in candidates:
                src_path = getattr(item, "source_path", getattr(item, "original_path", None))
                if not src_path:
                    continue
                # Try destination hash or source hash already present
                h = getattr(item, "destination_sha256", None) or getattr(item, "source_sha256", None)
                if not h and get_hash_func:
                    h = get_hash_func(src_path)

                if h:
                    hash_buckets.setdefault(h, []).append(src_path)

            for h, paths in hash_buckets.items():
                if len(paths) > 1:
                    gid = f"dup_{h[:12]}"
                    groups[gid] = DuplicateGroup(
                        group_id=gid,
                        sha256_hash=h,
                        size_bytes=sz,
                        primary_path=paths[0],
                        duplicate_paths=paths[1:],
                    )

        return groups

    @staticmethod
    def filter_for_deduplicated_acquisition(
        items: List[Any],
        dup_groups: Dict[str, DuplicateGroup],
    ) -> Tuple[List[Any], List[Any]]:
        """Separate items into (primary_eligible_items, excluded_duplicate_items)."""
        excluded_paths: Set[str] = set()
        for g in dup_groups.values():
            excluded_paths.update(g.duplicate_paths)

        eligible = []
        excluded = []
        for it in items:
            p = getattr(it, "source_path", getattr(it, "original_path", str(it)))
            if p in excluded_paths:
                excluded.append(it)
            else:
                eligible.append(it)

        return eligible, excluded
