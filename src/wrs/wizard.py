"""Recovery selection wizard and date-range filtering engine for WRS (Phase 4).

Provides interactive category selection, distinct chat history and media pipelines,
chronological chat timelines, DD-MM-YYYY date-range validation, available-date
calendar pickers, conversation selection, and comprehensive recovery previews.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .categorizer import (
    ALL_CATEGORIES,
    CAT_ANIMATED_GIFS,
    CAT_AUDIO,
    CAT_BACKUPS,
    CAT_DATABASES,
    CAT_DOCUMENTS,
    CAT_IMAGES,
    CAT_OTHER,
    CAT_STICKERS,
    CAT_THUMBNAILS,
    CAT_VIDEOS,
    CAT_VOICE_NOTES,
)
from .chat import Conversation, ReconstructedMessage
from .utils import format_bytes

logger = logging.getLogger("wrs.wizard")


# Mapping of wizard numeric options to category labels
CATEGORY_MENU_MAP: Dict[int, str] = {
    1: "All Supported Data",
    2: "Chat History",
    3: "Photos and Images",
    4: "Videos",
    5: "Audio Files",
    6: "Voice Notes",
    7: "Documents and Files",
    8: "Stickers",
    9: "GIFs and Animated Media",
    10: "Thumbnails",
    11: "Databases and Backups",
    12: "Other Supported Files",
}

# Mapping of wizard category labels to internal storage categories
LABEL_TO_STORAGE_CATS: Dict[str, List[str]] = {
    "Photos and Images": [CAT_IMAGES],
    "Videos": [CAT_VIDEOS],
    "Audio Files": [CAT_AUDIO],
    "Voice Notes": [CAT_VOICE_NOTES],
    "Documents and Files": [CAT_DOCUMENTS],
    "Stickers": [CAT_STICKERS],
    "GIFs and Animated Media": [CAT_ANIMATED_GIFS],
    "Thumbnails": [CAT_THUMBNAILS],
    "Databases and Backups": [CAT_DATABASES, CAT_BACKUPS],
    "Other Supported Files": [CAT_OTHER],
}


def parse_category_selection(user_input: str) -> Tuple[bool, List[str], bool, str]:
    """Parse and validate user category input string (e.g. '2,4,7', 'A', 'C', '0').

    Returns:
        (valid, selected_category_labels, includes_chat_history, message)
    """
    clean = user_input.strip()
    if not clean:
        return False, [], False, "No selection entered. Please choose one or more categories."

    clean_upper = clean.upper()

    if clean_upper in ("0", "BACK", "B"):
        return True, [], False, "BACK"

    if clean_upper == "C" or clean_upper == "CLEAR":
        return True, [], False, "Selection cleared."

    if clean_upper == "A" or clean_upper == "ALL" or clean == "1":
        # Select all supported categories + chat history
        all_labels = [CATEGORY_MENU_MAP[i] for i in range(2, 13)]
        return True, all_labels, True, "All supported data categories selected."

    # Parse comma-separated or space-separated numbers
    tokens = [t.strip() for t in clean.replace(" ", ",").split(",") if t.strip()]
    selected_labels: List[str] = []
    seen_ids: Set[int] = set()
    includes_chats = False

    for tok in tokens:
        if not tok.isdigit():
            return False, [], False, f"Invalid category token '{tok}'. Please enter numbers between 1 and 12."
        val = int(tok)
        if val < 1 or val > 12:
            return False, [], False, f"Option '{val}' is out of range. Choose numbers between 1 and 12."

        if val == 1:
            all_labels = [CATEGORY_MENU_MAP[i] for i in range(2, 13)]
            return True, all_labels, True, "All supported data categories selected."

        if val in seen_ids:
            continue
        seen_ids.add(val)

        label = CATEGORY_MENU_MAP[val]
        selected_labels.append(label)
        if val == 2:
            includes_chats = True

    if not selected_labels:
        return False, [], False, "No valid categories selected."

    return True, selected_labels, includes_chats, f"Selected {len(selected_labels)} category/categories."


def resolve_storage_categories(category_labels: List[str]) -> Set[str]:
    """Translate wizard category labels into underlying storage category names."""
    resolved: Set[str] = set()
    for lbl in category_labels:
        if lbl in LABEL_TO_STORAGE_CATS:
            resolved.update(LABEL_TO_STORAGE_CATS[lbl])
        elif lbl == "All Supported Data":
            resolved.update(ALL_CATEGORIES)
    return resolved


def parse_date_dd_mm_yyyy(date_str: str) -> Optional[datetime]:
    """Parse string strictly formatted as DD-MM-YYYY into a naive datetime.

    Rejects invalid calendar dates such as 31-02-2024.
    """
    clean = date_str.strip()
    if not clean:
        return None
    try:
        return datetime.strptime(clean, "%d-%m-%Y")
    except ValueError:
        return None


def message_to_datetime(msg: ReconstructedMessage) -> Optional[datetime]:
    """Convert a message's raw timestamp into a normalized local naive datetime."""
    ts = msg.timestamp
    if ts is None or ts == "" or ts == 0:
        return None
    try:
        val = float(ts)
        if val <= 0:
            return None
        if val > 1e11:
            val /= 1000.0
        dt = datetime.fromtimestamp(val, timezone.utc).astimezone()
        # Return naive datetime in local timezone for clean comparisons
        return dt.replace(tzinfo=None)
    except (ValueError, OSError, OverflowError):
        return None


@dataclass
class ChatTimeline:
    """Chronological timeline summary of available readable chat history."""

    oldest_dt: Optional[datetime] = None
    newest_dt: Optional[datetime] = None
    oldest_formatted: str = "Unavailable"
    newest_formatted: str = "Unavailable"
    total_messages: int = 0
    total_conversations: int = 0
    missing_timestamps_count: int = 0
    dates_calendar: Dict[str, int] = field(default_factory=dict)  # "DD-MM-YYYY" -> count


class DateRangeEngine:
    """Extracts chat timelines, validates date boundaries, and filters conversations."""

    @staticmethod
    def extract_timeline(conversations: List[Conversation]) -> ChatTimeline:
        """Extract ascending timeline, boundary dates, and calendar frequencies."""
        oldest: Optional[datetime] = None
        newest: Optional[datetime] = None
        total_msgs = 0
        missing_ts = 0
        calendar: Dict[str, int] = {}

        for conv in conversations:
            for msg in conv.messages:
                total_msgs += 1
                dt = message_to_datetime(msg)
                if dt is None:
                    missing_ts += 1
                    continue

                if oldest is None or dt < oldest:
                    oldest = dt
                if newest is None or dt > newest:
                    newest = dt

                date_key = dt.strftime("%d-%m-%Y")
                calendar[date_key] = calendar.get(date_key, 0) + 1

        # Sort calendar chronologically
        def parse_key(k: str) -> datetime:
            return datetime.strptime(k, "%d-%m-%Y")

        sorted_calendar = dict(sorted(calendar.items(), key=lambda item: parse_key(item[0])))

        oldest_str = oldest.strftime("%d-%m-%Y %H:%M") if oldest else "Unavailable"
        newest_str = newest.strftime("%d-%m-%Y %H:%M") if newest else "Unavailable"

        return ChatTimeline(
            oldest_dt=oldest,
            newest_dt=newest,
            oldest_formatted=oldest_str,
            newest_formatted=newest_str,
            total_messages=total_msgs,
            total_conversations=len(conversations),
            missing_timestamps_count=missing_ts,
            dates_calendar=sorted_calendar,
        )

    @classmethod
    def validate_date_range(
        cls,
        start_str: str,
        end_str: str,
        min_dt: Optional[datetime],
        max_dt: Optional[datetime],
    ) -> Tuple[bool, Optional[datetime], Optional[datetime], str]:
        """Validate DD-MM-YYYY date input against calendar rules and chat history boundaries.

        Returns:
            (valid, inclusive_start_dt, inclusive_end_dt, explanation_message)
        """
        start_date = parse_date_dd_mm_yyyy(start_str)
        if not start_date:
            return False, None, None, f"Invalid Start Date '{start_str}'. Use format DD-MM-YYYY with valid calendar dates."

        end_date = parse_date_dd_mm_yyyy(end_str)
        if not end_date:
            return False, None, None, f"Invalid End Date '{end_str}'. Use format DD-MM-YYYY with valid calendar dates."

        if end_date < start_date:
            return False, None, None, f"End date ({end_str}) cannot be earlier than start date ({start_str})."

        # Expand to inclusive day range
        inc_start = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
        inc_end = end_date.replace(hour=23, minute=59, second=59, microsecond=999999)

        if min_dt is None or max_dt is None:
            return True, inc_start, inc_end, "Date range accepted (no boundary constraints)."

        min_day = min_dt.replace(hour=0, minute=0, second=0, microsecond=0)
        max_day = max_dt.replace(hour=23, minute=59, second=59, microsecond=999999)

        # Entirely outside available history
        if inc_end < min_day or inc_start > max_day:
            min_fmt = min_dt.strftime("%d-%m-%Y")
            max_fmt = max_dt.strftime("%d-%m-%Y")
            return (
                False,
                None,
                None,
                f"Requested range ({start_str} to {end_str}) is entirely outside available history ({min_fmt} to {max_fmt}).",
            )

        # Partial overlap detected
        notes = []
        effective_start = inc_start
        effective_end = inc_end

        if inc_start < min_day:
            notes.append(f"Start date {start_str} precedes oldest message ({min_dt.strftime('%d-%m-%Y')}).")
            effective_start = min_day
        if inc_end > max_day:
            notes.append(f"End date {end_str} extends beyond newest message ({max_dt.strftime('%d-%m-%Y')}).")
            effective_end = max_day

        msg = "Date range is valid."
        if notes:
            msg = "Partial overlap: " + " ".join(notes)

        return True, effective_start, effective_end, msg

    @staticmethod
    def filter_conversations_by_date(
        conversations: List[Conversation],
        start_dt: datetime,
        end_dt: datetime,
    ) -> Tuple[List[Conversation], int]:
        """Filter messages in each conversation strictly within inclusive date range.

        Returns:
            (filtered_conversations, count_of_excluded_messages_with_missing_timestamps)
        """
        filtered_convs: List[Conversation] = []
        excluded_missing_ts = 0

        for conv in conversations:
            matching_msgs: List[ReconstructedMessage] = []
            for msg in conv.messages:
                dt = message_to_datetime(msg)
                if dt is None:
                    excluded_missing_ts += 1
                    continue
                if start_dt <= dt <= end_dt:
                    matching_msgs.append(msg)

            if matching_msgs:
                start_t = matching_msgs[0].formatted_time
                end_t = matching_msgs[-1].formatted_time
                media_cnt = sum(1 for m in matching_msgs if m.media_reference)
                summary = (
                    f"{len(matching_msgs)} messages matched between "
                    f"{start_dt.strftime('%d-%m-%Y')} and {end_dt.strftime('%d-%m-%Y')}. "
                    f"Referenced media: {media_cnt}."
                )

                filtered_convs.append(
                    Conversation(
                        conversation_id=conv.conversation_id,
                        display_name=conv.display_name,
                        messages=matching_msgs,
                        message_count=len(matching_msgs),
                        start_time=start_t,
                        end_time=end_t,
                        media_count=media_cnt,
                        completeness_summary=summary,
                    )
                )

        return filtered_convs, excluded_missing_ts

    @staticmethod
    def filter_conversations_by_specific_dates(
        conversations: List[Conversation],
        target_dates: Set[str],
    ) -> Tuple[List[Conversation], int]:
        """Filter messages in conversations belonging to specific DD-MM-YYYY dates."""
        filtered_convs: List[Conversation] = []
        excluded_missing_ts = 0

        for conv in conversations:
            matching_msgs: List[ReconstructedMessage] = []
            for msg in conv.messages:
                dt = message_to_datetime(msg)
                if dt is None:
                    excluded_missing_ts += 1
                    continue
                d_str = dt.strftime("%d-%m-%Y")
                if d_str in target_dates:
                    matching_msgs.append(msg)

            if matching_msgs:
                start_t = matching_msgs[0].formatted_time
                end_t = matching_msgs[-1].formatted_time
                media_cnt = sum(1 for m in matching_msgs if m.media_reference)

                filtered_convs.append(
                    Conversation(
                        conversation_id=conv.conversation_id,
                        display_name=conv.display_name,
                        messages=matching_msgs,
                        message_count=len(matching_msgs),
                        start_time=start_t,
                        end_time=end_t,
                        media_count=media_cnt,
                        completeness_summary=f"{len(matching_msgs)} messages matched across {len(target_dates)} selected date(s).",
                    )
                )

        return filtered_convs, excluded_missing_ts


@dataclass
class RecoverySelectionPreview:
    """Pre-operation preview consolidating category, chat, and date selections."""

    device_name: str
    operation: str
    categories: List[str]
    chat_source_status: str
    oldest_available_date: str
    newest_available_date: str
    requested_range: str
    selected_conversations_count: int
    selected_messages_count: int
    selected_files_count: int
    total_selected_size_bytes: int
    unreadable_records_count: int
    missing_timestamps_count: int
    unmatched_media_count: int
    destination_path: str

    @property
    def total_selected_size_human(self) -> str:
        return format_bytes(self.total_selected_size_bytes)
