"""Centralized runtime state management and Single Source of Truth for WRS.

Tracks ADB executable, ADB server, device enumeration, selected device,
operation lifecycles (NOT_STARTED, IN_PROGRESS, COMPLETED, etc.), and ensures
that all displayed and reported information is derived from real-time observations
and completed operations without fabricated or hardcoded placeholders.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("wrs.state")


class ValueLifecycle(str, Enum):
    """Categorization of runtime values."""
    CONFIGURED = "CONFIGURED"
    OBSERVED = "OBSERVED"
    CALCULATED = "CALCULATED"
    COMPLETED = "COMPLETED"
    UNAVAILABLE = "UNAVAILABLE"
    STALE = "STALE"


class OperationState(str, Enum):
    """Execution lifecycle of forensic operations."""
    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass
class RuntimeEntry:
    """An individual tracked runtime datum with lifecycle provenance."""
    name: str
    value: Any
    lifecycle: ValueLifecycle
    timestamp: str
    source: str
    error: Optional[str] = None


class RuntimeStateManager:
    """Centralized runtime state manager acting as the Single Source of Truth."""

    _instance: Optional["RuntimeStateManager"] = None

    def __init__(self) -> None:
        self.adb_installed: bool = False
        self.adb_available: bool = False
        self.adb_version: str = ""
        self.adb_status_display: str = "NOT INSTALLED"
        self.adb_server_responsive: bool = False
        self.device_enumeration_success: bool = False
        self.device_enumeration_error: Optional[str] = None
        self.device_count: int = 0
        self.device_status_display: str = "NONE DETECTED"
        self.devices: List[Any] = []
        self.selected_device: Optional[Any] = None

        self.scan_state: OperationState = OperationState.NOT_STARTED
        self.acquisition_state: OperationState = OperationState.NOT_STARTED
        self.verification_state: OperationState = OperationState.NOT_STARTED

        self.entries: Dict[str, RuntimeEntry] = {}
        self.last_refresh_timestamp: str = ""

    @classmethod
    def get_instance(cls) -> "RuntimeStateManager":
        """Access singleton runtime state manager."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton instance (useful for test isolation)."""
        cls._instance = cls()

    def set_entry(
        self,
        name: str,
        value: Any,
        lifecycle: ValueLifecycle,
        source: str,
        error: Optional[str] = None,
    ) -> None:
        """Record a validated runtime value with lifecycle and provenance."""
        from .utils import format_timestamp
        self.entries[name] = RuntimeEntry(
            name=name,
            value=value,
            lifecycle=lifecycle,
            timestamp=format_timestamp(),
            source=source,
            error=error,
        )

    def get_entry(self, name: str) -> Optional[RuntimeEntry]:
        """Retrieve entry by name."""
        return self.entries.get(name)

    def get_value(self, name: str, default: Any = None) -> Any:
        """Retrieve value by name."""
        entry = self.entries.get(name)
        return entry.value if entry else default

    def sync_device_status(self, status: Any) -> None:
        """Synchronize state with a DeviceStatusResult from AdbExecutor."""
        from .utils import format_timestamp
        self.adb_installed = status.adb_installed
        self.adb_available = status.adb_available
        self.adb_version = status.adb_version
        self.adb_status_display = status.adb_status_display
        self.adb_server_responsive = status.adb_server_responsive
        self.device_enumeration_success = status.enumeration_success
        self.device_enumeration_error = status.enumeration_error
        self.device_count = status.device_count
        self.device_status_display = status.device_status_display
        self.devices = status.devices
        self.selected_device = status.selected_device
        self.last_refresh_timestamp = format_timestamp()

        # Update provenance entries
        self.set_entry("adb_status", self.adb_status_display, ValueLifecycle.OBSERVED, "adb version")
        self.set_entry("device_status", self.device_status_display, ValueLifecycle.OBSERVED, "adb devices -l")
        self.set_entry("device_count", self.device_count, ValueLifecycle.OBSERVED, "adb devices -l")
        if self.selected_device:
            self.set_entry(
                "selected_device",
                self.selected_device.display_name,
                ValueLifecycle.OBSERVED,
                f"adb -s {self.selected_device.serial}",
            )
        else:
            self.set_entry("selected_device", None, ValueLifecycle.UNAVAILABLE, "device_manager")

    def invalidate_device(self, reason: str = "Device disconnected") -> None:
        """Mark active device state as stale or disconnected."""
        from .utils import format_timestamp
        if self.selected_device:
            self.set_entry(
                "selected_device",
                self.selected_device.display_name,
                ValueLifecycle.STALE,
                "disconnection_handler",
                error=reason,
            )
        self.selected_device = None
        self.device_status_display = f"DISCONNECTED ({reason})"
        self.last_refresh_timestamp = format_timestamp()

    def set_operation_state(self, operation: str, state: OperationState, details: Optional[str] = None) -> None:
        """Update lifecycle state of a forensic operation."""
        from .utils import format_timestamp
        if operation == "scan":
            self.scan_state = state
        elif operation == "acquisition":
            self.acquisition_state = state
        elif operation == "verification":
            self.verification_state = state

        self.set_entry(
            f"{operation}_state",
            state.value,
            ValueLifecycle.COMPLETED if state == OperationState.COMPLETED else ValueLifecycle.OBSERVED,
            f"{operation}_engine",
            error=details if state in (OperationState.FAILED, OperationState.CANCELLED) else None,
        )
