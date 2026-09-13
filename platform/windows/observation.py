"""Platform-specific Windows process observation records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


class CollectionStatus(str, Enum):
    """Non-authorization statuses for a Windows collection attempt."""

    SUCCESS = "SUCCESS"
    MISSING = "MISSING"
    INACCESSIBLE = "INACCESSIBLE"
    UNAVAILABLE = "UNAVAILABLE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    STALE = "STALE"
    MALFORMED = "MALFORMED"
    INVALID = "INVALID"
    UNSUPPORTED = "UNSUPPORTED"
    UNVERIFIABLE = "UNVERIFIABLE"
    CONFLICT = "CONFLICT"
    TIMEOUT = "TIMEOUT"


def _validate_timestamp(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware.")


@dataclass(frozen=True)
class WindowsObservation:
    """Complete, platform-specific process facts collected from Windows."""

    process_id: int
    process_name: str
    executable_path: str
    parent_process_id: int | None
    user_identity: str
    observed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.process_id, int) or isinstance(self.process_id, bool) or self.process_id <= 0:
            raise ValueError("process_id must be a positive integer.")
        if not isinstance(self.process_name, str) or not self.process_name.strip():
            raise ValueError("process_name must be a non-empty string.")
        if not isinstance(self.executable_path, str) or not self.executable_path.strip():
            raise ValueError("executable_path must be a non-empty string.")
        if self.parent_process_id is not None and (
            not isinstance(self.parent_process_id, int)
            or isinstance(self.parent_process_id, bool)
            or self.parent_process_id <= 0
        ):
            raise ValueError("parent_process_id must be a positive integer or None.")
        if not isinstance(self.user_identity, str) or not self.user_identity.strip():
            raise ValueError("user_identity must be a non-empty string.")
        _validate_timestamp(self.observed_at, "observed_at")

    @classmethod
    def from_mapping(cls, record: Mapping[str, Any]) -> "WindowsObservation":
        if not isinstance(record, Mapping):
            raise TypeError("Windows process records must be mappings.")
        fields = {
            "process_id",
            "process_name",
            "executable_path",
            "parent_process_id",
            "user_identity",
            "observed_at",
        }
        missing = fields - record.keys()
        if missing:
            raise ValueError(f"Missing Windows observation fields: {sorted(missing)}")
        return cls(**{field: record[field] for field in fields})


@dataclass(frozen=True)
class WindowsCollectionFailure:
    """An explicit non-affirmative result from Windows collection."""

    status: CollectionStatus
    source: str
    message: str
    process_id: int | None = None
    observed_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", CollectionStatus(self.status))
        if self.status is CollectionStatus.SUCCESS:
            raise ValueError("SUCCESS is not a collection failure.")
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("Failure source must be a non-empty string.")
        if not isinstance(self.message, str) or not self.message.strip():
            raise ValueError("Failure message must be a non-empty string.")
        if self.observed_at is not None:
            _validate_timestamp(self.observed_at, "observed_at")


@dataclass(frozen=True)
class WindowsCollectionResult:
    """Collection output containing observations and explicit failures only."""

    status: CollectionStatus
    observations: tuple[WindowsObservation, ...] = ()
    failures: tuple[WindowsCollectionFailure, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", CollectionStatus(self.status))
        object.__setattr__(self, "observations", tuple(self.observations))
        object.__setattr__(self, "failures", tuple(self.failures))
        if self.status is CollectionStatus.SUCCESS and self.failures:
            raise ValueError("Successful collection cannot contain failures.")

    @classmethod
    def failure(
        cls,
        *,
        status: CollectionStatus,
        source: str,
        message: str,
        process_id: int | None = None,
        observed_at: datetime | None = None,
    ) -> "WindowsCollectionResult":
        normalized = CollectionStatus(status)
        return cls(
            status=normalized,
            failures=(
                WindowsCollectionFailure(
                    status=normalized,
                    source=source,
                    message=message,
                    process_id=process_id,
                    observed_at=observed_at,
                ),
            ),
        )

    def to_evidence(self):
        """Convert successful observations through the canonical evidence adapter."""
        from platform.windows.evidence import observation_to_evidence

        return tuple(observation_to_evidence(item) for item in self.observations)
