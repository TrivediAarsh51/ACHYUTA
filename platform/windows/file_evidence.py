"""Read-only SHA-256 evidence collection for observed Windows executables."""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Callable

from engine.evidence import Evidence, create_evidence
from platform.windows.observation import CollectionStatus, WindowsObservation


SOURCE = "platform.windows.file"
CATEGORY = "windows_executable_sha256"


@dataclass(frozen=True)
class FileEvidenceResult:
    """Canonical evidence and status for one observed executable path."""

    status: CollectionStatus
    evidence: Evidence
    observation: WindowsObservation
    collected_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", CollectionStatus(self.status))
        if self.status is CollectionStatus.SUCCESS:
            if "sha256" not in self.evidence.value:
                raise ValueError("Successful file evidence must contain a SHA-256 digest.")
        elif "sha256" in self.evidence.value:
            raise ValueError("Non-affirmative file evidence cannot contain a digest.")


def collect_file_evidence(
    observation: WindowsObservation,
    *,
    platform_name: str | None = None,
    now: Callable[[], datetime] | None = None,
    reader: Callable[[Path], BinaryIO] | None = None,
) -> FileEvidenceResult:
    """Hash the observed executable path or return explicit non-affirmative evidence."""

    if not isinstance(observation, WindowsObservation):
        raise TypeError("File evidence requires a WindowsObservation.")

    collected_at = (now or (lambda: datetime.now(timezone.utc)))()
    _validate_timestamp(collected_at, "collected_at")

    if not _is_windows(platform_name):
        return _failure_result(
            observation,
            collected_at,
            CollectionStatus.UNSUPPORTED,
            "Executable file evidence requires a Windows runtime.",
        )

    try:
        path = _validated_path(observation.executable_path)
    except ValueError as error:
        return _failure_result(observation, collected_at, CollectionStatus.MALFORMED, str(error))

    try:
        if not path.exists():
            return _failure_result(
                observation,
                collected_at,
                CollectionStatus.MISSING,
                "Observed executable path does not exist.",
            )
        if not path.is_file():
            return _failure_result(
                observation,
                collected_at,
                CollectionStatus.MALFORMED,
                "Observed executable path is not a regular file.",
            )
    except OSError as error:
        return _failure_result(
            observation,
            collected_at,
            CollectionStatus.INACCESSIBLE,
            str(error) or "Unable to inspect the observed executable path.",
        )

    try:
        digest = _hash_file(path, reader or _open_file)
    except FileNotFoundError:
        return _failure_result(
            observation,
            collected_at,
            CollectionStatus.MISSING,
            "Observed executable disappeared before it could be read.",
        )
    except PermissionError as error:
        return _failure_result(
            observation,
            collected_at,
            CollectionStatus.INACCESSIBLE,
            str(error) or "Access to the observed executable was denied.",
        )
    except (OSError, ValueError, RuntimeError) as error:
        return _failure_result(
            observation,
            collected_at,
            CollectionStatus.UNVERIFIABLE,
            str(error) or "The observed executable could not be hashed reliably.",
        )

    value = {"sha256": digest}
    metadata = _metadata(observation, collected_at, status=CollectionStatus.SUCCESS)
    metadata["hashing_succeeded"] = True
    evidence = create_evidence(
        evidence_id=_evidence_id(observation, value),
        category=CATEGORY,
        source=SOURCE,
        value=value,
        strength="medium",
        verified=False,
        timestamp=observation.observed_at,
        metadata=metadata,
    )
    return FileEvidenceResult(CollectionStatus.SUCCESS, evidence, observation, collected_at)


def _hash_file(path: Path, reader: Callable[[Path], BinaryIO]) -> str:
    digest = hashlib.sha256()
    with reader(path) as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _open_file(path: Path) -> BinaryIO:
    return path.open("rb")


def _validated_path(raw_path: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("Observed executable path must be a non-empty string.")
    path = Path(raw_path)
    if not path.is_absolute():
        raise ValueError("Observed executable path must be absolute.")
    return path


def _is_windows(platform_name: str | None) -> bool:
    name = platform_name or sys.platform
    return name.lower() in {"windows", "win32"}


def _validate_timestamp(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware.")


def _metadata(
    observation: WindowsObservation,
    collected_at: datetime,
    *,
    status: CollectionStatus,
) -> dict[str, object]:
    return {
        "platform": "windows",
        "process_id": observation.process_id,
        "process_name": observation.process_name,
        "executable_path": observation.executable_path,
        "parent_process_id": observation.parent_process_id,
        "user_identity": observation.user_identity,
        "observation_timestamp": observation.observed_at.isoformat(),
        "collection_timestamp": collected_at.isoformat(),
        "status": status.value,
    }


def _evidence_id(observation: WindowsObservation, value: dict[str, object]) -> str:
    identity = {
        "process_id": observation.process_id,
        "process_name": observation.process_name,
        "executable_path": observation.executable_path,
        "parent_process_id": observation.parent_process_id,
        "user_identity": observation.user_identity,
        "observed_at": observation.observed_at.isoformat(),
        "value": value,
    }
    serialized = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return "WIN-FILE-" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:24]


def _failure_result(
    observation: WindowsObservation,
    collected_at: datetime,
    status: CollectionStatus,
    reason: str,
) -> FileEvidenceResult:
    value = {"status": status.value, "reason": reason}
    evidence = create_evidence(
        evidence_id=_evidence_id(observation, value),
        category=CATEGORY,
        source=SOURCE,
        value=value,
        strength="very_low",
        verified=False,
        timestamp=observation.observed_at,
        metadata=_metadata(observation, collected_at, status=status),
    )
    return FileEvidenceResult(status, evidence, observation, collected_at)
