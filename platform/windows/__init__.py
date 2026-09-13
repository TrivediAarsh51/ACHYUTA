"""Windows endpoint observation and evidence adapters."""

from platform.windows.collector import WindowsProcessCollector
from platform.windows.evidence import observation_to_evidence
from platform.windows.observation import (
    CollectionStatus,
    WindowsCollectionFailure,
    WindowsCollectionResult,
    WindowsObservation,
)

__all__ = [
    "CollectionStatus",
    "WindowsCollectionFailure",
    "WindowsCollectionResult",
    "WindowsObservation",
    "WindowsProcessCollector",
    "observation_to_evidence",
]
