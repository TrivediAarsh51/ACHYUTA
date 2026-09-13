"""Read-only Windows process collection boundary."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Mapping, Protocol

from platform.windows.observation import (
    CollectionStatus,
    WindowsCollectionResult,
    WindowsObservation,
)


SOURCE = "platform.windows.process"


class ProcessProvider(Protocol):
    """Provider contract for read-only process records."""

    def collect_processes(self) -> Iterable[Mapping[str, Any]]:
        ...


class WindowsProcessCollector:
    """Collect process observations without evaluating or enforcing anything."""

    def __init__(
        self,
        provider: ProcessProvider | None = None,
        *,
        platform_name: str | None = None,
        max_age: timedelta | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._provider = provider
        self._platform_name = platform_name
        self._max_age = max_age
        self._now = now or (lambda: datetime.now(timezone.utc))

    def collect(self) -> WindowsCollectionResult:
        if not self._is_windows():
            return WindowsCollectionResult.failure(
                status=CollectionStatus.UNSUPPORTED,
                source=SOURCE,
                message="Windows process collection requires a Windows runtime.",
            )

        provider = self._provider
        if provider is None:
            from platform.windows.system_provider import SystemWindowsProcessProvider

            provider = SystemWindowsProcessProvider()

        try:
            records = provider.collect_processes()
            if records is None:
                raise OSError("The process source returned no collection.")
        except PermissionError as error:
            return WindowsCollectionResult.failure(
                status=CollectionStatus.PERMISSION_DENIED,
                source=SOURCE,
                message=str(error) or "Windows process access was denied.",
            )
        except TimeoutError as error:
            return WindowsCollectionResult.failure(
                status=CollectionStatus.UNAVAILABLE,
                source=SOURCE,
                message=str(error) or "Windows process collection timed out.",
            )
        except (OSError, RuntimeError) as error:
            return WindowsCollectionResult.failure(
                status=CollectionStatus.UNAVAILABLE,
                source=SOURCE,
                message=str(error) or "Windows process source is unavailable.",
            )

        observations: list[WindowsObservation] = []
        failures = []
        for record in records:
            record_status = self._record_status(record)
            if record_status is not None:
                failures.append(
                    self._failure_for_record(record_status, record)
                )
                continue
            try:
                observation = WindowsObservation.from_mapping(record)
                if self._is_stale(observation):
                    failures.append(
                        self._failure_for_record(CollectionStatus.STALE, record)
                    )
                    continue
            except TypeError as error:
                failures.append(
                    self._failure_for_record(CollectionStatus.MALFORMED, record, str(error))
                )
                continue
            except ValueError as error:
                status = (
                    CollectionStatus.UNVERIFIABLE
                    if record.get("user_identity") is None
                    else CollectionStatus.MALFORMED
                )
                failures.append(self._failure_for_record(status, record, str(error)))
                continue
            observations.append(observation)

        status = self._result_status(observations, failures)
        return WindowsCollectionResult(
            status=status,
            observations=tuple(observations),
            failures=tuple(failures),
        )

    def _is_windows(self) -> bool:
        name = self._platform_name
        if name is None:
            return sys.platform == "win32"
        return name.lower() in {"windows", "win32"}

    def _is_stale(self, observation: WindowsObservation) -> bool:
        if self._max_age is None:
            return False
        now = self._now()
        return now - observation.observed_at > self._max_age

    @staticmethod
    def _record_status(record: Any) -> CollectionStatus | None:
        if not isinstance(record, Mapping):
            return CollectionStatus.MALFORMED
        raw_status = record.get("collection_status")
        if raw_status is None:
            return None
        try:
            status = CollectionStatus(raw_status)
        except ValueError:
            return CollectionStatus.MALFORMED
        return None if status is CollectionStatus.SUCCESS else status

    @staticmethod
    def _failure_for_record(
        status: CollectionStatus,
        record: Any,
        message: str | None = None,
    ):
        process_id = record.get("process_id") if isinstance(record, Mapping) else None
        observed_at = record.get("observed_at") if isinstance(record, Mapping) else None
        return WindowsCollectionResult.failure(
            status=status,
            source=SOURCE,
            message=message or f"Windows process observation is {status.value.lower()}.",
            process_id=process_id if isinstance(process_id, int) else None,
            observed_at=observed_at if isinstance(observed_at, datetime) else None,
        ).failures[0]

    @staticmethod
    def _result_status(observations, failures) -> CollectionStatus:
        by_process: dict[int, WindowsObservation] = {}
        conflict = False
        for observation in observations:
            previous = by_process.get(observation.process_id)
            if previous is not None and previous != observation:
                conflict = True
            by_process[observation.process_id] = observation
        if conflict:
            return CollectionStatus.CONFLICT
        if failures:
            return failures[0].status
        return CollectionStatus.SUCCESS
