import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from engine.evidence import Evidence
from engine.request import SecurityRequest
from engine.trust import EntityType, TrustEntity, TrustState
from platform.windows.collector import WindowsProcessCollector
from platform.windows.evidence import observation_to_evidence
from platform.windows.observation import (
    CollectionStatus,
    WindowsCollectionResult,
    WindowsObservation,
)
from platform.windows.system_provider import SystemWindowsProcessProvider


OBSERVED_AT = datetime(2026, 9, 9, 12, 30, tzinfo=timezone.utc)


def process_record(**overrides):
    record = {
        "process_id": 4242,
        "process_name": "tool.exe",
        "executable_path": r"C:\\Tools\\tool.exe",
        "parent_process_id": 1000,
        "user_identity": "S-1-5-21-test-user",
        "observed_at": OBSERVED_AT,
    }
    record.update(overrides)
    return record


class StaticProvider:
    def __init__(self, records):
        self.records = records

    def collect_processes(self):
        return self.records


def test_successful_observation_contains_all_six_fields_and_timestamp():
    result = WindowsProcessCollector(
        provider=StaticProvider([process_record()]),
        platform_name="Windows",
    ).collect()

    assert result.status is CollectionStatus.SUCCESS
    assert result.failures == ()
    assert result.observations == (
        WindowsObservation(
            process_id=4242,
            process_name="tool.exe",
            executable_path=r"C:\\Tools\\tool.exe",
            parent_process_id=1000,
            user_identity="S-1-5-21-test-user",
            observed_at=OBSERVED_AT,
        ),
    )


def test_observation_converts_to_canonical_evidence_with_provenance():
    observation = WindowsObservation(**process_record())

    evidence = observation_to_evidence(observation)

    assert isinstance(evidence, Evidence)
    assert evidence.category == "windows_process_observation"
    assert evidence.source == "platform.windows.process"
    assert evidence.timestamp == OBSERVED_AT
    assert evidence.metadata["platform"] == "windows"
    assert evidence.metadata["observation_timestamp"] == OBSERVED_AT.isoformat()
    assert evidence.value["process_id"] == 4242


def test_evidence_can_be_attached_to_existing_security_request():
    observation = WindowsObservation(**process_record())
    request = SecurityRequest(
        request_id="REQ-WINDOWS-001",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "process", "name": "tool.exe"},
        action={"type": "inspect"},
        resource={"type": "process", "path": r"C:\\Tools\\tool.exe"},
    )

    request.add_evidence(observation_to_evidence(observation))

    assert len(request.evidence) == 1
    assert isinstance(request.evidence[0], Evidence)
    assert request.evidence[0].evidence_id.startswith("WIN-PROC-")


@pytest.mark.parametrize(
    "status",
    [
        CollectionStatus.UNAVAILABLE,
        CollectionStatus.PERMISSION_DENIED,
        CollectionStatus.STALE,
        CollectionStatus.MALFORMED,
        CollectionStatus.UNSUPPORTED,
        CollectionStatus.UNVERIFIABLE,
    ],
)
def test_collection_failures_are_explicit_and_non_affirmative(status):
    result = WindowsCollectionResult.failure(
        status=status,
        source="platform.windows.process",
        message=f"{status.value} source",
    )

    assert result.status is status
    assert result.observations == ()
    assert result.failures[0].status is status
    assert result.to_evidence() == ()


def test_unavailable_source_is_reported_without_fake_observations():
    class UnavailableProvider:
        def collect_processes(self):
            raise OSError("process source unavailable")

    result = WindowsProcessCollector(
        provider=UnavailableProvider(),
        platform_name="Windows",
    ).collect()

    assert result.status is CollectionStatus.UNAVAILABLE
    assert result.observations == ()
    assert result.to_evidence() == ()


def test_permission_denied_is_reported_without_partial_evidence():
    class PermissionDeniedProvider:
        def collect_processes(self):
            raise PermissionError("access denied")

    result = WindowsProcessCollector(
        provider=PermissionDeniedProvider(),
        platform_name="Windows",
    ).collect()

    assert result.status is CollectionStatus.PERMISSION_DENIED
    assert result.to_evidence() == ()


def test_timeout_is_reported_without_partial_evidence():
    class TimeoutProvider:
        def collect_processes(self):
            raise TimeoutError("process source timed out")

    result = WindowsProcessCollector(
        provider=TimeoutProvider(),
        platform_name="Windows",
    ).collect()

    assert result.status is CollectionStatus.UNAVAILABLE
    assert result.failures[0].message == "process source timed out"
    assert result.to_evidence() == ()


def test_stale_observation_is_not_converted_to_evidence():
    stale = process_record(observed_at=OBSERVED_AT - timedelta(minutes=10))
    result = WindowsProcessCollector(
        provider=StaticProvider([stale]),
        platform_name="Windows",
        max_age=timedelta(minutes=1),
        now=lambda: OBSERVED_AT,
    ).collect()

    assert result.status is CollectionStatus.STALE
    assert result.observations == ()
    assert result.to_evidence() == ()


def test_malformed_observation_is_not_converted_to_evidence():
    malformed = process_record(process_id="not-an-int")
    result = WindowsProcessCollector(
        provider=StaticProvider([malformed]),
        platform_name="Windows",
    ).collect()

    assert result.status is CollectionStatus.MALFORMED
    assert result.observations == ()
    assert result.to_evidence() == ()


def test_unverifiable_observation_is_not_converted_to_evidence():
    unverifiable = process_record(user_identity=None)
    result = WindowsProcessCollector(
        provider=StaticProvider([unverifiable]),
        platform_name="Windows",
    ).collect()

    assert result.status is CollectionStatus.UNVERIFIABLE
    assert result.observations == ()
    assert result.to_evidence() == ()


def test_non_windows_environment_returns_unsupported_without_faking_data():
    result = WindowsProcessCollector(
        provider=StaticProvider([process_record()]),
        platform_name="Linux",
    ).collect()

    assert result.status is CollectionStatus.UNSUPPORTED
    assert result.observations == ()
    assert result.to_evidence() == ()


def test_conflicting_observations_remain_distinguishable():
    first = process_record()
    second = process_record(executable_path=r"C:\\Other\\tool.exe")
    result = WindowsProcessCollector(
        provider=StaticProvider([first, second]),
        platform_name="Windows",
    ).collect()

    assert result.status is CollectionStatus.CONFLICT
    assert len(result.observations) == 2
    assert len({item.executable_path for item in result.observations}) == 2
    assert len(result.to_evidence()) == 2
    assert len({item.evidence_id for item in result.to_evidence()}) == 2


def test_collector_exposes_no_authorization_decision_and_does_not_mutate_trust():
    entity = TrustEntity("process:windows-test", EntityType.PROCESS)
    before = (entity.state, tuple(entity.transition_history))

    result = WindowsProcessCollector(
        provider=StaticProvider([process_record()]),
        platform_name="Windows",
    ).collect()

    assert not hasattr(result, "decision")
    assert not hasattr(result, "effect")
    assert (entity.state, tuple(entity.transition_history)) == before
    assert entity.state is TrustState.UNKNOWN


def test_collector_module_has_no_downstream_engine_dependencies():
    import platform.windows.collector as collector_module

    source = open(collector_module.__file__, encoding="utf-8").read()

    for forbidden in (
        "engine.policy",
        "engine.risk",
        "engine.decision",
        "engine.trust",
        "engine.raksha",
        "engine.runtime",
    ):
        assert forbidden not in source


def test_evidence_adapter_has_no_downstream_engine_dependencies():
    import platform.windows.evidence as evidence_module

    source = Path(evidence_module.__file__).read_text(encoding="utf-8")

    for forbidden in (
        "engine.policy",
        "engine.risk",
        "engine.decision",
        "engine.trust",
        "engine.raksha",
        "engine.runtime",
    ):
        assert forbidden not in source


def test_protected_engine_modules_contain_no_windows_collection_logic():
    repository_root = Path(__file__).resolve().parents[1]
    protected_modules = (
        "engine/risk.py",
        "engine/policy.py",
        "engine/decision.py",
        "engine/trust.py",
        "engine/raksha.py",
    )

    for relative_path in protected_modules:
        source = (repository_root / relative_path).read_text(encoding="utf-8")
        assert "platform.windows" not in source
        assert "WindowsProcessCollector" not in source


@pytest.mark.skipif(sys.platform != "win32", reason="native provider requires Windows")
def test_native_windows_provider_smoke_is_read_only():
    result = WindowsProcessCollector(
        provider=SystemWindowsProcessProvider(),
        platform_name="Windows",
    ).collect()

    assert result.status in {
        CollectionStatus.SUCCESS,
        CollectionStatus.CONFLICT,
        CollectionStatus.UNAVAILABLE,
        CollectionStatus.PERMISSION_DENIED,
    }
    assert all(item.process_id > 0 for item in result.observations)