import hashlib
from datetime import datetime, timezone
from pathlib import Path

from engine.evidence import Evidence
from engine.request import SecurityRequest
from engine.trust import EntityType, TrustEntity, TrustState
from platform.windows.file_evidence import FileEvidenceResult, collect_file_evidence
from platform.windows.observation import CollectionStatus, WindowsObservation


OBSERVED_AT = datetime(2026, 9, 13, 12, 30, tzinfo=timezone.utc)


def observation(path):
    return WindowsObservation(
        process_id=4242,
        process_name="tool.exe",
        executable_path=str(path),
        parent_process_id=1000,
        user_identity="S-1-5-21-test-user",
        observed_at=OBSERVED_AT,
    )


def test_collects_deterministic_sha256_evidence_from_observed_path(tmp_path):
    executable = tmp_path / "tool.exe"
    contents = b"controlled executable fixture\n"
    executable.write_bytes(contents)

    result = collect_file_evidence(
        observation(executable),
        platform_name="Windows",
        now=lambda: OBSERVED_AT.replace(second=45),
    )

    assert isinstance(result, FileEvidenceResult)
    assert result.status is CollectionStatus.SUCCESS
    assert isinstance(result.evidence, Evidence)
    assert result.evidence.category == "windows_executable_sha256"
    assert result.evidence.source == "platform.windows.file"
    assert result.evidence.value["sha256"] == hashlib.sha256(contents).hexdigest()
    assert result.evidence.verified is False
    assert result.evidence.timestamp == OBSERVED_AT
    assert result.evidence.metadata["executable_path"] == str(executable)
    assert result.evidence.metadata["collection_timestamp"] == OBSERVED_AT.replace(second=45).isoformat()


def test_repeated_collection_of_unchanged_file_has_same_digest_and_id(tmp_path):
    executable = tmp_path / "tool.exe"
    executable.write_bytes(b"same bytes")
    first_observation = observation(executable)
    second_observation = observation(executable)

    first = collect_file_evidence(first_observation, platform_name="Windows", now=lambda: OBSERVED_AT)
    second = collect_file_evidence(second_observation, platform_name="Windows", now=lambda: OBSERVED_AT)

    assert first.evidence.value == second.evidence.value
    assert first.evidence.evidence_id == second.evidence.evidence_id


def test_result_can_be_attached_to_existing_security_request(tmp_path):
    executable = tmp_path / "tool.exe"
    executable.write_bytes(b"request evidence")
    result = collect_file_evidence(observation(executable), platform_name="Windows")
    request = SecurityRequest(
        request_id="REQ-FILE-001",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "process", "name": "tool.exe"},
        action={"type": "inspect"},
        resource={"type": "file", "path": str(executable)},
    )

    request.add_evidence(result.evidence)

    assert request.evidence == [result.evidence]


def test_missing_file_is_explicit_non_affirmative_evidence(tmp_path):
    result = collect_file_evidence(
        observation(tmp_path / "missing.exe"),
        platform_name="Windows",
        now=lambda: OBSERVED_AT,
    )

    assert result.status is CollectionStatus.MISSING
    assert result.evidence.value["status"] == "MISSING"
    assert "sha256" not in result.evidence.value
    assert result.evidence.verified is False
    assert result.evidence.timestamp == OBSERVED_AT


def test_invalid_path_is_malformed_without_file_access():
    invalid = observation("relative\\tool.exe")

    result = collect_file_evidence(invalid, platform_name="Windows")

    assert result.status is CollectionStatus.MALFORMED
    assert "sha256" not in result.evidence.value
    assert result.evidence.verified is False


def test_unsupported_runtime_skips_reader(tmp_path):
    executable = tmp_path / "tool.exe"
    executable.write_bytes(b"unsupported")
    reader_called = False

    def reader(_path):
        nonlocal reader_called
        reader_called = True
        raise AssertionError("reader must not run on unsupported runtime")

    result = collect_file_evidence(
        observation(executable),
        platform_name="Linux",
        reader=reader,
    )

    assert result.status is CollectionStatus.UNSUPPORTED
    assert reader_called is False
    assert "sha256" not in result.evidence.value


def test_reader_failure_is_unverifiable_without_partial_digest(tmp_path):
    executable = tmp_path / "tool.exe"
    executable.write_bytes(b"unstable")

    def reader(_path):
        raise RuntimeError("read became unstable")

    result = collect_file_evidence(
        observation(executable),
        platform_name="Windows",
        reader=reader,
    )

    assert result.status is CollectionStatus.UNVERIFIABLE
    assert result.evidence.value["reason"] == "read became unstable"
    assert "sha256" not in result.evidence.value
    assert result.evidence.verified is False


def test_file_adapter_has_no_downstream_engine_dependencies():
    source = Path(__file__).resolve().parents[1] / "platform" / "windows" / "file_evidence.py"
    contents = source.read_text(encoding="utf-8")

    for forbidden in (
        "engine.policy",
        "engine.risk",
        "engine.decision",
        "engine.trust",
        "engine.runtime",
        "engine.raksha",
    ):
        assert forbidden not in contents


def test_collection_is_read_only_and_does_not_mutate_trust(tmp_path):
    executable = tmp_path / "tool.exe"
    executable.write_bytes(b"read only")
    before_bytes = executable.read_bytes()
    before_mtime = executable.stat().st_mtime_ns
    entity = TrustEntity("process:4242", EntityType.PROCESS)
    before_trust = (entity.state, tuple(entity.transition_history))

    result = collect_file_evidence(observation(executable), platform_name="Windows")

    assert result.status is CollectionStatus.SUCCESS
    assert executable.read_bytes() == before_bytes
    assert executable.stat().st_mtime_ns == before_mtime
    assert (entity.state, tuple(entity.transition_history)) == before_trust
    assert entity.state is TrustState.UNKNOWN
