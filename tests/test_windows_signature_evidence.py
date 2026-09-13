from datetime import datetime, timezone
from pathlib import Path
import sys

import pytest

from engine.evidence import Evidence
from engine.trust import EntityType, TrustEntity, TrustState
from platform.windows.observation import CollectionStatus, WindowsObservation
from platform.windows.signature_evidence import (
    NativeAuthenticodeInspector,
    SignatureInspection,
    collect_signature_evidence,
)


OBSERVED_AT = datetime(2026, 9, 13, 14, 30, tzinfo=timezone.utc)
COLLECTED_AT = datetime(2026, 9, 13, 14, 31, tzinfo=timezone.utc)


def observation(path: str | Path) -> WindowsObservation:
    return WindowsObservation(
        process_id=4242,
        process_name="tool.exe",
        executable_path=str(path),
        parent_process_id=1000,
        user_identity="S-1-5-21-test-user",
        observed_at=OBSERVED_AT,
    )


def signed_inspection(**overrides) -> SignatureInspection:
    values = {
        "status": CollectionStatus.SUCCESS,
        "signature_present": True,
        "validation_status": "Valid",
        "signing_source": "embedded_authenticode",
        "signer_subject": "CN=Example Publisher",
        "issuer": "CN=Example Root",
        "certificate_identifier": "ABC123",
        "signature_algorithm": "sha256RSA",
        "chain_status": "Valid",
        "revocation_status": "NotRevoked",
    }
    values.update(overrides)
    return SignatureInspection(**values)


def unsigned_inspection() -> SignatureInspection:
    return SignatureInspection(
        status=CollectionStatus.SUCCESS,
        signature_present=False,
        validation_status="NotSigned",
        signing_source=None,
    )


class StaticInspector:
    def __init__(self, result: SignatureInspection):
        self.result = result
        self.paths: list[Path] = []

    def inspect(self, path: Path) -> SignatureInspection:
        self.paths.append(path)
        return self.result


def test_collects_signed_signature_observation_as_canonical_evidence(tmp_path):
    executable = tmp_path / "signed-tool.exe"
    executable.write_bytes(b"signed fixture")
    inspector = StaticInspector(signed_inspection())

    result = collect_signature_evidence(
        observation(executable),
        platform_name="Windows",
        now=lambda: COLLECTED_AT,
        inspector=inspector,
    )

    assert result.status is CollectionStatus.SUCCESS
    assert isinstance(result.evidence, Evidence)
    assert result.evidence.category == "windows_executable_signature"
    assert result.evidence.source == "platform.windows.signature"
    assert result.evidence.value["signature_present"] is True
    assert result.evidence.value["validation_status"] == "Valid"
    assert result.evidence.value["signer_subject"] == "CN=Example Publisher"
    assert result.evidence.value["certificate_identifier"] == "ABC123"
    assert result.evidence.verified is False
    assert result.evidence.timestamp == OBSERVED_AT
    assert result.evidence.metadata["collection_timestamp"] == COLLECTED_AT.isoformat()
    assert inspector.paths == [Path(executable)]


def test_collects_unsigned_signature_observation_without_trust_claim(tmp_path):
    executable = tmp_path / "unsigned-tool.exe"
    executable.write_bytes(b"unsigned fixture")
    inspector = StaticInspector(unsigned_inspection())

    result = collect_signature_evidence(
        observation(executable),
        platform_name="Windows",
        inspector=inspector,
    )

    assert result.status is CollectionStatus.SUCCESS
    assert result.evidence.value["signature_present"] is False
    assert result.evidence.value["validation_status"] == "NotSigned"
    assert result.evidence.verified is False
    assert "trusted" not in result.evidence.value
    assert "authorized" not in result.evidence.value


def test_repeated_unchanged_signature_observation_has_deterministic_identity(tmp_path):
    executable = tmp_path / "same-tool.exe"
    executable.write_bytes(b"same bytes")
    first = collect_signature_evidence(
        observation(executable),
        platform_name="Windows",
        now=lambda: COLLECTED_AT,
        inspector=StaticInspector(signed_inspection()),
    )
    second = collect_signature_evidence(
        observation(executable),
        platform_name="Windows",
        now=lambda: COLLECTED_AT,
        inspector=StaticInspector(signed_inspection()),
    )

    assert first.evidence.value == second.evidence.value
    assert first.evidence.evidence_id == second.evidence.evidence_id
    assert first.evidence.timestamp == OBSERVED_AT
    assert first.collected_at == COLLECTED_AT


def test_signature_result_preserves_originating_observation(tmp_path):
    executable = tmp_path / "tool.exe"
    executable.write_bytes(b"fixture")
    source_observation = observation(executable)

    result = collect_signature_evidence(
        source_observation,
        platform_name="Windows",
        inspector=StaticInspector(unsigned_inspection()),
    )

    assert result.observation == source_observation
    assert result.evidence.metadata["process_id"] == source_observation.process_id
    assert result.evidence.metadata["executable_path"] == source_observation.executable_path
    assert result.evidence.metadata["observation_timestamp"] == OBSERVED_AT.isoformat()


def test_partial_signature_metadata_is_preserved_without_fabricated_fields(tmp_path):
    executable = tmp_path / "partial-tool.exe"
    executable.write_bytes(b"partial metadata")
    inspection = signed_inspection(
        issuer=None,
        certificate_identifier=None,
        signature_algorithm=None,
        chain_status=None,
        revocation_status=None,
    )

    result = collect_signature_evidence(
        observation(executable),
        platform_name="Windows",
        inspector=StaticInspector(inspection),
    )

    assert result.evidence.value["signer_subject"] == "CN=Example Publisher"
    assert "issuer" not in result.evidence.value
    assert "certificate_identifier" not in result.evidence.value
    assert "signature_algorithm" not in result.evidence.value


def test_invalid_signature_is_explicit_non_affirmative_evidence(tmp_path):
    executable = tmp_path / "invalid-tool.exe"
    executable.write_bytes(b"invalid signature")
    inspection = SignatureInspection(
        status=CollectionStatus.INVALID,
        reason="Platform reported a hash mismatch.",
        validation_status="HashMismatch",
    )

    result = collect_signature_evidence(
        observation(executable),
        platform_name="Windows",
        inspector=StaticInspector(inspection),
    )

    assert result.status is CollectionStatus.INVALID
    assert result.evidence.value == {
        "status": "INVALID",
        "reason": "Platform reported a hash mismatch.",
    }
    assert result.evidence.verified is False


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (CollectionStatus.INACCESSIBLE, "access denied"),
        (CollectionStatus.UNSUPPORTED, "provider unavailable"),
        (CollectionStatus.MALFORMED, "malformed provider result"),
        (CollectionStatus.UNVERIFIABLE, "status unavailable"),
    ],
)
def test_non_affirmative_signature_outcomes_have_no_signature_claim(tmp_path, status, reason):
    executable = tmp_path / "outcome-tool.exe"
    executable.write_bytes(b"outcome")
    inspection = SignatureInspection(status=status, reason=reason)

    result = collect_signature_evidence(
        observation(executable),
        platform_name="Windows",
        inspector=StaticInspector(inspection),
    )

    assert result.status is status
    assert result.evidence.value["status"] == status.value
    assert result.evidence.value["reason"] == reason
    assert "signature_present" not in result.evidence.value
    assert result.evidence.verified is False


def test_missing_path_is_explicit_and_does_not_invoke_inspector(tmp_path):
    inspector = StaticInspector(unsigned_inspection())

    result = collect_signature_evidence(
        observation(tmp_path / "missing-tool.exe"),
        platform_name="Windows",
        inspector=inspector,
    )

    assert result.status is CollectionStatus.MISSING
    assert inspector.paths == []
    assert "signature_present" not in result.evidence.value


def test_malformed_path_is_rejected_before_inspection():
    inspector = StaticInspector(unsigned_inspection())

    result = collect_signature_evidence(
        observation("relative\\tool.exe"),
        platform_name="Windows",
        inspector=inspector,
    )

    assert result.status is CollectionStatus.MALFORMED
    assert inspector.paths == []


def test_unsupported_runtime_skips_inspector(tmp_path):
    executable = tmp_path / "unsupported-tool.exe"
    executable.write_bytes(b"unsupported")
    inspector = StaticInspector(unsigned_inspection())

    result = collect_signature_evidence(
        observation(executable),
        platform_name="Linux",
        inspector=inspector,
    )

    assert result.status is CollectionStatus.UNSUPPORTED
    assert inspector.paths == []
    assert "signature_present" not in result.evidence.value


def test_signature_collection_is_read_only_and_does_not_mutate_trust(tmp_path):
    executable = tmp_path / "read-only-tool.exe"
    executable.write_bytes(b"read only")
    before_bytes = executable.read_bytes()
    before_mtime = executable.stat().st_mtime_ns
    entity = TrustEntity("process:4242", EntityType.PROCESS)
    before_trust = (entity.state, tuple(entity.transition_history))

    result = collect_signature_evidence(
        observation(executable),
        platform_name="Windows",
        inspector=StaticInspector(unsigned_inspection()),
    )

    assert result.status is CollectionStatus.SUCCESS
    assert executable.read_bytes() == before_bytes
    assert executable.stat().st_mtime_ns == before_mtime
    assert (entity.state, tuple(entity.transition_history)) == before_trust
    assert entity.state is TrustState.UNKNOWN


def test_signature_adapter_has_no_downstream_engine_dependencies():
    source = Path(__file__).resolve().parents[1] / "platform" / "windows" / "signature_evidence.py"
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


@pytest.mark.skipif(sys.platform != "win32", reason="Native Authenticode smoke test requires Windows.")
def test_native_authenticode_smoke_is_read_only_on_current_python_executable():
    executable = Path(sys.executable)
    before_bytes = executable.read_bytes()
    before_mtime = executable.stat().st_mtime_ns
    source_observation = observation(executable)

    result = collect_signature_evidence(
        source_observation,
        platform_name="Windows",
        inspector=NativeAuthenticodeInspector(),
    )

    assert result.status in {
        CollectionStatus.SUCCESS,
        CollectionStatus.INVALID,
        CollectionStatus.UNVERIFIABLE,
        CollectionStatus.UNSUPPORTED,
    }
    assert executable.read_bytes() == before_bytes
    assert executable.stat().st_mtime_ns == before_mtime
