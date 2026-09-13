from datetime import datetime, timezone

from engine.decision import DecisionEffect
from engine.policy import PolicyRecord
from engine.raksha import EnforcementAction
from engine.request import SecurityRequest
from engine.runtime import evaluate_runtime_request
from engine.trust import EntityType, TrustEntity, TrustState
from platform.windows.collector import WindowsProcessCollector
from platform.windows.file_evidence import collect_file_evidence
from platform.windows.observation import WindowsObservation


class StaticProvider:
    def collect_processes(self):
        return [
            {
                "process_id": 5151,
                "process_name": "trusted-tool.exe",
                "executable_path": r"C:\\Tools\\trusted-tool.exe",
                "parent_process_id": 1000,
                "user_identity": "S-1-5-21-operator",
                "observed_at": datetime(2026, 9, 9, 13, 0, tzinfo=timezone.utc),
            }
        ]


def active_policy() -> PolicyRecord:
    policy = PolicyRecord(
        policy_id="P-WINDOWS-ACTIVE",
        name="Windows observation policy",
        version=1,
        provenance={"source": "windows-integration-test"},
        definition={
            "id": "P-WINDOWS-ACTIVE",
            "name": "Windows observation policy",
            "version": 1,
            "evidence": {"windows_process_observation": {"verified": False}},
            "effect": "permit",
        },
    )
    policy.validate({"validator": "test"})
    policy.verify({"verifier": "test"})
    policy.approve({"approver": "test"})
    policy.activate()
    return policy


def test_windows_evidence_uses_existing_runtime_flow():
    collection = WindowsProcessCollector(
        provider=StaticProvider(),
        platform_name="Windows",
    ).collect()
    request = SecurityRequest(
        request_id="REQ-WINDOWS-FLOW",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "process", "name": "trusted-tool.exe"},
        action={"type": "inspect"},
        resource={"type": "process", "path": r"C:\\Tools\\trusted-tool.exe"},
    )
    for evidence in collection.to_evidence():
        request.add_evidence(evidence)

    entity = TrustEntity("process:5151", EntityType.PROCESS)
    result = evaluate_runtime_request(
        request=request,
        entity=entity,
        policies=[
            {
                "id": "P-WINDOWS-OBSERVATION",
                "name": "Windows observation present",
                "evidence": {
                    "windows_process_observation": {
                        "verified": False,
                    }
                },
                "effect": "permit",
            }
        ],
    )

    assert result.request is request
    assert result.risk.evidence_ids == tuple(item.evidence_id for item in request.evidence)
    assert result.policy_results[0].matched is True
    assert result.decision.effect is DecisionEffect.PERMIT
    assert entity.state is TrustState.TRUSTED
    assert [item["stage"] for item in result.audit["evaluation_chain"]] == [
        "request",
        "risk",
        "evidence",
        "policy",
        "decision",
        "trust",
    ]


def test_request_without_windows_evidence_retains_existing_runtime_path():
    request = SecurityRequest(
        request_id="REQ-NO-WINDOWS",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "process", "name": "tool.exe"},
        action={"type": "inspect"},
        resource={"type": "process", "path": r"C:\\Tools\\tool.exe"},
    )

    result = evaluate_runtime_request(request=request, policies=[])

    assert result.request is request
    assert request.evidence == []
    assert result.decision is not None
    assert result.enforcement is None


def test_windows_evidence_reaches_optional_raksha_stage_through_runtime():
    collection = WindowsProcessCollector(
        provider=StaticProvider(),
        platform_name="Windows",
    ).collect()
    request = SecurityRequest(
        request_id="REQ-WINDOWS-RAKSHA",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "process", "name": "trusted-tool.exe"},
        action={"type": "inspect"},
        resource={"type": "process", "path": r"C:\\Tools\\trusted-tool.exe"},
    )
    for evidence in collection.to_evidence():
        request.add_evidence(evidence)

    policy = active_policy()
    result = evaluate_runtime_request(
        request=request,
        policy_records=[policy],
        enforce=True,
    )

    assert result.enforcement is not None
    assert result.enforcement.action is EnforcementAction.ALLOW
    assert result.enforcement.evidence_ids == tuple(item.evidence_id for item in request.evidence)
    assert [item["stage"] for item in result.audit["evaluation_chain"]] == [
        "request",
        "risk",
        "evidence",
        "policy",
        "decision",
        "enforcement",
    ]


def test_sha256_file_evidence_uses_existing_runtime_flow(tmp_path):
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"runtime file evidence")
    observation = WindowsObservation(
        process_id=5151,
        process_name="trusted-tool.exe",
        executable_path=str(executable),
        parent_process_id=1000,
        user_identity="S-1-5-21-operator",
        observed_at=datetime(2026, 9, 13, 13, 0, tzinfo=timezone.utc),
    )
    file_result = collect_file_evidence(observation, platform_name="Windows")
    request = SecurityRequest(
        request_id="REQ-FILE-FLOW",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "process", "name": "trusted-tool.exe"},
        action={"type": "inspect"},
        resource={"type": "file", "path": str(executable)},
    )
    request.add_evidence(file_result.evidence)

    result = evaluate_runtime_request(
        request=request,
        policies=[
            {
                "id": "P-FILE-HASH",
                "name": "File hash is available",
                "evidence": {"windows_executable_sha256": {"verified": False}},
                "effect": "permit",
            }
        ],
    )

    assert result.risk.evidence_ids == (file_result.evidence.evidence_id,)
    assert result.policy_results[0].matched is True
    assert result.decision is not None
    assert result.audit["evidence_ids"] == (file_result.evidence.evidence_id,)


def test_non_affirmative_file_evidence_reaches_risk_without_collector_decision(tmp_path):
    missing = tmp_path / "missing.exe"
    observation = WindowsObservation(
        process_id=5252,
        process_name="missing.exe",
        executable_path=str(missing),
        parent_process_id=1000,
        user_identity="S-1-5-21-operator",
        observed_at=datetime(2026, 9, 13, 13, 0, tzinfo=timezone.utc),
    )
    file_result = collect_file_evidence(observation, platform_name="Windows")
    request = SecurityRequest(
        request_id="REQ-FILE-MISSING",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "process", "name": "missing.exe"},
        action={"type": "inspect"},
        resource={"type": "file", "path": str(missing)},
    )
    request.add_evidence(file_result.evidence)
    entity = TrustEntity("process:5252", EntityType.PROCESS)

    result = evaluate_runtime_request(request=request, entity=entity, policies=[])

    assert file_result.evidence.value["status"] == "MISSING"
    assert result.risk.evidence_ids == (file_result.evidence.evidence_id,)
    assert not hasattr(file_result, "decision")
    assert entity.state is TrustState.QUARANTINED