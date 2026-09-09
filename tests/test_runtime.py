"""Tests for the runtime evaluation boundary."""

import pytest

from engine.decision import DecisionEffect
from engine.evidence import create_evidence
from engine.policy import PolicyLifecycleState, PolicyRecord
from engine.request import SecurityRequest, create_fresh_request
from engine.raksha import EnforcementAction
from engine.runtime import evaluate_runtime_request
from engine.trust import EntityType, ReEvaluationTrigger, TrustEntity, TrustState


def make_runtime_request(request_id: str = "REQ-RT-POLICY") -> SecurityRequest:
    request = SecurityRequest(
        request_id=request_id,
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "tool.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\tool.exe"},
    )
    request.add_evidence(
        create_evidence(
            evidence_id=f"E-{request_id}",
            category="signature",
            source="test",
            value="signed",
            strength="high",
            verified=True,
        )
    )
    return request


def make_runtime_policy() -> PolicyRecord:
    return PolicyRecord(
        policy_id="P-RT-LIFECYCLE",
        name="Runtime lifecycle policy",
        version=3,
        provenance={"source": "runtime-test"},
        definition={
            "id": "P-RT-LIFECYCLE",
            "name": "Runtime lifecycle policy",
            "version": 3,
            "conditions": {"action": {"type": "execute"}},
            "effect": "permit",
        },
    )


def activate_runtime_policy() -> PolicyRecord:
    policy = make_runtime_policy()
    policy.validate({"validator": "test"})
    policy.verify({"verifier": "test"})
    policy.approve({"approver": "test"})
    policy.activate()
    return policy


def test_runtime_can_execute_a_complete_evaluation():
    policy = {
        "id": "P-RT-001",
        "name": "Unsigned executable",
        "evidence": {
            "signature": {
                "value": "unsigned",
                "verified": True,
            }
        },
        "effect": "deny",
    }

    request = SecurityRequest(
        request_id="REQ-RT-FULL",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "unknown.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\Users\operator\Downloads\unknown.exe"},
        context={"origin": "internet"},
    )
    request.add_evidence(
        create_evidence(
            evidence_id="E-RT-001",
            category="signature",
            source="mock",
            value="unsigned",
            strength="high",
            verified=True,
        )
    )

    entity = TrustEntity(
        entity_id="process:runtime-eval",
        entity_type=EntityType.PROCESS,
    )

    result = evaluate_runtime_request(
        request=request,
        entity=entity,
        policies=[policy],
        auto_apply_state=True,
    )

    assert result.request is request
    assert result.risk.level.value in {"low", "medium", "high", "critical"}
    assert result.policy_results[0].matched is True
    assert result.decision.effect == DecisionEffect.DENY
    assert result.explanation.request is request
    assert result.audit["evaluation_chain"]
    assert entity.state in {TrustState.QUARANTINED, TrustState.TRUSTED, TrustState.UNVERIFIED}


def test_runtime_uses_a_fresh_current_request_context():
    original = SecurityRequest(
        request_id="REQ-RT-ORIGINAL",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "safe.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\safe.exe"},
        context={"origin": "initial-evaluation"},
    )
    fresh = create_fresh_request(
        original,
        request_id="REQ-RT-RECHECK",
        context={"origin": "fresh-evaluation"},
    )

    result = evaluate_runtime_request(
        request=fresh,
        previous_request=original,
        policies=[],
    )

    assert result.request is fresh
    assert result.request.request_id == "REQ-RT-RECHECK"
    assert result.previous_request_id == original.request_id
    assert result.request.history_id == original.request_id


def test_policy_and_decision_remain_separate_in_runtime():
    policy = {
        "id": "P-RT-002",
        "name": "Unsigned file",
        "evidence": {
            "signature": {
                "value": "unsigned",
                "verified": True,
            }
        },
        "effect": "deny",
    }

    request = SecurityRequest(
        request_id="REQ-RT-SEPARATE",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "broken.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\broken.exe"},
        context={"origin": "internet"},
    )
    request.add_evidence(
        create_evidence(
            evidence_id="E-RT-002",
            category="signature",
            source="mock",
            value="unsigned",
            strength="high",
            verified=True,
        )
    )

    result = evaluate_runtime_request(request=request, policies=[policy])

    assert result.policy_results[0].matched is True
    assert result.decision.effect == DecisionEffect.DENY
    assert result.policy_results[0] is not result.decision
    assert result.policy_results[0].effect == "deny"


def test_trusted_promotion_still_requires_the_controlled_boundary():
    entity = TrustEntity(
        entity_id="process:runtime-promotion",
        entity_type=EntityType.PROCESS,
    )
    request = SecurityRequest(
        request_id="REQ-RT-TRUSTED",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "trusted.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\trusted.exe"},
        context={"origin": "validated"},
    )
    request.add_evidence(
        create_evidence(
            evidence_id="E-RT-TRUSTED-001",
            category="signature",
            source="mock",
            value="signed",
            strength="high",
            verified=True,
        )
    )

    with pytest.raises((TypeError, ValueError, PermissionError)):
        evaluate_runtime_request(
            request=request,
            entity=entity,
            policies=[{"id": "P-RT-ALLOW", "effect": "permit"}],
            decision="permit",
        )

    assert entity.state == TrustState.UNKNOWN
    assert entity.transition_history == []


def test_runtime_keeps_audit_explanation_chain_for_re_evaluation():
    original = SecurityRequest(
        request_id="REQ-RT-AUDIT-ORIG",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "safe.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\safe.exe"},
        context={"origin": "initial-evaluation"},
    )
    original.add_evidence(
        create_evidence(
            evidence_id="E-RT-AUDIT-001",
            category="signature",
            source="mock",
            value="signed",
            strength="high",
            verified=True,
        )
    )

    fresh = create_fresh_request(
        original,
        request_id="REQ-RT-AUDIT-RECHECK",
        context={"origin": "continuous-re-evaluation"},
    )
    fresh.add_evidence(
        create_evidence(
            evidence_id="E-RT-AUDIT-002",
            category="signature",
            source="mock",
            value="unsigned",
            strength="high",
            verified=True,
        )
    )

    trigger = ReEvaluationTrigger(
        trigger_id="TRIGGER-RT-AUDIT",
        entity_id="process:runtime-audit",
        trigger_type="evidence_update",
        source="mock",
        relevance_reason="Fresh contradictory evidence is present.",
    )

    result = evaluate_runtime_request(
        request=fresh,
        previous_request=original,
        policies=[{
            "id": "P-RT-AUDIT",
            "name": "Unsigned executable",
            "evidence": {"signature": {"value": "unsigned", "verified": True}},
            "effect": "deny",
        }],
        trigger=trigger,
    )

    assert result.previous_request_id == original.request_id
    assert "request" in result.audit["evaluation_chain"][0]
    assert "risk" in result.audit["evaluation_chain"][1]
    assert result.explanation.previous_request_id == original.request_id
    assert result.explanation.trigger_id == trigger.trigger_id


def test_runtime_keeps_continuous_re_evaluation_behavior_intact():
    original = SecurityRequest(
        request_id="REQ-RT-REVAL-ORIG",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "safe.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\safe.exe"},
        context={"origin": "initial-evaluation"},
    )
    original.add_evidence(
        create_evidence(
            evidence_id="E-RT-REVAL-OLD",
            category="signature",
            source="mock",
            value="signed",
            strength="high",
            verified=True,
        )
    )

    fresh = create_fresh_request(
        original,
        request_id="REQ-RT-REVAL-NEW",
        context={"origin": "re-evaluation"},
    )

    result = evaluate_runtime_request(
        request=fresh,
        previous_request=original,
        policies=[],
    )

    assert result.request.request_id == "REQ-RT-REVAL-NEW"
    assert result.request.history_id == original.request_id
    assert result.previous_request_id == original.request_id


def test_runtime_active_policy_reaches_raksha_with_policy_lineage():
    policy = activate_runtime_policy()
    result = evaluate_runtime_request(
        request=make_runtime_request(),
        policy_records=[policy],
        enforce=True,
    )

    assert result.enforcement.action is EnforcementAction.ALLOW
    assert result.enforcement.policy_context[policy.policy_id]["version"] == 3
    assert result.enforcement.policy_context[policy.policy_id]["integrity_digest"] == policy.integrity_digest
    assert result.enforcement.request_id == result.request.request_id
    assert result.enforcement.evidence_ids == (f"E-{result.request.request_id}",)
    assert result.enforcement.decision_id == result.decision.decision_id
    assert result.audit["enforcement_record"] is result.enforcement


@pytest.mark.parametrize(
    "state_builder",
    [
        lambda policy: None,
        lambda policy: policy.validate({"validator": "test"}),
        lambda policy: (
            policy.validate({"validator": "test"}),
            policy.verify({"verifier": "test"}),
            policy.approve({"approver": "test"}),
        ),
    ],
    ids=["draft", "validated", "approved-not-active"],
)
def test_runtime_non_active_policy_fails_conservatively(state_builder):
    policy = make_runtime_policy()
    state_builder(policy)

    result = evaluate_runtime_request(
        request=make_runtime_request(),
        policy_records=[policy],
        enforce=True,
    )

    assert result.enforcement.action is EnforcementAction.REQUIRE_VERIFICATION
    assert policy.lifecycle_state is not PolicyLifecycleState.ACTIVE


def test_runtime_modified_policy_and_old_approval_fail_closed():
    policy = activate_runtime_policy()
    policy.definition["effect"] = "deny"

    result = evaluate_runtime_request(
        request=make_runtime_request(),
        policy_records=[policy],
        enforce=True,
    )

    assert result.enforcement.action is EnforcementAction.REQUIRE_VERIFICATION
    assert policy.integrity_valid is False
    assert policy.lifecycle_state is not PolicyLifecycleState.ACTIVE


def test_runtime_raw_policy_cannot_bypass_lifecycle():
    result = evaluate_runtime_request(
        request=make_runtime_request(),
        policies=[{
            "id": "P-RT-LIFECYCLE",
            "name": "Raw policy",
            "effect": "permit",
            "conditions": {"action": {"type": "execute"}},
        }],
        enforce=True,
    )

    assert result.policy_results[0].matched is True
    assert result.enforcement.action is EnforcementAction.REQUIRE_VERIFICATION


def test_runtime_enforcement_does_not_modify_trust_state_and_preserves_chain():
    policy = activate_runtime_policy()
    entity = TrustEntity(
        entity_id="process:runtime-lineage",
        entity_type=EntityType.PROCESS,
        state=TrustState.UNVERIFIED,
    )
    before = (entity.state, tuple(entity.transition_history))

    result = evaluate_runtime_request(
        request=make_runtime_request("REQ-RT-LINEAGE"),
        policy_records=[policy],
        entity=entity,
        auto_apply_state=False,
        enforce=True,
    )

    assert (entity.state, tuple(entity.transition_history)) == before
    assert [stage["stage"] for stage in result.audit["evaluation_chain"]] == [
        "request", "risk", "evidence", "policy", "decision", "enforcement",
    ]
    assert result.enforcement.policy_ids == (policy.policy_id,)
