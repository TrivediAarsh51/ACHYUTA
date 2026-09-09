"""Regression tests for the abstract Raksha enforcement boundary."""

from datetime import timezone

import pytest

from engine.decision import Decision, DecisionEffect
from engine.evidence import create_evidence
from engine.policy import PolicyLifecycleState, PolicyRecord
from engine.raksha import EnforcementAction, RakshaEnforcer
from engine.request import SecurityRequest
from engine.risk import RiskAssessment, RiskLevel
from engine.trust import EntityType, TrustEntity, TrustState


def make_request() -> SecurityRequest:
    request = SecurityRequest(
        request_id="REQ-RAKSHA-001",
        identity={"name": "operator"},
        subject={"name": "tool.exe"},
        action={"type": "execute"},
        resource={"path": r"C:\tool.exe"},
    )
    request.add_evidence(
        create_evidence(
            evidence_id="E-RAKSHA-001",
            category="signature",
            source="test",
            value="signed",
            strength="high",
            verified=True,
        )
    )
    return request


def make_decision(effect: DecisionEffect = DecisionEffect.PERMIT) -> Decision:
    return Decision(
        effect=effect,
        matched_policy_ids=("POL-001",),
        reason="Policy evaluation completed.",
        decision_id="DEC-001",
    )


def make_policy() -> PolicyRecord:
    return PolicyRecord(
        policy_id="POL-001",
        name="Raksha policy",
        version=1,
        provenance={"source": "test"},
        definition={"effect": "permit"},
    )


def make_active_policy() -> PolicyRecord:
    policy = make_policy()
    policy.validate({"validator": "test"})
    policy.verify({"verifier": "test"})
    policy.approve({"approver": "test"})
    policy.activate()
    return policy


def enforce_with_active_policy(
    enforcer: RakshaEnforcer | None = None,
    *,
    decision: Decision | None = None,
    request: SecurityRequest | None = None,
    **kwargs,
):
    return (enforcer or RakshaEnforcer()).enforce(
        request or make_request(),
        decision or make_decision(),
        policy_records=[make_active_policy()],
        **kwargs,
    )


def test_permit_maps_to_allow_only_with_valid_context():
    result = RakshaEnforcer().enforce(
        make_request(),
        make_decision(),
        policy_records=[make_active_policy()],
        policy_context={"POL-001": {"version": 1, "state": "active"}},
    )

    assert result.action is EnforcementAction.ALLOW


def test_deny_maps_to_deny():
    result = enforce_with_active_policy(decision=make_decision(DecisionEffect.DENY))

    assert result.action is EnforcementAction.DENY


def test_high_risk_decision_maps_to_restrictive_action():
    risk = RiskAssessment(
        score=80,
        level=RiskLevel.HIGH,
        reasons=("High-risk request.",),
        evidence_ids=("E-RAKSHA-001",),
    )

    result = enforce_with_active_policy(risk=risk)

    assert result.action in {
        EnforcementAction.RESTRICT,
        EnforcementAction.QUARANTINE,
        EnforcementAction.REQUIRE_VERIFICATION,
        EnforcementAction.DENY,
    }
    assert result.action is not EnforcementAction.ALLOW


def test_contradictory_or_incomplete_evidence_uses_conservative_fallback():
    request = make_request()
    request.evidence.clear()

    incomplete_result = enforce_with_active_policy(request=request)

    assert incomplete_result.action is EnforcementAction.REQUIRE_VERIFICATION

    risk = RiskAssessment(
        score=0,
        level=RiskLevel.LOW,
        reasons=(),
        evidence_ids=(),
        contradictory=True,
    )

    result = enforce_with_active_policy(request=request, risk=risk)

    assert result.action is EnforcementAction.REQUIRE_VERIFICATION
    assert "fallback" in result.reason.lower()


def test_raw_permit_cannot_authorize_allow():
    with pytest.raises(TypeError):
        RakshaEnforcer().enforce(make_request(), "permit")


def test_enforcement_result_preserves_request_decision_policy_and_evidence_lineage():
    result = RakshaEnforcer().enforce(
        make_request(),
        make_decision(),
        policy_records=[make_active_policy()],
        policy_context={"POL-001": {"version": 1, "state": "active"}},
    )

    assert result.request_id == "REQ-RAKSHA-001"
    assert result.decision_id == "DEC-001"
    assert result.policy_ids == ("POL-001",)
    assert result.policy_context["POL-001"]["state"] == "active"
    assert result.evidence_ids == ("E-RAKSHA-001",)
    assert result.action is EnforcementAction.ALLOW
    assert result.previous_state is None
    assert result.resulting_state is EnforcementAction.ALLOW
    assert result.decision_context == {
        "decision_id": "DEC-001",
        "effect": "permit",
        "matched_policy_ids": ("POL-001",),
        "reason": "Policy evaluation completed.",
    }
    assert result.reason
    assert result.timestamp.tzinfo == timezone.utc


def test_enforcement_record_context_and_state_are_immutable():
    enforcer = RakshaEnforcer()
    first = enforcer.enforce(
        make_request(),
        make_decision(),
        policy_records=[make_active_policy()],
        policy_context={"POL-001": {"version": 1, "state": "active"}},
    )
    second = enforcer.enforce(
        make_request(),
        make_decision(DecisionEffect.DENY),
        policy_records=[make_active_policy()],
        policy_context={"POL-001": {"version": 1, "state": "active"}},
    )

    assert second.previous_state is first.resulting_state
    assert second.resulting_state is EnforcementAction.DENY
    with pytest.raises(TypeError):
        first.policy_context["POL-001"]["state"] = "tampered"
    with pytest.raises(TypeError):
        first.decision_context["effect"] = "deny"


def test_enforcement_does_not_mutate_trust_entity():
    entity = TrustEntity(
        entity_id="process:raksha",
        entity_type=EntityType.PROCESS,
        state=TrustState.UNVERIFIED,
    )
    before = (entity.state, entity.reason, tuple(entity.transition_history))

    enforce_with_active_policy(trust_entity=entity)

    assert (entity.state, entity.reason, tuple(entity.transition_history)) == before


def test_enforcement_history_is_append_only_and_records_are_immutable():
    enforcer = RakshaEnforcer()
    first = enforce_with_active_policy(enforcer)
    history = enforcer.history

    assert history == (first,)
    with pytest.raises((AttributeError, TypeError)):
        first.action = EnforcementAction.DENY
    with pytest.raises(AttributeError):
        history.append(first)


def test_draft_policy_cannot_enforce():
    result = RakshaEnforcer().enforce(
        make_request(), make_decision(), policy_records=[make_policy()]
    )

    assert result.action is EnforcementAction.REQUIRE_VERIFICATION
    assert "lifecycle" in result.reason.lower()


def test_validated_but_unapproved_policy_cannot_enforce():
    policy = make_policy()
    policy.validate({"validator": "test"})

    result = RakshaEnforcer().enforce(
        make_request(), make_decision(), policy_records=[policy]
    )

    assert result.action is EnforcementAction.REQUIRE_VERIFICATION


def test_approved_but_not_active_policy_cannot_enforce():
    policy = make_policy()
    policy.validate({"validator": "test"})
    policy.verify({"verifier": "test"})
    policy.approve({"approver": "test"})

    assert policy.lifecycle_state is PolicyLifecycleState.APPROVED
    result = RakshaEnforcer().enforce(
        make_request(), make_decision(), policy_records=[policy]
    )

    assert result.action is EnforcementAction.REQUIRE_VERIFICATION


def test_active_policy_can_enforce_when_integrity_is_valid():
    result = enforce_with_active_policy()

    assert result.action is EnforcementAction.ALLOW


def test_modification_invalidates_active_policy():
    policy = make_active_policy()
    policy.definition["effect"] = "deny"

    result = RakshaEnforcer().enforce(
        make_request(), make_decision(), policy_records=[policy]
    )

    assert result.action is EnforcementAction.REQUIRE_VERIFICATION
    assert policy.integrity_valid is False


def test_invalidated_policy_cannot_enforce():
    policy = make_active_policy()
    policy.definition["effect"] = "deny"
    assert policy.integrity_valid is False

    result = RakshaEnforcer().enforce(
        make_request(), make_decision(), policy_records=[policy]
    )

    assert result.action is EnforcementAction.REQUIRE_VERIFICATION


def test_trusted_storage_path_cannot_activate_policy():
    policy = make_policy()
    policy.provenance["path"] = r"C:\ProgramData\ACHYUTA\policies"

    result = RakshaEnforcer().enforce(
        make_request(), make_decision(), policy_records=[policy]
    )

    assert result.action is EnforcementAction.REQUIRE_VERIFICATION


def test_policy_context_cannot_bypass_policy_record_lifecycle():
    result = RakshaEnforcer().enforce(
        make_request(),
        make_decision(),
        policy_context={"POL-001": {"version": 1, "state": "active"}},
    )

    assert result.action is EnforcementAction.REQUIRE_VERIFICATION


def test_lifecycle_failure_audit_identifies_policy_version_and_state():
    policy = make_policy()
    result = RakshaEnforcer().enforce(
        make_request(), make_decision(), policy_records=[policy]
    )

    assert result.action is EnforcementAction.REQUIRE_VERIFICATION
    assert result.policy_context["POL-001"]["version"] == 1
    assert result.policy_context["POL-001"]["lifecycle_state"] == "draft"
