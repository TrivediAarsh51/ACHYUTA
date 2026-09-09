"""Adversarial regression tests for the Feature 003 security boundary."""

import pytest

from engine.decision import Decision, DecisionEffect
from engine.evidence import create_evidence
from engine.policy import PolicyLifecycleState, PolicyRecord
from engine.raksha import EnforcementAction, RakshaEnforcer
from engine.request import SecurityRequest
from engine.risk import RiskAssessment, RiskLevel
from engine.runtime import evaluate_runtime_request
from engine.trust import EntityType, TrustEntity, TrustState


def make_request(request_id: str = "REQ-B6") -> SecurityRequest:
    request = SecurityRequest(
        request_id=request_id,
        identity={"name": "operator"},
        subject={"name": "tool.exe"},
        action={"type": "execute"},
        resource={"path": r"C:\tool.exe"},
    )
    request.add_evidence(
        create_evidence(
            evidence_id=f"E-{request_id}",
            category="signature",
            source="test",
            value="signed",
            strength="low",
            verified=True,
        )
    )
    return request


def make_policy(policy_id: str = "POL-B6", effect: str = "permit") -> PolicyRecord:
    return PolicyRecord(
        policy_id=policy_id,
        name="Batch 6 policy",
        version=1,
        provenance={"source": "test"},
        definition={
            "id": policy_id,
            "name": "Batch 6 policy",
            "version": 1,
            "conditions": {"action": {"type": "execute"}},
            "effect": effect,
        },
    )


def activate(policy: PolicyRecord) -> PolicyRecord:
    policy.validate({"validator": "test"})
    policy.verify({"verifier": "test"})
    policy.approve({"approver": "test"})
    policy.activate()
    return policy


def make_decision(
    policy_id: str = "POL-B6",
    effect: DecisionEffect = DecisionEffect.PERMIT,
) -> Decision:
    return Decision(
        effect=effect,
        matched_policy_ids=(policy_id,),
        reason="Validated decision for the request.",
        decision_id="DEC-B6",
    )


def enforce(
    *,
    request: SecurityRequest | None = None,
    decision: Decision | str | None = None,
    policy_records=None,
    policy_context=None,
    risk=None,
    trust_entity=None,
):
    return RakshaEnforcer().enforce(
        request or make_request(),
        decision or make_decision(),
        policy_records=policy_records,
        policy_context=policy_context,
        risk=risk,
        trust_entity=trust_entity,
    )


def test_raw_active_policy_state_cannot_authorize_enforcement():
    result = enforce(
        policy_context={"POL-B6": {"state": "ACTIVE", "approved": True}},
    )

    assert result.action is not EnforcementAction.ALLOW


def test_caller_policy_context_cannot_bypass_record_lifecycle():
    policy = make_policy()

    result = enforce(
        policy_records=[policy],
        policy_context={"POL-B6": {"state": "active", "approved": True}},
    )

    assert result.action is EnforcementAction.REQUIRE_VERIFICATION


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
def test_incomplete_policy_lifecycle_cannot_produce_allow(state_builder):
    policy = make_policy()
    state_builder(policy)

    result = enforce(policy_records=[policy])

    assert result.action is EnforcementAction.REQUIRE_VERIFICATION
    assert result.reason


def test_modified_policy_and_old_approval_cannot_produce_allow():
    policy = activate(make_policy())
    policy.definition["effect"] = "deny"

    result = enforce(policy_records=[policy])

    assert result.action is EnforcementAction.REQUIRE_VERIFICATION
    assert policy.lifecycle_state is not PolicyLifecycleState.ACTIVE


def test_old_decision_cannot_authorize_a_new_policy_version():
    policy = activate(make_policy())
    policy.version = 2

    result = enforce(policy_records=[policy])

    assert result.action is not EnforcementAction.ALLOW


def test_fake_decision_values_cannot_authorize_allow():
    with pytest.raises(TypeError):
        enforce(decision="PERMIT")


def test_decision_policy_mismatch_cannot_authorize_allow():
    policy = activate(make_policy("POL-B"))

    result = enforce(
        decision=make_decision("POL-A"),
        policy_records=[policy],
    )

    assert result.action is not EnforcementAction.ALLOW


def test_permit_without_evidence_cannot_authorize_allow():
    request = make_request()
    request.evidence.clear()

    result = enforce(request=request, policy_records=[activate(make_policy())])

    assert result.action is EnforcementAction.REQUIRE_VERIFICATION
    assert result.reason


@pytest.mark.parametrize(
    "risk",
    [
        RiskAssessment(80, RiskLevel.HIGH, ("high risk",), ("E-REQ-B6",)),
        RiskAssessment(1, RiskLevel.LOW, ("contradiction",), ("E-REQ-B6",), True),
        RiskAssessment(1, RiskLevel.LOW, (), ("E-FORGED",)),
    ],
    ids=["high-risk", "contradictory", "foreign-evidence"],
)
def test_unsafe_or_unrelated_risk_cannot_authorize_allow(risk):
    result = enforce(policy_records=[activate(make_policy())], risk=risk)

    assert result.action is not EnforcementAction.ALLOW
    assert result.reason


def test_trusted_state_alone_cannot_authorize_raksha():
    entity = TrustEntity("process:b6", EntityType.PROCESS)
    entity.promote_to_trusted(
        reason="Controlled test promotion.",
        decision=make_decision(),
        evidence_ids=("E-TRUSTED",),
    )

    result = enforce(trust_entity=entity)

    assert result.action is not EnforcementAction.ALLOW


def test_trust_state_mutation_and_direct_trusted_transition_are_blocked():
    entity = TrustEntity("process:b6-mutation", EntityType.PROCESS)

    with pytest.raises((AttributeError, TypeError, ValueError)):
        entity.state = TrustState.TRUSTED
    with pytest.raises(ValueError):
        entity.transition(TrustState.TRUSTED, "forged", evidence_ids=("E",))


def test_enforcement_and_nested_audit_metadata_are_immutable_and_append_only():
    enforcer = RakshaEnforcer()
    record = enforcer.enforce(
        make_request(),
        make_decision(),
        policy_records=[activate(make_policy())],
        policy_context={
            "POL-B6": {
                "nested": {"approved": True},
                "evidence": {"source": {"trusted": True}},
            }
        },
    )

    with pytest.raises(TypeError):
        record.policy_context["POL-B6"]["nested"]["approved"] = False
    with pytest.raises(TypeError):
        record.policy_context["POL-B6"]["evidence"]["source"]["trusted"] = False
    with pytest.raises(TypeError):
        record.decision_context["effect"] = "deny"
    with pytest.raises(AttributeError):
        enforcer.history.append(record)
    with pytest.raises(AttributeError):
        record.action = EnforcementAction.DENY


def test_enforcement_does_not_mutate_trust_and_history_is_append_only():
    entity = TrustEntity("process:b6-history", EntityType.PROCESS)
    entity.transition(TrustState.UNVERIFIED, "Verification is pending.")
    before = (entity.state, tuple(entity.transition_history))

    enforce(
        policy_records=[activate(make_policy())],
        trust_entity=entity,
    )

    assert (entity.state, tuple(entity.transition_history)) == before
    with pytest.raises(AttributeError):
        entity.transition_history.clear()
    with pytest.raises(AttributeError):
        entity.re_evaluation_history.append("forged")


def test_complete_lineage_and_conservative_reason_are_reconstructable():
    policy = activate(make_policy())
    request = make_request("REQ-B6-LINEAGE")
    result = evaluate_runtime_request(
        request=request,
        policy_records=[policy],
        enforce=True,
    )

    stages = [item["stage"] for item in result.audit["evaluation_chain"]]
    assert stages == ["request", "risk", "evidence", "policy", "decision", "enforcement"]
    assert result.enforcement.action is EnforcementAction.ALLOW
    assert result.enforcement.reason
    assert result.enforcement.request_id == request.request_id
    assert result.enforcement.decision_id == result.decision.decision_id
    assert result.enforcement.policy_ids == (policy.policy_id,)
    assert result.enforcement.evidence_ids == tuple(item.evidence_id for item in request.evidence)
