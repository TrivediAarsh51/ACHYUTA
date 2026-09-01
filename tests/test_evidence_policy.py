"""
ACHYUTA - Pramana -> Request -> Niyama Integration

Tests the first evidence-driven policy evaluation pipeline.
"""

from engine.decision import Decision, DecisionEffect, resolve_current_decision
from engine.evidence import create_evidence
from engine.policy import evaluate_policy, load_policy
from engine.request import SecurityRequest, create_fresh_request
from engine.trust import (
    EntityType,
    ReEvaluationTrigger,
    TrustEntity,
    TrustState,
    build_trust_explanation,
)


def test_verified_unsigned_evidence_causes_policy_match():

    # ---------------------------------------------------------------
    # Pramana
    # ---------------------------------------------------------------

    evidence = create_evidence(
        evidence_id="E-001",
        category="signature",
        source="mock",
        value="unsigned",
        strength="high",
        verified=True,
    )

    # ---------------------------------------------------------------
    # Request
    # ---------------------------------------------------------------

    request = SecurityRequest(
        request_id="REQ-002",

        identity={
            "type": "local_user",
            "name": "test-user",
        },

        subject={
            "type": "executable",
            "name": "unknown.exe",
        },

        action={
            "type": "execute",
        },

        resource={
            "type": "executable",
            "path": r"C:\Users\test\Downloads\unknown.exe",
        },

        context={
            "origin": "internet",
        },
    )

    request.add_evidence(evidence)

    # ---------------------------------------------------------------
    # Niyama
    # ---------------------------------------------------------------

    policy = load_policy(
        "lab/scenarios/evidence_based_execution.yaml"
    )

    result = evaluate_policy(
        policy,
        request,
    )

    # ---------------------------------------------------------------
    # Assertions
    # ---------------------------------------------------------------

    assert result.matched is True
    assert result.effect == "deny"
    assert result.policy_id == "P-004"

    assert any(
        "E-001" in reason
        for reason in result.reason
    )

def test_unverified_evidence_does_not_match():

    evidence = create_evidence(
        evidence_id="E-002",
        category="signature",
        source="mock",
        value="unsigned",
        strength="high",
        verified=False,
    )

    request = SecurityRequest(
        request_id="REQ-003",

        identity={
            "type": "local_user",
            "name": "test-user",
        },

        subject={
            "type": "executable",
            "name": "unknown.exe",
        },

        action={
            "type": "execute",
        },

        resource={
            "type": "executable",
            "path": r"C:\Users\test\Downloads\unknown.exe",
        },

        context={
            "origin": "internet",
        },
    )

    request.add_evidence(evidence)

    policy = load_policy(
        "lab/scenarios/evidence_based_execution.yaml"
    )

    result = evaluate_policy(
        policy,
        request,
    )

    assert result.matched is False
    assert result.effect is None


def test_re_evaluation_explainability_keeps_previous_state_trigger_request_evidence_policy_decision_and_new_state():

    entity = TrustEntity(
        entity_id="process:explainability",
        entity_type=EntityType.PROCESS,
    )
    entity.promote_to_trusted(
        reason="Initial trust established.",
        decision=Decision(
            effect=DecisionEffect.PERMIT,
            matched_policy_ids=("P-TRACE-INIT",),
            reason="Initial trust established.",
            decision_id="DEC-TRACE-INIT",
        ),
        evidence_ids=("E-TRACE-000",),
    )

    original = SecurityRequest(
        request_id="REQ-TRACE-ORIGINAL",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "trusted.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\trusted.exe"},
        context={"origin": "initial-evaluation"},
    )
    original.add_evidence(
        create_evidence(
            evidence_id="E-TRACE-001",
            category="signature",
            source="mock",
            value="signed",
            strength="high",
            verified=True,
        )
    )

    refreshed = create_fresh_request(
        original,
        request_id="REQ-TRACE-RECHECK",
        context={"origin": "continuous-re-evaluation"},
    )
    refreshed.add_evidence(
        create_evidence(
            evidence_id="E-TRACE-001",
            category="signature",
            source="mock",
            value="unsigned",
            strength="high",
            verified=True,
        )
    )

    trigger = ReEvaluationTrigger(
        trigger_id="TRIGGER-TRACE-001",
        entity_id="process:explainability",
        trigger_type="evidence_update",
        source="mock",
        relevance_reason="Contradictory evidence was introduced.",
    )

    policy = {
        "id": "P-TRACE-001",
        "name": "Unsigned executable evidence",
        "evidence": {
            "signature": {
                "value": "unsigned",
                "verified": True,
            }
        },
        "effect": "deny",
    }
    policy_result = evaluate_policy(policy, refreshed)
    decision = resolve_current_decision([policy_result])
    transition = entity.transition(
        TrustState.QUARANTINED,
        "Fresh evidence contradicts the previously trusted state.",
        evidence_ids=("E-TRACE-001",),
    )

    explanation = build_trust_explanation(
        request=refreshed,
        policy_results=(policy_result,),
        decision=decision,
        trust_state=TrustState.QUARANTINED,
        transition=transition,
        previous_state=TrustState.TRUSTED,
        trigger=trigger,
        previous_request_id=original.request_id,
        decision_id=decision.decision_id,
        policy_summary="signature policy -> deny",
        transition_reason="Fresh evidence contradicts the previously trusted state.",
    )

    assert explanation.request.request_id == refreshed.request_id
    assert explanation.decision.effect.value == "deny"
    assert explanation.trust_state == TrustState.QUARANTINED
    assert explanation.previous_state == TrustState.TRUSTED
    assert explanation.trigger_id == trigger.trigger_id
    assert explanation.request.history_id == original.request_id