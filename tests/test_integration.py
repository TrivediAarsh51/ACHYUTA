"""
ACHYUTA - End-to-End Evidence + Policy Test
"""

from engine.decision import Decision, DecisionEffect
from engine.evidence import create_evidence
from engine.request import SecurityRequest, create_fresh_request, requires_re_evaluation
from engine.policy import evaluate_policy
from engine.trust import EntityType, TrustEntity, TrustState


def test_unsigned_execution_is_denied_using_evidence():

    evidence = create_evidence(
        evidence_id="E-001",
        category="signature",
        source="mock",
        value="unsigned",
        strength="high",
        verified=True,
    )

    request = SecurityRequest(

        request_id="REQ-001",

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

    # The evidence is attached to the request.
    assert len(request.evidence) == 1

    assert request.evidence[0].value == "unsigned"


def test_request_evidence_identifier_can_be_recorded_by_trust_layer():

    evidence = create_evidence(
        evidence_id="E-TRUST-001",
        category="signature",
        source="mock",
        value="signed",
    )

    request = SecurityRequest(
        request_id="REQ-TRUST-001",
        identity={"type": "local_user", "name": "test-user"},
        subject={"type": "executable", "name": "trusted.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\trusted.exe"},
    )
    request.add_evidence(evidence)

    entity = TrustEntity(
        entity_id="process:trusted",
        entity_type=EntityType.PROCESS,
    )
    transition = entity.promote_to_trusted(
        reason="Signature evidence supports the process.",
        decision=Decision(
            effect=DecisionEffect.PERMIT,
            matched_policy_ids=("POL-TRUSTED-REQ",),
            reason="Signature evidence supports the process.",
            decision_id="DEC-TRUSTED-REQ",
        ),
        evidence_ids=tuple(item.evidence_id for item in request.evidence),
    )

    assert request.evidence[0] is evidence
    assert transition.evidence_ids == ("E-TRUST-001",)
    assert entity.state == TrustState.TRUSTED


def test_re_evaluation_for_fresh_request_uses_distinct_request_context():

    original = SecurityRequest(
        request_id="REQ-ORIGINAL-INT",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "safe.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\safe.exe"},
    )
    original.add_evidence(
        create_evidence(
            evidence_id="E-INT-001",
            category="signature",
            source="mock",
            value="signed",
            strength="high",
            verified=True,
        )
    )

    refreshed = create_fresh_request(
        original,
        request_id="REQ-RECHECK-INT",
        context={"origin": "re-evaluation"},
    )

    assert refreshed.request_id != original.request_id
    assert refreshed.history_id == original.request_id
    assert refreshed.context["origin"] == "re-evaluation"


def test_re_evaluation_request_keeps_explicit_previous_request_lineage():

    original = SecurityRequest(
        request_id="REQ-ORIGINAL-ISO",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "safe.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\safe.exe"},
        context={"origin": "initial-evaluation"},
    )
    original.add_evidence(
        create_evidence(
            evidence_id="E-ISO-001",
            category="signature",
            source="mock",
            value="signed",
            strength="high",
            verified=True,
        )
    )

    refreshed = create_fresh_request(
        original,
        request_id="REQ-RECHECK-ISO",
        context={"origin": "continuous-re-evaluation"},
    )

    assert refreshed is not original
    assert refreshed.request_id != original.request_id
    assert refreshed.history_id == original.request_id
    assert refreshed.context is not original.context
    assert refreshed.context["previous_request_id"] == original.request_id
    assert refreshed.context["request_history"] == [original.request_id]
    assert original.context.get("previous_request_id") is None
    assert original.context.get("request_history") is None


def test_irrelevant_signal_does_not_trigger_trust_transition():

    original = SecurityRequest(
        request_id="REQ-ORIGINAL-IRRELEVANT",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "safe.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\safe.exe"},
        context={"origin": "initial-evaluation"},
    )
    original.add_evidence(
        create_evidence(
            evidence_id="E-IRR-001",
            category="signature",
            source="mock",
            value="signed",
            strength="high",
            verified=True,
        )
    )

    refreshed = create_fresh_request(
        original,
        request_id="REQ-IRRELEVANT-RECHECK",
        context={"origin": "user-activity-log", "event_type": "mouse-move"},
    )

    assert refreshed.history_id == original.request_id
    assert requires_re_evaluation(refreshed, original) is False
    assert refreshed.context["event_type"] == "mouse-move"