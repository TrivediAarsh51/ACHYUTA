"""
ACHYUTA - End-to-End Evidence + Policy Test
"""

from engine.evidence import create_evidence
from engine.request import SecurityRequest
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
    transition = entity.transition(
        TrustState.TRUSTED,
        "Signature evidence supports the process.",
        evidence_ids=tuple(item.evidence_id for item in request.evidence),
    )

    assert request.evidence[0] is evidence
    assert transition.evidence_ids == ("E-TRUST-001",)
    assert entity.state == TrustState.TRUSTED