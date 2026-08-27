"""
ACHYUTA - Pramana -> Request -> Niyama Integration

Tests the first evidence-driven policy evaluation pipeline.
"""

from engine.evidence import create_evidence
from engine.policy import evaluate_policy, load_policy
from engine.request import SecurityRequest


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