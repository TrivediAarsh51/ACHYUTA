"""
Tests for ACHYUTA Viveka Decision Engine v0.1.
"""

from engine.decision import (
    DecisionEffect,
    resolve_decision,
)
from engine.policy import PolicyResult


def test_deny_beats_permit():

    results = [

        PolicyResult(
            policy_id="P-001",
            policy_name="Allow Trusted Executable",
            matched=True,
            effect="permit",
            reason=["Trusted executable"],
        ),

        PolicyResult(
            policy_id="P-002",
            policy_name="Deny Unsigned Executable",
            matched=True,
            effect="deny",
            reason=["Unsigned executable"],
        ),
    ]

    decision = resolve_decision(results)

    assert decision.effect == DecisionEffect.DENY

    assert "P-002" in decision.matched_policy_ids


def test_quarantine_beats_permit():

    results = [

        PolicyResult(
            policy_id="P-001",
            policy_name="Allow",
            matched=True,
            effect="permit",
            reason=["Normal request"],
        ),

        PolicyResult(
            policy_id="P-003",
            policy_name="Quarantine Suspicious Request",
            matched=True,
            effect="quarantine",
            reason=["Suspicious context"],
        ),
    ]

    decision = resolve_decision(results)

    assert decision.effect == DecisionEffect.QUARANTINE


def test_unmatched_policies_are_ignored():

    results = [

        PolicyResult(
            policy_id="P-001",
            policy_name="Permit",
            matched=False,
            effect=None,
            reason=["Policy did not match"],
        ),

        PolicyResult(
            policy_id="P-002",
            policy_name="Deny",
            matched=True,
            effect="deny",
            reason=["Malicious evidence"],
        ),
    ]

    decision = resolve_decision(results)

    assert decision.effect == DecisionEffect.DENY


def test_no_matching_policy_requires_verification():

    results = [

        PolicyResult(
            policy_id="P-001",
            policy_name="Deny Unsigned",
            matched=False,
            effect=None,
            reason=["No unsigned evidence"],
        ),
    ]

    decision = resolve_decision(results)

    assert decision.effect == DecisionEffect.REQUIRE_VERIFICATION

    assert decision.matched_policy_ids == ()