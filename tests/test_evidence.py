"""
Tests for ACHYUTA Pramana Evidence Engine v0.1
"""

import pytest

from engine.evidence import (
    Evidence,
    create_evidence,
    validate_evidence,
    filter_verified_evidence,
    filter_by_category,
)


def test_create_valid_evidence():

    evidence = create_evidence(
        evidence_id="E-001",
        category="signature",
        source="mock",
        value="unsigned",
        strength="high",
        verified=True,
    )

    assert evidence.evidence_id == "E-001"
    assert evidence.category == "signature"
    assert evidence.value == "unsigned"
    assert evidence.strength == "high"
    assert evidence.verified is True


def test_invalid_strength_is_rejected():

    evidence = Evidence(
        evidence_id="E-002",
        category="signature",
        source="mock",
        value="unsigned",
        strength="invalid",
    )

    with pytest.raises(ValueError):
        validate_evidence(evidence)


def test_verified_evidence_filter():

    verified = create_evidence(
        evidence_id="E-003",
        category="signature",
        source="mock",
        value="valid",
        strength="high",
        verified=True,
    )

    unverified = create_evidence(
        evidence_id="E-004",
        category="signature",
        source="mock",
        value="unknown",
        strength="low",
        verified=False,
    )

    result = filter_verified_evidence(
        [verified, unverified]
    )

    assert len(result) == 1
    assert result[0].evidence_id == "E-003"


def test_filter_by_category():

    signature = create_evidence(
        evidence_id="E-005",
        category="signature",
        source="mock",
        value="unsigned",
    )

    hash_evidence = create_evidence(
        evidence_id="E-006",
        category="hash",
        source="mock",
        value="abc123",
    )

    result = filter_by_category(
        [signature, hash_evidence],
        "signature",
    )

    assert len(result) == 1
    assert result[0].category == "signature"