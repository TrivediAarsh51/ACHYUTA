"""Tests for ACHYUTA risk assessment."""

from engine.evidence import create_evidence
from engine.request import SecurityRequest, create_fresh_request
from engine.risk import RiskLevel, assess_risk
from engine.trust import EntityType, TrustEntity


def test_risk_calculation_is_deterministic_and_explainable():
    request = SecurityRequest(
        request_id="REQ-RISK-001",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "unknown.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\Users\operator\Downloads\unknown.exe"},
        context={"origin": "internet"},
    )
    request.add_evidence(
        create_evidence(
            evidence_id="E-RISK-001",
            category="signature",
            source="mock",
            value="unsigned",
            strength="high",
            verified=True,
        )
    )

    assessment = assess_risk(request)

    assert assessment.score == assess_risk(request).score
    assert assessment.level in {RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert assessment.evidence_ids == ("E-RISK-001",)
    assert assessment.reasons
    assert assessment.summary


def test_risk_levels_and_contradictory_high_risk_evidence():
    original = SecurityRequest(
        request_id="REQ-RISK-ORIGINAL",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "trusted.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\trusted.exe"},
        context={"origin": "initial-evaluation"},
    )
    original.add_evidence(
        create_evidence(
            evidence_id="E-RISK-CONTRADICTION",
            category="signature",
            source="mock",
            value="signed",
            strength="high",
            verified=True,
        )
    )

    contradictory = create_fresh_request(
        original,
        request_id="REQ-RISK-RECHECK",
        context={"origin": "internet"},
    )
    contradictory.add_evidence(
        create_evidence(
            evidence_id="E-RISK-CONTRADICTION",
            category="signature",
            source="mock",
            value="unsigned",
            strength="high",
            verified=True,
        )
    )

    assessment = assess_risk(contradictory, previous_request=original)

    assert assessment.contradictory is True
    assert assessment.level in {RiskLevel.HIGH, RiskLevel.CRITICAL}


def test_risk_engine_does_not_mutate_trust():
    entity = TrustEntity(
        entity_id="process:risk-check",
        entity_type=EntityType.PROCESS,
    )

    request = SecurityRequest(
        request_id="REQ-RISK-TRUST",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "suspicious.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\Users\operator\Downloads\suspicious.exe"},
        context={"origin": "internet"},
    )
    request.add_evidence(
        create_evidence(
            evidence_id="E-RISK-TRUST-001",
            category="signature",
            source="mock",
            value="unsigned",
            strength="high",
            verified=True,
        )
    )

    before = entity.state
    assess_risk(request, trust_entity=entity)

    assert entity.state == before
    assert entity.transition_history == []
