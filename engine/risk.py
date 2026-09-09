"""ACHYUTA - Risk Engine v0.1

This module performs a minimal, deterministic risk assessment for a request
using validated evidence and the current evaluation context.

Architectural boundaries:
- It does not mutate TrustState.
- It does not issue a final authorization decision.
- It is separate from Pramana, Niyama, Viveka, and Trust State.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from engine.evidence import normalize_evidence_item, validate_evidence
from engine.request import SecurityRequest
from engine.trust import TrustEntity


class RiskLevel(str, Enum):
    """Small, explicit risk model for the prototype."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class RiskAssessment:
    """Structured, auditable risk assessment suitable for review."""

    score: int
    level: RiskLevel
    reasons: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    contradictory: bool = False
    summary: str = ""


def _score_for_strength(strength: str) -> int:
    mapping = {
        "very_low": 5,
        "low": 10,
        "medium": 15,
        "high": 25,
        "very_high": 35,
    }
    return mapping.get(strength, 10)


def _risk_level_for_score(score: int) -> RiskLevel:
    if score >= 60:
        return RiskLevel.CRITICAL
    if score >= 40:
        return RiskLevel.HIGH
    if score >= 20:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _is_contradictory_evidence(
    current_request: SecurityRequest,
    previous_request: SecurityRequest | None = None,
) -> bool:
    if previous_request is None:
        return False

    previous_by_id = {
        item.evidence_id: item
        for item in [normalize_evidence_item(item) for item in previous_request.evidence]
    }

    for item in [normalize_evidence_item(item) for item in current_request.evidence]:
        previous = previous_by_id.get(item.evidence_id)
        if previous is None:
            continue
        if (
            previous.category != item.category
            or previous.value != item.value
            or previous.verified != item.verified
            or previous.strength != item.strength
        ):
            return True

    return False


def assess_risk(
    request: SecurityRequest,
    *,
    previous_request: SecurityRequest | None = None,
    trust_entity: TrustEntity | None = None,
) -> RiskAssessment:
    """Assess risk for the current request without mutating trust state.

    Rules are deterministic and intentionally simple for the prototype:
    - evidence strength contributes directly to score;
    - invalid or unverified evidence with suspicious values increases risk;
    - contradictory evidence raises risk further;
    - external or internet-like contexts further elevate risk.
    """

    if not isinstance(request, SecurityRequest):
        raise TypeError("Risk assessment requires a SecurityRequest instance.")

    evidence_items = [normalize_evidence_item(item) for item in request.evidence]
    for item in evidence_items:
        validate_evidence(item)

    score = 0
    reasons: list[str] = []
    evidence_ids = tuple(item.evidence_id for item in evidence_items)

    if not evidence_items:
        reasons.append("No evidence was attached to the request; risk remains minimal.")
        score = 5
    else:
        for item in evidence_items:
            score += _score_for_strength(item.strength)
            reasons.append(
                f"Evidence {item.evidence_id} ({item.category}) adds { _score_for_strength(item.strength) } risk points."
            )

            if item.verified:
                score += 5
                reasons.append(f"Verified evidence {item.evidence_id} adds 5 points.")

            suspicious_values = {
                "unsigned",
                "unknown",
                "invalid",
                "suspicious",
                "malicious",
                "tampered",
            }
            if str(item.value).lower() in suspicious_values:
                score += 20
                reasons.append(f"Suspicious evidence value '{item.value}' adds 20 points.")

            if item.category in {"signature", "integrity", "certificate"} and not item.verified:
                score += 10
                reasons.append(f"Unverified {item.category} evidence adds 10 points.")

    origin = str(request.context.get("origin", "")).lower()
    if origin in {"internet", "remote", "external", "unknown"}:
        score += 15
        reasons.append("Request context indicates an external or untrusted origin.")

    if request.subject.get("signature") == "unsigned":
        score += 10
        reasons.append("Subject signature is explicitly unsigned.")

    contradictory = _is_contradictory_evidence(request, previous_request)
    if contradictory:
        score += 25
        reasons.append("Contradictory evidence was observed relative to the prior request.")

    if trust_entity is not None and trust_entity.state is not None:
        if trust_entity.state in {"untrusted", "quarantined"}:
            score += 10
            reasons.append("Current trust posture is already degraded.")

    level = _risk_level_for_score(score)
    summary = (
        f"Risk score {score} -> {level.value}. "
        + "; ".join(reasons)
    )

    return RiskAssessment(
        score=score,
        level=level,
        reasons=tuple(reasons),
        evidence_ids=evidence_ids,
        contradictory=contradictory,
        summary=summary,
    )
