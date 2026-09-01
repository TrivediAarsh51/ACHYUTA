"""
ACHYUTA - Pramana Evidence Engine v0.1

Pramana is the evidence layer of ACHYUTA.

Its responsibility is to represent and validate security-relevant
evidence used during request evaluation.

Important architectural separation:

    Telemetry -> raw observation
    Pramana  -> structured evidence
    Niyama   -> policy evaluation
    Viveka   -> final decision
    Raksha   -> enforcement

This v0.1 implementation is intentionally platform-independent.

It does NOT yet collect real Windows telemetry.

Windows-specific collectors will be implemented later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def normalize_evidence_item(evidence: Evidence | dict[str, Any]) -> Evidence:
    """Normalize evidence represented as object or mapping into the canonical Evidence model."""
    if isinstance(evidence, Evidence):
        return evidence

    if isinstance(evidence, dict):
        metadata = evidence.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {"raw": metadata}

        return Evidence(
            evidence_id=str(evidence.get("evidence_id") or evidence.get("id") or "unknown"),
            category=str(evidence.get("category") or "unknown"),
            source=str(evidence.get("source") or "unknown"),
            value=evidence.get("value"),
            strength=str(evidence.get("strength") or "medium"),
            timestamp=evidence.get("timestamp") or datetime.now(timezone.utc),
            verified=bool(evidence.get("verified", False)),
            metadata=metadata,
        )

    raise TypeError("Evidence must be an Evidence instance or mapping.")


# ---------------------------------------------------------------------------
# Evidence Model
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """
    Represents a single piece of security-relevant evidence.

    Example:

        category = "signature"
        source = "mock"
        value = "unsigned"
        strength = "high"
    """

    evidence_id: str
    category: str
    source: str
    value: Any

    strength: str = "medium"

    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    verified: bool = False

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        if key in self.metadata:
            return self.metadata[key]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


# ---------------------------------------------------------------------------
# Evidence Validation
# ---------------------------------------------------------------------------

VALID_STRENGTHS = {
    "very_low",
    "low",
    "medium",
    "high",
    "very_high",
}


def validate_evidence(evidence: Evidence) -> bool:
    """
    Validate the basic structure of an Evidence object.

    This is structural validation only.

    Cryptographic verification, source trust, attestation,
    and evidence provenance will be implemented later.
    """

    if not evidence.evidence_id:
        raise ValueError("Evidence ID cannot be empty.")

    if not evidence.category:
        raise ValueError("Evidence category cannot be empty.")

    if not evidence.source:
        raise ValueError("Evidence source cannot be empty.")

    if evidence.strength not in VALID_STRENGTHS:
        raise ValueError(
            f"Invalid evidence strength: {evidence.strength}"
        )

    return True


# ---------------------------------------------------------------------------
# Evidence Collection
# ---------------------------------------------------------------------------

def create_evidence(
    evidence_id: str,
    category: str,
    source: str,
    value: Any,
    strength: str = "medium",
    verified: bool = False,
    metadata: dict[str, Any] | None = None,
) -> Evidence:
    """
    Create and validate an Evidence object.
    """

    evidence = Evidence(
        evidence_id=evidence_id,
        category=category,
        source=source,
        value=value,
        strength=strength,
        verified=verified,
        metadata=metadata or {},
    )

    validate_evidence(evidence)

    return evidence


# ---------------------------------------------------------------------------
# Evidence Filtering
# ---------------------------------------------------------------------------

def filter_verified_evidence(
    evidence_items: list[Evidence],
) -> list[Evidence]:
    """
    Return only evidence explicitly marked as verified.
    """

    return [
        evidence
        for evidence in evidence_items
        if evidence.verified
    ]


def filter_by_category(
    evidence_items: list[Evidence],
    category: str,
) -> list[Evidence]:
    """
    Return evidence belonging to a specific category.
    """

    return [
        evidence
        for evidence in evidence_items
        if evidence.category == category
    ]