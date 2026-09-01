"""
ACHYUTA - Request Model v0.1

A request is the central object evaluated by ACHYUTA.

This follows ADR-003:
Trust evaluation is Request-Centric.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from engine.evidence import Evidence, normalize_evidence_item


@dataclass
class SecurityRequest:
    """
    Represents a security-relevant request.

    Example:

        A user attempts to execute a file.

    ACHYUTA evaluates the request using:
        - identity
        - subject
        - action
        - resource
        - context
        - evidence
    """

    request_id: str

    identity: dict[str, Any]

    subject: dict[str, Any]

    action: dict[str, Any]

    resource: dict[str, Any]

    context: dict[str, Any] = field(
        default_factory=dict
    )

    evidence: list[Evidence] = field(
        default_factory=list
    )
    history_id: str = field(default="")

    def __post_init__(self) -> None:
        if not self.history_id:
            object.__setattr__(self, "history_id", self.request_id)
        object.__setattr__(
            self,
            "evidence",
            [normalize_evidence_item(item) for item in self.evidence],
        )

    def add_evidence(self, evidence: Evidence | dict[str, Any]) -> None:
        """Attach evidence to this request."""

        self.evidence.append(normalize_evidence_item(evidence))

    def get_evidence(
        self,
        category: str,
    ) -> list[Evidence]:
        """Return evidence belonging to a category."""

        return [
            item
            for item in self.evidence
            if item.category == category
        ]


def is_relevant_request(
    current_request: SecurityRequest,
    entity_id: str | None = None,
    *,
    subject: dict[str, Any] | None = None,
    resource: dict[str, Any] | None = None,
    identity: dict[str, Any] | None = None,
) -> bool:
    """Determine whether the request is relevant to a trust evaluation."""

    if entity_id is not None and current_request.identity.get("entity_id") == entity_id:
        return True

    if subject is not None and current_request.subject == subject:
        return True

    if resource is not None and current_request.resource == resource:
        return True

    if identity is not None and current_request.identity == identity:
        return True

    return bool(
        current_request.context.get("entity_id")
        or current_request.subject.get("name")
        or current_request.resource.get("path")
    )


def create_fresh_request(
    base_request: SecurityRequest,
    *,
    request_id: str | None = None,
    identity: dict[str, Any] | None = None,
    subject: dict[str, Any] | None = None,
    action: dict[str, Any] | None = None,
    resource: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
    evidence: list[Evidence] | None = None,
) -> SecurityRequest:
    """Create a distinct request context for trust re-evaluation."""

    request_history = deepcopy(base_request.context.get("request_history", [base_request.request_id]))
    if not isinstance(request_history, list):
        request_history = [request_history]
    if base_request.request_id not in request_history:
        request_history.append(base_request.request_id)

    fresh_context = {
        **deepcopy(base_request.context),
        **(deepcopy(context) or {}),
    }
    fresh_context["previous_request_id"] = base_request.request_id
    fresh_context["request_history"] = request_history

    fresh = SecurityRequest(
        request_id=request_id or f"{base_request.request_id}-fresh",
        identity=deepcopy(identity or base_request.identity),
        subject=deepcopy(subject or base_request.subject),
        action=deepcopy(action or base_request.action),
        resource=deepcopy(resource or base_request.resource),
        context=fresh_context,
        evidence=deepcopy(evidence if evidence is not None else base_request.evidence),
    )
    object.__setattr__(fresh, "history_id", base_request.request_id)
    return fresh


def request_history_id(request: SecurityRequest) -> str:
    """Return the historical request identifier associated with this request."""

    return request.history_id or request.request_id


def request_context_for_re_evaluation(
    base_request: SecurityRequest,
    *,
    request_id: str,
    context: dict[str, Any] | None = None,
) -> SecurityRequest:
    """Compatibility wrapper for creating a fresh re-evaluation request."""

    return create_fresh_request(
        base_request,
        request_id=request_id,
        context=context,
    )


def _normalized_evidence_items(
    request: SecurityRequest,
) -> list[Evidence]:
    """Return evidence items as canonical Evidence objects."""
    return [normalize_evidence_item(item) for item in request.evidence]


def has_fresh_evidence(
    current_request: SecurityRequest,
    previous_request: SecurityRequest | None = None,
) -> bool:
    """Detect if a request includes fresh, security-relevant evidence not seen before."""
    if not previous_request:
        return len(current_request.evidence) > 0

    previous_evidence = _normalized_evidence_items(previous_request)
    current_evidence = _normalized_evidence_items(current_request)

    previous_evidence_ids = {e.evidence_id for e in previous_evidence}
    current_evidence_ids = {e.evidence_id for e in current_evidence}

    fresh_ids = current_evidence_ids - previous_evidence_ids
    if not fresh_ids:
        return False

    for evidence in current_evidence:
        if evidence.evidence_id in fresh_ids:
            if evidence.verified or evidence.strength in ("high", "critical"):
                return True

    return False


def has_contradictory_evidence(
    current_request: SecurityRequest,
    previous_request: SecurityRequest | None = None,
) -> bool:
    """Return True when the same evidence is changed in a way that contradicts prior observations."""
    if not previous_request:
        return False

    current_evidence = {item.evidence_id: item for item in _normalized_evidence_items(current_request)}
    previous_evidence = {item.evidence_id: item for item in _normalized_evidence_items(previous_request)}

    for evidence_id, current_item in current_evidence.items():
        previous_item = previous_evidence.get(evidence_id)
        if previous_item is None:
            continue
        if current_item.category != previous_item.category:
            return True
        if current_item.value != previous_item.value:
            return True
        if current_item.verified != previous_item.verified:
            return True

    return False


def requires_re_evaluation(
    current_request: SecurityRequest,
    previous_request: SecurityRequest | None = None,
    previous_decision: dict[str, Any] | None = None,
) -> bool:
    """Detect if the current request warrants a re-evaluation of trust state.
    
    Returns True if:
    1. Fresh evidence is present (security-relevant updates)
    2. Request context has changed materially (new entity or different action)
    3. Previous decision was uncertain or expires (indicated by context hints)
    """
    
    # Check for fresh evidence
    if has_fresh_evidence(current_request, previous_request):
        return True

    # Check for contradictory evidence that invalidates a prior trust assessment
    if has_contradictory_evidence(current_request, previous_request):
        return True

    # Check for new security request (entity change or action change)
    if previous_request:
        if (
            current_request.subject.get("name") != previous_request.subject.get("name")
            or current_request.resource.get("path") != previous_request.resource.get("path")
            or current_request.action.get("type") != previous_request.action.get("type")
        ):
            return True

    # Check for explicit re-evaluation hints in context
    if current_request.context.get("requires_re_evaluation"):
        return True

    # Check if evidence contradicts previous decision
    if previous_decision and current_request.evidence:
        previous_effect = previous_decision.get("effect")
        for evidence in current_request.evidence:
            if evidence.category == "signature":
                if previous_effect == "allow" and evidence.value == "unsigned":
                    return True
                if previous_effect == "deny" and evidence.value == "signed":
                    return True

    return False