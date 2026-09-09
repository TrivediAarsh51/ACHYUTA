"""
ACHYUTA - Niyama Policy Engine v0.1

Niyama is responsible for evaluating security policies against
a security request and its available evidence.

Important architectural separation:

    Evidence -> provides observations
    Niyama   -> evaluates policies
    Viveka   -> will eventually make the final decision
    Raksha   -> will eventually enforce the decision

Niyama v0.1 intentionally does NOT:
    - execute processes
    - block files
    - modify Windows Firewall
    - kill processes
    - make final trust decisions

It only determines which policies match a request.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from engine.evidence import normalize_evidence_item
from engine.request import SecurityRequest


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
class PolicyLifecycleState(str, Enum):
    """States in the controlled policy activation lifecycle."""

    DRAFT = "draft"
    VALIDATED = "validated"
    VERIFIED = "verified"
    APPROVED = "approved"
    ACTIVE = "active"
    RETIRED = "retired"
    SUSPENDED = "suspended"


PolicyState = PolicyLifecycleState


@dataclass(frozen=True)
class PolicyLifecycleEvent:
    """Immutable record of a controlled policy lifecycle transition."""

    from_state: PolicyLifecycleState
    to_state: PolicyLifecycleState
    context: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


@dataclass
class PolicyRecord:
    """Versioned policy metadata and its controlled lifecycle state."""

    policy_id: str
    name: str
    version: int | str
    provenance: dict[str, Any]
    definition: dict[str, Any]
    lifecycle_state: PolicyLifecycleState = PolicyLifecycleState.DRAFT
    validation_context: dict[str, Any] | None = None
    verification_context: dict[str, Any] | None = None
    approval_context: dict[str, Any] | None = None
    lifecycle_history: list[PolicyLifecycleEvent] = field(default_factory=list)
    integrity_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if not self.policy_id.strip() or not self.name.strip():
            raise ValueError("Policy ID and name cannot be empty.")
        if not isinstance(self.provenance, dict) or not self.provenance:
            raise ValueError("Policy provenance is required.")
        if not isinstance(self.definition, dict):
            raise ValueError("Policy definition must be a mapping.")
        self.lifecycle_state = PolicyLifecycleState(self.lifecycle_state)
        self.integrity_digest = self._calculate_integrity_digest()

    @classmethod
    def from_policy(cls, policy: dict[str, Any], *, provenance: dict[str, Any]) -> "PolicyRecord":
        """Create a lifecycle record from an existing evaluator policy mapping."""

        if not isinstance(policy, dict):
            raise TypeError("Policy must be a mapping.")
        return cls(
            policy_id=str(policy.get("id") or ""),
            name=str(policy.get("name") or "Unnamed Policy"),
            version=policy.get("version", 1),
            provenance=provenance,
            definition=dict(policy),
        )

    def _integrity_payload(self) -> str:
        return json.dumps(
            {
                "policy_id": self.policy_id,
                "name": self.name,
                "version": self.version,
                "provenance": self.provenance,
                "definition": self.definition,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )

    def _calculate_integrity_digest(self) -> str:
        return hashlib.sha256(self._integrity_payload().encode("utf-8")).hexdigest()

    @property
    def integrity_valid(self) -> bool:
        """Return whether the policy still matches its recorded digest."""

        valid = self._calculate_integrity_digest() == self.integrity_digest
        if not valid and self.lifecycle_state in {
            PolicyLifecycleState.APPROVED,
            PolicyLifecycleState.ACTIVE,
        }:
            previous_state = self.lifecycle_state
            self.lifecycle_state = PolicyLifecycleState.DRAFT
            self.lifecycle_history.append(
                PolicyLifecycleEvent(
                    from_state=previous_state,
                    to_state=PolicyLifecycleState.DRAFT,
                    reason="Policy integrity changed; re-validation is required.",
                )
            )
        return valid

    def _transition(
        self,
        target: PolicyLifecycleState,
        context: dict[str, Any],
        reason: str,
    ) -> None:
        event = PolicyLifecycleEvent(
            from_state=self.lifecycle_state,
            to_state=target,
            context=dict(context),
            reason=reason,
        )
        self.lifecycle_history.append(event)
        self.lifecycle_state = target

    def validate(self, context: dict[str, Any]) -> None:
        """Record explicit validation and establish the current integrity baseline."""

        if self.lifecycle_state is not PolicyLifecycleState.DRAFT:
            raise ValueError("Only draft policies can be validated.")
        if not isinstance(context, dict) or not context:
            raise ValueError("Validation context is required.")
        self.validation_context = dict(context)
        self.verification_context = None
        self.approval_context = None
        self.integrity_digest = self._calculate_integrity_digest()
        self._transition(PolicyLifecycleState.VALIDATED, context, "Policy validated.")

    def verify(self, context: dict[str, Any]) -> None:
        """Record explicit verification of the validated policy contents."""

        if self.lifecycle_state is not PolicyLifecycleState.VALIDATED:
            raise ValueError("Only validated policies can be verified.")
        if not isinstance(context, dict) or not context:
            raise ValueError("Verification context is required.")
        if not self.integrity_valid:
            raise PermissionError("Modified policies must be revalidated before verification.")
        self.verification_context = dict(context)
        self._transition(PolicyLifecycleState.VERIFIED, context, "Policy verified.")

    def approve(self, context: dict[str, Any]) -> None:
        """Record explicit approval after validation and verification."""

        if self.lifecycle_state is not PolicyLifecycleState.VERIFIED:
            raise ValueError("Only verified policies can be approved.")
        if not isinstance(context, dict) or not context:
            raise ValueError("Approval context is required.")
        if not self.integrity_valid:
            raise PermissionError("Modified policies must be revalidated before approval.")
        self.approval_context = dict(context)
        self._transition(PolicyLifecycleState.APPROVED, context, "Policy approved.")

    def activate(self) -> None:
        """Activate only an intact policy with all required lifecycle context."""

        if not self.integrity_valid:
            raise PermissionError("Policy integrity is invalid; revalidation and reapproval are required.")
        if self.lifecycle_state is not PolicyLifecycleState.APPROVED:
            raise PermissionError("Only approved policies can be activated.")
        if not self.validation_context or not self.verification_context or not self.approval_context:
            raise PermissionError("Validation, verification, and approval context are required.")
        self._transition(PolicyLifecycleState.ACTIVE, {}, "Policy activated.")


@dataclass
class PolicyResult:
    """
    Result produced by Niyama after evaluating one policy.
    """

    policy_id: str
    policy_name: str
    matched: bool
    effect: str | None
    reason: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Policy Loading
# ---------------------------------------------------------------------------

def load_policy(policy_path: str | Path) -> dict[str, Any]:
    """
    Load a YAML policy from disk.

    This function currently performs basic YAML parsing.

    Cryptographic verification, policy signatures, provenance,
    and controlled activation will be implemented in a later
    version according to ADR-006.
    """

    path = Path(policy_path)

    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        policy = yaml.safe_load(file)

    if not isinstance(policy, dict):
        raise ValueError("Policy must contain a YAML mapping/object.")

    if "policy" not in policy:
        raise ValueError("Policy file must contain a 'policy' section.")

    return policy["policy"]


# ---------------------------------------------------------------------------
# Condition Evaluation
# ---------------------------------------------------------------------------

def _check_conditions(
    conditions: dict[str, Any],
    request: SecurityRequest,
) -> tuple[bool, list[str]]:
    """
    Evaluate policy conditions against a request.

    v0.1 supports simple exact attribute matching.

    Example:

        subject:
            signature: unsigned

    matches:

        request.subject["signature"] == "unsigned"
    """

    reasons: list[str] = []

    request_sections = {
        "identity": request.identity,
        "subject": request.subject,
        "action": request.action,
        "resource": request.resource,
        "context": request.context,
    }

    for section_name, expected_values in conditions.items():

        if section_name not in request_sections:
            return False, [
                f"Unknown request section: {section_name}"
            ]

        actual_section = request_sections[section_name]

        if not isinstance(expected_values, dict):
            return False, [
                f"Conditions for '{section_name}' must be a mapping."
            ]

        for attribute, expected_value in expected_values.items():

            actual_value = actual_section.get(attribute)

            if actual_value != expected_value:
                return False, [
                    (
                        f"{section_name}.{attribute}: "
                        f"expected '{expected_value}', "
                        f"observed '{actual_value}'"
                    )
                ]

            reasons.append(
                f"{section_name}.{attribute} matched '{expected_value}'"
            )

    return True, reasons


def _check_evidence_conditions(
    conditions: dict[str, Any],
    request: SecurityRequest,
) -> tuple[bool, list[str]]:
    """
    Evaluate evidence-based policy conditions.

    Example policy:

        evidence:
            signature:
                value: unsigned
                verified: true
    """

    reasons: list[str] = []

    for category, expected in conditions.items():

        if not isinstance(expected, dict):
            return False, [
                f"Evidence condition '{category}' must be a mapping."
            ]

        matching_evidence = [
            normalize_evidence_item(evidence)
            for evidence in request.evidence
            if normalize_evidence_item(evidence).category == category
        ]

        if not matching_evidence:
            return False, [
                f"No evidence found for category '{category}'."
            ]

        matched = False

        for evidence in matching_evidence:

            expected_value = expected.get("value")
            expected_verified = expected.get("verified")

            if (
                expected_value is not None
                and evidence.value != expected_value
            ):
                continue

            if (
                expected_verified is not None
                and evidence.verified != expected_verified
            ):
                continue

            matched = True

            reasons.append(
                f"Evidence {evidence.evidence_id} matched "
                f"category '{category}'"
            )

            break

        if not matched:
            return False, [
                f"Evidence condition '{category}' did not match."
            ]

    return True, reasons


# ---------------------------------------------------------------------------
# Policy Evaluation
# ---------------------------------------------------------------------------

def evaluate_policy(
    policy: dict[str, Any],
    request: SecurityRequest,
) -> PolicyResult:
    """
    Evaluate a single policy against a security request.

    A policy may contain:

        conditions:
            subject:
                ...
            action:
                ...

        evidence:
            signature:
                value: unsigned
                verified: true

    Both sections must match for the policy to match.
    """

    policy_id = policy.get("id")
    policy_name = policy.get("name", "Unnamed Policy")
    conditions = policy.get("conditions", {})
    evidence_conditions = policy.get("evidence", {})
    effect = policy.get("effect")

    if not policy_id:
        raise ValueError(
            "Policy is missing required field: id"
        )

    if not effect:
        raise ValueError(
            f"Policy '{policy_id}' is missing required field: effect"
        )

    # ---------------------------------------------------------------
    # Evaluate request conditions
    # ---------------------------------------------------------------

    condition_match, condition_reasons = _check_conditions(
        conditions,
        request,
    )

    if not condition_match:
        return PolicyResult(
            policy_id=policy_id,
            policy_name=policy_name,
            matched=False,
            effect=None,
            reason=condition_reasons,
        )

    # ---------------------------------------------------------------
    # Evaluate evidence conditions
    # ---------------------------------------------------------------

    evidence_match, evidence_reasons = _check_evidence_conditions(
        evidence_conditions,
        request,
    )

    if not evidence_match:
        return PolicyResult(
            policy_id=policy_id,
            policy_name=policy_name,
            matched=False,
            effect=None,
            reason=evidence_reasons,
        )

    # ---------------------------------------------------------------
    # Policy matched
    # ---------------------------------------------------------------

    return PolicyResult(
        policy_id=policy_id,
        policy_name=policy_name,
        matched=True,
        effect=effect,
        reason=condition_reasons + evidence_reasons,
    )


def current_policy_summary(
    policy_results: list[PolicyResult] | tuple[PolicyResult, ...],
) -> str:
    """Create a minimal policy summary string for a re-evaluation audit record."""

    if not policy_results:
        return "no policy results"

    details: list[str] = []
    for result in policy_results:
        if result.matched:
            details.append(f"{result.policy_id}:{result.effect}")
        else:
            details.append(f"{result.policy_id}:no-match")

    return "; ".join(details)


def evaluate_current_policy(
    policy: dict[str, Any],
    request: SecurityRequest,
    *,
    fallback_to_conservative: bool = True,
) -> PolicyResult:
    """Compatibility seam for current evidence + request evaluation in re-evaluation flows."""

    try:
        return evaluate_policy(policy, request)
    except (TypeError, ValueError, KeyError):
        if not fallback_to_conservative:
            raise
        return PolicyResult(
            policy_id=policy.get("id", "unknown"),
            policy_name=policy.get("name", "Unnamed Policy"),
            matched=False,
            effect="restrict",
            reason=[
                "Current policy evaluation was inconclusive; conservative fallback applied."
            ],
        )

# ---------------------------------------------------------------------------
# Multiple Policy Evaluation
# ---------------------------------------------------------------------------

def evaluate_policies(
    policies: list[dict[str, Any]],
    request: SecurityRequest,
) -> list[PolicyResult]:
    """
    Evaluate multiple policies against the same request.

    NOTE:

    Conflict resolution is intentionally NOT implemented yet.

    This is important because ADR-006 leaves the final policy
    precedence algorithm as a deferred architectural decision.

    Niyama v0.1 therefore reports all matching policies.
    """

    results: list[PolicyResult] = []

    for policy in policies:
        result = evaluate_policy(policy, request)
        results.append(result)

    return results