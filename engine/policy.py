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

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from engine.request import SecurityRequest


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
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
            evidence
            for evidence in request.evidence
            if evidence.category == category
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