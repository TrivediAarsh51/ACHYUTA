"""
ACHYUTA - Viveka Decision Engine v0.1

Viveka resolves the results produced by Niyama.

Niyama:
    Determines which policies match.

Viveka:
    Determines the final decision.

Viveka does NOT enforce the decision.
Enforcement belongs to Raksha.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

from engine.policy import PolicyResult
from engine.request import SecurityRequest


class DecisionEffect(str, Enum):
    """
    Possible authorization outcomes.

    Ordering represents restrictiveness.
    """

    PERMIT = "permit"
    MONITOR = "monitor"
    REQUIRE_VERIFICATION = "require_verification"
    RESTRICT = "restrict"
    QUARANTINE = "quarantine"
    DENY = "deny"


# Higher number = more restrictive
RESTRICTIVENESS = {
    DecisionEffect.PERMIT: 0,
    DecisionEffect.MONITOR: 1,
    DecisionEffect.REQUIRE_VERIFICATION: 2,
    DecisionEffect.RESTRICT: 3,
    DecisionEffect.QUARANTINE: 4,
    DecisionEffect.DENY: 5,
}


@dataclass(frozen=True)
class Decision:
    """
    Final decision produced by Viveka.
    """

    effect: DecisionEffect

    matched_policy_ids: tuple[str, ...]

    reason: str

    decision_id: str = ""


def resolve_decision(
    policy_results: Iterable[PolicyResult],
) -> Decision:
    """
    Resolve multiple policy results into one final decision.

    Rule:

        More restrictive matching policy wins.

    Policies that did not match are ignored.
    """

    matched = [
        result
        for result in policy_results
        if result.matched and result.effect is not None
    ]

    if not matched:
        return Decision(
            effect=DecisionEffect.REQUIRE_VERIFICATION,
            matched_policy_ids=(),
            reason="No policy matched the request.",
        )

    def restrictiveness(result: PolicyResult) -> int:

        effect = DecisionEffect(result.effect)

        return RESTRICTIVENESS[effect]

    winning_result = max(
        matched,
        key=restrictiveness,
    )

    winning_effect = DecisionEffect(
        winning_result.effect
    )

    winning_policies = tuple(
        result.policy_id
        for result in matched
        if DecisionEffect(result.effect) == winning_effect
    )

    decision_id = (
        "DEC-" + "-".join(winning_policies)
        if winning_policies
        else f"DEC-{winning_effect.value.upper()}"
    )

    return Decision(
        effect=winning_effect,
        matched_policy_ids=winning_policies,
        reason=(
            f"Decision '{winning_effect.value}' selected "
            f"because it is the most restrictive matching effect."
        ),
        decision_id=decision_id,
    )


def resolve_current_decision(
    policy_results: Iterable[PolicyResult],
    *,
    fallback_to_conservative: bool = True,
) -> Decision:
    """Compatibility seam for current policy evaluation during re-evaluation."""

    results = list(policy_results)
    if not results:
        if fallback_to_conservative:
            return Decision(
                effect=DecisionEffect.RESTRICT,
                matched_policy_ids=(),
                reason="No current policy results available; conservative fallback applied.",
                decision_id="DEC-RESTRICT",
            )
        return Decision(
            effect=DecisionEffect.REQUIRE_VERIFICATION,
            matched_policy_ids=(),
            reason="No policy results were available for evaluation.",
            decision_id="DEC-REQUIRE-VERIFICATION",
        )

    return resolve_decision(results)


def orchestrate_re_evaluation(
    current_request: SecurityRequest,
    *,
    evaluate_policy_fn,
    evaluate_decision_fn,
    entity_policies: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Orchestrate a re-evaluation flow: Request -> Policies -> Decision.
    
    This seam coordinates evidence evaluation and decision-making without
    becoming a second policy/decision engine. It delegates to existing
    policy and decision functions.
    
    Args:
        current_request: Fresh request context for re-evaluation
        evaluate_policy_fn: Function to evaluate policies (e.g., evaluate_policies)
        evaluate_decision_fn: Function to resolve decision (e.g., resolve_decision)
        entity_policies: List of policies to evaluate (if available)
    
    Returns:
        dict with keys: decision, policy_results, summary_reason
    """
    
    # Step 1: Evaluate current policies against fresh request
    if not entity_policies:
        entity_policies = []
    
    policy_results = evaluate_policy_fn(entity_policies, current_request)
    
    # Step 2: Resolve decision from policy results
    decision = evaluate_decision_fn(policy_results)
    
    # Step 3: Create summary for audit trail
    summary_reason = f"Re-evaluation of {current_request.history_id}: {decision.reason}"
    
    return {
        "decision": decision,
        "policy_results": policy_results,
        "summary_reason": summary_reason,
        "evidence_summary": _evidence_summary(current_request),
    }


def _evidence_summary(request: SecurityRequest) -> str:
    """Create a brief summary of evidence for audit logging."""
    if not request.evidence:
        return "no evidence"
    
    categories = {}
    for evidence in request.evidence:
        cat = evidence.category
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(evidence.evidence_id)
    
    parts = []
    for cat, ids in categories.items():
        parts.append(f"{cat}({len(ids)})")
    
    return ";".join(parts)