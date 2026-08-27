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
from typing import Iterable

from engine.policy import PolicyResult


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

    return Decision(
        effect=winning_effect,
        matched_policy_ids=winning_policies,
        reason=(
            f"Decision '{winning_effect.value}' selected "
            f"because it is the most restrictive matching effect."
        ),
    )