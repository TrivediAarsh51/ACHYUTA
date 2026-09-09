"""ACHYUTA runtime evaluation boundary.

This module orchestrates the existing evidence -> policy -> decision -> trust
flow without introducing a second policy engine or trust-state mutation layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from engine.decision import Decision, resolve_current_decision, resolve_decision
from engine.policy import PolicyRecord, PolicyResult, evaluate_policy
from engine.raksha import EnforcementRecord, RakshaEnforcer
from engine.request import SecurityRequest
from engine.risk import RiskAssessment, assess_risk
from engine.trust import (
    TrustEntity,
    TrustState,
    build_trust_explanation,
    trust_state_from_decision,
)


@dataclass(frozen=True)
class RuntimeEvaluationResult:
    """Structured result produced by the runtime boundary."""

    request: SecurityRequest
    previous_request_id: str | None
    risk: RiskAssessment
    policy_results: tuple[PolicyResult, ...] = ()
    decision: Decision | None = None
    enforcement: EnforcementRecord | None = None
    explanation: Any = None
    audit: dict[str, Any] = field(default_factory=dict)
    transition: Any | None = None
    entity: TrustEntity | None = None


def evaluate_runtime_request(
    *,
    request: SecurityRequest,
    policies: Iterable[dict[str, Any]] | None = None,
    policy_records: Iterable[PolicyRecord] | None = None,
    previous_request: SecurityRequest | None = None,
    entity: TrustEntity | None = None,
    trigger: Any | None = None,
    decision: Decision | str | None = None,
    auto_apply_state: bool = True,
    enforce: bool = False,
    enforcer: RakshaEnforcer | None = None,
    evaluate_policy_fn: Callable[..., PolicyResult] = evaluate_policy,
    resolve_decision_fn: Callable[..., Decision] = resolve_decision,
) -> RuntimeEvaluationResult:
    """Execute a request through the existing evidence/risk/policy/decision/trust flow.

    Runtime orchestration remains separate from policy evaluation and trust-state
    mutation. It simply coordinates the existing engine boundaries.
    """

    if not isinstance(request, SecurityRequest):
        raise TypeError("Runtime evaluation requires a SecurityRequest instance.")

    if decision is not None and not isinstance(decision, Decision):
        raise TypeError("Raw decision values are not valid runtime decision context.")

    if policies is not None and policy_records is not None:
        raise ValueError("Provide policy_records or legacy policies, not both.")

    current_records = list(policy_records or [])
    for record in current_records:
        if not isinstance(record, PolicyRecord):
            raise TypeError("Runtime enforcement requires PolicyRecord instances.")

    legacy_policies = list(policies or [])
    if current_records:
        current_policies = [record.definition for record in current_records]
    else:
        current_policies = legacy_policies

    if enforce and legacy_policies:
        current_records = [
            PolicyRecord.from_policy(
                policy,
                provenance={"source": "legacy-runtime-policy"},
            )
            for policy in legacy_policies
        ]

    risk_assessment = assess_risk(
        request,
        previous_request=previous_request,
        trust_entity=entity,
    )

    policy_results: list[PolicyResult] = []
    for policy in current_policies:
        policy_results.append(evaluate_policy_fn(policy, request))

    policy_context = {
        result.policy_id: {
            "name": result.policy_name,
            "matched": result.matched,
            "effect": result.effect,
            "reasons": tuple(result.reason),
        }
        for result in policy_results
    }

    if decision is not None:
        resolved_decision = decision
    elif policy_results:
        resolved_decision = resolve_decision_fn(policy_results)
    else:
        resolved_decision = resolve_current_decision([], fallback_to_conservative=True)

    previous_state = entity.state if entity is not None else None
    target_state: TrustState | None = None
    transition = None

    if entity is not None and auto_apply_state:
        target_state = trust_state_from_decision(
            resolved_decision.effect.value,
            entity.entity_type,
        )
        evidence_ids = tuple(item.evidence_id for item in request.evidence)
        transition_reason = (
            resolved_decision.reason
            if resolved_decision.reason
            else "Runtime evaluation applied the current decision to trust state."
        )
        decision_context = {
            "decision_id": resolved_decision.decision_id,
            "effect": resolved_decision.effect.value,
            "matched_policy_ids": tuple(resolved_decision.matched_policy_ids),
            "reason": resolved_decision.reason,
        }

        if target_state is TrustState.TRUSTED:
            transition = entity.promote_to_trusted(
                reason=transition_reason,
                decision=resolved_decision,
                evidence_ids=evidence_ids,
                policy_context=policy_context,
                decision_context=decision_context,
            )

        else:
            transition = entity.transition(
                target_state,
                transition_reason,
                evidence_ids=evidence_ids,
                policy_context=policy_context,
                decision_context=decision_context,
            )

    enforcement = None
    if enforce:
        enforcement_context = {
            result.policy_id: {
                **policy_context.get(result.policy_id, {}),
                "policy_id": record.policy_id,
                "version": record.version,
                "integrity_digest": record.integrity_digest,
                "lifecycle_state": record.lifecycle_state.value,
                "provenance": dict(record.provenance),
            }
            for record in current_records
            for result in policy_results
            if result.policy_id == record.policy_id
        }
        enforcement = (enforcer or RakshaEnforcer()).enforce(
            request,
            resolved_decision,
            policy_context=enforcement_context,
            policy_records=current_records,
            risk=risk_assessment,
            trust_entity=entity,
        )

    explanation = build_trust_explanation(
        request=request,
        policy_results=tuple(policy_results),
        decision=resolved_decision,
        trust_state=target_state if target_state is not None else (entity.state if entity is not None else TrustState.UNKNOWN),
        transition=transition,
        previous_state=previous_state,
        trigger=trigger,
        previous_request_id=previous_request.request_id if previous_request is not None else None,
        decision_id=resolved_decision.decision_id,
        policy_summary="; ".join(
            f"{result.policy_id}:{result.effect or 'no-match'}"
            for result in policy_results
        )
        or "no policy evaluation performed",
        evidence_ids=tuple(item.evidence_id for item in request.evidence),
        transition_reason=(transition.reason if transition is not None else resolved_decision.reason),
    )

    evaluation_chain = [
        {
            "stage": "request",
            "request": {
                "request_id": request.request_id,
                "history_id": request.history_id,
                "previous_request_id": previous_request.request_id if previous_request is not None else None,
            },
        },
        {
            "stage": "risk",
            "risk": {
                "score": risk_assessment.score,
                "level": risk_assessment.level.value,
                "summary": risk_assessment.summary,
                "contradictory": risk_assessment.contradictory,
            },
        },
        {
            "stage": "evidence",
            "evidence_ids": tuple(item.evidence_id for item in request.evidence),
            "count": len(request.evidence),
        },
        {
            "stage": "policy",
            "policy": {
                "matched_policy_ids": tuple(result.policy_id for result in policy_results if result.matched),
                "count": len(policy_results),
            },
        },
        {
            "stage": "decision",
            "decision": {
                "effect": resolved_decision.effect.value,
                "decision_id": resolved_decision.decision_id,
                "reason": resolved_decision.reason,
            },
        },
    ]

    if entity is not None and auto_apply_state:
        evaluation_chain.append(
            {
                "stage": "trust",
                "previous_state": previous_state.value if previous_state is not None else None,
                "resulting_state": target_state.value if target_state is not None else None,
                "transition_reason": transition.reason if transition is not None else resolved_decision.reason,
            }
        )

    if enforcement is not None:
        evaluation_chain.append(
            {
                "stage": "enforcement",
                "enforcement": {
                    "action": enforcement.action.value,
                    "policy_ids": enforcement.policy_ids,
                    "request_id": enforcement.request_id,
                    "decision_id": enforcement.decision_id,
                },
            }
        )

    return RuntimeEvaluationResult(
        request=request,
        previous_request_id=previous_request.request_id if previous_request is not None else None,
        risk=risk_assessment,
        policy_results=tuple(policy_results),
        decision=resolved_decision,
        explanation=explanation,
        audit={
            "evaluation_chain": evaluation_chain,
            "trigger_id": getattr(trigger, "trigger_id", None),
            "request_id": request.request_id,
            "decision_id": resolved_decision.decision_id,
            "previous_request_id": previous_request.request_id if previous_request is not None else None,
            "evidence_ids": tuple(item.evidence_id for item in request.evidence),
            "enforcement_record": enforcement,
        },
        transition=transition,
        entity=entity,
        enforcement=enforcement,
    )
