# Contract: Continuous Trust Re-Evaluation

## Scope

This contract defines the conceptual interface between the re-evaluation flow and the existing ACHYUTA responsibility boundaries. It is intentionally modeled as a research-level contract, not a production network protocol or enforcement API.

The implementation preserves the existing separation of concerns:

- Pramana owns evidence representation and provenance.
- The request layer owns fresh request context and request lineage.
- Niyama owns policy evaluation and policy matching.
- Viveka owns decision resolution and decision metadata.
- Trust State owns transition integrity and history.
- Raksha remains the future enforcement boundary and is not part of this contract.

## Trigger input

A re-evaluation trigger is represented by a `ReEvaluationTrigger` object with the following fields:

- `trigger_id`
- `entity_id`
- `trigger_type`
- `source`
- `timestamp`
- `relevance_reason`

A re-evaluation trigger is valid when:

1. a new `SecurityRequest` is relevant to an existing entity, or
2. fresh evidence changes the trust context for that entity

The trigger MUST NOT originate from a scheduler or from the trust-state layer itself.

## Re-evaluation context

Each re-evaluation must create a fresh request context and preserve the prior request lineage. The contractually relevant audit context is:

- `entity_id`
- `previous_state`
- `trigger_id`
- `request_id`
- `previous_request_id`
- `request_history[]`
- `evidence_ids[]`
- `policy_summary`
- `decision_id`
- `resulting_state`
- `transition_reason`

The existing implementation explicitly stores lineage in the request context using:

- `request.context["previous_request_id"]`
- `request.context["request_history"]`
- `request.history_id` for the originating request

The re-evaluation audit record also stores `trigger_id` and the distinct `request_id` for the fresh evaluation.

## Boundary contract

- Pramana: owns evidence representation and provenance.
- Request layer: owns fresh request creation and distinct request lineage.
- Niyama: owns policy evaluation and policy matching.
- Viveka: owns decision resolution and decision metadata.
- Trust State: owns the transition boundary, transition history, and re-evaluation record metadata.
- Re-evaluation orchestration: coordinates the sequence and preserves traceability without duplicating policy or decision logic.

## Required behavior

- The re-evaluation MUST operate on a fresh request context rather than reusing a prior request object.
- The previous trust state, prior request, and fresh request must remain separately auditable.
- The resulting trust state MUST be applied through the controlled `TrustEntity` transition boundary for ordinary state changes and through the dedicated `TrustEntity.promote_to_trusted()` boundary for `TRUSTED` promotion.
- `transition(..., TrustState.TRUSTED, ...)` remains rejected by design; `TRUSTED` promotion requires an explicit decision-backed boundary.
- Current evidence and current policy evaluation MUST drive the decision rather than a stale trust state.
- If evidence is insufficient, contradictory, or inconclusive, the system MUST default to verification, restriction, or quarantine instead of silently preserving elevated trust.
- The decision and trust-state record MUST remain distinct; a raw decision string MUST NOT act as a trust promotion mechanism.
- A re-evaluation record MUST preserve the chain from previous state → trigger → request → evidence → policy → decision → resulting state.

## Implementation alignment notes

This contract matches the current implementation in the repository:

- `create_fresh_request()` creates a new request while preserving request lineage.
- `requires_re_evaluation()` detects fresh or contradictory evidence and materially changed request context.
- `evaluate_policy()` and `resolve_decision()` remain owned by Niyama and Viveka, respectively.
- `TrustEntity.transition()` validates ordinary state transitions, while `TrustEntity.promote_to_trusted()` is the dedicated `TRUSTED` boundary.
- `TrustEntity.evaluate_re_evaluation()` routes the re-evaluation to the correct controlled path and preserves audit metadata.
- `TrustEntity.record_re_evaluation()` records the minimal audit metadata required for explainability.
- `build_trust_explanation()` exposes the request → evidence → policy → decision → trust-state trace.

## Non-contractual assumptions

- No external endpoint or network protocol is introduced by this feature.
- No production event bus or scheduler is part of the contract.
- No direct trust-state mutation or raw decision string is accepted as a promotion mechanism.
- No enforcement logic or endpoint control effect is introduced in this contract.
