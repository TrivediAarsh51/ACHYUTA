# Quickstart: Continuous Trust Re-Evaluation

## Purpose

This quickstart documents the continuous trust re-evaluation behavior that is currently implemented in the repository. It is intentionally aligned with the actual ACHYUTA model and tests, not with a planned future architecture.

The current implementation keeps the existing responsibility boundaries intact:

- Pramana: `engine/evidence.py`
- Request context: `engine/request.py`
- Niyama: `engine/policy.py`
- Viveka: `engine/decision.py`
- Trust State: `engine/trust.py`

This feature does not introduce a second policy engine or a direct trust-mutation path. It adds a re-evaluation-aware flow that preserves request lineage, evidence provenance, and controlled trust-state transitions.

## Fresh security requests trigger re-evaluation

A re-evaluation is triggered when a request is treated as a fresh security evaluation rather than a continuation of an earlier request.

The implementation is centered on `SecurityRequest` and `requires_re_evaluation()` in `engine/request.py`.

A request is considered relevant for re-evaluation when:

- the new request includes fresh evidence not previously seen
- the same evidence was changed in a contradictory way
- the subject, resource, or action changed materially from the previous request
- the request context explicitly marks `requires_re_evaluation`
- a prior decision and current evidence contradict each other

The key detection functions are:

- `has_fresh_evidence(current_request, previous_request)`
- `has_contradictory_evidence(current_request, previous_request)`
- `requires_re_evaluation(current_request, previous_request, previous_decision)`

Freshness is not based on a scheduler or a separate control plane. It is request-centric and evidence-driven, matching the architecture described in the feature spec.

## Fresh evidence participates in the re-evaluation flow

Evidence is normalized through `normalize_evidence_item()` and stored as canonical `Evidence` objects. Evidence is attached to the request through `SecurityRequest.add_evidence()` and filtered by category through `get_evidence()`.

The re-evaluation logic uses fresh evidence in two important ways:

1. It compares current and prior evidence IDs.
   - `has_fresh_evidence()` computes the set difference between current evidence IDs and previous evidence IDs.
   - A request only counts as fresh when the new evidence set contains evidence that was not seen before and that is either verified or of high/critical strength.

2. It treats contradictory evidence as a re-evaluation trigger.
   - `has_contradictory_evidence()` compares the same evidence ID across request histories and flags category, value, or verification changes as contradictory.

This keeps evidence provenance in Pramana and ensures that policy and trust decisions are driven by current evidence rather than old trust state alone.

## Request lineage and separation are preserved

The current implementation creates a new request context explicitly instead of rewriting the old one.

`create_fresh_request()` does the following:

- deep-copies the base request
- preserves the original request in `history_id`
- stores `previous_request_id` in the new request context
- stores a request chain in `context["request_history"]`
- keeps the new request as a distinct object with its own `request_id`

This means a re-evaluation remains separate from the original evaluation even when the same entity is being re-checked.

The request relationship is visible in the resulting object graph:

- `request.request_id` is the current request identifier
- `request.history_id` points to the originating request
- `request.context["previous_request_id"]` captures the immediate predecessor request
- `request.context["request_history"]` records the request lineage chain

This is the actual separation boundary used by the repository tests, such as the fresh-request and lineage assertions in `tests/test_integration.py` and `tests/test_trust.py`.

## Policy → Decision → Trust State flow

The repo implements the current flow as a standard request evaluation pipeline:

1. Request has evidence
2. Policy evaluates the request and evidence
3. Decision resolves the strongest matching policy outcome
4. Trust state is updated through the controlled trust boundary

The actual functions are:

- `evaluate_policy(policy, request)` in `engine/policy.py`
- `resolve_decision(policy_results)` in `engine/decision.py`
- `trust_state_from_decision(decision_effect, entity_type)` in `engine/trust.py`

The policy result contains:

- `policy_id`
- `policy_name`
- `matched`
- `effect`
- `reason`

`resolve_decision()` does not invent new logic; it takes the matching policy results and selects the most restrictive effect. The decision object is distinct from the trust state and carries:

- `effect`
- `matched_policy_ids`
- `reason`
- `decision_id`

`trust_state_from_decision()` then maps that decision to a conservative trust-state response:

- `permit` -> `TRUSTED`
- `monitor` or `require_verification` -> `UNVERIFIED`
- `restrict`, `quarantine`, or deny on process/subject/resource -> `QUARANTINED`

This is intentionally conservative and prevents the decision layer from acting like a raw trust-promotion mechanism.

## Controlled trust-state transition

Trust state is owned by `TrustEntity` in `engine/trust.py`. Direct state mutation is intentionally blocked. The class prevents direct writes to `state` and requires transitions through controlled methods rather than raw assignment.

The implemented boundary is:

- `transition(new_state, reason, evidence_ids)` validates the target state for non-`TRUSTED` transitions
- `promote_to_trusted(reason, decision, evidence_ids)` is the controlled `TRUSTED` promotion path
- `evaluate_re_evaluation()` routes the re-evaluation decision to the appropriate transition behavior
- re-evaluation history is recorded through `record_re_evaluation()`

`transition()` explicitly rejects `TrustState.TRUSTED` and raises a value error requiring the dedicated `promote_to_trusted()` boundary. That method accepts a real `Decision` object from the Viveka layer, requires a non-empty reason and supporting evidence IDs, and only allows a `DecisionEffect.PERMIT` to establish `TRUSTED`.

This preserves the existing trust boundary and prevents silent mutation or bypass. Recovery remains an explicit, constrained operation under `recover()`, requiring evidence, explicit recovery mode, and authorization checks.

## Re-evaluation audit metadata

A dedicated re-evaluation record is created for each re-check. The record stores the minimal explainability chain required by the feature spec.

`ReEvaluationRecord` includes:

- `record_id`
- `entity_id`
- `previous_state`
- `trigger_id`
- `request_id`
- `previous_request_id`
- `evidence_ids`
- `policy_summary`
- `decision_id`
- `resulting_state`
- `transition_reason`
- `created_at`

`TrustEntity.record_re_evaluation()` adds this information to `re_evaluation_history`, and `evaluate_re_evaluation()` creates the transition and attaches the record. The record is not a substitute for the policy or decision; it is the audit record that explains the request-to-state sequence.

## Conservative fallback behavior

The implementation intentionally defaults to a restrictive outcome when policy evaluation is inconclusive or absent.

Concrete behavior in the repo:

- `evaluate_current_policy(..., fallback_to_conservative=True)` catches evaluation errors and returns a `PolicyResult` with `effect="restrict"`.
- `resolve_current_decision(..., fallback_to_conservative=True)` returns a `Decision` with `effect=RESTRICT` when there are no current policy results.
- `decision.py` maps no matching policy to `REQUIRE_VERIFICATION`.
- `trust_state_from_decision()` converts restrictive decisions into trust states that are not trusted.

This is the safety behavior behind the feature requirement: ambiguous or incomplete facts do not allow elevated trust to remain unchallenged.

## Explainability chain

The implementation exposes an explicit explainability path using `build_trust_explanation()` in `engine/trust.py`.

That function assembles the chain:

- request
- evidence
- policy results
- decision
- trust state
- transition
- previous state
- trigger
- previous request ID
- decision ID
- policy summary
- evidence IDs
- transition reason

This is the reviewer-visible trace that connects the re-evaluation trigger to the request, evidence, policy outcome, decision, and final trust state. The tests explicitly assert this chain in `tests/test_evidence_policy.py` and `tests/test_trust.py`.

## Current validation commands and expected results

The repository currently validates the feature with the following commands:

```powershell
python -m pytest tests/test_trust.py -q
```

Expected passing result:

```text
48 passed in 0.08s
```

```powershell
python -m pytest -v
```

Expected passing result:

```text
67 passed in 0.16s
```

These commands are the authoritative regression checks for the current implementation and should be used instead of stale or planned-only instructions.

The targeted trust re-evaluation coverage is represented by these files:

- `tests/test_trust.py`
- `tests/test_decision.py`
- `tests/test_evidence_policy.py`
- `tests/test_integration.py`
- `tests/test_policy.py`
- `tests/test_evidence.py`

## Current implementation summary

The feature in this repository is not a new runtime service or broader enforcement architecture. It is a request-centric re-evaluation model that:

- creates fresh request contexts for each re-check
- compares current and previous evidence
- evaluates policy on the new request
- resolves a decision separately from trust state
- applies trust updates only through the controlled trust boundary
- records explainable audit metadata for every re-evaluation
- falls back conservatively when evidence or policy outcome is inconclusive

This is the behavior that the working code and automated tests currently enforce.
