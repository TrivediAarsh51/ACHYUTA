# Data Model: Continuous Trust Re-Evaluation

## Entity overview

The feature adds a re-evaluation layer without changing the authoritative responsibilities already defined in the architecture.

```text
TrustEntity
  ├── entity_id
  ├── entity_type
  ├── state
  ├── reason
  ├── state_since
  ├── transition_history[]
  └── re_evaluation_history[]

ReevaluationTrigger
  ├── trigger_id
  ├── entity_id
  ├── trigger_type
  ├── source
  ├── timestamp
  └── relevance_reason

ReevaluationRecord
  ├── record_id
  ├── entity_id
  ├── previous_state
  ├── trigger_id
  ├── request_id
  ├── evidence_ids[]
  ├── policy_summary
  ├── decision_id
  ├── resulting_state
  ├── transition_reason
  └── created_at

TrustTransition
  ├── from_state
  ├── to_state
  ├── reason
  ├── timestamp
  ├── evidence_ids[]
  └── recovery_mode (optional)

TrustExplanation
  ├── request
  ├── evidence[]
  ├── policy_results[]
  ├── decision
  ├── trust_state
  └── transition
```

## Relationships

- A `TrustEntity` has many `TrustTransition` records in chronological order.
- A `TrustEntity` may have many `ReevaluationRecord` entries that are distinct from the original request history.
- A `ReevaluationTrigger` results in a `ReevaluationRecord` and, when appropriate, a new `TrustTransition`.
- `TrustExplanation` links a request, supporting evidence, policy outcomes, decision, and resulting trust state into one reviewable chain.
- `Decision` and `TrustState` remain distinct concepts; the `Decision` is not treated as the entity's trust state.

## Validation rules

### TrustEntity

- `entity_id` must be stable and unique within the canonical entity set.
- `entity_type` must be one of: identity, subject, process, resource, device.
- `state` must be one of the supported values: unknown, unverified, trusted, quarantined, untrusted.
- Direct mutation of `state` after initialization is prohibited.
- Promotion to `TRUSTED` requires a controlled transition path and validation context.

### TrustTransition

- `from_state` and `to_state` must be supported trust states.
- `reason` must be non-empty and human-readable.
- `timestamp` must be valid and comparable for audit ordering.
- `evidence_ids` must be associated with existing evidence references; they cannot silently create new evidence.
- Recovery transitions must include exactly one recovery mode when recovery is used.

### ReevaluationRecord

- `request_id` must reference a fresh request context, not a previous one.
- `policy_summary` must reflect the active policy outcome without duplicating the policy logic inside the trust layer.
- `decision_id` and outcome must remain separate from the trust-state record.
- `resulting_state` must be applied through the existing Trust State transition boundary.

### Conservative fallback

- If evidence is contradictory or insufficient, a re-evaluation result must not silently preserve an elevated trust state.
- The preferred outcomes are verification, restriction, or quarantine.

## State transition semantics

```text
UNKNOWN -> UNVERIFIED -> TRUSTED
     \         \         ^
      \         \         |
       -> QUARANTINED -> UNTRUSTED

TRUSTED -> QUARANTINED or UNVERIFIED (more restrictive re-evaluation)
QUARANTINED -> UNVERIFIED or TRUSTED (recovery path)
UNVERIFIED -> TRUSTED or QUARANTINED
```

The exact transition rules remain controlled by the existing Trust State implementation and are not re-implemented in the orchestration layer.

## Non-goals for data model

- No new production event bus schema.
- No ML scoring fields or cloud-enforcement metadata.
- No timer or scheduler state in the model.
- No direct policy logic embedded in TrustEntity or TrustState.
