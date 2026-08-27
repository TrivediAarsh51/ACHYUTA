# Data Model: Trust State Management

## Trust State

An explicit assessment of a canonical entity. The allowed values are:

- `UNKNOWN`: no sufficient trust assessment exists.
- `UNVERIFIED`: the entity requires additional verification or evidence.
- `TRUSTED`: current evidence and recovery conditions support trust for the applicable context.
- `QUARANTINED`: access or activity requires restriction while suspicious conditions are investigated or resolved.
- `UNTRUSTED`: an explicit trust transition has established that the entity should not be trusted.

Trust state is not an authorization decision and is not a permanent identity classification.

## Entity Type

The canonical entity categories are:

- `IDENTITY`: principal under which a subject operates.
- `SUBJECT`: active execution entity initiating a request.
- `PROCESS`: supported subject subtype or process identity tracked directly for trust.
- `RESOURCE`: object, service, capability, or system component targeted by a request.
- `DEVICE`: endpoint or device identity associated with a request.

## Trust Entity

| Field | Type | Required | Rules |
|---|---|---:||---|
| `entity_id` | string | yes | Stable identifier within the entity type; must not be empty. |
| `entity_type` | EntityType | yes | One of the five canonical entity types. |
| `state` | TrustState | yes | Defaults to `UNKNOWN`; current state reflects the latest accepted transition. |
| `reason` | string | yes | Reason for the current state; blank is allowed only for the initial implicit `UNKNOWN` state. |
| `state_since` | UTC timestamp | yes | Timestamp at which the current state began. |
| `transition_history` | ordered list of TrustTransition | yes | Append-only audit history for accepted transitions. |

## Trust Transition

| Field | Type | Required | Rules |
|---|---|---:||---|
| `from_state` | TrustState | yes | Must equal the entity state immediately before the transition. |
| `to_state` | TrustState | yes | Must be a supported trust state. |
| `reason` | string | yes | Human-readable and non-blank after trimming. |
| `timestamp` | UTC timestamp | yes | Comparable audit timestamp; generated in UTC when omitted by the caller. |
| `evidence_ids` | ordered tuple of strings | no | Preserve all supplied identifiers; empty when no evidence applies. |
| `recovery_mode` | RecoveryMode or absent | conditional | Required for recovery transitions; absent for ordinary state changes. |

A transition is immutable after recording. The entity state and history entry must be updated as one logical operation.

## Recovery Mode

Recovery mode records how an entity moved toward a safer trust posture, as defined by ADR-002:

- `AUTOMATIC`: low-risk temporary conditions may recover automatically.
- `STRONG_REVERIFICATION`: additional verification is required.
- `HUMAN_APPROVAL`: a human must approve recovery for high-impact events.

Recovery remains entity-specific and does not update related entities.

## Relationships

```text
SecurityRequest
  ├── identity, subject, resource, context
  └── Evidence[]
        └── evidence_id referenced by TrustTransition.evidence_ids

SecurityRequest -> Niyama policy results -> Viveka Decision
                                      \            |
                                       \           v
                                        ----> Trust State / TrustTransition
```

The trust layer consumes request, evidence, policy, and decision outcomes as inputs or references. It does not collect evidence, evaluate policy, resolve authorization decisions, or enforce outcomes.

## State and Decision Rules

- A new entity begins at `UNKNOWN`.
- A `DENY` decision never directly establishes permanent `UNTRUSTED`.
- Existing conservative mappings remain: suspicious Process, Subject, or Resource may become `QUARANTINED`; other denied entities become `UNVERIFIED` unless a separate explicit transition says otherwise.
- Recovery changes only the selected entity and records exactly one recovery mode.
- `UNTRUSTED` requires a separate explicit transition with its own reason, timestamp, and supporting evidence where applicable.
- Unsupported values or blank transition reasons are rejected without mutating the entity.
