# Contract: Continuous Trust Re-Evaluation

## Scope

This contract defines the conceptual interface between the re-evaluation orchestration flow and the existing ACHYUTA decision and trust boundaries. It is intentionally modeled as a research-level contract, not a production network protocol.

## Trigger input

A re-evaluation trigger must satisfy one of the following:

1. a new SecurityRequest relevant to an existing entity
2. an evidence update that changes the trust context for that entity

The trigger MUST NOT originate from a scheduler or from the trust-state layer itself.

## Re-evaluation context

Each re-evaluation must create or reference the following context:

- `entity_id`
- `previous_state`
- `request_id`
- `evidence_ids[]`
- `policy_summary`
- `decision_id`
- `resulting_state`
- `transition_reason`

## Boundary contract

- Pramana: owns evidence representation and provenance.
- Niyama: owns policy evaluation and policy matching.
- Viveka: owns decision resolution and decision metadata.
- Trust State: owns transition integrity and history.
- Re-evaluation orchestration: coordinates sequence and preserves traceability without duplicating policy or decision logic.

## Required behavior

- The re-evaluation must operate on a fresh request context.
- The previous trust state must remain auditable.
- The resulting trust state must be applied through the controlled transition boundary.
- If evidence is insufficient or contradictory, the system must default to verification, restriction, or quarantine.

## Non-contractual assumptions

- No external endpoint or network protocol is introduced by this feature.
- No production bus or cloud infrastructure is part of the contract.
- No direct trust-state mutation or raw decision string is accepted as a promotion mechanism.
