# Quickstart: Trust State Management

## Prerequisites

- Windows 11 Pro or the repository's controlled lab environment
- Python 3.11.1 or compatible Python 3.11 runtime
- Repository virtual environment activated when available
- pytest installed in the active environment

## Run the Existing Regression Suite

From the repository root:

```powershell
python -m pytest -q
```

Expected result: all currently collected tests pass, including the existing decision, evidence, policy, integration, and trust tests.

## Run Focused Trust Tests

```powershell
python -m pytest tests/test_trust.py -q
```

Expected coverage includes:

- Initial `UNKNOWN` state
- All supported decision-to-trust conservative mappings
- `QUARANTINED` for suspicious Process, Subject, and Resource outcomes
- Immutable transition audit fields
- Evidence identifier association
- Required transition reasons
- Recovery mode validation and entity isolation
- Explicit `UNTRUSTED` transitions independent of `DENY`

## Trust Domain API

Create a canonical entity with `TrustEntity(entity_id, entity_type)`. New entities
start in `TrustState.UNKNOWN`. Record an ordinary state change with:

```python
transition = entity.transition(
TrustState.QUARANTINED,
"Suspicious execution was observed.",
evidence_ids=("E-001",),
)
```

Each transition is immutable and retains `from_state`, `to_state`, `reason`,
UTC `timestamp`, and `evidence_ids` in `entity.transition_history`.

Recovery is explicitly scoped to the entity instance and requires evidence,
authorization, and exactly one `RecoveryMode`:

```python
transition = entity.recover(
TrustState.TRUSTED,
"Strong reverification completed.",
evidence_ids=("E-002",),
recovery_mode=RecoveryMode.STRONG_REVERIFICATION,
authorized=True,
)
```

`RecoveryMode.HUMAN_APPROVAL` additionally requires `human_approved=True`.
Recovery is valid from `QUARANTINED` or `UNVERIFIED`; invalid recovery requests
leave both the current state and transition history unchanged.

The conservative `trust_state_from_decision()` mapping remains separate from
authorization decisions: `DENY`, `RESTRICT`, and `QUARANTINE` produce a
restrictive posture, while `MONITOR` and `REQUIRE_VERIFICATION` produce
`UNVERIFIED`. A `DENY` result does not establish permanent `UNTRUSTED` status.

## Validate the Explainability Chain

Use a controlled test or lab scenario that:

1. Creates a `SecurityRequest` with identity, subject, action, resource, context, and evidence.
2. Evaluates the request through the existing policy module.
3. Resolves policy results through the existing decision module.
4. Applies the resulting conservative trust response to the selected canonical entity.
5. Verifies that the trust transition records its reason and evidence identifiers while the original request, evidence, policy, and decision remain unchanged.

The expected trace is:

```text
Request -> Evidence -> Policy -> Decision -> Trust State
```

## Safety Boundaries

This feature is a trust-model validation layer only. Do not run endpoint blocking, process termination, firewall modification, or other Windows enforcement actions as part of these checks. Use mock or controlled evidence and scenarios only.

See [data-model.md](data-model.md) for fields, relationships, and state rules.
