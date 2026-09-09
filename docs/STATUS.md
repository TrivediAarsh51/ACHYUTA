# ACHYUTA Development Status

## Current Milestone

ACHYUTA is a working request-centric trust-engine prototype with risk assessment, controlled policy lifecycle, continuous re-evaluation, and an abstract Raksha enforcement boundary. It is not yet a production endpoint security platform. The executable flow is coordinated by [engine/runtime.py](../engine/runtime.py) across request, evidence, risk, policy, decision, trust, and enforcement layers.

## Test Status

Last verified on 2026-09-03:

- `129 passed`
- `0 failed`

The suite covers trust hardening, continuous re-evaluation, policy lifecycle and integrity, risk assessment, Raksha enforcement, runtime orchestration, adversarial fallbacks, and integration behavior. Key test modules include [tests/test_runtime.py](../tests/test_runtime.py), [tests/test_raksha.py](../tests/test_raksha.py), [tests/test_risk.py](../tests/test_risk.py), and [tests/test_batch6_adversarial.py](../tests/test_batch6_adversarial.py).

## Implemented Features

### Trust State Management

- Canonical entity types and five trust states are validated in [engine/trust.py](../engine/trust.py).
- Direct state mutation and direct initialization to `TRUSTED` are blocked.
- Ordinary transitions cannot promote to `TRUSTED`; controlled promotion requires a validated permit [Decision](../engine/decision.py) and supporting evidence.
- Transition and recovery histories are append-only, immutable, evidence-linked, and explainable.

### Continuous Trust Re-Evaluation

- Fresh request creation preserves previous request lineage in [engine/request.py](../engine/request.py).
- Re-evaluation triggers and records capture changed context, prior state, evidence, policy, decision, and resulting state.
- Re-evaluation remains separate from authorization and supports conservative handling of contradictory or incomplete evidence.

### Risk Assessment

[engine/risk.py](../engine/risk.py) provides a deterministic, non-mutating risk model with:

- `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL` levels
- evidence-strength and verification scoring
- suspicious-value, external-origin, degraded-trust, and contradictory-evidence signals
- structured reasons, evidence identifiers, and a summary

### Policy Integrity and Raksha Enforcement

- [engine/policy.py](../engine/policy.py) provides `DRAFT`, `VALIDATED`, `VERIFIED`, `APPROVED`, `ACTIVE`, `RETIRED`, and `SUSPENDED` lifecycle states.
- Policy records contain provenance, version, validation/verification/approval context, lifecycle history, and an integrity digest.
- Modified or incomplete policies cannot be activated or authorize enforcement.
- [engine/raksha.py](../engine/raksha.py) maps validated [Decision](../engine/decision.py) outcomes to explicit `ALLOW`, `RESTRICT`, `QUARANTINE`, `REQUIRE_VERIFICATION`, or `DENY` actions.
- Missing evidence, contradictory evidence, high risk, missing policy context, and lifecycle failures use conservative fallback behavior.
- Enforcement records preserve request, decision, policy, evidence, reason, and prior/resulting action lineage without mutating trust state.

### Runtime Orchestration

[engine/runtime.py](../engine/runtime.py) provides `evaluate_runtime_request()` to coordinate risk, policy evaluation, decision resolution, optional controlled trust-state application, enforcement, and an auditable evaluation chain.

## Current Engine Components

- [engine/request.py](../engine/request.py): request model, evidence attachment, fresh requests, and re-evaluation triggers
- [engine/evidence.py](../engine/evidence.py): evidence creation, normalization, validation, and filtering
- [engine/risk.py](../engine/risk.py): deterministic risk assessment
- [engine/policy.py](../engine/policy.py): policy evaluation and controlled lifecycle/integrity records
- [engine/decision.py](../engine/decision.py): decision resolution and conservative effect mapping
- [engine/trust.py](../engine/trust.py): trust state, controlled transitions, recovery, and explanations
- [engine/raksha.py](../engine/raksha.py): abstract enforcement records and action mapping
- [engine/runtime.py](../engine/runtime.py): end-to-end evaluation coordination

## Current Security Boundaries

- Trust state is distinct from authorization and enforcement.
- Risk assessment does not mutate trust state or issue authorization decisions.
- Policy activation requires validation, verification, approval, and valid integrity.
- Raksha consumes a `Decision`; raw effects cannot authorize enforcement.
- Enforcement does not mutate the supplied request, decision, policy records, risk assessment, or trust entity.
- Audit records retain evidence and policy lineage for accepted transitions and enforcement outcomes.

## Current Trust States

The trust-state enum in [engine/trust.py](../engine/trust.py) defines `UNKNOWN`, `UNVERIFIED`, `TRUSTED`, `QUARANTINED`, and `UNTRUSTED`.

## Known Issues and Architectural Gaps

- [README.md](../README.md) and [docs/Security-Features-by-default.md](Security-Features-by-default.md) are still empty.
- Policy conflict resolution remains intentionally outside the current policy evaluator.
- Cryptographic evidence provenance, signatures, and attestation remain deferred.
- Raksha is an abstract, platform-independent enforcement boundary; it does not block files, execute processes, modify Windows Firewall, or provide endpoint integration.
- The SpecKit task files contain stale unchecked items and should be reconciled with the implemented tests and modules.
- The implementation remains a research prototype and lacks production persistence, telemetry, deployment, and operational controls.

## Completed Design Artifacts

The repository contains ADRs 001 through 007 covering trust states, recovery, request-centric evaluation, evidence-centric decisions, the canonical domain model, policy integrity, and controlled trust-state promotion. These documents describe the governing architecture; this status file records the subset now exercised by the runtime and tests.

## Next Recommended Work

1. Reconcile completion markers and acceptance evidence in the SpecKit task files for features 001, 002, and 003.
2. Add root-level project documentation and usage examples.
3. Define production persistence, telemetry, cryptographic evidence verification, and endpoint enforcement integrations.
4. Add explicit policy conflict-resolution behavior when the policy model is ready to support it.
