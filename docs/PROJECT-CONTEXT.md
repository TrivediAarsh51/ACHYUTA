# ACHYUTA Project Context

## 1. Project identity

### Project name

The repository is named ACHYUTA.

The working code identifies the trust-layer implementation as:

- `engine/trust.py`: `ACHYUTA - Trust State Engine v0.1`
- `engine/decision.py`: `ACHYUTA - Viveka Decision Engine v0.1`
- `engine/policy.py`: `ACHYUTA - Niyama Policy Engine v0.1`
- `engine/evidence.py`: `ACHYUTA - Pramana Evidence Engine v0.1`
- `engine/request.py`: `ACHYUTA - Request Model v0.1`

### Project purpose

The current repository is a research/implementation prototype of a request-centric Zero Trust security architecture for evaluating trust and security-relevant requests.

The strongest source-of-truth statements are in the engine module docstrings and the ADRs:

- `engine/trust.py` states trust state is distinct from authorization.
- `engine/decision.py` defines `Viveka` as the decision engine and notes that enforcement belongs to `Raksha`.
- `engine/policy.py` states `Niyama` is responsible for evaluating policies against a security request and does not enforce decisions.
- `engine/evidence.py` states `Pramana` is the evidence layer.
- `docs/ADR/ADR-003-request-centric-model.md` explicitly adopts a request-centric trust evaluation model.
- `docs/ADR/ADR-005-Canonical-Domain-Model.md` defines the canonical model around Identity, Subject, Request, Action, Resource, Evidence, Policy, Trust State, Decision, and Enforcement.

Important discrepancy:

- The top-level `README.md` is empty, so the repository itself does not currently provide a project narrative or product description.
- The repository contains architecture and design docs, but no production deployment or product configuration is present in the current tree.

### Current repository structure

Current repository layout as observed in the workspace:

```text
ACHYUTA/
├── README.md
├── collector/
├── dashboard/
├── docs/
│   ├── Security-Features-by-default.md
│   ├── ADR/
│   │   ├── ADR-001-trust-states.md
│   │   ├── ADR-002-trust-recovery.md
│   │   ├── ADR-003-request-centric-model.md
│   │   ├── ADR-004-Evidence-Centric-Decision-Making.md
│   │   ├── ADR-005-Canonical-Domain-Model.md
│   │   ├── ADR-006-policy-integrity-and-controlled-activation.md
│   │   └── ADR-007-Controlled Trust-State Promotion and Transition Integrity
│   └── Architecture/
│       ├── ACHYUTA-V1.excalidraw
│       ├── Entity-specification-of-Architecture.excalidraw
│       ├── Trust-Core-Hardening.md
│       ├── core-domain-model.md
│       ├── core-domain-model.mmd
│       └── domain-glossary.md
├── engine/
│   ├── __init__.py
│   ├── decision.py
│   ├── evidence.py
│   ├── policy.py
│   ├── request.py
│   ├── risk.py
│   └── trust.py
├── lab/
│   ├── mock_telemetry/
│   └── scenarios/
│       ├── evidence_based_execution.yaml
│       ├── policy_conflict.yaml
│       ├── signed_execution.yaml
│       ├── suspicious_powershell.yaml
│       └── unsigned_execution.yaml
├── scripts/
├── specs/
│   ├── 001-trust-state-management/
│   │   ├── checklists/
│   │   ├── data-model.md
│   │   ├── plan.md
│   │   ├── quickstart.md
│   │   ├── research.md
│   │   ├── spec.md
│   │   └── tasks.md
│   └── 002-continuous-trust-re-evaluation/
│       ├── checklists/
│       ├── contracts/
│       ├── data-model.md
│       ├── plan.md
│       ├── quickstart.md
│       ├── research.md
│       ├── spec.md
│       └── tasks.md
├── tests/
│   ├── __init__.py
│   ├── test_decision.py
│   ├── test_evidence.py
│   ├── test_evidence_policy.py
│   ├── test_integration.py
│   ├── test_policy.py
│   └── test_trust.py
├── .github/
├── .specify/
├── venv/
└── ...
```

## 2. Current architecture

### All active engine modules

The active modules under `engine/` are:

- `engine/trust.py`
- `engine/request.py`
- `engine/evidence.py`
- `engine/policy.py`
- `engine/decision.py`

The file `engine/risk.py` exists but is empty and is not currently contributing implemented logic.

### Responsibility of each module

#### `engine/request.py`

Responsible for request structure and request-centric evaluation support.

Key ideas from the source:

- `SecurityRequest` is the central object evaluated by ACHYUTA.
- It groups `identity`, `subject`, `action`, `resource`, `context`, and `evidence`.
- It normalizes evidence via `normalize_evidence_item()` when attached.
- It supports `create_fresh_request()` to create a fresh request for re-evaluation while preserving prior request lineage.
- It exposes `requires_re_evaluation()` for detecting whether new evidence or relevant context should trigger re-evaluation.

#### `engine/evidence.py`

Responsible for evidence representation and basic validation.

Key features:

- `Evidence` dataclass for evidence objects.
- `validate_evidence()` enforces required fields and valid `strength` values.
- `create_evidence()` builds and validates evidence objects.
- `normalize_evidence_item()` converts an `Evidence` instance or a mapping into canonical `Evidence` objects.
- `filter_verified_evidence()` and `filter_by_category()` provide basic evidence filters.

Important implementation note:

- The module explicitly documents that cryptographic verification, provenance, and attestation are deferred for later implementation.

#### `engine/policy.py`

Responsible for evaluating a YAML policy against a `SecurityRequest`.

Key features:

- `load_policy()` loads a policy from disk and validates that the YAML contains a `policy` object.
- `_check_conditions()` compares request sections against expected values.
- `_check_evidence_conditions()` checks matching evidence categories and values against the request.
- `evaluate_policy()` evaluates a single policy.
- `evaluate_policies()` evaluates multiple policies.
- `evaluate_current_policy()` is a compatibility seam for re-evaluation flows.
- `current_policy_summary()` creates a compact policy summary for audit records.

Important implementation note:

- `evaluate_policies()` explicitly states that conflict resolution is intentionally not implemented yet.

#### `engine/decision.py`

Responsible for turning matching policy results into a final decision.

Key features:

- `DecisionEffect` enum enumerates authorization outcomes: `permit`, `monitor`, `require_verification`, `restrict`, `quarantine`, `deny`.
- `resolve_decision()` selects the most restrictive matching policy result.
- `resolve_current_decision()` is a compatibility seam for re-evaluation flows.
- `orchestrate_re_evaluation()` coordinates the re-evaluation flow: request -> policy -> decision.

Important implementation note:

- The docstring states that `Viveka` does not enforce decisions; enforcement is assigned to `Raksha`.
- The decision layer is not the trust-state mutation layer.

#### `engine/trust.py`

Responsible for entity trust state, transitions, recovery, and explainability.

Key features:

- `TrustState` enum contains actual runtime values.
- `EntityType` enum contains canonical entity types.
- `TrustTransition` is the immutable transition record.
- `TrustEntity` owns an entity's `state`, `reason`, `state_since`, and `transition_history`.
- `TrustEntity.transition()` performs ordinary transitions.
- `TrustEntity.promote_to_trusted()` implements the controlled `TRUSTED` promotion boundary.
- `TrustEntity.record_re_evaluation()` records re-evaluation metadata.
- `TrustEntity.evaluate_re_evaluation()` applies a re-evaluation update.
- `TrustEntity.recover()` applies entity-scoped recovery.
- `ReEvaluationTrigger` and `ReEvaluationRecord` capture trigger and audit records.
- `build_trust_explanation()` assembles the request-to-trust trace.
- `trust_state_from_decision()` maps a decision effect to a trust state.
- `apply_re_evaluation_transition()` converts decision effects to target states and executes a controlled re-evaluation transition.

### Data flow between modules

The data flow that is actually implemented is:

1. `SecurityRequest` in `engine/request.py` groups identity, subject, action, resource, context, and evidence.
2. Evidence is created via `create_evidence()` in `engine/evidence.py` and attached to the request.
3. Policies are loaded from YAML using `load_policy()` in `engine/policy.py`.
4. `evaluate_policy()` compares request fields and evidence conditions to the policy.
5. One or more `PolicyResult` values are passed to `resolve_decision()` in `engine/decision.py`.
6. `Decision` is returned with `effect`, `matched_policy_ids`, `reason`, and `decision_id`.
7. `TrustEntity` receives a decision context when trusted promotion is needed, but trust is kept distinct from authorization.
8. `TrustEntity` transitions and records `TrustTransition` and `ReEvaluationRecord` entries in `engine/trust.py`.

This is the real implemented flow in the codebase; it is not a formal enforcement engine.

### Trust evaluation flow

The repository's implemented trust evaluation flow is best expressed as:

```text
SecurityRequest
    -> Evidence
    -> Policy evaluation (Niyama)
    -> Decision resolution (Viveka)
    -> TrustEntity state update (Trust State boundary)
    -> Transition history / re-evaluation audit record
```

The code strongly enforces separation between:

- request and evidence
- policy evaluation
- decision selection
- trust-state mutation and history

Important discrepancy:

- The ADR and architecture-doc narrative mentions a broader risk assessment / enforcement path (`Risk Assessment`, `Enforcement Action`, `Telemetry Event`), but `engine/risk.py` is empty and no enforcement implementation exists under `engine/`.
- The architecture docs therefore describe a larger intended system than the currently implemented codebase.

## 3. Domain model

The codebase includes a canonical domain model implicitly and explicitly in the engine dataclasses and the ADRs.

### Identity

Current code usage:

- `SecurityRequest.identity: dict[str, Any]` in `engine/request.py`
- Identity is described as a request attribute, not a dedicated class.

### Subject

Current code usage:

- `SecurityRequest.subject: dict[str, Any]`
- Used in policy matching and re-evaluation checks.

### Request

Current code usage:

- `SecurityRequest` dataclass in `engine/request.py`
- Fields:
  - `request_id`
  - `identity`
  - `subject`
  - `action`
  - `resource`
  - `context`
  - `evidence`
  - `history_id`

### Action

Current code usage:

- `SecurityRequest.action: dict[str, Any]`
- Used by policy conditions and re-evaluation comparison.

### Resource

Current code usage:

- `SecurityRequest.resource: dict[str, Any]`
- Used by policy matching and re-evaluation comparison.

### Evidence

Current code usage:

- `Evidence` dataclass in `engine/evidence.py`
- Fields:
  - `evidence_id`
  - `category`
  - `source`
  - `value`
  - `strength`
  - `timestamp`
  - `verified`
  - `metadata`

### Policy

Current code usage:

- `PolicyResult` dataclass in `engine/policy.py`
- `load_policy()` loads a YAML policy.
- Policy structure is dynamic and dictionary-based rather than a dedicated Python policy class.

### Decision

Current code usage:

- `Decision` dataclass in `engine/decision.py`
- Fields:
  - `effect: DecisionEffect`
  - `matched_policy_ids: tuple[str, ...]`
  - `reason: str`
  - `decision_id: str = ""`

### Trust State

Current code usage:

- `TrustState` enum in `engine/trust.py`
- Actual values are:
  - `UNKNOWN`
  - `UNVERIFIED`
  - `TRUSTED`
  - `QUARANTINED`
  - `UNTRUSTED`

### Trust transition

Current code usage:

- `TrustTransition` dataclass in `engine/trust.py`
- Fields:
  - `from_state`
  - `to_state`
  - `reason`
  - `timestamp`
  - `evidence_ids`
  - `recovery_mode`

### Re-evaluation trigger / record / explanation

Current code usage:

- `ReEvaluationTrigger` dataclass in `engine/trust.py`
- `ReEvaluationRecord` dataclass in `engine/trust.py`
- `TrustExplanation` dataclass in `engine/trust.py`
- `build_trust_explanation()` assembles the trace from request, policy results, decision, and resulting state.

### Other canonical entities actually present

The actual codebase contains these additional concrete elements:

- `EntityType` enum in `engine/trust.py` with `IDENTITY`, `SUBJECT`, `PROCESS`, `RESOURCE`, and `DEVICE`.
- `RecoveryMode` enum in `engine/trust.py` with `AUTOMATIC`, `STRONG_REVERIFICATION`, and `HUMAN_APPROVAL`.
- `TrustEntity` dataclass in `engine/trust.py` holding the authoritative state and history for an entity.

## 4. Security boundaries

### What can mutate Trust State

From `engine/trust.py`, the implemented mutation paths are:

- `TrustEntity.transition()`
- `TrustEntity.promote_to_trusted()`
- `TrustEntity.record_re_evaluation()`
- `TrustEntity.evaluate_re_evaluation()`
- `TrustEntity.recover()`

These are the only implemented mutation mechanisms. The code explicitly prevents direct mutation of `TrustEntity.state` via `__setattr__` when `_state_locked` is true.

### What cannot mutate Trust State

The code explicitly forbids or rejects:

- direct initialization into `TRUSTED`
- direct assignment to `entity.state`
- raw string decision values being used as promotion context
- ordinary transitions directly promoting to `TRUSTED`
- bypassing recovery requirements through ordinary transitions
- external mutation of transition history after creation

This is enforced in `engine/trust.py` by validation inside `TrustEntity.__post_init__()`, `TrustEntity.__setattr__()`, `TrustEntity.transition()`, `TrustEntity.promote_to_trusted()`, and `recover()`.

### TRUSTED promotion mechanism

The actual controlled boundary is:

- `TrustEntity.promote_to_trusted()`

Requirements enforced by code:

- `reason` must be non-empty.
- At least one evidence ID must be supplied.
- `decision` cannot be `None`.
- `decision` cannot be a raw string.
- `decision` must be an instance of `Decision`.
- The decision's `effect` must be a recognized `DecisionEffect`.
- Only `DecisionEffect.PERMIT` is accepted for trust promotion.

This is a real boundary and not merely a convenience wrapper.

### Evidence requirements

The current implementation requires evidence values to satisfy `validate_evidence()` in `engine/evidence.py`:

- evidence ID cannot be empty
- category cannot be empty
- source cannot be empty
- strength must be in `VALID_STRENGTHS` = `{"very_low", "low", "medium", "high", "very_high"}`

Additionally, `TrustEntity.promote_to_trusted()` requires a non-empty evidence ID tuple.

### Decision requirements

For `TRUSTED` promotion, `engine/trust.py` requires:

- a `Decision` object, not a string
- a valid `DecisionEffect`
- the effect must be `PERMIT`
- `decision_id` is not required by the constructor, but the code expects a decision context to exist

### Request-centric boundaries

The code enforces a request-centric evaluation model in `engine/request.py` and `engine/policy.py`:

- `SecurityRequest` is the central evaluation object.
- Auth decisions are resolved against request + evidence + policy.
- `TrustEntity` stores entity-level trust state separately from request-level authorization.

The code explicitly distinguishes:

- `Decision` = what should happen to this request?
- `TrustState` = what ACHYUTA believes about this entity?

This appears in the module-level docstring for `engine/trust.py`.

### Audit/history behavior

The code preserves audit history in `TrustTransition` and `ReEvaluationRecord`:

- `TrustTransition` records `from_state`, `to_state`, `reason`, `timestamp`, `evidence_ids`, and `recovery_mode`.
- `TrustEntity.transition_history` is append-only in normal usage.
- `ReEvaluationRecord` captures `trigger_id`, `request_id`, `previous_request_id`, `evidence_ids`, `policy_summary`, `decision_id`, `resulting_state`, and `transition_reason`.
- `build_trust_explanation()` assembles a traceable request/policy/decision/trust-state summary.

## 5. Current TrustState values

These values are read directly from `engine/trust.py`:

```python
class TrustState(str, Enum):
    UNKNOWN = "unknown"
    UNVERIFIED = "unverified"
    TRUSTED = "trusted"
    QUARANTINED = "quarantined"
    UNTRUSTED = "untrusted"
```

Therefore the current supported trust states are exactly:

- `TrustState.UNKNOWN`
- `TrustState.UNVERIFIED`
- `TrustState.TRUSTED`
- `TrustState.QUARANTINED`
- `TrustState.UNTRUSTED`

This is the source-of-truth set, not the broader list described in some ADRs.

## 6. Current implementation

### Important classes and their file paths

- `engine/evidence.py`
  - `Evidence`
  - `normalize_evidence_item()`
  - `VALID_STRENGTHS`
  - `validate_evidence()`
  - `create_evidence()`
  - `filter_verified_evidence()`
  - `filter_by_category()`

- `engine/request.py`
  - `SecurityRequest`
  - `is_relevant_request()`
  - `create_fresh_request()`
  - `request_history_id()`
  - `request_context_for_re_evaluation()`
  - `has_fresh_evidence()`
  - `has_contradictory_evidence()`
  - `requires_re_evaluation()`

- `engine/policy.py`
  - `PolicyResult`
  - `load_policy()`
  - `evaluate_policy()`
  - `evaluate_policies()`
  - `evaluate_current_policy()`
  - `current_policy_summary()`

- `engine/decision.py`
  - `DecisionEffect`
  - `Decision`
  - `resolve_decision()`
  - `resolve_current_decision()`
  - `orchestrate_re_evaluation()`

- `engine/trust.py`
  - `TrustState`
  - `EntityType`
  - `RecoveryMode`
  - `TrustTransition`
  - `TrustEntity`
  - `ReEvaluationTrigger`
  - `ReEvaluationRecord`
  - `TrustExplanation`
  - `build_trust_explanation()`
  - `trust_state_from_decision()`
  - `apply_re_evaluation_transition()`

### Important APIs

The actual public APIs that matter to the current repository are these:

- `engine/evidence.py`
  - `create_evidence(...)`
  - `validate_evidence(...)`
  - `normalize_evidence_item(...)`

- `engine/request.py`
  - `SecurityRequest(...)`
  - `SecurityRequest.add_evidence(...)`
  - `create_fresh_request(...)`
  - `requires_re_evaluation(...)`

- `engine/policy.py`
  - `load_policy(...)`
  - `evaluate_policy(...)`
  - `evaluate_policies(...)`

- `engine/decision.py`
  - `resolve_decision(...)`
  - `resolve_current_decision(...)`

- `engine/trust.py`
  - `TrustEntity.transition(...)`
  - `TrustEntity.promote_to_trusted(...)`
  - `TrustEntity.recover(...)`
  - `build_trust_explanation(...)`
  - `apply_re_evaluation_transition(...)`

## 7. ADR alignment

The repository includes ADRs under `docs/ADR/`:

- `docs/ADR/ADR-001-trust-states.md`
- `docs/ADR/ADR-002-trust-recovery.md`
- `docs/ADR/ADR-003-request-centric-model.md`
- `docs/ADR/ADR-004-Evidence-Centric-Decision-Making.md`
- `docs/ADR/ADR-005-Canonical-Domain-Model.md`
- `docs/ADR/ADR-006-policy-integrity-and-controlled-activation.md`
- `docs/ADR/ADR-007-Controlled Trust-State Promotion and Transition Integrity`

### ADR-001: Adoption of Trust States Instead of Binary Authorization

Alignment: Mostly aligned.

Evidence from code:

- `TrustState` enum exists and is used by `TrustEntity`.
- `TrustEntity` is not simply a boolean allow/deny result.

Discrepancy:

- The ADR lists a broader set of conceptual states (`Observe`, `Verify`, `Restricted`, `Elevated`, `Revoked`, `Denied`) that are not present in the implemented `TrustState` enum in `engine/trust.py`.
- The current code only supports the five enum values enumerated in the source.

### ADR-002: Entity-Based Trust Recovery Model

Alignment: Partially aligned.

Evidence from code:

- `RecoveryMode` enum exists with `AUTOMATIC`, `STRONG_REVERIFICATION`, and `HUMAN_APPROVAL`.
- `TrustEntity.recover()` enforces entity-scoped recovery logic.
- Transition records can carry `recovery_mode`.

Discrepancy:

- `engine/trust.py` includes the recovery modes, but the repository does not implement a full entity-specific recovery policy framework beyond a method-level validation boundary.
- The ADR describes a richer policy model than the concrete code currently provides.

### ADR-003: Request-Centric Trust Evaluation Model

Alignment: Strongly aligned.

Evidence from code:

- `SecurityRequest` centralizes identity, subject, action, resource, context, and evidence.
- `create_fresh_request()` creates a distinct request context for re-evaluation.
- `requires_re_evaluation()` triggers based on fresh evidence or material request changes.

This is one of the clearest alignments between ADR and implementation.

### ADR-004: Evidence Is First-Class

Alignment: Strongly aligned in the implemented model.

Evidence from code:

- `Evidence` dataclass is first-class in `engine/evidence.py`.
- `SecurityRequest` stores evidence.
- Policy evaluation can match evidence conditions.
- `TrustEntity.promote_to_trusted()` requires evidence IDs.

Discrepancy:

- The ADR suggests stronger provenance and verification semantics than the current implementation actually enforces. The code is structural validation only; it does not yet check cryptographic provenance or attestation trust.

### ADR-005: Canonical Domain Model

Alignment: Moderately aligned.

Evidence from code:

- The domain model is represented in the request/evidence/policy/decision/trust objects.
- The canonical entities and lifecycle are largely reflected in the engine dataclasses.

Discrepancy:

- `Risk Assessment`, `Enforcement Action`, and `Telemetry Event` are described in the ADR, but there is no implemented `RiskAssessment` class and `engine/risk.py` is empty.
- `Raksha` does not exist as a currently active engine module under `engine/`.

### ADR-006: Policy Integrity and Controlled Activation

Alignment: Weakly aligned or not implemented.

Evidence from code:

- `load_policy()` loads and validates a YAML policy structure.
- `engine/policy.py` documents that cryptographic verification, policy signatures, provenance, and controlled activation are deferred.

Discrepancy:

- The ADR describes a controlled lifecycle: `Draft -> Validated -> Verified -> Approved -> Active -> Suspended/Retired`.
- No such lifecycle is implemented in code.
- This is explicitly acknowledged in the module docstring: policy integrity and controlled activation are deferred.

### ADR-007: Controlled Trust-State Promotion and Transition Integrity

Alignment: Strongly aligned with the hardening boundary implemented in `engine/trust.py`.

Evidence from code:

- Direct initialization to `TRUSTED` is rejected.
- `entity.state` is protected from direct mutation.
- Direct promotion via ordinary `transition()` is forbidden.
- `promote_to_trusted()` requires decision + evidence + reason.
- `TrustTransition` stores authoritative state metadata and the history is effectively append-only.

Discrepancy:

- The ADR discusses broader transition integrity and audit guarantees than the current public API exposes in a full operational system, but the actual code does enforce several of the core invariants.

## 8. SpecKit status

The repository contains SpecKit feature folders under `specs/`:

- `specs/001-trust-state-management/`
- `specs/002-continuous-trust-re-evaluation/`

### Feature 001: `specs/001-trust-state-management/`

Current tasks in `specs/001-trust-state-management/tasks.md` show a mixture of completed and incomplete work.

Completed tasks (actual `[x]` entries):

- T001
- T002
- T003
- T004
- T005
- T006
- T007
- T008
- T009
- T010
- T011
- T012
- T013
- T014
- T015
- T016
- T021
- T022
- T023
- T024
- T026

Not completed (actual `[ ]` entries):

- T017
- T018
- T019
- T020
- T025
- T027
- T028
- T029
- T030
- T031
- T032
- T033
- T034
- T035
- T036
- T037
- T038
- T039

This means the trust-state management feature is not fully completed; the repository contains partial implementation and partial task completion, with the ADR-007 hardening tasks still unchecked.

### Feature 002: `specs/002-continuous-trust-re-evaluation/`

Current tasks in `specs/002-continuous-trust-re-evaluation/tasks.md` show the feature is still incomplete.

Completed tasks (actual `[x]` entries):

- T001
- T003
- T004
- T005
- T006
- T007
- T026
- T027
- T028
- T029

Not completed (actual `[ ]` entries):

- T002
- T008
- T009
- T010
- T011
- T012
- T013
- T014
- T015
- T016
- T017
- T018
- T019
- T020
- T021
- T022
- T023
- T024
- T025

This indicates that the continuous trust re-evaluation feature has not yet reached a complete implementation state despite substantial foundational work.

### Important caution

The SpecKit task lists are a source of truth for task status only when checked in the file itself. The task checkboxes are therefore used as the authoritative status signal, not the prose surrounding them.

## 9. Test status

The repository test suite was run as-is using:

```bash
cd "h:\Live_Projects\Hacking_projects\ACHYUTA"; .\venv\Scripts\python.exe -m pytest -q
```

Result:

- 67 passed in 0.16s
- 0 failed

The tests present in the repository are:

- `tests/test_trust.py`
- `tests/test_decision.py`
- `tests/test_policy.py`
- `tests/test_evidence.py`
- `tests/test_evidence_policy.py`
- `tests/test_integration.py`

This indicates the current implemented engine is in a green state relative to the repository's test suite.

## 10. Current security invariants

### Invariants actually enforced by code/tests

The following invariants are backed by implementation and tests:

1. `TrustEntity` starts in `TrustState.UNKNOWN` unless intentionally configured otherwise.
   - Verified by `tests/test_trust.py`.

2. `TrustEntity.state` is not directly writable outside controlled mutation paths.
   - Enforced in `TrustEntity.__setattr__()`.

3. Direct initialization to `TRUSTED` is rejected.
   - Enforced in `TrustEntity.__post_init__()` and tested in `tests/test_trust.py`.

4. Ordinary transitions cannot directly promote to `TRUSTED`.
   - Enforced in `TrustEntity.transition()`.

5. `TRUSTED` promotion requires a valid `Decision` object and a permit decision.
   - Enforced in `TrustEntity.promote_to_trusted()`.

6. Recovery requires a supported recovery mode and can only run from `QUARANTINED` or `UNVERIFIED`.
   - Enforced in `TrustEntity.recover()`.

7. Evidence validation enforces required fields and valid strength values.
   - Enforced in `engine/evidence.py` and tested in `tests/test_evidence.py`.

8. Policy evaluation requires a matching policy against request and evidence criteria.
   - Enforced in `engine/policy.py` and tested in `tests/test_policy.py`.

9. Decision resolution chooses the most restrictive matching policy effect.
   - Enforced in `engine/decision.py` and tested in `tests/test_decision.py`.

10. Re-evaluation logic preserves a fresh request context and previous request lineage.

    - Enforced in `engine/request.py` and `tests/test_integration.py`.

### Documented requirements vs implemented guarantees

The following are documented requirements or architecture goals but not fully enforced by the current repository implementation:

- Full policy integrity and controlled activation lifecycle from ADR-006.
- Full cryptographic provenance/verification of evidence.
- Full risk assessment engine.
- Full enforcement layer (`Raksha`).
- Automated conflict-resolution logic between multiple policies.
- Production telemetry integration beyond the model.
- End-to-end Windows endpoint enforcement.

These are architectural intentions or documentation statements, not presently complete code guarantees.

## 11. Known gaps

The following issues are visible from the current repository state:

1. `engine/risk.py` is empty.
   - This is a direct functional gap relative to the domain model described by `docs/ADR/ADR-005-Canonical-Domain-Model.md` and `docs/Architecture/core-domain-model.md`.

2. `README.md` is empty.
   - The repository lacks a clear front-door description of purpose, setup, and current status.

3. There is no `pyproject.toml`, `requirements.txt`, or other package configuration file visible in the repository root.
   - The code currently appears to rely on a pre-existing virtual environment (`venv/`) rather than checked-in project configuration.

4. No real enforcement module exists under `engine/`.
   - The docstrings reference `Raksha`, but no code path implements it.

5. `engine/policy.py` describes policy integrity and activation as deferred,
   - but ADR-006 documents a richer policy lifecycle that is not implemented.

6. `docs/Security-Features-by-default.md` is empty.
   - This is documentation drift relative to the rest of the architecture.

7. Some architecture docs refer to future or broader system components that are not implemented in the codebase.
   - Example: `Risk Assessment`, `Enforcement Action`, and `Telemetry Event` are modeled conceptually, but not implemented as actual runtime modules.

8. Duplicate or deferred re-evaluation seams exist in the code.
   - `engine/decision.py` and `engine/policy.py` include compatibility seams for current-policy/current-decision evaluation, indicating a partial transition from earlier assumptions into later re-evaluation work.

9. `engine/request.py` contains logic that checks previous decisions via string values like `"allow"` and `"deny"`, while `engine/decision.py` defines `DecisionEffect` values as `permit` and `deny`.
   - This is a concrete mismatch between data values and runtime enum expectations and should be reviewed.

10. The repository has a partial feature pipeline, but the task checkboxes show several tasks still unchecked.

    - This indicates an in-progress rather than fully stabilized architecture.

## 12. Current milestone

The repository appears to be at a research/implementation milestone best described as:

- `v0.1 trust-state and request-centric evaluation prototype`
- partial trust-state management + re-evaluation scaffolding
- green repository test baseline
- architecture and ADR work ahead of full end-to-end enforcement

What has actually been completed:

- The trust-state domain is implemented in `engine/trust.py`.
- The request/evidence/policy/decision path is implemented in `engine/request.py`, `engine/evidence.py`, `engine/policy.py`, and `engine/decision.py`.
- The test suite is green (`67 passed in 0.16s`).
- The repo has substantial ADR and SpecKit documentation describing a larger intended architecture.
- The current codebase does not yet implement the broader production architecture described in the ADRs.

What remains incomplete in the repository state:

- full enforcement path (`Raksha`)
- full risk-assessment engine
- completed re-evaluation feature tasks from `specs/002-continuous-trust-re-evaluation/tasks.md`
- full ADR-006 lifecycle and ADR-007 hardening tasks from `specs/001-trust-state-management/tasks.md`

## 13. Recommended next investigation

Before defining the next feature, these architectural questions should be reviewed:

1. What is the authoritative lifecycle for `TrustEntity` persistence and state restoration across runs?
2. What are the exact responsibilities of `Raksha` and how will it interact with `Decision` and `TrustState` in a future enforcement layer?
3. What is the intended ownership model for `Risk Assessment`—is it a real runtime component, a policy sidecar, or a documentation-only concept?
4. How should policy precedence and conflict resolution work when multiple policies match the same request?
5. What is the actual source of evidence and how should provenance, attestation, and cryptographic verification be represented in production?
6. What is the intended event model for re-evaluation triggers: just request changes and new evidence, or broader telemetry or scheduled checks?
7. How should `TrustEntity` recovery and trust promotion integrate with a future operational policy engine instead of remaining method-level validation only?
8. What is the right boundary for request history and entity trust history when multiple entities are involved in a single operation?
9. What is the expected persistence contract for `TrustTransition` and `ReEvaluationRecord` in long-lived systems?
10. Does the current repository want to remain a model-level prototype or evolve into an enforceable runtime system with real telemetry and policy activation controls?

## Source of Truth

The following information was derived from the actual repository state:

- Source code:
  - `engine/trust.py`
  - `engine/request.py`
  - `engine/evidence.py`
  - `engine/policy.py`
  - `engine/decision.py`
  - `engine/risk.py`
  - `engine/__init__.py`

- Tests:
  - `tests/test_trust.py`
  - `tests/test_decision.py`
  - `tests/test_policy.py`
  - `tests/test_evidence.py`
  - `tests/test_evidence_policy.py`
  - `tests/test_integration.py`

- ADRs:
  - `docs/ADR/ADR-001-trust-states.md`
  - `docs/ADR/ADR-002-trust-recovery.md`
  - `docs/ADR/ADR-003-request-centric-model.md`
  - `docs/ADR/ADR-004-Evidence-Centric-Decision-Making.md`
  - `docs/ADR/ADR-005-Canonical-Domain-Model.md`
  - `docs/ADR/ADR-006-policy-integrity-and-controlled-activation.md`
  - `docs/ADR/ADR-007-Controlled Trust-State Promotion and Transition Integrity`

- SpecKit documents:
  - `specs/001-trust-state-management/spec.md`
  - `specs/001-trust-state-management/tasks.md`
  - `specs/002-continuous-trust-re-evaluation/spec.md`
  - `specs/002-continuous-trust-re-evaluation/tasks.md`

- Configuration:
  - The repository does not currently contain a checked-in root-level Python project config or dependency manifest in the inspected tree.
  - The active environment is a local virtual environment under `venv/`.

This document therefore reflects the actual implementation and repository artifacts currently present, including where implementation and specification intentionally differ.
