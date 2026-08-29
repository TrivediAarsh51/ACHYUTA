---

description: "Task list for Trust State Management"
---

# Tasks: Trust State Management

**Input**: Design documents from `/specs/001-trust-state-management/`

**Prerequisites**: [plan.md](plan.md), [spec.md](spec.md), [research.md](research.md), [data-model.md](data-model.md), [quickstart.md](quickstart.md)

**Tests**: Included because the specification explicitly requires new automated coverage and preservation of the existing suite.

**Organization**: Tasks are grouped by user story so each story can be implemented and validated independently after the foundational phase.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Confirm the existing Python and pytest baseline before changing the trust domain.

- [X] T001 Run the baseline test and collection commands from [quickstart.md](quickstart.md) and record the existing 20-test result.
- [X] T002 [P] Review the ownership boundaries and implementation constraints in [plan.md](plan.md), [research.md](research.md), and [data-model.md](data-model.md) before editing [engine/trust.py](../../engine/trust.py).

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Establish the compatibility and domain-contract checks shared by all user stories.

**Checkpoint**: Foundation ready when the existing trust public names and request/evidence contracts are understood and covered by a baseline test run.

- [X] T003 Add a compatibility regression test for existing `TrustState`, `EntityType`, `TrustEntity`, `TrustTransition`, and `trust_state_from_decision` behavior in [tests/test_trust.py](../../tests/test_trust.py).
- [X] T004 Add a request/evidence boundary regression test confirming trust-related evidence identifiers remain compatible with [engine/request.py](../../engine/request.py) and [engine/evidence.py](../../engine/evidence.py).

---

## Phase 3: User Story 1 - Maintain Explicit Entity Trust (Priority: P1) MVP

**Goal**: Represent all five canonical entity types and five supported trust states with safe initialization and validated transitions.

**Independent Test**: Run the US1 tests in [tests/test_trust.py](../../tests/test_trust.py) to create each canonical entity, verify `UNKNOWN`, transition to supported states, and reject unsupported values without mutation.

### Tests for User Story 1

- [X] T005 [US1] Add tests for `IDENTITY`, `SUBJECT`, `PROCESS`, `RESOURCE`, and `DEVICE` initialization to `UNKNOWN` in [tests/test_trust.py](../../tests/test_trust.py).
- [X] T006 [US1] Add tests for all supported `TrustState` values and successful state transitions in [tests/test_trust.py](../../tests/test_trust.py).
- [X] T007 [US1] Add negative tests for unsupported entity/state values and verify the entity remains unchanged in [tests/test_trust.py](../../tests/test_trust.py).

### Implementation for User Story 1

- [X] T008 [US1] Implement or refine validation for canonical entity types, supported trust states, non-empty entity identifiers, and default `UNKNOWN` state in [engine/trust.py](../../engine/trust.py).
- [X] T009 [US1] Preserve backward-compatible construction and transition behavior for `TrustEntity` and `TrustTransition` while enforcing atomic state/history updates in [engine/trust.py](../../engine/trust.py).
- [X] T010 [US1] Run the focused US1 tests in [tests/test_trust.py](../../tests/test_trust.py) and confirm the existing state and transition tests pass.

**Checkpoint**: User Story 1 is independently functional when canonical entities initialize safely and supported transitions pass without changing authorization decisions.

---

## Phase 4: User Story 2 - Explain and Audit Trust Transitions (Priority: P1)

**Goal**: Make every accepted transition explainable, timestamped, evidence-linked, immutable, and chronologically auditable.

**Independent Test**: Run the US2 tests in [tests/test_trust.py](../../tests/test_trust.py) to perform multiple transitions and inspect every history record.

### Tests for User Story 2

- [X] T011 [US2] Add tests verifying previous state, new state, reason, UTC timestamp, and evidence identifiers on each transition in [tests/test_trust.py](../../tests/test_trust.py).
- [X] T012 [US2] Add tests for chronological multi-transition history, immutable transition records, blank reasons, empty evidence, and invalid timestamp handling in [tests/test_trust.py](../../tests/test_trust.py).

### Implementation for User Story 2

- [X] T013 [US2] Extend the transition record in [engine/trust.py](../../engine/trust.py) to preserve immutable UTC audit metadata and optional evidence identifiers without mutating [engine/evidence.py](../../engine/evidence.py).
- [X] T014 [US2] Implement transition validation and append-only history consistency in [engine/trust.py](../../engine/trust.py), including rejection of blank reasons and non-comparable timestamps.
- [X] T015 [US2] Add an explainability integration test tracing request evidence through policy and decision inputs to the selected trust transition without moving ownership across [engine/request.py](../../engine/request.py), [engine/evidence.py](../../engine/evidence.py), [engine/policy.py](../../engine/policy.py), or [engine/decision.py](../../engine/decision.py).
- [X] T016 [US2] Run the focused audit and explainability tests in [tests/test_trust.py](../../tests/test_trust.py) and [tests/test_integration.py](../../tests/test_integration.py).

**Checkpoint**: User Story 2 is independently functional when reviewers can reconstruct every accepted transition and its evidence-backed reason from entity history.

---

## Phase 5: User Story 3 - Apply Conservative, Entity-Specific Trust Recovery (Priority: P2)

**Goal**: Support quarantine, conservative DENY handling, explicit UNTRUSTED transitions, and ADR-002 recovery modes scoped to one entity.

**Independent Test**: Run the US3 tests in [tests/test_trust.py](../../tests/test_trust.py) to deny or quarantine entities, recover one entity with each mode, and verify unrelated entities remain unchanged.

### Tests for User Story 3

- [ ] T017 [US3] Add tests confirming DENY maps to `QUARANTINED` for Process, Subject, and Resource and never directly establishes permanent `UNTRUSTED` in [tests/test_trust.py](../../tests/test_trust.py).
- [ ] T018 [US3] Add tests for `AUTOMATIC`, `STRONG_REVERIFICATION`, and `HUMAN_APPROVAL` recovery modes on recovery transitions in [tests/test_trust.py](../../tests/test_trust.py).
- [ ] T019 [US3] Add tests proving recovery changes only the selected entity, requires its applicable evidence/reason, and allows explicit `UNTRUSTED` only as a separate transition in [tests/test_trust.py](../../tests/test_trust.py).

### Implementation for User Story 3

- [ ] T020 [US3] Add a constrained `RecoveryMode` representation and conditional recovery-mode field to transition records in [engine/trust.py](../../engine/trust.py).
- [X] T021 [US3] Implement entity-scoped recovery validation in [engine/trust.py](../../engine/trust.py), requiring exactly one ADR-002 recovery mode and preventing implicit recovery of related entities.
- [X] T022 [US3] Preserve and test conservative decision-to-trust mapping for DENY, RESTRICT, QUARANTINE, MONITOR, and REQUIRE_VERIFICATION in [engine/trust.py](../../engine/trust.py) without changing [engine/decision.py](../../engine/decision.py).
- [X] T023 [US3] Run the focused recovery tests in [tests/test_trust.py](../../tests/test_trust.py) and verify no endpoint enforcement code is introduced under [engine](../../engine).

**Checkpoint**: User Story 3 is independently functional when quarantine and recovery are auditable, entity-specific, and separate from authorization outcomes.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Validate the complete feature against the specification, architecture, and safety boundaries.

- [X] T024 [P] Update the trust-model implementation notes and validation references in [quickstart.md](quickstart.md) if the final public domain signature differs from the planned examples.
- [ ] T025 Run the complete regression suite from [quickstart.md](quickstart.md) and confirm all existing tests plus new trust coverage pass.
- [X] T026 Review [engine/trust.py](../../engine/trust.py), [tests/test_trust.py](../../tests/test_trust.py), and [tests/test_integration.py](../../tests/test_integration.py) against the constitution and [data-model.md](data-model.md), confirming no evidence, policy, decision, or enforcement responsibility has leaked into trust-state management.

---

## Phase 7: ADR-007 Security Hardening & Controlled Trust-State Promotion

**Purpose**: Implement ADR-007 security controls to prevent unauthorized promotion to `TRUSTED`, ensure transition integrity, protect history from mutation, and establish controlled state machine semantics.

**Related Document**: [docs/ADR/ADR-007-Controlled Trust-State Promotion and Transition Integrity](../../docs/ADR/ADR-007-Controlled%20Trust-State%20Promotion%20and%20Transition%20Integrity)

**Baseline**: Existing 48-passing-test foundation from Phase 1-6.

### Tests for ADR-007 Security Hardening

- [ ] T027 [P] Establish a regression-test baseline snapshot in [tests/test_trust.py](../../tests/test_trust.py) and [tests/test_integration.py](../../tests/test_integration.py) before implementing any ADR-007 hardening to verify all 48 existing tests remain passing throughout Phase 7.
- [ ] T028 Add tests confirming that direct `TRUSTED` initialization is rejected and an entity initializes only to `UNKNOWN` state in [tests/test_trust.py](../../tests/test_trust.py).
- [ ] T029 Add tests verifying that direct mutation of an entity's current trust state through public interfaces is unavailable or rejected in [tests/test_trust.py](../../tests/test_trust.py).
- [ ] T030 Add tests confirming that transition history is immutable and protected from external modification, reordering, insertion, deletion, or replacement in [tests/test_trust.py](../../tests/test_trust.py).
- [ ] T031 Add tests proving that ordinary transitions CANNOT independently promote an entity to `TRUSTED` and that `TRUSTED` promotion is blocked as an ordinary state transition in [tests/test_trust.py](../../tests/test_trust.py).
- [ ] T032 Add tests verifying that recovery requirements CANNOT be bypassed through ordinary transitions and that recovery modes remain distinct from routine transitions in [tests/test_trust.py](../../tests/test_trust.py).
- [ ] T033 Add tests confirming that a raw decision value such as `"permit"` CANNOT independently produce `TRUSTED` promotion and that only validated decision contexts satisfy promotion requirements in [tests/test_trust.py](../../tests/test_trust.py).
- [ ] T034 Add tests validating that evidence identifiers supplied during transitions cannot promote an entity without correlated decision authority and that fabricated or unvalidated evidence references cannot independently justify `TRUSTED` in [tests/test_trust.py](../../tests/test_trust.py).
- [ ] T035 Add tests ensuring that every accepted transition records and preserves the authoritative source state, and that rejected operations never modify current state or transition history in [tests/test_trust.py](../../tests/test_trust.py).

### Implementation for ADR-007 Security Hardening

- [ ] T036 Implement the minimum Trust State changes in [engine/trust.py](../../engine/trust.py) required to enforce ADR-007 controls: protected `TRUSTED` promotion, no-direct-initialization, no-direct-state-mutation, history immutability, source-state validation, and separation of recovery from ordinary transitions.
- [ ] T037 [P] Review [engine/trust.py](../../engine/trust.py) against ADR-007 Section 2.1 responsibility boundaries to confirm that Pramana (evidence), Niyama (policy), Viveka (decision), and Raksha (enforcement) responsibilities remain outside the trust state component and that boundaries are preserved.

### Validation for ADR-007 Security Hardening

- [ ] T038 Run the complete regression suite from [quickstart.md](quickstart.md), confirming all 48+ existing tests plus all new ADR-007 hardening tests pass and no regression has occurred.
- [ ] T039 [P] Perform a final constitutional and ADR-007 security review of [engine/trust.py](../../engine/trust.py), the new test coverage in [tests/test_trust.py](../../tests/test_trust.py), and [tests/test_integration.py](../../tests/test_integration.py), confirming that ADR-007 decision points are met and that no unauthorized trust-state mutations, bypasses, or audit gaps remain.

**Checkpoint**: ADR-007 is fully implemented when all security hardening tests pass, `TRUSTED` promotion is controlled, transition history is immutable, recovery cannot be bypassed, and responsibility boundaries are preserved.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: T001 and T002 can start immediately; T003-T004 follow the baseline review.
- **Foundational (Phase 2)**: T003-T004 depend on T001-T002 and block all user-story work.
- **User Stories (Phase 3+)**: US1, US2, and US3 depend on Phase 2. US2 and US3 use the US1 trust domain, so the recommended delivery order is US1 -> US2 -> US3, although their tests can be prepared in parallel after the foundation.
- **Polish (Phase 6)**: Depends on all desired user stories being complete.
- **Security Hardening (Phase 7)**: Depends on Phase 1-6 being complete; implements ADR-007 controls on top of the stable Phase 1-6 foundation.

### User Story Dependencies

- **User Story 1 (P1)**: Depends only on the foundational compatibility checks; this is the MVP.
- **User Story 2 (P1)**: Depends on US1 transition behavior for history assertions, but remains independently testable against the trust domain.
- **User Story 3 (P2)**: Depends on US1 transitions and US2 audit fields so recovery modes are recorded and reviewable.

### Parallel Opportunities

- T002 can run in parallel with T001.
- T003 and T004 can run in parallel after T001-T002.
- After Phase 2, T005-T007 can be prepared in parallel only if separate workers coordinate edits to [tests/test_trust.py](../../tests/test_trust.py); otherwise execute them sequentially to avoid conflicts.
- T011 and T012 can be prepared in parallel with separate test-file ownership, then T013-T014 execute sequentially in [engine/trust.py](../../engine/trust.py).
- T017-T019 can be prepared in parallel with separate test-file ownership, then T020-T022 execute sequentially in [engine/trust.py](../../engine/trust.py).
- T024 can run in parallel with the final review before T025.
- T028-T035 (Phase 7 security hardening tests) can be prepared in parallel with explicit test-file ownership of non-overlapping regions in [tests/test_trust.py](../../tests/test_trust.py), but should execute sequentially to avoid merge conflicts. T036-T037 then implement sequentially in [engine/trust.py](../../engine/trust.py).

## Parallel Example: User Story 1

```text
Task: T005 Add canonical entity initialization tests in tests/test_trust.py
Task: T006 Add supported state transition tests in tests/test_trust.py
Task: T007 Add invalid input and no-mutation tests in tests/test_trust.py
```

These tests touch the same file, so they should be parallelized only with explicit ownership of non-overlapping regions; otherwise run them sequentially. T008-T009 then implement the shared domain behavior.

## Parallel Example: User Story 2

```text
Task: T011 Add transition audit-field tests in tests/test_trust.py
Task: T015 Add request/evidence/policy/decision explainability coverage in tests/test_integration.py
```

These tasks use different test files and can run in parallel after US1 is available.

## Parallel Example: User Story 3

```text
Task: T017 Add conservative DENY mapping tests in tests/test_trust.py
Task: T018 Add recovery-mode tests in tests/test_trust.py
Task: T019 Add recovery isolation and explicit UNTRUSTED tests in tests/test_trust.py
```

These tests share [tests/test_trust.py](../../tests/test_trust.py), so use explicit ownership or run sequentially. Implementation tasks T020-T022 share [engine/trust.py](../../engine/trust.py) and should run sequentially.

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 baseline setup.
2. Complete Phase 2 compatibility foundation.
3. Implement and validate Phase 3 User Story 1.
4. Stop and verify canonical entities, supported states, and safe transitions independently.

### Incremental Delivery

1. Add User Story 1 for explicit trust state representation.
2. Add User Story 2 for auditable, evidence-linked transition history.
3. Add User Story 3 for quarantine, conservative denial handling, and entity-specific recovery modes.
4. Run the full regression and constitutional boundary review.
5. Implement ADR-007 security hardening (Phase 7) to enforce controlled trust-state promotion, prevent unauthorized mutations, and protect audit integrity.

### ADR-007 Security Hardening Execution

Phase 7 tasks execute only after Phase 1-6 baseline stability is confirmed. The strategy is:

1. **T027**: Snapshot the 48 passing tests as a regression baseline.
2. **T028-T035**: Write all ADR-007 security tests in [tests/test_trust.py](../../tests/test_trust.py) (these will initially fail).
3. **T036**: Implement minimum Trust State changes to satisfy all ADR-007 tests.
4. **T037**: Boundary review confirming Pramana, Niyama, Viveka, Raksha remain outside Trust State.
5. **T038-T039**: Full regression validation and security sign-off.

### Notes

- Every task uses the required checkbox, sequential ID, optional parallel marker, story label where applicable, and an exact repository file path.
- No contract tasks are included because the plan identifies no external API, CLI, or UI contract.
- No Windows enforcement task is included; Raksha remains outside this feature.
- Phase 7 assumes Phase 1-6 are stable; no modifications to existing Phase 1-6 tasks are required or permitted.
