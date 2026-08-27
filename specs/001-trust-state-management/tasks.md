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

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: T001 and T002 can start immediately; T003-T004 follow the baseline review.
- **Foundational (Phase 2)**: T003-T004 depend on T001-T002 and block all user-story work.
- **User Stories (Phase 3+)**: US1, US2, and US3 depend on Phase 2. US2 and US3 use the US1 trust domain, so the recommended delivery order is US1 -> US2 -> US3, although their tests can be prepared in parallel after the foundation.
- **Polish (Phase 6)**: Depends on all desired user stories being complete.

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

### Notes

- Every task uses the required checkbox, sequential ID, optional parallel marker, story label where applicable, and an exact repository file path.
- No contract tasks are included because the plan identifies no external API, CLI, or UI contract.
- No Windows enforcement task is included; Raksha remains outside this feature.
