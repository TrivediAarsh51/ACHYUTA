# Tasks: Continuous Trust Re-Evaluation

**Input**: Design documents from `/specs/002-continuous-trust-re-evaluation/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: The feature specification includes independent test criteria for each user story, so test tasks are included for validation.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Confirm the baseline and working contracts for the feature before implementation.

- [x] T001 Confirm the existing trust, policy, decision, request, and evidence model boundaries in `engine/trust.py`, `engine/policy.py`, `engine/decision.py`, `engine/request.py`, and `engine/evidence.py`
- [ ] T002 [P] Re-run the current regression baseline with `pytest` to confirm the pre-feature behavior in `tests/test_trust.py`, `tests/test_decision.py`, `tests/test_policy.py`, `tests/test_evidence.py`, and `tests/test_integration.py`
- [x] T003 [P] Define the re-evaluation trigger and audit metadata contract in `specs/002-continuous-trust-re-evaluation/research.md` and `specs/002-continuous-trust-re-evaluation/contracts/re-evaluation-contract.md`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Establish the shared mechanisms that all re-evaluation flows depend on.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [x] T004 Implement the shared re-evaluation trigger and audit record metadata at the trust boundary in `engine/trust.py`
- [x] T005 [P] Add evidence provenance and current-context extraction helpers in `engine/evidence.py`
- [x] T006 [P] Add the fresh-request creation and request-history separation logic in `engine/request.py`
- [x] T007 Add the policy/decision integration seam for current evaluation inputs in `engine/policy.py` and `engine/decision.py`

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Re-evaluate Trust When Security Conditions Change (Priority: P1) 🎯 MVP

**Goal**: Enable a new evaluation when fresh evidence or a relevant request indicates that the prior trust state may no longer be valid.

**Independent Test**: Create a trusted entity, introduce a relevant security change, and verify the new evaluation creates a fresh request and a controlled trust-state transition instead of reusing the prior state.

### Tests for User Story 1

- [ ] T008 [P] [US1] Add a failing stale-trust regression test in `tests/test_trust.py` for re-evaluation on fresh evidence
- [ ] T009 [P] [US1] Add a failing re-evaluation integration test in `tests/test_integration.py` for fresh request-driven trust updates

### Implementation for User Story 1

- [ ] T010 [P] [US1] Implement trigger detection for newly added evidence and relevant new requests in `engine/request.py`
- [ ] T011 [P] [US1] Add the re-evaluation orchestration flow that reads current evidence, current policy, and current decision inputs in `engine/decision.py` and `engine/policy.py`
- [ ] T012 [US1] Update the trust-state transition path in `engine/trust.py` so it accepts a controlled re-evaluation without direct mutation of the previous state
- [ ] T013 [US1] Preserve the previous trust state while recording the new decision-backed transition reason and evidence references in `engine/trust.py`
- [ ] T014 [US1] Validate the user story through the acceptance scenarios in `specs/002-continuous-trust-re-evaluation/spec.md`

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: User Story 2 - Preserve Request-Centric Evaluation Boundaries (Priority: P1)

**Goal**: Ensure re-evaluation remains traceable and isolated so previous requests and decisions are never silently overwritten.

**Independent Test**: Run an original evaluation and a subsequent re-evaluation for the same entity and verify that request histories, decisions, and trust transitions remain distinct and explainable.

### Tests for User Story 2

- [ ] T015 [P] [US2] Add a failing request-isolation test in `tests/test_integration.py` confirming the new re-evaluation uses a different request context
- [ ] T016 [P] [US2] Add a regression test in `tests/test_trust.py` confirming historical and current trust states remain distinct audit entries

### Implementation for User Story 2

- [ ] T017 [P] [US2] Ensure fresh re-evaluation requests are created as separate request instances in `engine/request.py`
- [ ] T018 [US2] Record audit metadata for prior state, trigger, request id, evidence ids, policy summary, decision id, and resulting state in `engine/trust.py`
- [ ] T019 [US2] Keep authorization decision records separate from trust-state records while still passing decision context into transition validation in `engine/decision.py`
- [ ] T020 [US2] Verify that irrelevant signals do not trigger needless trust transitions in `tests/test_integration.py`

**Checkpoint**: At this point, User Stories 1 and 2 should both work independently

---

## Phase 5: User Story 3 - Apply Conservative Trust Effects and Explainability (Priority: P2)

**Goal**: Default to conservative trust handling when new evidence is insufficient or contradictory, while retaining an explainable audit trail.

**Independent Test**: Submit contradictory or incomplete evidence during re-evaluation and confirm the system restricts or quarantines the entity instead of silently retaining elevated trust.

### Tests for User Story 3

- [ ] T021 [P] [US3] Add a failing conservative fallback test in `tests/test_policy.py` for contradictory or incomplete evidence
- [ ] T022 [P] [US3] Add a failing audit explainability test in `tests/test_evidence_policy.py` covering the complete re-evaluation trail

### Implementation for User Story 3

- [ ] T023 [P] [US3] Implement conservative fallback handling in `engine/trust.py` when evidence is incomplete, contradictory, or inconclusive
- [ ] T024 [US3] Add the summary/audit chain generation that preserves Previous Trust State -> Trigger -> Request -> Evidence -> Policy -> Decision -> New Trust State in `engine/evidence.py` and `engine/trust.py`
- [ ] T025 [US3] Confirm that a previously trusted entity that remains trusted after a valid re-evaluation still keeps a distinct audit record and continues to pass review criteria

**Checkpoint**: All user stories should now be independently functional

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final verification, documentation, and regression safety checks.

- [x] T026 [P] Update the validation notes in `specs/002-continuous-trust-re-evaluation/quickstart.md` to reflect the implemented re-evaluation workflow
- [x] T027 [P] Review the feature contract in `specs/002-continuous-trust-re-evaluation/contracts/re-evaluation-contract.md` against the final implementation and update any mismatches
- [x] T028 Run the full repository regression suite for the trust and evaluation flow using `pytest` across `tests/`
- [x] T029 Remove redundant or dead code paths and confirm the architecture remains aligned with the constitution and ADRs in `engine/` and the feature docs

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
  - User Story 1 can start immediately after phase 2
  - User Story 2 can start after phase 2 and may run in parallel with US1 when capacity allows
  - User Story 3 can start after phase 2 and may run in parallel with US1/US2 when capacity allows
- **Polish (Final Phase)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Builds the core re-evaluation flow and can stand alone as the MVP
- **User Story 2 (P2)**: Depends on the request and audit boundary established in US1 but should remain independently testable
- **User Story 3 (P3)**: Depends on the trust fallback and audit model built in US1 and US2 but should remain independently testable

### Within Each User Story

- Tests MUST be written and fail before implementation
- Models and shared contracts before service logic
- Re-evaluation logic before audit and final validation
- Story complete before moving to the next priority

### Parallel Opportunities

- `T002` and `T003` can run in parallel during Setup
- `T005`, `T006`, and `T007` can run in parallel during Foundational work
- `T008` and `T009` can run in parallel for US1 test setup
- `T010` and `T011` can run in parallel for the US1 orchestration work
- `T015` and `T016` can run in parallel for US2 test setup
- `T017` and `T018` can run in parallel for US2 records and request isolation work
- `T021` and `T022` can run in parallel for US3 test setup
- `T023` and `T024` can run in parallel for US3 conservative fallback and audit work
- `T026` and `T027` can run in parallel during policy polish

---

## Parallel Example: User Story 1

```bash
# Launch all failing tests for User Story 1 together
pytest tests/test_trust.py -k reevaluation
pytest tests/test_integration.py -k reevaluation

# Launch the model and orchestration tasks together after the shared foundation is complete
# T010: trigger detection in engine/request.py
# T011: orchestration inputs in engine/decision.py and engine/policy.py
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories)
3. Complete Phase 3: User Story 1
4. Stop and validate the independent test criteria for the first story only
5. Continue with User Story 2 and then User Story 3 after the MVP passes

### Incremental Delivery

- Step 1: fix the stale-trust failure path with fresh requests and updated trust transitions
- Step 2: preserve trial history and audit separation without rewriting prior records
- Step 3: add conservative fallback rules and explainability review for contradictory evidence
- Step 4: run the full regression suite and finalize cross-cutting documentation

---

## Completion Criteria

- [ ] All tasks in this file follow the required checklist format
- [ ] Every user story has explicit independent test criteria
- [ ] Tasks map cleanly to the existing engine and test files
- [ ] The feature remains within the existing ACHYUTA boundaries, including trust-state integrity and request-centric evaluation
- [ ] The implementation can be validated by running the quickstart and the repository pytest suite
