---

description: "Task list for Windows endpoint evidence collection"
---

# Tasks: Windows Endpoint Evidence Collection

**Input**: Design documents from `/specs/004-windows-endpoint-evidence-collection/`

**Prerequisites**: [plan.md](plan.md), [spec.md](spec.md)

**Tests**: Included because Feature 004 requires tests-first implementation, focused failure coverage, integration coverage, and full regression validation.

**Organization**: Tasks are grouped by the three P1 user stories in the specification. User Story 1 is the suggested MVP; User Stories 2 and 3 complete the bounded feature.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the repository paths and test entry points required by the implementation plan.

- [X] T001 Create the `platform/__init__.py` and `platform/windows/__init__.py` package boundaries without adding Windows logic to engine modules
- [X] T002 [P] Add the Feature 004 Windows test module paths `tests/test_windows_collector.py` and `tests/test_windows_integration.py`
- [X] T003 [P] Confirm the existing pytest command and baseline test targets from `tests/test_evidence.py`, `tests/test_runtime.py`, and `tests/test_integration.py`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Define the platform-specific observation contract and the one justified canonical evidence extension before story work begins.

- [X] T004 [P] Write red validation tests for the six-field `WindowsObservation` contract in `tests/test_windows_collector.py`
- [X] T005 [P] Write the explicit `CollectionStatus` and `WindowsCollectionResult` contract tests for SUCCESS, UNAVAILABLE, PERMISSION_DENIED, STALE, MALFORMED, UNSUPPORTED, UNVERIFIABLE, and CONFLICT in `tests/test_windows_collector.py`
- [X] T006 [P] Add the optional timestamp regression test for canonical Evidence creation in `tests/test_evidence.py`
- [X] T007 Implement the backward-compatible `timestamp: datetime | None = None` parameter in `engine/evidence.py`, preserving the default timestamp behavior for existing callers
- [X] T008 [P] Implement immutable `WindowsObservation`, `WindowsCollectionFailure`, `WindowsCollectionResult`, and `CollectionStatus` in `platform/windows/observation.py`
- [X] T009 Run `python -m pytest tests/test_windows_collector.py tests/test_windows_integration.py tests/test_evidence.py -q` and verify failures are limited to the not-yet-implemented platform boundary or timestamp extension before proceeding

**Checkpoint**: Canonical evidence timestamp support and the platform-specific collection contracts are available without changing request, risk, policy, decision, trust, runtime, or Raksha behavior.

---

## Phase 3: User Story 1 - Collect Windows Endpoint Observations as Evidence (Priority: P1) 🎯 MVP

**Goal**: Collect the six scoped process fields and convert complete observations into the existing canonical Evidence model with provenance and timestamp preservation.

**Independent Test**: An injected controlled provider produces a complete Windows observation, the result exposes all six fields, conversion returns `engine.evidence.Evidence`, and the evidence can be attached through `SecurityRequest.add_evidence()` without exposing an authorization result.

### Tests for User Story 1

- [X] T010 [P] [US1] Add successful six-field observation and timestamp assertions in `tests/test_windows_collector.py`
- [X] T011 [P] [US1] Add canonical Evidence conversion, source/provenance, deterministic evidence ID, and timestamp assertions in `tests/test_windows_collector.py`
- [X] T012 [P] [US1] Add SecurityRequest association assertions proving attached values are canonical `Evidence` objects in `tests/test_windows_collector.py`

### Implementation for User Story 1

- [X] T013 [US1] Implement the provider protocol and `WindowsProcessCollector.collect()` success path in `platform/windows/collector.py` using injected provider records
- [X] T014 [US1] Implement `observation_to_evidence()` in `platform/windows/evidence.py` using `engine.evidence.create_evidence()` and preserving source, metadata, six process fields, and observation timestamp
- [X] T015 [US1] Add the read-only native Windows provider for process ID, process name, executable path, parent process ID, user identity, and observation timestamp in `platform/windows/system_provider.py`
- [X] T016 [US1] Export only the Windows observation, result, collector, and evidence adapter interfaces from `platform/windows/__init__.py`
- [X] T017 [US1] Verify the collector and evidence adapter contain no imports or calls to `engine/risk.py`, `engine/policy.py`, `engine/decision.py`, `engine/trust.py`, `engine/raksha.py`, or `engine/runtime.py`

**Checkpoint**: User Story 1 is independently functional: complete Windows observations become canonical evidence and can be attached to the existing request model without making decisions.

---

## Phase 4: User Story 2 - Continue Evaluation When Endpoint Evidence Is Incomplete (Priority: P1)

**Goal**: Represent every supported collection failure explicitly and ensure failures never become affirmative Evidence.

**Independent Test**: Controlled providers and records for unavailable, permission-denied, stale, malformed, unsupported, unverifiable, and contradictory conditions produce explicit result statuses, preserve diagnostic context, and produce no Evidence for failed records.

### Tests for User Story 2

- [X] T018 [P] [US2] Add provider-level unavailable, permission-denied, and timeout failure tests in `tests/test_windows_collector.py`
- [X] T019 [P] [US2] Add stale, malformed, unsupported, and unverifiable record tests in `tests/test_windows_collector.py`
- [X] T020 [P] [US2] Add contradictory observation tests proving complete conflicting records remain distinguishable and retain separate evidence IDs in `tests/test_windows_collector.py`
- [X] T021 [P] [US2] Add assertions that every failure result has empty evidence output and cannot expose an authorization effect in `tests/test_windows_collector.py`

### Implementation for User Story 2

- [X] T022 [US2] Implement explicit failure mapping and non-affirmative result handling in `platform/windows/collector.py`
- [X] T023 [US2] Implement validation for missing, invalid, incomplete, and unverifiable process fields in `platform/windows/observation.py`
- [X] T024 [US2] Implement freshness evaluation and STALE result handling in `platform/windows/collector.py`
- [X] T025 [US2] Preserve complete contradictory observations without collapsing records in `platform/windows/collector.py` and `platform/windows/observation.py`
- [X] T026 [US2] Ensure `WindowsCollectionResult.to_evidence()` converts successful observations only and never converts `WindowsCollectionFailure` in `platform/windows/observation.py`

**Checkpoint**: User Stories 1 and 2 are independently testable; collection failures are explicit, conservative, and cannot be interpreted as affirmative security evidence.

---

## Phase 5: User Story 3 - Preserve the Canonical Request-to-Trust Flow (Priority: P1)

**Goal**: Prove Windows-derived Evidence enters the existing SecurityRequest and runtime flow without a parallel evaluator or collector-side security responsibilities.

**Independent Test**: Attach Windows Evidence to a canonical SecurityRequest, run `evaluate_runtime_request()`, and verify risk, policy, decision, trust, and optional Raksha stages remain owned by their existing engine interfaces.

### Tests for User Story 3

- [X] T027 [P] [US3] Add the end-to-end Windows observation -> Evidence -> SecurityRequest -> Risk -> Policy -> Decision -> Trust integration test in `tests/test_windows_integration.py`
- [X] T028 [P] [US3] Add assertions that the collector does not return decisions, mutate TrustEntity state, invoke policy/decision/Raksha, or enforce Windows controls in `tests/test_windows_collector.py`
- [X] T029 [P] [US3] Add regression coverage proving requests without Windows Evidence retain existing runtime behavior in `tests/test_windows_integration.py`
- [X] T030 [P] [US3] Add optional Raksha-stage integration coverage using an active PolicyRecord and `enforce=True` in `tests/test_windows_integration.py`

### Implementation for User Story 3

- [X] T031 [US3] Attach converted Windows Evidence only through `SecurityRequest.add_evidence()` in `platform/windows/evidence.py` and `tests/test_windows_integration.py`
- [X] T032 [US3] Keep runtime orchestration delegated to `engine/runtime.py` and document or assert that the collector never calls `evaluate_runtime_request()` in `platform/windows/collector.py`
- [X] T033 [US3] Validate non-Windows execution returns UNSUPPORTED without invoking the provider or fabricating observations in `platform/windows/collector.py`
- [X] T034 [US3] Validate the existing engine modules remain unchanged except for the planned timestamp extension in `engine/evidence.py`

**Checkpoint**: All three user stories are independently demonstrable while preserving the canonical request-centric evaluation and enforcement boundaries.

---

## Phase 6: Polish & Cross-Cutting Validation

**Purpose**: Complete regression, safety, and implementation-boundary checks before integration.

- [X] T035 [P] Add focused test coverage for read-only native provider behavior and conditional Windows 11 Pro smoke execution in `tests/test_windows_collector.py`
- [X] T036 [P] Add module-boundary assertions that protected engine files contain no Windows-specific collection logic in `tests/test_windows_collector.py`
- [X] T037 Run `python -m pytest tests/test_windows_collector.py -q` and record the focused result
- [X] T038 Run `python -m pytest -v` and verify all existing and Feature 004 tests pass
- [X] T039 Run `git diff --check` and inspect changed files for unrelated modifications, generated artifacts, or prohibited endpoint-control behavior
- [X] T040 Update the Feature 004 checklist at `specs/004-windows-endpoint-evidence-collection/checklists/requirements.md` only after implementation validation confirms each acceptance criterion is satisfied

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies; establishes package and test paths.
- **Foundational (Phase 2)**: Depends on Setup; blocks all user story implementation.
- **User Story 1 (Phase 3)**: Depends on Foundational; is the MVP and establishes successful observation-to-evidence conversion.
- **User Story 2 (Phase 4)**: Depends on User Story 1's observation/result interfaces; hardens the same collector with explicit failure behavior.
- **User Story 3 (Phase 5)**: Depends on User Stories 1 and 2; proves canonical request/runtime integration and boundary preservation.
- **Polish (Phase 6)**: Depends on all desired user stories.

### User Story Dependencies

- **User Story 1 (P1)**: Can begin after Phase 2; no dependency on another story.
- **User Story 2 (P1)**: Depends on the observation and result contracts from User Story 1, but remains independently testable after those contracts exist.
- **User Story 3 (P1)**: Depends on successful evidence conversion and explicit failure semantics from User Stories 1 and 2.

### Parallel Opportunities

- T002, T003, T004, T005, and T006 can begin in parallel after repository setup inspection.
- T010, T011, and T012 can be written in parallel because they target separate test concerns in the same story.
- T018, T019, T020, and T021 can be written in parallel before failure implementation.
- T027, T028, T029, and T030 can be written in parallel before runtime integration changes.
- T035 and T036 can run in parallel with each other after implementation.

## Parallel Example: User Story 1

```text
Task T010: Add successful six-field observation tests in tests/test_windows_collector.py
Task T011: Add canonical Evidence conversion tests in tests/test_windows_collector.py
Task T012: Add SecurityRequest association tests in tests/test_windows_collector.py
```

These tests can be authored together before T013-T016 implement the collection and evidence adapter paths. They must fail first, then pass after the story implementation is complete.

## Parallel Example: User Story 2

```text
Task T018: Add unavailable and permission-denied tests in tests/test_windows_collector.py
Task T019: Add stale, malformed, unsupported, and unverifiable tests in tests/test_windows_collector.py
Task T020: Add contradictory-observation tests in tests/test_windows_collector.py
Task T021: Add non-affirmative failure assertions in tests/test_windows_collector.py
```

These tests share the collector boundary but cover independent failure classes; implementation tasks T022-T026 should follow the red test pass.

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 setup and Phase 2 foundational contracts.
2. Complete Phase 3 User Story 1.
3. Run `python -m pytest tests/test_windows_collector.py -q` and verify successful observation-to-Evidence behavior.
4. Stop for review if only the MVP is required; do not claim full Feature 004 completion until User Stories 2 and 3 pass.

### Incremental Delivery

1. Add User Story 1 for complete supported process observations.
2. Add User Story 2 for explicit conservative failure handling.
3. Add User Story 3 for canonical request-to-trust integration.
4. Complete Phase 6 full regression and architectural boundary validation.

### Safety Constraints

- Do not create a second Evidence or SecurityRequest model.
- Do not add Windows-specific logic to `engine/risk.py`, `engine/policy.py`, `engine/decision.py`, `engine/trust.py`, `engine/raksha.py`, or unrelated engine modules.
- Do not execute collected paths, launch or modify processes, change firewall or WDAC settings, alter registry policy, disable controls, or invoke endpoint enforcement.
- Keep the collector observation/evidence-only; downstream runtime/domain interfaces own risk, policy, decision, trust, and Raksha behavior.

## Notes

- `[P]` tasks target different concerns or files and can proceed concurrently when their listed dependencies are satisfied.
- Every task has a checkbox, sequential ID, and exact file path(s); user story tasks also carry the required story label.
- The task list reflects the current plan and repository structure; no optional data-model, research, or contract artifacts were available.