---

description: "Task list for Executable/File Evidence (SHA-256)"
---

# Tasks: Executable/File Evidence (SHA-256)

**Input**: Design documents from `/specs/005-executable-file-evidence-sha256/`

**Prerequisites**: [plan.md](plan.md), [spec.md](spec.md), [research.md](research.md), [data-model.md](data-model.md), [contracts/windows-file-evidence-contract.md](contracts/windows-file-evidence-contract.md)

**Tests**: Included because the feature specification requires automated tests for successful, negative, ambiguous, contract, integration, and regression behavior.

**Organization**: Tasks are grouped by user story so each story can be implemented and tested independently after the shared foundation.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the feature-specific source and test surfaces without changing protected engine responsibilities.

- [X] T001 [P] Create the file-evidence test module at `tests/test_windows_file_evidence.py` with shared `WindowsObservation` and controlled file-fixture helpers.
- [X] T002 [P] Add the platform-local file-evidence module at `platform/windows/file_evidence.py` with the public adapter boundary and no imports from `engine.risk`, `engine.policy`, `engine.decision`, `engine.trust`, `engine.runtime`, or `engine.raksha`.
- [X] T003 [P] Record the Feature 005 validation commands and expected outcomes in `specs/005-executable-file-evidence-sha256/quickstart.md`.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Define shared result, status, provenance, and canonical evidence construction used by all user stories.

**Checkpoint**: Foundation ready - user story implementation can now begin.

- [X] T004 Define the `FileEvidenceResult` shape and status lifecycle in `platform/windows/file_evidence.py`, including exactly one canonical evidence item per attempt and separate collection timestamp handling.
- [X] T005 Implement shared path validation, regular-file checks, observation provenance extraction, and deterministic evidence identity helpers in `platform/windows/file_evidence.py`.
- [X] T006 [P] Add foundational validation tests for timezone-aware observation timestamps, preserved process/path provenance, `verified=False`, and absence of authorization fields in `tests/test_windows_file_evidence.py`.

---

## Phase 3: User Story 1 - Record Deterministic Executable Evidence (Priority: P1) 🎯 MVP

**Goal**: Hash the executable path from a complete `WindowsObservation` with SHA-256 and return repeatable canonical evidence without making trust or authorization claims.

**Independent Test**: Hash an unchanged controlled fixture twice and verify identical lowercase SHA-256 values, canonical `Evidence`, source/path provenance, preserved observation timestamp, separate collection timestamp, and `verified=False`.

### Tests for User Story 1

- [X] T007 [P] [US1] Add contract tests for successful SHA-256 evidence shape, lowercase 64-character digest, canonical category/source, and omitted decision fields in `tests/test_windows_file_evidence.py`.
- [X] T008 [P] [US1] Add deterministic-repeat and observed-path-selection tests using unchanged and alternate fixture files in `tests/test_windows_file_evidence.py`.

### Implementation for User Story 1

- [X] T009 [US1] Implement one-pass read-only SHA-256 hashing from `WindowsObservation.executable_path` in `platform/windows/file_evidence.py` using the standard library.
- [X] T010 [US1] Build successful canonical `Evidence` in `platform/windows/file_evidence.py` with category `windows_executable_sha256`, source `platform.windows.file`, `verified=False`, preserved observation timestamp, collection timestamp metadata, and deterministic evidence ID.
- [X] T011 [US1] Add successful file-evidence attachment coverage through `SecurityRequest.add_evidence()` in `tests/test_windows_integration.py` and verify the request contains the canonical evidence item.

**Checkpoint**: User Story 1 is independently functional and demonstrates deterministic, unverified executable evidence.

---

## Phase 4: User Story 2 - Report File Evidence Limitations Without Claiming Safety (Priority: P1)

**Goal**: Preserve missing, inaccessible, unsupported, malformed, and unverifiable file conditions as explicit non-affirmative canonical evidence with status and reason but no digest.

**Independent Test**: Exercise controlled failure readers and paths, then verify each result has an explicit status/reason, preserved observation provenance, `verified=False`, no `value.sha256`, and no file/process mutation.

### Tests for User Story 2

- [X] T012 [P] [US2] Add missing-file, invalid-path, directory/special-file, and inaccessible-reader tests to `tests/test_windows_file_evidence.py`.
- [X] T013 [P] [US2] Add unsupported-runtime and unstable/read-failure tests with injected readers that prove file access is skipped or converted to `UNVERIFIABLE` in `tests/test_windows_file_evidence.py`.
- [X] T014 [P] [US2] Add non-affirmative request-evidence tests verifying status/reason retention, no digest, and no authorization/trust fields in `tests/test_windows_integration.py`.

### Implementation for User Story 2

- [X] T015 [US2] Implement explicit status mapping for missing, inaccessible, unsupported, malformed, directory/special-file, and unstable reads in `platform/windows/file_evidence.py`.
- [X] T016 [US2] Implement non-affirmative canonical evidence construction with status/reason value, `verified=False`, preserved process/path/timestamp provenance, and no digest in `platform/windows/file_evidence.py`.
- [X] T017 [US2] Ensure failure results attach through the existing `SecurityRequest.add_evidence()` path without changing `engine/request.py` in `platform/windows/file_evidence.py` and `tests/test_windows_integration.py`.

**Checkpoint**: User Stories 1 and 2 independently preserve both positive hash facts and collection uncertainty without affirmative safety claims.

---

## Phase 5: User Story 3 - Preserve the Canonical Security Evaluation Flow (Priority: P1)

**Goal**: Carry successful and non-affirmative file evidence through the existing request, risk, policy, decision, trust, and Raksha responsibilities without collector-side authorization.

**Independent Test**: Attach file evidence to a `SecurityRequest`, invoke `evaluate_runtime_request()` from the caller/test, and verify the existing evaluation trace and trust/enforcement ownership remain intact while the collector emits no decision.

### Tests for User Story 3

- [X] T018 [P] [US3] Add an end-to-end successful-evidence flow test through `SecurityRequest.add_evidence()` and `evaluate_runtime_request()` in `tests/test_windows_integration.py`.
- [X] T019 [P] [US3] Add a non-affirmative-evidence flow test confirming risk/policy evaluation receives the limitation and the collector does not resolve allow/deny or trust promotion in `tests/test_windows_integration.py`.
- [X] T020 [P] [US3] Add boundary tests that inspect `platform/windows/file_evidence.py` and protected engine modules for forbidden downstream imports or Windows collection logic in `tests/test_windows_file_evidence.py`.
- [X] T021 [P] [US3] Add read-only mutation assertions for fixture bytes, file metadata where practical, process observations, and `TrustEntity` state in `tests/test_windows_file_evidence.py`.

### Implementation for User Story 3

- [X] T022 [US3] Keep request/runtime integration caller-owned and document the adapter-to-request handoff in `platform/windows/file_evidence.py` and `specs/005-executable-file-evidence-sha256/contracts/windows-file-evidence-contract.md`.
- [X] T023 [US3] Preserve requests without Windows file evidence and existing process-only collection behavior by adding compatibility coverage in `tests/test_windows_integration.py` and `tests/test_windows_collector.py`.

**Checkpoint**: All three user stories preserve the canonical evidence-to-request-to-runtime path and keep authorization, trust, and enforcement outside the collector.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Complete regression, documentation, and security review gates across the feature.

- [X] T024 [P] Review `platform/windows/file_evidence.py` and `tests/test_windows_file_evidence.py` against the Feature 005 contract for secret-safe diagnostics and no out-of-scope WDAC/signature/malware/trust behavior.
- [X] T025 [P] Update `specs/005-executable-file-evidence-sha256/data-model.md` and `specs/005-executable-file-evidence-sha256/research.md` if implementation-level status names or result fields differ from the approved design.
- [X] T026 Run focused validation from `specs/005-executable-file-evidence-sha256/quickstart.md` with `python -m pytest tests/test_windows_file_evidence.py tests/test_windows_collector.py tests/test_windows_integration.py -q`.
- [X] T027 Run the complete regression suite with `python -m pytest -q` and record the result against `specs/005-executable-file-evidence-sha256/spec.md` success criterion SC-004.
- [X] T028 Run the conditional native Windows smoke test on an authorized Windows 11 Pro host with `python -m pytest tests/test_windows_collector.py -q`, confirming no endpoint mutation.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 Setup**: No implementation dependency; T001-T003 can run in parallel.
- **Phase 2 Foundational**: Depends on T001-T002; T004-T005 establish shared adapter behavior, while T006 can run in parallel after the test module exists.
- **Phase 3 User Story 1**: Depends on Phase 2; T007-T008 are written first, then T009-T011 implement and integrate the successful path.
- **Phase 4 User Story 2**: Depends on Phase 2 and the adapter surface from US1; T012-T014 precede T015-T017.
- **Phase 5 User Story 3**: Depends on the successful and failure result contracts from US1 and US2; T018-T023 validate caller-owned runtime integration and compatibility.
- **Phase 6 Polish**: Depends on all desired user stories; T026-T028 are final executable gates.

### User Story Dependencies

- **User Story 1 (P1)**: Starts after Phase 2; no dependency on another user story.
- **User Story 2 (P1)**: Starts after Phase 2 and shares the adapter/result foundation with US1; it extends the same adapter but has independent failure tests.
- **User Story 3 (P1)**: Depends on US1 and US2 evidence shapes so both successful and non-affirmative evidence can be evaluated through the same request path.

### Parallel Opportunities

- T001, T002, and T003 can run in parallel during setup.
- T006 can run alongside T004-T005 after the test module exists.
- T007 and T008 can run in parallel because they add distinct test cases in the same test module only if coordinated; otherwise run sequentially to avoid edit conflicts.
- T012, T013, and T014 can run in parallel across their distinct test concerns/files.
- T018-T021 can run in parallel across independent integration and boundary assertions.
- T024 and T025 can run in parallel with each other before the final test gates.

## Parallel Example: User Story 1

```text
Task T007: Add successful SHA-256 evidence contract tests in tests/test_windows_file_evidence.py
Task T008: Add deterministic-repeat and observed-path-selection tests in tests/test_windows_file_evidence.py

After the tests are ready:
Task T009: Implement read-only hashing in platform/windows/file_evidence.py
Task T010: Build canonical successful Evidence in platform/windows/file_evidence.py
Task T011: Verify SecurityRequest attachment in tests/test_windows_integration.py
```

## Parallel Example: User Story 2

```text
Task T012: Add missing/inaccessible/path failure tests in tests/test_windows_file_evidence.py
Task T013: Add unsupported/unstable reader tests in tests/test_windows_file_evidence.py
Task T014: Add non-affirmative request evidence tests in tests/test_windows_integration.py

After the tests are ready:
Task T015: Implement failure status mapping in platform/windows/file_evidence.py
Task T016: Build non-affirmative canonical Evidence in platform/windows/file_evidence.py
Task T017: Verify failure attachment through SecurityRequest.add_evidence()
```

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 setup and Phase 2 foundation.
2. Complete Phase 3 User Story 1.
3. Run the focused deterministic hashing and request-attachment tests.
4. Stop only when successful evidence is canonical, unverified, provenance-preserving, and read-only.

### Incremental Delivery

1. Deliver US1 for deterministic SHA-256 evidence.
2. Add US2 for explicit non-affirmative failure evidence.
3. Add US3 for full request/runtime flow and compatibility guarantees.
4. Complete the full regression and Windows smoke gates.

### Parallel Team Strategy

1. Complete setup and foundation together.
2. Assign US1 success-path tests/implementation, US2 failure-path tests/implementation, and US3 integration/boundary tests to separate contributors after the shared adapter contract is agreed.
3. Reconcile shared edits to `platform/windows/file_evidence.py` before the final validation phase.

## Requirement Traceability

- **FR-001 to FR-003**: T002, T005, T007-T010.
- **FR-004 to FR-006**: T005, T006, T010, T011.
- **FR-007 to FR-009**: T012-T016.
- **FR-010 to FR-012**: T014, T017-T022.
- **FR-013 to FR-015**: T013, T020-T021, T024, T028.
- **FR-016 to FR-017**: T007-T023, T026-T027.
- **SC-001**: T007-T011.
- **SC-002**: T012-T017.
- **SC-003**: T018-T022.
- **SC-004**: T023, T026-T027.
- **SC-005 to SC-007**: T005-T006, T018-T021, T024, T028.

## Notes

- `[P]` tasks touch distinct concerns/files and may run concurrently when edit conflicts are avoided.
- `[US1]`, `[US2]`, and `[US3]` map directly to the three P1 user stories in `spec.md`.
- Every task has a checkbox, sequential task ID, required story label where applicable, and at least one concrete repository path or executable validation command.
