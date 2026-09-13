---

description: "Executable task list for Authenticode signature evidence"
---

# Tasks: Executable Integrity / Authenticode Signature Evidence

**Input**: Design documents from `/specs/006-executable-authenticode-signature-evidence/`

**Prerequisites**: [plan.md](plan.md), [spec.md](spec.md), [research.md](research.md), [data-model.md](data-model.md), [contracts/windows-signature-evidence-contract.md](contracts/windows-signature-evidence-contract.md), and [quickstart.md](quickstart.md)

**Tests**: Included because the specification requires controlled positive, negative, integration, mutation-safety, and regression coverage.

**Organization**: Tasks are grouped by user story so each P1 story can be implemented and validated as an incremental slice.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Confirm the existing platform/evidence boundaries and establish the focused test surface.

- [X] T001 Review Feature 006 design artifacts and existing `platform/windows/observation.py`, `platform/windows/file_evidence.py`, `engine/evidence.py`, and `engine/request.py` before implementation

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Define the shared normalized signature result and canonical evidence boundary required by all user stories.

- [X] T002 [P] Add the `SignatureInspection` and `SignatureEvidenceResult` dataclass/protocol skeletons with timezone-aware timestamp and no-decision invariants in `platform/windows/signature_evidence.py`
- [X] T003 [P] Add shared observation fixtures, injected inspector doubles, and signature metadata builders for Feature 006 tests in `tests/test_windows_signature_evidence.py`

**Checkpoint**: Shared signature result types and deterministic test inputs are ready; user story implementation can proceed.

---

## Phase 3: User Story 1 - Observe Executable Signature State (Priority: P1) 🎯 MVP

**Goal**: Report signed and unsigned Authenticode observations through canonical, unverified Evidence.

**Independent Test**: Inject signed and unsigned inspection results for a valid `WindowsObservation`, collect both results, and verify explicit signature state, platform validation status, provenance, deterministic evidence identity, `verified=False`, and no authorization result.

### Tests for User Story 1

- [X] T004 [US1] Add failing unit tests for signed and unsigned inspection results, canonical evidence category/source, separate signature presence and validation fields, and `verified=False` in `tests/test_windows_signature_evidence.py`
- [X] T005 [US1] Add failing unit tests for deterministic evidence IDs across repeated unchanged observations and preservation of observation versus collection timestamps in `tests/test_windows_signature_evidence.py`

### Implementation for User Story 1

- [X] T006 [US1] Implement normalized signed/unsigned `SignatureInspection` handling and explicit `SignatureEvidenceResult` validation in `platform/windows/signature_evidence.py`
- [X] T007 [US1] Implement canonical signature evidence creation with category `windows_executable_signature`, source `platform.windows.signature`, deterministic identity, provenance metadata, and `verified=False` in `platform/windows/signature_evidence.py`
- [X] T008 [US1] Implement the injected inspector path using only `WindowsObservation.executable_path` and preserve the originating `WindowsObservation` unchanged in `platform/windows/signature_evidence.py`

**Checkpoint**: User Story 1 is independently functional for signed and unsigned observations.

---

## Phase 4: User Story 2 - Preserve Signature Details and Limitations (Priority: P1)

**Goal**: Preserve available signer/certificate metadata and represent every inspection limitation conservatively without fabricated signature claims.

**Independent Test**: Inject partial metadata, invalid, missing, inaccessible, unsupported, malformed, and unverifiable inspection outcomes and verify explicit status/reason, absent fabricated fields, provenance, read-only behavior, and no downstream engine side effects.

### Tests for User Story 2

- [X] T009 [US2] Add failing tests for signer subject, issuer, certificate identifier, signature algorithm, chain/revocation status, signing source, and partial metadata availability in `tests/test_windows_signature_evidence.py`
- [X] T010 [US2] Add failing parameterized tests for missing, inaccessible, unsupported, malformed, invalid, and unverifiable outcomes with no affirmative signature fields in `tests/test_windows_signature_evidence.py`
- [X] T011 [US2] Add failing tests that malformed paths and unsupported runtimes skip the inspector, preserve provenance, and expose no downstream engine imports or trust mutation in `tests/test_windows_signature_evidence.py`

### Implementation for User Story 2

- [X] T012 [US2] Implement literal observed-path validation, runtime gating, exception/status mapping, and explicit non-affirmative evidence in `platform/windows/signature_evidence.py`
- [X] T013 [US2] Implement partial metadata normalization, signing-source handling, and explicit catalog/non-Authenticode unsupported or unverifiable outcomes in `platform/windows/signature_evidence.py`
- [X] T014 [US2] Implement the Windows-native inspector boundary using literal-path `Get-AuthenticodeSignature` output normalization without adding third-party dependencies in `platform/windows/signature_evidence.py`

**Checkpoint**: User Stories 1 and 2 both preserve observable signature facts and handle uncertainty conservatively.

---

## Phase 5: User Story 3 - Route Signature Evidence Through Canonical Evaluation (Priority: P1)

**Goal**: Attach signature evidence to `SecurityRequest` and prove the existing evaluation flow remains the sole owner of risk, policy, decision, trust, and Raksha behavior.

**Independent Test**: Attach successful and non-affirmative signature evidence to an existing request, invoke normal runtime evaluation from the caller, and verify evidence traceability, downstream stage ordering, unchanged trust ownership, and unchanged behavior for requests without signature evidence.

### Tests for User Story 3

- [X] T015 [US3] Add an integration test for attaching signed and unsigned signature evidence through `SecurityRequest.add_evidence()` and evaluating it through risk, policy, decision, trust, and audit stages in `tests/test_windows_integration.py`
- [X] T016 [US3] Add an integration test for non-affirmative signature evidence reaching risk/policy evaluation without a collector decision or trust mutation in `tests/test_windows_integration.py`
- [X] T017 [US3] Add a regression test confirming requests without signature evidence and requests containing Feature 005 SHA-256 evidence retain their existing runtime behavior in `tests/test_windows_integration.py`

### Implementation for User Story 3

- [X] T018 [US3] Add any required public adapter export or compatibility wiring for `collect_signature_evidence` without changing `engine/request.py`, `engine/runtime.py`, `engine/risk.py`, `engine/policy.py`, `engine/decision.py`, `engine/trust.py`, or `engine/raksha.py`
- [X] T019 [US3] Add source-boundary assertions that `platform/windows/signature_evidence.py` does not import or call downstream engine components in `tests/test_windows_signature_evidence.py`

**Checkpoint**: All three user stories are independently validated through the canonical request-centric flow.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Complete regression, safety, and documentation validation across the feature.

- [X] T020 [P] Add conditional Windows native smoke coverage for literal-path inspection, read-only behavior, and platform-reported status in `tests/test_windows_signature_evidence.py`
- [X] T021 [P] Update Feature 006 validation references and implementation notes if the final provider behavior changes in `specs/006-executable-authenticode-signature-evidence/quickstart.md` and `specs/006-executable-authenticode-signature-evidence/contracts/windows-signature-evidence-contract.md`
- [X] T022 Run focused Feature 006 tests from `specs/006-executable-authenticode-signature-evidence/quickstart.md` and resolve failures without changing unrelated behavior
- [X] T023 Run the Windows regression tests in `tests/test_windows_collector.py`, `tests/test_windows_file_evidence.py`, and `tests/test_windows_integration.py`, then run the full `python -m pytest -q` suite and confirm requests without signature evidence remain compatible

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: T001 has no implementation dependency and establishes the local constraints.
- **Foundational (Phase 2)**: T002 and T003 depend on T001 and block all story work.
- **User Story 1 (Phase 3)**: T004-T008 depend on T002-T003; this is the MVP increment.
- **User Story 2 (Phase 4)**: T009-T014 depend on the shared types and US1 evidence shape, especially T006-T008.
- **User Story 3 (Phase 5)**: T015-T019 depend on the completed adapter behavior from US1 and US2; no engine changes are expected.
- **Polish (Phase 6)**: T020-T023 depend on all desired story phases and validate the complete feature.

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational; no dependency on another user story.
- **User Story 2 (P1)**: Depends on the US1 canonical result shape, but its failure and metadata tests remain independently runnable with injected inspectors.
- **User Story 3 (P1)**: Depends on the completed US1/US2 evidence contract to verify both positive and non-affirmative request evaluation.

### Parallel Opportunities

- T002 and T003 can run in parallel after T001 because they touch different files.
- Within US1, T004 and T005 can be drafted in parallel before implementation; T006-T008 are sequential within the adapter file.
- Within US2, T009-T011 can be drafted in parallel before T012-T014; implementation tasks in the same adapter file should be applied sequentially.
- T015 and T016 can run in parallel because they add separate integration tests; T020 and T021 can run in parallel with each other after story completion.

## Parallel Example: User Story 1

```text
Task T004: Add signed/unsigned contract tests in tests/test_windows_signature_evidence.py
Task T005: Add deterministic identity and timestamp tests in tests/test_windows_signature_evidence.py

After both test tasks are ready:
Task T006: Implement normalized signed/unsigned result handling in platform/windows/signature_evidence.py
Task T007: Implement canonical evidence creation in platform/windows/signature_evidence.py
Task T008: Implement observed-path inspector integration in platform/windows/signature_evidence.py
```

## Parallel Example: User Story 3

```text
Task T015: Add successful signed/unsigned request-flow integration test in tests/test_windows_integration.py
Task T016: Add non-affirmative request-flow integration test in tests/test_windows_integration.py
```

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete T001-T003 foundational setup.
2. Write T004-T005 and confirm the new tests fail before implementation.
3. Complete T006-T008.
4. Validate signed and unsigned observations independently.
5. Stop at the US1 checkpoint before adding failure and runtime integration breadth.

### Incremental Delivery

1. Add US1 for signed/unsigned evidence and deterministic provenance.
2. Add US2 for metadata, native provider normalization, and conservative failure outcomes.
3. Add US3 for canonical request/runtime integration and compatibility.
4. Complete polish, Windows smoke coverage, and full regression validation.

## Notes

- `[P]` tasks touch different files or are test-authoring tasks that can be prepared independently; implementation tasks in the same adapter file remain sequential.
- `[US1]`, `[US2]`, and `[US3]` map directly to the three P1 stories in `spec.md`.
- No task authorizes modifying files, processes, certificate stores, trust state, or downstream engine ownership.
