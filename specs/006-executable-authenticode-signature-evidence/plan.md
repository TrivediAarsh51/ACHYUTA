# Implementation Plan: Executable Integrity / Authenticode Signature Evidence

**Branch**: `006-executable-authenticode-signature-evidence` | **Date**: 2026-09-13 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from [spec.md](spec.md)

**Note**: This template is filled in by the `/speckit-plan` command; its definition describes the execution workflow.

## Summary

Add a read-only Windows signature-evidence adapter that inspects the executable path from an existing `WindowsObservation` and represents observable Authenticode facts as canonical, unverified `Evidence`. The adapter will use an injected inspector contract for deterministic tests and a replaceable Windows-native provider for endpoint use, preserve signer/certificate metadata and both timestamps, represent limitations explicitly, and leave request evaluation to the existing runtime flow.

## Technical Context

<!--
  ACTION REQUIRED: Replace the content in this section with the technical details
  for the project. The structure here is presented in advisory capacity to guide
  the iteration process.
-->

**Language/Version**: Python 3.x, matching the existing dataclass-based engine

**Primary Dependencies**: Python standard library and existing project modules; optional Windows-native `Get-AuthenticodeSignature` provider boundary; no new third-party dependency

**Storage**: In-memory canonical evidence and collection result objects; persistence is out of scope

**Testing**: pytest with injected inspectors, controlled observations, temporary fixtures, integration tests, mutation-safety checks, and conditional Windows native smoke coverage

**Target Platform**: Windows 11 Pro endpoint for native inspection; portable tests run on non-Windows hosts; core engine remains platform-independent

**Project Type**: Python security-model library with Windows platform adapters

**Performance Goals**: One bounded inspection per observed executable path; no new authorization latency or throughput target

**Constraints**: Use only the observed path; preserve observation and collection timestamps; keep `verified=False`; use literal path semantics; do not modify files, processes, certificate stores, or endpoint state; do not define publisher trust, revocation policy, WDAC enforcement, malware scanning, authorization, or trust promotion

**Scale/Scope**: One signature result per supported Windows process observation; embedded Authenticode observation only; catalog-only and unrelated signing mechanisms remain explicit out-of-scope outcomes; no persistence, scheduling, bulk inventory, or policy changes

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Evidence-centric security**: Signature presence, platform validation, and certificate metadata are recorded as observations; every result remains canonical and unverified.
- **Request-centric evaluation**: The caller attaches evidence through `SecurityRequest.add_evidence()` before normal runtime evaluation.
- **Separation of responsibilities**: Signature inspection remains under `platform/windows`; engine risk, policy, decision, trust, and Raksha owners remain unchanged.
- **Decision/trust separation**: The collector emits no authorization decision and performs no trust transition.
- **Conservative security**: Missing, inaccessible, unsupported, malformed, invalid, and unverifiable results remain explicit and non-affirmative.
- **Explainability/auditability**: Evidence retains process provenance, observed path, observation timestamp, collection timestamp, status, and available signature metadata.
- **Test before integration**: Unit, negative, provider-boundary, integration, mutation-safety, and regression tests are required.
- **Windows focus and safety**: Native inspection is Windows-specific and all endpoint operations are read-only.

No constitution exception is required.

## Project Structure

### Documentation (this feature)

```text
specs/[###-feature]/
├── plan.md              # This file (/speckit-plan command output)
├── research.md          # Phase 0 output (/speckit-plan command)
├── data-model.md        # Phase 1 output (/speckit-plan command)
├── quickstart.md        # Phase 1 output (/speckit-plan command)
├── contracts/           # Phase 1 output (/speckit-plan command)
└── tasks.md             # Phase 2 output (/speckit-tasks command - NOT created by /speckit-plan)
```

### Source Code (repository root)
<!--
  ACTION REQUIRED: Replace the placeholder tree below with the concrete layout
  for this feature. Delete unused options and expand the chosen structure with
  real paths (e.g., apps/admin, packages/something). The delivered plan must
  not include Option labels.
-->

```text
engine/
├── evidence.py                 # Existing canonical Evidence factory; unchanged unless timestamp compatibility requires reuse
├── request.py                  # Existing SecurityRequest.add_evidence(); unchanged
└── runtime.py                  # Existing evaluation boundary; unchanged

platform/windows/
├── observation.py              # Existing WindowsObservation and CollectionStatus
├── evidence.py                 # Existing process-observation adapter; unchanged
├── file_evidence.py            # Existing Feature 005 SHA-256 adapter; unchanged
└── signature_evidence.py       # New inspector boundary, native adapter, and canonical signature evidence

tests/
├── test_windows_signature_evidence.py # New unit/provider-boundary/mutation tests
└── test_windows_integration.py        # Existing runtime integration tests extended for signature evidence
```

**Structure Decision**: Keep Feature 006 in a focused `platform/windows/signature_evidence.py` adapter. Reuse `WindowsObservation`, `CollectionStatus`, `engine.evidence.create_evidence()`, and `SecurityRequest.add_evidence()`; do not add a Windows request/evidence model or modify downstream engine components.

## Phase 0: Research Decisions

Research is complete in [research.md](research.md). Key decisions are:

- Normalize injected/native inspection results behind a narrow inspector contract.
- Use the Windows-native Authenticode capability without adding a third-party package.
- Keep signature presence, platform validation, and certificate metadata separate.
- Treat missing or unreliable inspection as explicit non-affirmative evidence.
- Preserve the existing request and runtime boundary.

## Phase 1: Design Outputs

- [data-model.md](data-model.md) defines `SignatureInspection`, `SignatureEvidenceResult`, canonical evidence fields, relationships, and lifecycle rules.
- [contracts/windows-signature-evidence-contract.md](contracts/windows-signature-evidence-contract.md) defines inspector, adapter, failure, request, compatibility, and safety contracts.
- [quickstart.md](quickstart.md) defines focused, regression, native smoke, and end-to-end validation scenarios.

## Implementation Sequence

1. Add the signature inspection result normalization and provider protocol under `platform/windows/signature_evidence.py`.
2. Add path/runtime validation, deterministic evidence identity, provenance metadata, status mapping, and canonical Evidence creation.
3. Add injected-inspector tests for signed, unsigned, invalid, partial metadata, missing, inaccessible, unsupported, malformed, and unverifiable outcomes.
4. Add request/runtime integration coverage and assertions that collection has no downstream engine dependencies or trust side effects.
5. Run focused tests, Windows-specific regression tests, and the full pytest suite.

## Complexity Tracking

No constitution violations or complexity exceptions.
