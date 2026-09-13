# Implementation Plan: Executable/File Evidence (SHA-256)

**Branch**: `005-executable-file-evidence-sha256` | **Date**: 2026-09-13 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from [spec.md](spec.md)

**Note**: This template is filled in by the `/speckit-plan` command; its definition describes the execution workflow.

## Summary

Extend the existing read-only Windows process evidence adapter so each complete process observation can produce deterministic SHA-256 file evidence from its observed executable path. Add a platform-local file hashing adapter and explicit non-affirmative evidence for missing, inaccessible, unsupported, malformed, or unverifiable reads, while preserving canonical `Evidence` and `SecurityRequest` models and the existing request-to-Raksha evaluation boundary.

## Technical Context

<!--
  ACTION REQUIRED: Replace the content in this section with the technical details
  for the project. The structure here is presented in advisory capacity to guide
  the iteration process.
-->

**Language/Version**: Python 3.x, matching the existing dataclass-based engine

**Primary Dependencies**: Python standard library (`hashlib`, file I/O) and existing project modules; no new dependency

**Storage**: In-memory canonical evidence and collection result objects; persistence is out of scope

**Testing**: pytest with temporary-file fixtures, injected readers/providers, integration tests, and conditional Windows smoke coverage

**Target Platform**: Windows 11 Pro endpoint; portable tests run on non-Windows hosts; core engine remains platform-independent

**Project Type**: Python security-model library with platform adapters

**Performance Goals**: Hash files in a single read-only pass with bounded test fixtures; no authorization latency or throughput target is introduced

**Constraints**: Use only the observed executable path; preserve observation and collection timestamps; keep `verified=False`; do not modify files/processes; do not implement WDAC, signature validation, malware scanning, trust promotion, or collector-to-runtime calls

**Scale/Scope**: One file-evidence result per supported Windows process observation; SHA-256 only; no persistence, scheduling, scanning, or bulk inventory

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Evidence-centric security**: SHA-256 results are canonical but unverified; failures become explicit non-affirmative evidence and never a positive claim.
- **Request-centric evaluation**: Successful and non-affirmative file evidence is attached through `SecurityRequest.add_evidence()` before normal evaluation.
- **Separation of responsibilities**: File collection remains under `platform/windows`; risk, policy, decision, trust, and Raksha remain in existing owners.
- **Decision and trust separation**: Hashing never emits a decision or promotes trust.
- **Conservative security**: Missing, inaccessible, unsupported, malformed, and unstable reads remain explicit and non-affirmative.
- **Explainability and auditability**: Evidence retains process provenance, path, observation timestamp, collection timestamp, status, and reason.
- **Test before integration**: Unit, negative, integration, mutation-safety, and regression tests are required.
- **Windows endpoint focus and safety**: File access is read-only and tested with controlled fixtures.

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

```text
engine/
├── evidence.py                 # Existing canonical Evidence factory
├── request.py                  # Existing SecurityRequest model
└── runtime.py                  # Existing evaluation boundary

platform/windows/
├── observation.py              # Existing process observations and statuses
├── collector.py                # Existing read-only process collector
├── evidence.py                 # Existing process adapter and canonical adapter surface
└── file_evidence.py            # New read-only executable hashing adapter

tests/
├── test_windows_collector.py   # Existing process collection regression tests
├── test_windows_file_evidence.py # New hashing and failure tests
└── test_windows_integration.py # Existing request/runtime integration tests
```

**Structure Decision**: Keep all new behavior in `platform/windows` and extend only established canonical evidence/request interfaces. Use a focused `platform/windows/file_evidence.py` module for file access so process collection remains narrow; reuse `CollectionStatus` and `engine.evidence.create_evidence()` rather than adding domain models.

## Complexity Tracking

No constitution violations or complexity exceptions.
