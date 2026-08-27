# Implementation Plan: Trust State Management

**Branch**: `001-trust-state-management` | **Date**: 2026-08-27 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/001-trust-state-management/spec.md`

**Note**: This template is filled in by the `/speckit-plan` command; its definition describes the execution workflow.

## Summary

Add an explicit, auditable trust-state model for Identity, Subject, Process, Resource, and Device entities. Extend the existing Python trust domain with recovery-mode metadata while keeping authorization decisions, evidence representation, policy evaluation, decision resolution, and future enforcement in their existing components.

## Technical Context

<!--
  ACTION REQUIRED: Replace the content in this section with the technical details
  for the project. The structure here is presented in advisory capacity to guide
  the iteration process.
-->

**Language/Version**: Python 3.11.1

**Primary Dependencies**: Python standard library dataclasses, enum, datetime, and typing; PyYAML remains owned by policy loading

**Storage**: In-memory domain objects for v1; durable persistence is out of scope

**Testing**: pytest; existing suite currently collects 20 tests

**Target Platform**: Windows 11 Pro workstation, with platform-independent core model and controlled lab tests

**Project Type**: Internal Python security-domain library with test and laboratory scenario support

**Performance Goals**: Trust reads and transitions remain ordinary in-memory operations for the current test and laboratory scale; no production throughput target is defined for v1

**Constraints**: Preserve SecurityRequest and Evidence compatibility; require explainable transition records; do not infer permanent UNTRUSTED from DENY; do not implement Windows endpoint enforcement

**Scale/Scope**: Five canonical entity types, five trust states, three recovery modes, transition history per entity, and focused unit/integration coverage

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- [x] Evidence-Centric Security: transitions accept supporting evidence identifiers and do not collect or mutate evidence.
- [x] Request-Centric Evaluation: trust outcomes remain explainable in the Request -> Evidence -> Policy -> Decision -> Trust State chain.
- [x] Separation of Responsibilities: Pramana, Niyama, Viveka, Trust State Management, and Raksha responsibilities remain separate.
- [x] Decision and Trust State Are Different: DENY maps conservatively and does not establish permanent UNTRUSTED.
- [x] Conservative Security and Entity-Specific Recovery: QUARANTINED is supported and recovery records one ADR-002 mode per entity.
- [x] Explainability and Auditability: every accepted transition records before/after state, reason, timestamp, and evidence identifiers where supplied.
- [x] Test Before Integration and No Security Regression: new negative and ambiguous cases are planned alongside the existing full suite.
- [x] Windows Endpoint Focus and Safety: no endpoint enforcement or destructive behavior is included.
- [x] Zero-Cost Development: implementation uses the existing standard-library and pytest tooling.

**Gate status**: PASS. No constitution violations or exceptions are required.

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
  The concrete layout below records the selected repository structure.
-->

```text
engine/
├── trust.py       # TrustState, EntityType, RecoveryMode, entity, and transition domain
├── request.py     # Existing SecurityRequest contract
├── evidence.py    # Existing Evidence contract
├── policy.py      # Existing Niyama policy evaluation
└── decision.py    # Existing Viveka decision resolution

tests/
├── test_trust.py        # Trust state, transitions, recovery, and denial mapping
├── test_evidence.py     # Existing evidence behavior
├── test_evidence_policy.py
├── test_policy.py
├── test_decision.py
└── test_integration.py  # Existing request/evidence flow

lab/scenarios/           # Existing controlled scenario definitions
```

**Structure Decision**: Keep the capability in `engine/trust.py` and extend the existing `tests/test_trust.py`. Add no new application layer, database, endpoint, or platform enforcement module. The feature documentation is generated under this feature directory.

## Phase 0: Research Decisions

See [research.md](research.md). The repository and accepted ADRs resolve all technical unknowns; no external technology research is required.

## Phase 1: Design Outputs

- [data-model.md](data-model.md) defines the trust entities, states, transitions, recovery modes, and relationships to existing request/evidence/decision concepts.
- [quickstart.md](quickstart.md) defines runnable validation for the full suite and focused trust scenarios.
- `contracts/` is intentionally omitted because this feature exposes no external API, CLI, or user-interface contract; its internal Python domain contract is documented in the data model and existing module boundaries.

## Implementation Notes

- Preserve existing public names and behavior in `engine.trust` unless a backward-compatible enum or field extension is required.
- Use UTC-aware timestamps and immutable transition records.
- Keep decision-to-trust mapping conservative and explicit; a DENY result must not directly create permanent UNTRUSTED status.
- Recovery transitions require exactly one ADR-002 recovery mode and remain scoped to one entity.
- Verify both focused trust tests and the complete existing test suite after implementation.

## Post-Design Constitution Check

**Status**: PASS. The design keeps trust-state ownership in the trust module, references rather than owns evidence and requests, preserves decision separation, records audit evidence, and excludes enforcement. Planned tests cover regression, negative cases, recovery isolation, and explainability.

## Complexity Tracking

No constitution violations; no complexity exceptions.
