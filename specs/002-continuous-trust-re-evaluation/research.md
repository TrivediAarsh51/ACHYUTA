# Research: Continuous Trust Re-Evaluation

## Decision: Trigger contract is limited to existing evidence/request flows

ACHYUTA will treat a trust re-evaluation as valid only when:

- a new or refreshed evidence item is added to the existing evidence model, or
- a new SecurityRequest is created that is relevant to an existing entity identity, subject, resource, or context.

This keeps the feature aligned with ADR-003 and ADR-004 while avoiding timers, polling loops, or an ad hoc event bus. It also prevents the trust layer from becoming an unbounded signal consumer.

### Rationale

- The architecture already defines Request, Evidence, Policy, Decision, and Trust State as distinct responsibilities.
- Re-evaluation is a decision-synchronization event, not a discovery mechanism.
- The trust state boundary must remain constrained to transition integrity, not security telemetry acquisition.

### Alternatives considered

1. Periodic polling or scheduler-based re-evaluation
   - Rejected because the specification explicitly excludes timers and background schedulers unless the architecture later requires them.

2. Unbounded event observation by the trust layer
   - Rejected because it risks turning Trust State into another evidence-collection or policy engine.

3. Direct trust promotion from a raw permit/deny string
   - Rejected because ADR-007 explicitly forbids raw caller-controlled authorization values from driving trust state.

---

## Decision: each re-evaluation must create a new request context

Every trust re-evaluation MUST use a fresh SecurityRequest object or equivalent request context. The prior request remains part of the historical record and is never silently rewritten.

### Rationale

- Request-centric evaluation requires that a new evaluation reflects the current request and current evidence.
- This preserves auditable history and prevents stale trust from being silently folded into a previous outcome.

### Alternatives considered

1. Reusing the original request object
   - Rejected because it hides the distinction between original evaluation and later re-evaluation.

2. Overwriting previous result fields in place
   - Rejected because it destroys historical explainability and auditability.

---

## Decision: re-evaluation orchestration is coordinator-only

The orchestration layer may coordinate trigger handling, request creation, evidence selection, policy evaluation, and decision handoff, but it must not duplicate Niyama policy logic or Viveka decision logic.

### Rationale

- The architecture requires separation of responsibilities.
- This keeps re-evaluation aligned with the canonical domain model while preserving the existing boundaries.

### Alternatives considered

1. Let Trust State evaluate policy itself
   - Rejected because it violates the separation of responsibilities established by the constitution and ADRs.

2. Let the orchestration layer decide policy outcome directly
   - Rejected because it creates a second decision engine and weakens explainability.

---

## Decision: minimum audit record is trigger + request + evidence + policy + decision + resulting state

The minimal required explainability record for every re-evaluation is:

- previous trust state
- re-evaluation trigger
- request identifier
- evidence identifiers
- policy summary or matching policy id(s)
- decision identifier or decision summary
- resulting trust state

This satisfies the clarified requirement while keeping the research implementation minimal and consistent with the project architecture.

### Rationale

- A reviewer must be able to explain why trust remained the same or changed.
- The record must preserve the chain from trust state to trigger to request to evidence to policy to decision to final trust state.

### Alternatives considered

1. Full object deep-copy chain for every event
   - Rejected as more overhead than needed for a research implementation.

2. Recording only the final trust state
   - Rejected because it prevents explainability and audit review.

---

## Decision: conservative fallback persists when evidence is contradictory or insufficient

When the evidence or decision context is not sufficient, ACHYUTA will prefer verification, restriction, or quarantine instead of silently preserving `TRUSTED`.

### Rationale

- This aligns with the constitution's conservative security principles.
- It preserves the boundary between trust state and authorization while reducing stale-trust risk.

### Alternatives considered

1. Reusing the old state whenever the new evaluation is inconclusive
   - Rejected because it is the precise stale-trust failure the feature intends to prevent.

2. Automatically promoting on insufficient evidence
   - Rejected because it violates zero-trust assumptions and explicit auditability requirements.

---

## Decision: no production enforcement, scheduler, or cloud/event-bus scope

The feature remains research-only and deliberately excludes endpoint enforcement, process termination, network isolation, Windows kernel actions, cloud infrastructure, and ML-based scoring.

### Rationale

- The scope statement explicitly reserves enforcement to Raksha and excludes operational infrastructure from this feature.
- This keeps the design aligned with the architecture and the existing test baseline.

---

## Research outcome

The design resolves the clarifications and keeps the feature within the existing ACHYUTA responsibilities:

- Pramana owns evidence representation and provenance.
- Niyama owns policy evaluation.
- Viveka owns decision resolution.
- Trust State owns controlled transitions.
- Re-evaluation orchestration coordinates the process without absorbing other component responsibilities.
