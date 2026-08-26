# ADR-005: Canonical Domain Model

## Status

Accepted

## Date

2026-08-13

## Context

ACHYUTA is designed as a Request-Centric Zero Trust Architecture for Windows 11 Pro workstations.

The architecture currently contains multiple conceptual components, including evidence collection, policy evaluation, risk assessment, trust evaluation, decision-making, enforcement, and telemetry.

Without a canonical vocabulary, different components may interpret fundamental security concepts differently. This can lead to inconsistent architecture, implementation, documentation, and testing.

ACHYUTA therefore requires a formally defined domain model that establishes the primary entities used throughout the system.

## Decision

ACHYUTA will use a canonical domain model consisting of the following core entities:

1. Identity
2. Subject
3. Request
4. Action
5. Resource
6. Evidence
7. Policy
8. Risk Assessment
9. Trust State
10. Decision
11. Enforcement Action
12. Telemetry Event

All ACHYUTA documentation, software components, APIs, policies, and validation procedures should use these definitions consistently.

## Core Relationship

The primary conceptual flow is:

Identity and Subject initiate a Request.

A Request describes an Action against a Resource under a specific Context.

Evidence is collected and associated with the Request.

Applicable Policies are evaluated.

A Risk Assessment is produced.

The Trust State and Decision are determined.

The Decision is translated into an Enforcement Action.

The resulting activity generates Telemetry for continuous evaluation.

## Rationale

The canonical domain model provides:

* Consistent terminology across the architecture.
* Clear boundaries between evidence, policy, risk, and decision-making.
* A foundation for software interfaces and data structures.
* Traceability between architectural decisions and implementation.
* A foundation for future testing and validation.

## Consequences

### Positive

* Components can be developed independently using shared contracts.
* Security decisions become easier to explain.
* Evidence can be traced to individual decisions.
* New telemetry sources can be integrated without redesigning the entire decision engine.
* Policies can evolve independently from evidence collection.
* The architecture becomes easier to document and validate.

### Negative

* Additional modeling effort is required before implementation.
* The domain model may need revision as implementation reveals previously unknown requirements.
* Maintaining consistent terminology across documentation and code becomes an ongoing responsibility.

## Alternatives Considered

### Entity-Centric Trust Model

Rejected because permanently assigning trust to users, devices, or processes does not adequately represent changing behavior and context.

### User-Centric Authorization

Rejected because the same identity may generate requests with substantially different security implications.

### Process-Centric Authorization

Rejected because a process can perform both legitimate and malicious operations during its lifetime.

### Unstructured Event-Based Architecture

Rejected because raw telemetry does not provide a sufficiently consistent abstraction for policy and decision engines.

## Architectural Principle

> ACHYUTA shall evaluate security-relevant requests using a canonical domain model rather than assigning permanent trust to an identity, device, or process.

## Related ADRs

* ADR-001: Adoption of Trust States Instead of Binary Authorization
* ADR-002: Entity-Based Trust Recovery Model
* ADR-003: Request-Centric Trust Evaluation Model
* ADR-004: Evidence-Centric Decision Making
