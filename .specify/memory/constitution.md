# ACHYUTA Constitution

<!--
Sync Impact Report
- Version change: unratified scaffold -> 1.0.0
- Modified principles: none; established all 17 initial principles
- Added sections: Core Principles, Additional Constraints, Development Workflow
	and Quality Gates, Governance
- Removed sections: none
- Follow-up TODOs: none
-->

## Core Principles

### I. Evidence-Centric Security

Every security decision MUST be supported by one or more evidence items whenever
evidence is applicable. Evidence quality and reliability MUST take precedence over
evidence quantity.

### II. Request-Centric Evaluation

Trust evaluation MUST occur in the context of a specific security request. A request
MUST identify the identity, subject, action, resource, context, and supporting evidence.

### III. Explicit Policy Evaluation

Security policies MUST be explicit, deterministic, and testable. Policy logic MUST NOT
be hidden inside unrelated components.

### IV. Separation of Responsibilities

Pramana MUST own evidence collection and representation. Niyama MUST own policy
evaluation. Viveka MUST resolve policy results into a decision. Trust State management
MUST represent entity trust. Raksha is reserved for future enforcement responsibility.
Components MUST NOT silently absorb another component's security responsibility.

### V. Decision and Trust State Are Different

An authorization decision, including DENY, MUST NOT automatically make an entity
permanently UNTRUSTED. Decisions and trust-state transitions MUST be modeled and
evaluated independently.

### VI. Conservative Security

When trustworthy information is insufficient, ACHYUTA MUST prefer verification,
restriction, or quarantine over silently granting access.

### VII. Least Privilege

Access and execution MUST be limited to the minimum scope required for the specific
request, subject, resource, and action.

### VIII. Explainability

Important security decisions MUST be explainable through a traceable chain:
Request -> Evidence -> Policy -> Decision -> Trust State.

### IX. Auditability

Important security decisions and trust-state transitions MUST maintain an auditable
history containing the reason and supporting evidence where applicable.

### X. Test Before Integration

New security behavior MUST have automated tests before integration. Existing tests MUST
continue to pass unless a deliberate architectural change has been approved and
documented.

### XI. No Security Regression

Code changes MUST NOT weaken existing security controls merely to make tests pass.
Tests MUST be corrected or the security behavior explicitly reviewed when a conflict
reveals a deliberate architectural change.

### XII. Architecture Before Implementation

Major security behavior MUST be specified and architecturally reviewed before
implementation begins. Architectural decisions MUST be recorded in the appropriate
design documentation.

### XIII. Human Oversight

High-impact or ambiguous security conditions MAY require human verification. Automatic
trust MUST NOT be granted when the defined policy requires human oversight.

### XIV. Entity-Specific Trust Recovery

Trust recovery MUST depend on the type and condition of the affected entity. Recovery
MUST NOT be implemented as a universal TRUSTED transition.

### XV. Zero-Cost Development Constraint

The core research implementation MUST prioritize free and open-source technologies
and MUST NOT depend on paid infrastructure. Any exception requires explicit
architectural approval and documentation.

### XVI. Windows Endpoint Focus

The target implementation MUST support a Windows 11 Pro workstation. Virtualization
MAY be used for safe laboratory testing without changing the target platform focus.

### XVII. Security Research Safety

Testing MUST occur in controlled environments. Tests MUST NOT intentionally damage
systems, data, or networks outside authorized test environments.

## Additional Constraints

ACHYUTA is a Windows endpoint Zero Trust security architecture and research
implementation. The canonical domain model and terminology defined in the project
architecture documentation MUST be used consistently across code, policies, APIs,
tests, and documentation.

Security components MUST preserve the boundaries defined by the architecture:
evidence, policy, risk, decision, trust state, enforcement, and telemetry. Changes
that cross those boundaries require architectural review.

## Development Workflow and Quality Gates

Every feature that changes security behavior MUST have a written specification and an
architectural review before implementation. The implementation plan MUST identify
affected responsibilities, trust-state effects, evidence requirements, policy rules,
and audit implications.

Before integration, automated tests MUST cover the new behavior, relevant negative and
ambiguous cases, and any changed contracts. The full existing test suite MUST pass.
Security-sensitive changes MUST include an explainable decision path and evidence
traceability where evidence applies.

Code review MUST check compliance with this constitution, relevant ADRs, and the
canonical domain model. Failures in security, auditability, or safety gates MUST block
integration until they are resolved or explicitly approved as an architectural change.

## Governance

This constitution is authoritative for project engineering and security practices.
When another document conflicts with it, the conflict MUST be resolved in favor of
this constitution unless the constitution is formally amended.

Amendments MUST describe the affected principles, rationale, compatibility impact,
required documentation or migration work, and updated tests or review gates. Changes
MUST be reviewed by the project maintainers before adoption.

Versioning follows semantic versioning:

- MAJOR: backward-incompatible removal or redefinition of a principle.
- MINOR: addition of a principle or material expansion of governance requirements.
- PATCH: clarifications, wording fixes, and other non-semantic refinements.

Every feature review MUST verify compliance with the constitution and record any
approved exceptions. Constitution compliance MUST be reconsidered when architecture,
security behavior, target platform, or development constraints change.

**Version**: 1.0.0 | **Ratified**: 2026-08-26 | **Last Amended**: 2026-08-26
