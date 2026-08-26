# ADR-003: Request-Centric Trust Evaluation Model

## Status

Accepted

## Date

2026-08-06

## Context

Traditional security models often associate trust with:

- User identity
- Device identity
- Application identity

However, a trusted entity may perform both legitimate and malicious actions.

Examples:

- An administrator account can perform maintenance or malicious changes.
- A signed application can perform unexpected behavior.
- A trusted process may access sensitive resources incorrectly.

Therefore, trust should not be assigned permanently to an entity.

## Decision

ACHYUTA will evaluate individual security requests instead of assigning permanent trust.

Every request will contain:

- Subject
- Identity
- Action
- Resource
- Context
- Evidence

### Example

powershell.exe

requests:

Action:
Read

Resource:
LSASS Memory

Identity:
Administrator

Context:
2:00 AM

Evidence:
Unsigned Script

The decision engine evaluates each request independently.

## Consequences

### Positive

- Enables continuous verification.
- Supports least privilege.
- Reduces implicit trust.
- Allows dynamic authorization decisions.

### Negative

- Requires detailed telemetry.
- Requires efficient decision processing.
- Increases architectural complexity.

## Alternatives Considered

### User-Centric Trust

Rejected because users can perform different risk-level actions.

### Device-Centric Trust

Rejected because a healthy device can still execute malicious actions.

### Process-Centric Trust

Rejected because process behavior changes over time.

## Related Components

- Viveka (Decision Engine)
- Pramana (Evidence Engine)
- Netra (Telemetry Layer)
- Niyama (Policy Engine)
