# ADR-001: Adoption of Trust States Instead of Binary Authorization

## Status

Accepted

## Date

2026-08-06

## Context

Traditional security models often use binary authorization decisions:

- Allow
- Deny

However, modern computing environments contain dynamic and continuously changing risks.

A user, device, or process may not always be completely trusted or completely malicious.

Examples:

- A valid application may suddenly perform suspicious actions.
- A user may authenticate successfully but from an unusual context.
- A process may require restricted capabilities rather than complete permission denial.

A binary authorization model cannot represent these intermediate security conditions.

## Decision

ACHYUTA will not use binary authorization as the primary trust model.

Instead, ACHYUTA will implement a dynamic Trust State model.

Entities will exist in different trust states based on:

- Evidence
- Context
- Risk
- Policy evaluation
- Historical behavior

Initial trust states:

1. Unknown
2. Observe
3. Verify
4. Restricted
5. Trusted
6. Elevated
7. Quarantined
8. Revoked
9. Denied

Trust will be continuously evaluated and may increase or decrease over time.

## Consequences

### Positive

- Allows adaptive security decisions.
- Supports continuous verification.
- Reduces unnecessary blocking.
- Enables capability-based access control.

### Negative

- More complex than allow/deny decisions.
- Requires continuous monitoring.
- Requires a trust evaluation mechanism.

## Alternatives Considered

### Binary Authorization Model

Rejected because it cannot represent uncertainty or changing risk conditions.

### Permanent Trust Assignment

Rejected because trust is not static in a changing environment.

## Related Components

- Viveka (Decision Engine)
- Pramana (Evidence Engine)
- Niyama (Policy Engine)
