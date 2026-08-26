# ADR-002: Entity-Based Trust Recovery Model

## Status

Accepted

## Date

2026-08-06

## Context

In a Zero Trust environment, trust is not permanent.

An entity that was previously trusted may become suspicious due to:

- Abnormal behavior
- Policy violation
- Security events
- Risk changes

A major architectural question is:

Should trust automatically recover after a security event?

Different entities have different risk levels.

For example:

- A user account recovering after failed authentication.
- A browser recovering after unusual activity.
- A kernel driver recovering after suspicious behavior.

These cannot follow the same recovery process.

## Decision

ACHYUTA will implement entity-specific trust recovery policies.

Trust recovery will depend on:

- Entity type
- Risk severity
- Historical behavior
- Available evidence
- Security impact

Recovery modes:

### Automatic Recovery

Used for low-risk temporary conditions.

Example:

- Temporary network failure
- Expired security signature update

### Strong Reverification

Requires additional verification.

Example:

- New location login
- Device health change

### Human Approval

Required for high-impact security events.

Example:

- Credential dumping
- Malware execution
- Kernel modification
- Security control tampering

## Consequences

### Positive

- Prevents automatic restoration of compromised entities.
- Reduces risk of repeated attacks.
- Allows flexible recovery depending on severity.

### Negative

- Human approval may increase operational overhead.
- Recovery logic becomes more complex.

## Alternatives Considered

### Automatic Trust Restoration

Rejected because compromised entities may regain privileges without sufficient verification.

### Permanent Revocation

Rejected because legitimate entities may be incorrectly blocked permanently.

## Related Components

- Viveka (Decision Engine)
- Pramana (Evidence Engine)
- Raksha (Protection Layer)
