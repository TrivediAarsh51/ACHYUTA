# ADR-006: Policy Integrity and Controlled Activation

## Status

Accepted

## Date

2026-08-26

## Context

ACHYUTA relies on policies to determine how security-relevant requests should be evaluated.

Because policies directly influence authorization and enforcement decisions, unauthorized or corrupted policies represent a critical security risk.

A policy cannot be considered trustworthy solely because it exists within a protected or trusted storage location.

An attacker who obtains sufficient privileges to modify the system may also be able to modify policy files.

Therefore, ACHYUTA requires a mechanism to establish:

- Policy integrity
- Policy provenance
- Policy authorization
- Policy version
- Policy lifecycle state
- Policy change accountability

Policy changes must also be controlled so that modification of a policy file does not automatically result in activation.

## Decision

ACHYUTA will implement a controlled policy lifecycle.

A policy must progress through explicit lifecycle states before becoming active:

```text
Draft
  ↓
Validated
  ↓
Verified
  ↓
Approved
  ↓
Active
  ↓
Suspended / Retired
