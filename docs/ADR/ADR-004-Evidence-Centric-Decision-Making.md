# ADR-004 — Evidence Is First-Class

## Decision

ACHYUTA treats evidence as a first-class architectural object.

Every trust decision must be supported by one or more evidence items.

Each evidence item belongs to a category and has an associated strength.

## Reasoning

- Different evidence sources have different reliability.
- Trust decisions should be explainable.
- Confidence should be derived from evidence quality rather than evidence quantity.
