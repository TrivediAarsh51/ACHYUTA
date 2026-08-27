# Research: Trust State Management

## Decision: Extend the existing trust domain in `engine/trust.py`

**Rationale**: The repository already defines `TrustState`, `EntityType`, `TrustEntity`, `TrustTransition`, and conservative decision-effect mapping in the owning module. Keeping the capability there preserves the established responsibility boundary and minimizes compatibility risk.

**Alternatives considered**: A new trust service or persistence repository was rejected for v1 because the feature is an internal domain-library capability and the specification explicitly leaves durable storage out of scope.

## Decision: Represent recovery mode as a constrained transition attribute

**Rationale**: ADR-002 defines `AUTOMATIC`, `STRONG_REVERIFICATION`, and `HUMAN_APPROVAL`. Recording one mode on recovery transitions makes recovery auditable without moving recovery policy into evidence, policy, or decision components.

**Alternatives considered**: Recording only the resulting state would lose an important audit fact. A free-form string would weaken validation and make tests and review ambiguous.

## Decision: Preserve existing request and evidence models by reference

**Rationale**: `SecurityRequest` already aggregates identity, subject, action, resource, context, and `Evidence` items. `Evidence` already has stable identifiers. Trust transitions should retain supplied evidence identifiers and remain independent from collection and policy evaluation.

**Alternatives considered**: Duplicating request or evidence objects in the trust module would violate separation of responsibilities and risk divergence from the canonical models.

## Decision: Use the existing Python standard-library and pytest toolchain

**Rationale**: The runtime is Python 3.11.1, the current trust model uses dataclasses, enums, and UTC-aware datetimes, and the suite collects 20 tests with pytest. No additional dependency is needed for the domain behavior.

**Alternatives considered**: External state-management or audit packages were rejected because they add cost and complexity without a requirement for durable or distributed operation.

## Decision: Keep DENY mapping conservative

**Rationale**: Existing behavior maps DENY for Process, Subject, and Resource to `QUARANTINED`, and other supported entities to `UNVERIFIED`. This satisfies the constitutional distinction between authorization and trust while providing a safe intermediate state.

**Alternatives considered**: Mapping every DENY to `UNTRUSTED` was rejected by the specification, ADR-003, and the constitution because a request-specific denial is not proof of permanent entity compromise.
