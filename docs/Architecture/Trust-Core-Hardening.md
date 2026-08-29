# Trust Core Hardening

## Status and Scope

This document defines the proposed hardening direction for ACHYUTA Trust State
Management after the completed T001-T026 implementation work and the subsequent
read-only security review. It is an architectural design document, not an
implementation change and not a replacement for the existing feature
specification or accepted ADRs.

The existing implementation and the proposed hardened behavior are explicitly
distinguished below. The hardening described here is intentionally limited to
trust-state integrity. It does not add endpoint enforcement, change the existing
specification silently, or assign another component's responsibilities to Trust
State Management.

## 1. Purpose

Trust State Management must be treated as a controlled security state machine,
not as a mutable data object. A trust state is a security assertion about a
canonical entity that can influence later evaluation. If callers can freely
construct, mutate, or rewrite that assertion, the state no longer represents a
controlled assessment and its audit history cannot be trusted.

The state machine must therefore control how an entity enters a state, how it
leaves a state, what context supports the change, and how the change is recorded.
This protects the distinction established by ADR-001 and ADR-003: trust is
dynamic and contextual, while an authorization decision applies to a specific
request.

## 2. Security Problem

The completed v1 implementation provides useful domain structure, validation,
immutable `TrustTransition` records, conservative handling for most restrictive
decision effects, and entity-scoped recovery. The read-only security review
identified integrity gaps that the current public model still permits:

- **Direct `TRUSTED` initialization:** `TrustEntity` accepts a caller-supplied initial state, including `TRUSTED`, without requiring a controlled promotion decision or applicable evidence.
- **Direct state mutation:** `TrustEntity.state` is publicly writable, so a caller can change the current state without creating a transition.
- **Unrestricted transitions:** `transition()` permits any supported state change, including promotions that should require a stronger security path.
- **Publicly mutable transition history:** `transition_history` is a public mutable list. A caller can append, remove, reorder, or replace audit entries.
- **Recovery bypass:** the ordinary transition surface can be used to reach a safer state without the recovery checks enforced by `recover()`.
- **Unaudited trusted initialization:** a trusted entity can exist without an accepted transition recording why the trust assertion was made.
- **Arbitrary supported state jumps:** enum validation confirms that a state is supported, but does not by itself establish that the requested jump is authorized for the current state and context.
- **Fabricated evidence references:** transition evidence identifiers are preserved as supplied identifiers; the trust layer does not establish that they resolve to genuine evidence. Without an upstream provenance boundary, callers can present identifiers that do not support the assertion.
- **Raw caller-supplied `permit` affecting trust:** `trust_state_from_decision()` currently maps the string `"permit"` directly to `TRUSTED`. A raw string is not a validated Viveka decision context and must not be sufficient to promote trust.

These are integrity problems, not merely API-style concerns. They permit a
state to change without the evidence, decision authority, recovery path, or
audit record that should make the assertion trustworthy.

## 3. Trust Boundary

Trust State Management owns:

- the current trust state of a supported canonical entity;
- controlled creation of that trust record;
- validation of state changes against the authoritative current state and the applicable controlled operation;
- transition integrity, including accepted/rejected operation behavior; and
- an append-only audit record of accepted transitions.

Trust State Management does **not** own:

- evidence collection, evidence provenance, or evidence validation;
- policy authoring, integrity, evaluation, or activation;
- risk assessment as an independent domain responsibility;
- authorization decision resolution;
- authentication or identity proofing; or
- endpoint enforcement.

The architectural names and boundaries remain:

| Component | Responsibility |
| --- | --- |
| **Pramana** | Evidence representation, provenance, and validation |
| **Niyama** | Policy and policy evaluation |
| **Viveka** | Decision resolution and validated decision context |
| **Trust State** | Entity trust state and transition integrity |
| **Raksha** | Future enforcement |

Trust State may consume references and validated outputs from these components,
but must not silently absorb their responsibilities.

## 4. State Integrity Invariants

The hardened design must preserve these invariants:

1. Every newly created supported entity defaults to `UNKNOWN`.
2. A caller cannot independently mutate the current state.
3. State changes occur only through controlled operations.
4. Every accepted transition has an auditable before state, after state, reason, timestamp, and applicable evidence references.
5. A rejected operation changes neither the current state nor transition history.
6. The transition source state must equal the authoritative current state at the moment the transition is accepted.
7. A state and its history entry are updated as one logical operation.
8. Transition history is externally read-only and cannot be rewritten through a returned collection or record.
9. Recovery requirements cannot be bypassed through an ordinary transition.
10. A trust promotion cannot be justified solely by a raw caller string or an unvalidated reference.
11. Trust state remains distinct from the authorization result for any one request; `DENY` alone does not establish permanent `UNTRUSTED`.

The existing implementation satisfies some of these invariants, particularly
transition-record immutability, reason validation, and no mutation after many
validation failures. It does not yet satisfy the encapsulation and controlled
promotion invariants described as proposed behavior here.

## 5. TRUSTED Promotion Boundary

`TRUSTED` is a promotion boundary, not an ordinary destination available to
any state-changing caller.

Under the proposed hardened behavior, an entity may enter `TRUSTED` only when
an authorized decision supports that promotion and the evidence required by the
applicable policy or recovery path is present. The authorization must be
represented by validated decision context from Viveka, and the supporting
evidence must remain owned and validated by Pramana. The transition must record
the resulting trust assertion and its audit context.

This document deliberately does not invent a universal evidence threshold,
transition graph, decision schema, or recovery rule. Those conditions belong to
the applicable policy and recovery design. The architectural requirement is
that a caller cannot bypass them by supplying an initial `TRUSTED` state or by
using an ordinary unrestricted transition.

## 6. History Integrity

Transition history is an append-only audit log of accepted state changes. Once
recorded, an entry must not be edited, deleted, reordered, or replaced through
the public domain surface. External consumers may inspect history but must have
read-only access to it.

The current implementation uses immutable transition records but exposes the
containing list publicly. The hardened design must preserve the immutable record
property and add read-only access to the collection itself. Rejected operations,
including rejected promotions and recoveries, must not append placeholder or
partial entries.

## 7. Recovery Boundary

Recovery is separate from ordinary transitions because it restores trust after
an entity has entered a suspicious or insufficiently verified condition. It
requires a distinct justification, applicable evidence, and authorization. If
ordinary transitions can reach the same safer state without those checks, the
recovery control becomes optional.

Recovery remains entity-specific and must not update related entities. The three
ADR-002 recovery modes remain the only architectural modes:

- `AUTOMATIC` for eligible low-risk temporary conditions;
- `STRONG_REVERIFICATION` when additional verification is required; and
- `HUMAN_APPROVAL` for high-impact or ambiguous conditions requiring human oversight.

The mode used by an accepted recovery must be recorded in its transition. The
mode does not itself prove that recovery is justified; the applicable policy,
evidence, and authorized decision still govern the recovery.

## 8. Evidence Boundary

Trust State must not invent, collect, or verify evidence. Pramana owns evidence
representation, provenance, and validation. A trust transition may retain
evidence identifiers so a reviewer can trace the assertion, but retaining an
identifier is not proof that the evidence is real, relevant, or sufficient.

The hardened boundary therefore requires the promotion or recovery operation to
receive evidence through the applicable validated architecture path. Trust State
must not manufacture evidence records or upgrade an arbitrary identifier into
validated support. Handling of unresolved identifiers must be defined by the
Pramana contract and applicable policy; it must not be silently treated as
trustworthy support.

## 9. Decision Boundary

Trust State must not treat a raw string such as `"permit"` as sufficient
authorization for trust promotion. A string can be caller-controlled input and
does not carry the policy results, request context, rationale, provenance, or
authority needed to support a security assertion.

Viveka provides the validated decision context. Trust State may use that context
as an input to a controlled operation, while leaving policy evaluation and
decision resolution in Niyama and Viveka. A request-level `PERMIT` and an
entity-level `TRUSTED` state remain different concepts; one must not be
implicitly substituted for the other.

## 10. Security Properties to Test

Before accepting the hardened implementation, tests must verify that:

- every supported entity type initializes only to `UNKNOWN` through the normal creation path;
- direct `TRUSTED` initialization is rejected or requires the documented controlled promotion path;
- direct assignment to current state is unavailable or ineffective;
- ordinary transitions cannot bypass promotion or recovery requirements;
- arbitrary state jumps are rejected when not allowed by the applicable controlled operation;
- the source state of an accepted transition matches authoritative current state;
- accepted transitions update state and history atomically;
- rejected transitions and recoveries leave both state and history unchanged;
- history and its entries are externally read-only and remain append-only;
- every accepted transition has complete audit metadata;
- `TRUSTED` promotion requires an authorized decision context and the evidence required by the applicable policy or recovery path;
- fabricated or unvalidated evidence references cannot independently justify trust promotion;
- a raw `"permit"` value cannot promote an entity to `TRUSTED`;
- `DENY` does not alone establish permanent `UNTRUSTED`;
- recovery is restricted to the selected entity and records exactly one of `AUTOMATIC`, `STRONG_REVERIFICATION`, or `HUMAN_APPROVAL`; and
- the Request -> Evidence -> Policy -> Decision -> Trust State explanation remains traceable without moving ownership across components.

The focused trust tests and the complete existing suite remain regression gates.
Tests that conflict with the hardened security boundary should be changed only
as an intentional, documented contract migration.

## 11. Migration Impact

The following existing usage patterns may need to change because they are
intentionally no longer supported by the hardened contract:

- callers constructing `TrustEntity` with an initial state other than `UNKNOWN`, especially `TRUSTED`;
- callers assigning `entity.state`, `entity.reason`, or `entity.state_since` directly;
- callers mutating `entity.transition_history` directly;
- callers using `transition()` for a promotion or recovery that should use a controlled operation;
- tests that expect every supported state to be reachable from `UNKNOWN` by an unrestricted ordinary transition;
- tests that use a raw decision effect such as `"permit"` as trust-promotion authority; and
- integration code that supplies evidence identifiers without an applicable Pramana validation/provenance path.

The existing request and evidence models, canonical entity types, trust-state
values, conservative denial behavior, recovery modes, and future Raksha boundary
should remain conceptually compatible. Any public API replacement must document
its compatibility impact and update focused negative, audit, recovery, and
explainability tests before integration.

## 12. Open Architectural Questions

The following questions remain unresolved and must not be answered by assumption
in this hardening document:

1. What exact state-transition graph is permitted for each entity type and current state?
2. Which component or service is the authority that authorizes a trust promotion, and what validated decision contract does it provide to Trust State?
3. What exact policy-specific evidence requirements must be satisfied before `TRUSTED` promotion for each entity type and context?
4. How should Pramana expose evidence provenance and validation status to the trust boundary without transferring evidence ownership?
5. Which recovery modes and evidence conditions apply to each entity type and severity level?
6. How should concurrent transition attempts be serialized or rejected when the source state is stale?
7. Should an initial `UNKNOWN` record have an explicit creation audit event, and what actor or authority should that event identify?
8. What durable audit and retention guarantees are required beyond the current in-memory v1 model?
9. How should legacy callers migrate from direct mutation while preserving explainability and avoiding a compatibility bypass?

These questions require explicit architectural or component-level decisions
before implementation details are finalized.
