# Feature Specification: Trust State Management

**Feature Branch**: `001-trust-state-management`

**Created**: 2026-08-27

**Status**: Draft

**Input**: User description: "Implement the ACHYUTA Trust State Management capability. ACHYUTA must maintain an explicit trust state for canonical security entities, preserve auditable transitions, keep trust separate from authorization decisions, support quarantine and entity-specific recovery, and remain compatible with existing SecurityRequest and Evidence models without adding endpoint enforcement."

## Clarifications

### Session 2026-08-27

- Q: Should Trust State Management represent the recovery mode used for each entity recovery? -> A: Record one of the three recovery modes on recovery transitions, aligned with ADR-002.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Maintain Explicit Entity Trust (Priority: P1)

As a security decision system, ACHYUTA needs to represent the current trust state of each canonical security entity so that trust can be evaluated independently from authorization.

**Why this priority**: Explicit trust is the foundation for conservative, explainable security evaluation and is required before other trust workflows can be reliable.

**Independent Test**: Create one entity of each supported type, verify its initial state, and transition it through supported states without changing any authorization decision.

**Acceptance Scenarios**:

1. **Given** a newly observed Identity, Subject, Process, Resource, or Device, **When** ACHYUTA creates its trust record, **Then** the entity starts in `UNKNOWN` unless an explicit state is supplied.
2. **Given** an entity with a current trust state, **When** an authorized trust-state transition occurs, **Then** the entity's current state becomes the requested supported state.
3. **Given** an unsupported entity type or trust state, **When** a trust record or transition is requested, **Then** the request is rejected without changing existing trust data.

---

### User Story 2 - Explain and Audit Trust Transitions (Priority: P1)

As a security reviewer, I need to understand why an entity's trust changed and what evidence supported that change.

**Why this priority**: Auditability and evidence traceability are core ACHYUTA security properties, especially when trust affects later evaluation.

**Independent Test**: Perform multiple transitions for one entity and verify that each history entry preserves the before state, after state, reason, timestamp, and supporting evidence identifiers.

**Acceptance Scenarios**:

1. **Given** an entity with a current state, **When** it transitions to another state, **Then** the system records the previous state, new state, human-readable reason, and transition timestamp.
2. **Given** supporting evidence for a transition, **When** the transition is recorded, **Then** the transition references every supplied evidence identifier.
3. **Given** an entity with multiple transitions, **When** its history is reviewed, **Then** all transitions remain available in chronological order and the current state agrees with the latest transition.
4. **Given** a transition with a blank reason, **When** it is requested, **Then** the transition is rejected because it cannot be explained or audited.

---

### User Story 3 - Apply Conservative, Entity-Specific Trust Recovery (Priority: P2)

As a security operator, I need suspicious or insufficiently trusted entities to be quarantined and recovered based on their own evidence and condition, without granting trust globally or permanently equating denial with distrust.

**Why this priority**: Quarantine and carefully scoped recovery reduce risk while preserving the distinction between a request outcome and an entity's longer-lived trust posture.

**Independent Test**: Evaluate denied and suspicious requests for different entity types, verify conservative intermediate states, then recover only the selected entity after entity-specific verification.

**Acceptance Scenarios**:

1. **Given** a suspicious Process, Subject, or Resource, **When** its trust is reduced, **Then** ACHYUTA can place that entity in `QUARANTINED` as an intermediate state.
2. **Given** an authorization `DENY` decision, **When** trust state is derived or reviewed, **Then** the decision does not by itself create a permanent `UNTRUSTED` state.
3. **Given** an entity in `QUARANTINED` or `UNVERIFIED`, **When** recovery evidence satisfies that entity's recovery conditions, **Then** only that entity transitions to the appropriate next state and the recovery is recorded.
4. **Given** multiple entities with different trust conditions, **When** one entity recovers, **Then** the other entities retain their existing states.
5. **Given** a recovery transition, **When** it is recorded, **Then** it identifies whether recovery was `AUTOMATIC`, `STRONG_REVERIFICATION`, or `HUMAN_APPROVAL`.

### Edge Cases

- A transition to the entity's current state is allowed only when it still records a meaningful reason and audit event; otherwise it is rejected as a no-op.
- Evidence identifiers may be absent when no supporting evidence exists, but the transition reason remains mandatory.
- Evidence identifiers that do not resolve to known Evidence records are preserved as supplied identifiers and do not silently create evidence.
- A missing, malformed, or non-UTC transition timestamp is rejected or normalized consistently without changing the recorded event order.
- A partially completed transition must not update the current state without also appending its history entry.
- A decision involving an entity type outside the supported canonical set must not alter trust state.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST maintain an explicit trust state for each supported canonical entity type: Identity, Subject, Process, Resource, and Device.
- **FR-002**: System MUST support exactly these trust states: `UNKNOWN`, `UNVERIFIED`, `TRUSTED`, `QUARANTINED`, and `UNTRUSTED`.
- **FR-003**: System MUST initialize a newly observed entity to `UNKNOWN` unless a separately justified initial state is provided.
- **FR-004**: System MUST allow a trust-state transition to record the previous state and the new state.
- **FR-005**: System MUST require every trust-state transition to include a human-readable reason and a transition timestamp.
- **FR-006**: System MUST associate all supplied supporting evidence identifiers with the corresponding trust-state transition.
- **FR-007**: System MUST preserve an auditable, chronological transition history for every entity and keep the current state consistent with that history.
- **FR-008**: System MUST keep authorization decisions and entity trust states as distinct concepts and records.
- **FR-009**: System MUST NOT automatically or permanently set an entity to `UNTRUSTED` solely because an authorization decision is `DENY`.
- **FR-010**: System MUST support `QUARANTINED` as an intermediate state for suspicious or insufficiently trusted Processes, Subjects, and Resources.
- **FR-011**: System MUST make trust recovery entity-specific and MUST NOT automatically transition every affected or related entity to `TRUSTED`.
- **FR-012**: System MUST record the recovery mode for each recovery transition as `AUTOMATIC`, `STRONG_REVERIFICATION`, or `HUMAN_APPROVAL`.
- **FR-013**: System MUST preserve compatibility with the existing `SecurityRequest` and `Evidence` models and accept their existing identity, subject, action, resource, context, and evidence relationships where applicable.
- **FR-014**: System MUST support an explainable relationship from Request to Evidence to Policy to Decision to Trust State without moving evidence collection, policy evaluation, decision resolution, or enforcement responsibilities into trust-state management.
- **FR-015**: System MUST preserve existing security behavior and pass all existing automated tests after the capability is added.
- **FR-016**: System MUST exclude Windows-specific endpoint enforcement from this capability; enforcement remains the future responsibility of Raksha.

### Key Entities

- **Trust Entity**: A canonical Identity, Subject, Process, Resource, or Device with a stable identifier, entity type, current trust state, and state-change metadata.
- **Trust State**: The explicit current assessment of an entity: `UNKNOWN`, `UNVERIFIED`, `TRUSTED`, `QUARANTINED`, or `UNTRUSTED`.
- **Trust Transition**: An immutable audit record connecting one state to another with the previous state, new state, reason, timestamp, optional supporting evidence identifiers, and, for recovery transitions, the recovery mode used.
- **Recovery Mode**: The controlled method used to restore an entity's trust posture: `AUTOMATIC`, `STRONG_REVERIFICATION`, or `HUMAN_APPROVAL`.
- **Evidence**: Existing ACHYUTA evidence that can support or explain a trust transition without being collected or represented by the trust-state capability.
- **Security Request**: Existing ACHYUTA request context that connects identity, subject, action, resource, context, and evidence to a policy evaluation and decision.
- **Authorization Decision**: The result for a specific request, distinct from the longer-lived trust state of any entity involved in that request.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of supported canonical entity types can be created with an explicit initial trust state and can be queried without consulting an authorization decision.
- **SC-002**: 100% of accepted trust-state transitions contain a previous state, new state, human-readable reason, timestamp, and complete supplied evidence-identifier set.
- **SC-003**: 100% of reviewed entity histories reproduce the exact chronological sequence of accepted transitions and their current final state.
- **SC-004**: 100% of authorization `DENY` scenarios leave the affected entity in a non-permanent state unless a separate, explicit trust transition establishes `UNTRUSTED`.
- **SC-005**: 100% of recovery scenarios change only the entity selected for recovery and never grant `TRUSTED` status to unrelated entities automatically.
- **SC-006**: 100% of accepted recovery transitions identify exactly one recovery mode: `AUTOMATIC`, `STRONG_REVERIFICATION`, or `HUMAN_APPROVAL`.
- **SC-007**: All existing automated tests continue to pass, and new automated coverage verifies supported states, entity types, transition audit fields, denial handling, quarantine, recovery isolation, recovery modes, and request/evidence explainability.
- **SC-008**: A reviewer can trace every tested trust outcome through Request, applicable Evidence, Policy, Decision, and Trust State records without relying on undocumented behavior.

## Assumptions

- Trust state is maintained in memory or through the repository's existing persistence approach; selecting durable storage is outside this feature's requirements.
- Existing `SecurityRequest`, `Evidence`, policy, and decision models remain the authoritative representations for their respective responsibilities.
- A transition's evidence identifiers refer to existing or externally resolvable evidence identifiers; this capability does not collect, validate, or mutate evidence.
- Recovery rules may vary by entity type and evidence condition; the implementation will define testable conservative defaults and record one ADR-002 recovery mode for every recovery transition.
- Authentication, user-interface workflows, Windows endpoint enforcement, and Raksha enforcement actions are outside the scope of this trust-model layer.
- All transition timestamps are expected to be comparable and represented consistently for audit ordering.
