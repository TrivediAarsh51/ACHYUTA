# Feature Specification: Executable/File Evidence (SHA-256)

**Feature Branch**: `[005-executable-file-evidence-sha256]`

**Created**: 2026-09-13

**Status**: Draft

**Input**: User description: "Feature 005 — Executable/File Evidence (SHA-256): Extend ACHYUTA's Windows endpoint evidence capability so that an observed executable can be represented with deterministic SHA-256 file evidence. The feature must operate read-only, use the executable path obtained from the existing Windows process observation capability, preserve canonical Evidence and SecurityRequest models, preserve provenance and observation timestamps, explicitly represent missing/inaccessible/unsupported/unverifiable files without creating affirmative evidence, and feed the resulting evidence into the existing Evidence → Request → Risk → Policy → Decision → Trust → Raksha flow. The collector must not make authorization decisions, modify files or processes, or implement WDAC, signature validation, malware scanning, or trust promotion."

## Clarifications

### Session 2026-09-13

- Q: Should a successfully computed SHA-256 digest be marked as verified evidence, or as unverified evidence that only confirms the file bytes were read and hashed? → A: Mark the digest as unverified evidence; record successful hashing separately. Computing a digest does not validate authorship, signature validity, malware status, authorization, or trust.
- Q: Should missing, inaccessible, unsupported, and unverifiable file results be attached to the SecurityRequest as non-affirmative canonical evidence, or remain separate collection outcomes that the caller may pass alongside the request? → A: Attach explicit non-affirmative outcomes as canonical evidence with status and reason, leaving `verified` false and omitting any digest.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Record deterministic executable evidence (Priority: P1)

Security reviewers need an observed executable to produce a repeatable SHA-256 file claim so that the same file content can be recognized and evaluated consistently across requests.

**Why this priority**: Deterministic file evidence is the core value of this feature and enables downstream evaluation to reason about the executable that was observed.

**Independent Test**: Provide a controlled Windows process observation whose executable path points to a readable fixture file, collect the file evidence twice without changing the file, and verify that both results contain the same SHA-256 digest, source path provenance, and observation time while the collector returns no authorization result.

**Acceptance Scenarios**:

1. **Given** a valid Windows process observation with a readable executable path, **When** file evidence is collected, **Then** the result contains a canonical, unverified evidence item whose value identifies the SHA-256 digest of the file bytes and whose collection context records that hashing succeeded.
2. **Given** the same unchanged file is collected more than once, **When** the results are compared, **Then** the digest is identical and each result retains the observation and collection context needed to distinguish the observations.
3. **Given** a process observation with an executable path, **When** file evidence is collected, **Then** the path is taken from that observation rather than from an independently selected or user-supplied target.

---

### User Story 2 - Report file evidence limitations without claiming safety (Priority: P1)

Security reviewers need missing, inaccessible, unsupported, and unverifiable executable files to be reported explicitly so that downstream evaluation can treat uncertainty conservatively instead of mistaking it for positive evidence.

**Why this priority**: File access can fail for ordinary endpoint reasons. Explicit non-affirmative outcomes prevent silent gaps in the evidence record and protect the integrity of later risk and policy evaluation.

**Independent Test**: Run controlled collection cases for a missing path, inaccessible file, unsupported runtime, unreadable or changing file, and invalid observation path; verify that each outcome is explicit, preserves its reason and provenance where available, and produces no affirmative file evidence.

**Acceptance Scenarios**:

1. **Given** an observed executable path that does not exist, **When** file evidence is requested, **Then** the result records a missing-file outcome and does not create affirmative evidence.
2. **Given** an observed executable path that cannot be read, **When** file evidence is requested, **Then** the result records an inaccessible or unverifiable outcome with the access failure context and does not create affirmative evidence.
3. **Given** a runtime that does not support this collection capability, **When** file evidence is requested, **Then** the result records an unsupported outcome without attempting file access.
4. **Given** file contents cannot be read consistently or the executable path is invalid, **When** file evidence is requested, **Then** the result records an unverifiable outcome rather than asserting a digest or safety claim.

---

### User Story 3 - Preserve the canonical security evaluation flow (Priority: P1)

Security maintainers need SHA-256 file evidence to enter the existing request-centric evaluation path so that risk, policy, decision, trust, and Raksha responsibilities remain centralized and auditable.

**Why this priority**: The feature extends endpoint evidence; it must not create a parallel authorization path or allow a collector to promote trust based on a file digest.

**Independent Test**: Attach a successful SHA-256 evidence item to an existing security request, run normal evaluation, and verify the ordered trace `Evidence -> Request -> Risk -> Policy -> Decision -> Trust -> Raksha`; separately verify that file collection itself returns evidence or status only.

**Acceptance Scenarios**:

1. **Given** successful SHA-256 file evidence, **When** it is attached to a security request, **Then** the request is evaluated through the existing risk, policy, decision, trust, and Raksha stages in order.
2. **Given** a non-affirmative file outcome, **When** it is attached to the associated security request as canonical evidence, **Then** its status and reason remain available as uncertainty or limitation and it is not converted by the collector into an allow, deny, or trust-promotion result.
3. **Given** a file collector invocation, **When** it completes, **Then** it has not modified the executable, process, or endpoint state and has not performed authorization, WDAC enforcement, signature validation, malware scanning, or trust promotion.
4. **Given** a request without Windows executable evidence, **When** it is evaluated, **Then** existing platform-independent behavior remains unchanged.

### Edge Cases

- What happens when the executable path is empty, malformed, relative, or otherwise not a usable file path?
- How is a file represented when it disappears between path observation and hashing?
- How is a file represented when its contents or metadata change while hashing is in progress?
- What happens when a file is a directory, reparse point, special file, or otherwise not a regular executable file?
- How are repeated observations of the same path distinguished when their process observation timestamps differ?
- What happens when the endpoint runtime is not Windows or the required file-reading capability is unavailable?
- How is provenance preserved when hashing fails after the process observation was successfully captured?
- How does the system prevent a SHA-256 digest from being treated as proof of signature validity, malware status, authorization, or trust?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST provide a read-only Windows file-evidence capability within the existing `platform/windows` boundary.
- **FR-002**: The capability MUST obtain the target executable path from the existing Windows process observation and MUST NOT select a separate target path for collection.
- **FR-003**: For a readable regular file, the capability MUST calculate and represent the SHA-256 digest of the file bytes deterministically.
- **FR-004**: The capability MUST represent successful file evidence using the canonical Evidence model and MUST NOT introduce a second evidence model.
- **FR-004a**: A successfully computed SHA-256 digest MUST remain unverified evidence; the capability MUST record successful hashing without representing the digest as proof of authorship, signature validity, malware status, authorization, or trust.
- **FR-005**: The capability MUST preserve the originating process observation's source, subject, executable path, endpoint context, and observation timestamp as provenance associated with the resulting evidence or outcome.
- **FR-006**: The capability MUST preserve the observation timestamp and MUST distinguish it from the time at which file collection occurs when both times are available.
- **FR-007**: The capability MUST represent missing, inaccessible, unsupported, and unverifiable file conditions with explicit non-affirmative statuses and reasons.
- **FR-008**: The capability MUST NOT create affirmative file evidence when the file is missing, inaccessible, unsupported, malformed, unstable during reading, or otherwise unverifiable.
- **FR-009**: The capability MUST represent each missing, inaccessible, unsupported, malformed, unstable, or otherwise unverifiable outcome as non-affirmative canonical evidence with an explicit status and reason, leaving `verified` false and omitting any digest.
- **FR-010**: The capability MUST attach successful and non-affirmative canonical evidence to the existing SecurityRequest through its established evidence-association behavior.
- **FR-011**: The resulting evidence or non-affirmative outcome MUST remain within the existing flow `Evidence -> Request -> Risk -> Policy -> Decision -> Trust -> Raksha` when the request proceeds to evaluation.
- **FR-012**: The collector MUST return observations, canonical evidence, or explicit collection outcomes only and MUST NOT make, imply, or return an authorization decision.
- **FR-013**: The collector MUST NOT modify files, processes, or other endpoint state while collecting file evidence.
- **FR-014**: The feature MUST NOT implement WDAC enforcement, executable signature validation, malware scanning, or trust promotion.
- **FR-015**: The capability MUST report unsupported runtime or platform conditions without attempting unsupported file collection.
- **FR-016**: The capability MUST support controlled test inputs for successful hashing, missing files, inaccessible files, unsupported environments, invalid paths, and unverifiable or unstable reads.
- **FR-017**: Existing Evidence, SecurityRequest, runtime, risk, policy, decision, trust, Raksha, and platform-independent behaviors MUST remain compatible when no SHA-256 file evidence is present.

### Key Entities *(include if feature involves data)*

- **Windows Process Observation**: The existing read-only endpoint observation containing the executable path, process identity, source, and observation timestamp that supplies the file target.
- **Executable File Evidence**: A canonical, unverified Evidence item representing a deterministic SHA-256 digest for readable file bytes, together with file provenance and collection context indicating successful hashing.
- **File Evidence Outcome**: An explicit status and reason represented as non-affirmative canonical evidence for missing, inaccessible, unsupported, malformed, or unverifiable collection, with no fabricated digest.
- **Security Request**: The existing request-domain object that receives successful and non-affirmative canonical evidence and carries it through normal evaluation.
- **Evaluation Trace**: The auditable progression from endpoint observation and evidence through request, risk, policy, decision, trust, and Raksha processing.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In 100% of controlled readable-file scenarios, repeated collection of unchanged bytes produces the same SHA-256 digest and retains the originating path and observation timestamp.
- **SC-002**: In 100% of controlled missing, inaccessible, unsupported, malformed, and unverifiable scenarios, the result contains an explicit non-affirmative status and no affirmative file evidence.
- **SC-003**: In 100% of integration scenarios with successful file evidence, reviewers can trace the request through `Evidence -> Request -> Risk -> Policy -> Decision -> Trust -> Raksha`, with no authorization result emitted by collection.
- **SC-004**: 100% of existing tests pass after the feature is introduced, and requests without Windows executable evidence retain their prior behavior.
- **SC-005**: At least 95% of sampled successful and failed file-evidence records retain source, executable path, endpoint context, observation timestamp, and collection outcome without manual reconstruction.
- **SC-006**: In 100% of reviewed collection runs, endpoint files and processes remain unchanged by the collector.
- **SC-007**: In 100% of reviewed feature changes, no WDAC enforcement, signature validation, malware scanning, or trust-promotion behavior is introduced into the collector.

## Assumptions

- The existing Windows process observation capability already supplies a normalized executable path and observation timestamp.
- SHA-256 is the only required digest for this feature; additional algorithms and trust decisions are out of scope.
- File reading is performed only for evidence collection and does not grant permission to access files that the caller cannot already read.
- A successful digest describes file bytes at collection time and successful hashing, but remains unverified evidence and does not establish authorship, signature validity, malware status, authorization, or trustworthiness.
- Existing Evidence and SecurityRequest models remain authoritative and are extended only through established interfaces.
- Downstream risk, policy, decision, trust, and Raksha components remain responsible for their existing responsibilities.
- Controlled fixtures and test doubles may represent access failures and unsupported environments without requiring unsafe endpoint manipulation.
- The feature remains isolated under the Windows platform boundary and does not make the core engine platform-dependent.
