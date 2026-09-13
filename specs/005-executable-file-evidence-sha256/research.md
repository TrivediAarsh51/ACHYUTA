# Research: Executable/File Evidence (SHA-256)

## Decision: Keep file hashing inside the Windows platform boundary

- **Decision**: Add a focused read-only file-evidence adapter under `platform/windows`, using the executable path from `WindowsObservation`.
- **Rationale**: The path and endpoint provenance are already owned by the Windows observation boundary. Keeping file access there prevents platform-specific behavior from entering the platform-independent engine.
- **Alternatives considered**: Adding hashing to `engine/evidence.py` was rejected because the engine owns canonical representation, not Windows file access. Hashing from a caller-supplied path was rejected because it could detach evidence from the observed process.

## Decision: Use standard-library SHA-256 and injected file access for tests

- **Decision**: Use the standard-library SHA-256 implementation and a narrow injectable reader/opening boundary for deterministic tests.
- **Rationale**: No dependency or paid infrastructure is needed, and injected readers can model missing, denied, unsupported, and unstable reads without damaging endpoint state.
- **Alternatives considered**: A malware or signature library was rejected because scanning and signature validation are explicitly out of scope. A native-only implementation was rejected because it would make portable tests unnecessarily dependent on Windows.

## Decision: Represent successful hashes as unverified canonical evidence

- **Decision**: Create canonical `Evidence` with a SHA-256 value, `verified=False`, deterministic identity, observation provenance, and separate collection-success metadata.
- **Rationale**: Hashing establishes the bytes read, not authorship, signature validity, malware status, authorization, or trust. This preserves conservative downstream policy behavior.
- **Alternatives considered**: Marking the hash verified was rejected because it overstates the claim. A second file-evidence model was rejected by the canonical domain-model requirement.

## Decision: Represent every failed file attempt as non-affirmative canonical evidence

- **Decision**: Convert missing, inaccessible, unsupported, malformed, and unverifiable outcomes into canonical evidence with explicit status and reason, `verified=False`, and no digest.
- **Rationale**: The request-centric flow must retain uncertainty for risk and policy evaluation without turning it into affirmative evidence. The existing `Evidence` metadata/value fields can carry the status while preserving the public model.
- **Alternatives considered**: Dropping failed outcomes was rejected because it hides collection limitations. Returning a parallel outcome model only was rejected because it disconnects uncertainty from the request evidence trace.

## Decision: Treat unstable reads conservatively

- **Decision**: If the reader detects a read failure or cannot establish a stable byte stream, return `UNVERIFIABLE` non-affirmative evidence and do not publish a digest.
- **Rationale**: A digest of an incomplete or indeterminate read could be misleading. The collector must not make claims stronger than the observation supports.
- **Alternatives considered**: Publishing a partial digest was rejected because it is not a digest of the executable file. Retrying indefinitely was rejected because collection must remain bounded and read-only.

## Decision: Preserve both observation and collection timestamps

- **Decision**: Keep the process observation timestamp in the canonical evidence timestamp/provenance and record file collection time separately in metadata.
- **Rationale**: The observation identifies when the process fact was captured; the collection time identifies when bytes were read. Both are needed for freshness and auditability.
- **Alternatives considered**: Replacing the observation time with hash time was rejected because it destroys source provenance. Storing only the observation time was rejected because it hides the age of file access.

## Decision: Keep the collector independent of runtime evaluation

- **Decision**: The file adapter returns evidence only; the caller attaches it to `SecurityRequest` and invokes the existing runtime boundary.
- **Rationale**: This preserves the sequence `Evidence -> Request -> Risk -> Policy -> Decision -> Trust -> Raksha` and prevents a platform collector from making authorization or trust decisions.
- **Alternatives considered**: Direct collector-to-runtime calls were rejected because they bypass request ownership and make collection responsible for downstream security decisions.
