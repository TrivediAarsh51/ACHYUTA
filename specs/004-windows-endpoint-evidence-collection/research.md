# Research: Windows Endpoint Evidence Collection

## Decision: Use a platform adapter with injected providers

- **Decision**: Keep Windows collection under `platform/windows`, expose a narrow provider protocol, and inject test providers.
- **Rationale**: This preserves engine platform independence, supports deterministic tests on non-Windows hosts, and prevents collection code from acquiring policy or authorization responsibilities.
- **Alternatives considered**: Adding Windows logic to `engine/evidence.py` was rejected because it violates the protected engine boundary. Calling the runtime from the collector was rejected because it bypasses the request-centric application boundary.

## Decision: Limit the first source to six read-only process fields

- **Decision**: Support process ID, process name, executable path, parent process ID, user identity, and observation timestamp.
- **Rationale**: The scope is now explicit in `FR-001a`, matches the existing implementation surface, and provides useful endpoint provenance without expanding into policy or endpoint-control telemetry.
- **Alternatives considered**: Services, registry, security configuration, and kernel or driver telemetry are deferred and must be reported as unsupported rather than approximated.

## Decision: Represent collection outcomes with `CollectionStatus`

- **Decision**: Use immutable `WindowsObservation`, `WindowsCollectionFailure`, and `WindowsCollectionResult` records with explicit non-affirmative statuses.
- **Rationale**: A shared status enum makes unavailable, denied, stale, malformed, unsupported, unverifiable, timeout, and conflict outcomes testable and prevents failed records from becoming positive evidence.
- **Alternatives considered**: Returning `None`, raising all provider errors, or encoding failures as incomplete observations were rejected because they lose diagnostic context or risk conservative-evaluation failures.

## Decision: Adapt successful observations to canonical evidence only

- **Decision**: Convert complete observations through `engine.evidence.create_evidence()` and attach results with `SecurityRequest.add_evidence()`.
- **Rationale**: This preserves the existing evidence and request models, carries source and observation time into the evaluation, and leaves risk, policy, decision, trust, and Raksha ownership unchanged.
- **Alternatives considered**: A second Windows evidence class or direct collector-to-runtime calls were rejected by the feature constraints and constitution.

## Decision: Preserve observation timestamps through one backward-compatible factory extension

- **Decision**: Allow `create_evidence()` to accept an optional timestamp while retaining its existing default clock behavior.
- **Rationale**: Evidence must retain collection freshness without mutating the canonical object after construction, and existing callers must remain compatible.
- **Alternatives considered**: Replacing the evidence factory, changing all callers, or storing the timestamp only in adapter metadata were rejected because they increase compatibility risk or weaken canonical timestamp semantics.

## Decision: Use conditional native Windows smoke coverage

- **Decision**: Test the native provider only when running on Windows 11 Pro; use injected providers for all portable tests.
- **Rationale**: This verifies the target platform without making the full suite dependent on a live process table, permissions, or a Windows host.
- **Alternatives considered**: Requiring Windows for all tests was rejected because it would prevent platform-independent regression testing and local development on non-Windows hosts.
