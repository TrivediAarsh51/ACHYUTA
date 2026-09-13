# Windows Executable Signature Evidence Contract

## Scope

This contract defines the read-only adapter from an existing `WindowsObservation` to canonical ACHYUTA evidence about observable Authenticode signature facts. It does not authorize access, define publisher trust, evaluate policy, mutate trust, enforce controls, or scan for malware.

## Inspector contract

The platform-local inspector accepts exactly the observed executable path and returns a normalized `SignatureInspection` value or a mapped non-affirmative error.

The inspector MUST:

- use `WindowsObservation.executable_path` as the only target;
- avoid wildcard expansion and unrelated path discovery;
- be skipped when the runtime is unsupported or the observed path is malformed;
- inspect without modifying the executable, owning process, certificate store, or endpoint state;
- preserve platform-reported status and available signer/certificate metadata;
- identify the signing source when the platform exposes it;
- avoid converting platform status into ACHYUTA authorization or trust semantics.

The default Windows implementation may delegate to `Get-AuthenticodeSignature -LiteralPath` through a controlled native boundary. The boundary must use literal path semantics, normalize structured output, and map command failure or unavailable fields to explicit outcomes. Tests inject the inspector and do not require a live Windows signature.

## Adapter contract

`collect_signature_evidence(observation: WindowsObservation) -> SignatureEvidenceResult`

The adapter MUST:

- reject a non-`WindowsObservation` input;
- validate the observed path before inspection;
- return `UNSUPPORTED` without invoking the inspector on a non-Windows runtime;
- return canonical `Evidence` for signed, unsigned, invalid, inaccessible, unsupported, malformed, or unverifiable outcomes;
- keep `verified=False` for every result;
- preserve `observation.observed_at` as the evidence timestamp;
- record a separate collection timestamp;
- preserve process and endpoint provenance in evidence metadata;
- omit unavailable signer/certificate fields rather than fabricating them;
- return no decision, policy result, trust mutation, enforcement action, or runtime output.

## Success and observable-state contract

A result with an observable signature state MUST have:

- category `windows_executable_signature`;
- source `platform.windows.signature`;
- explicit `signature_present` value;
- platform-reported `validation_status` when available;
- signing source when available;
- available signer subject, issuer, certificate identifier, algorithm, chain, revocation, expiration, and timestamp details;
- `verified=False`;
- observation and collection timestamps;
- deterministic evidence identity for observation identity and normalized signature outcome.

Signed and unsigned are distinct observations. A platform-valid signature is not a publisher trust assertion.

## Failure evidence contract

A non-affirmative result MUST have:

- one explicit status and diagnostic reason;
- `verified=False`;
- no fabricated affirmative signature or certificate fields;
- originating observation provenance where available;
- enough metadata for downstream risk, policy, and audit handling.

Catalog-only or otherwise out-of-scope signing sources MUST be reported explicitly as unsupported or unverifiable when the inspector can identify them, rather than silently being treated as embedded Authenticode.

## Request integration

The caller attaches the result through:

`SecurityRequest.add_evidence(result.evidence)`

The caller then invokes the existing runtime boundary. The adapter does not invoke `evaluate_runtime_request()` and does not decide how policy or trust responds to the evidence.

## Compatibility and safety guarantees

- Existing `Evidence`, `SecurityRequest`, `WindowsObservation`, and `CollectionStatus` contracts remain authoritative.
- Feature 005 SHA-256 evidence remains independent and available for correlation by callers.
- Requests without signature evidence retain prior behavior.
- The collector has no imports from downstream engine components.
- Signature collection does not modify files, processes, certificate stores, or endpoint state.
