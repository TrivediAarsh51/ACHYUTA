# Research: Executable Integrity / Authenticode Signature Evidence

## Decision: Add a sibling signature adapter under the Windows platform boundary

- **Decision**: Add `platform/windows/signature_evidence.py` beside `file_evidence.py`. It accepts an existing `WindowsObservation`, inspects only `observation.executable_path`, and returns one platform-local result containing one canonical `Evidence` item.
- **Rationale**: Feature 005 already owns observed executable path handling and timestamp/provenance conventions. A sibling adapter keeps signature inspection separate from hashing while preserving the same request-centric integration boundary.
- **Alternatives considered**: Extending `engine/evidence.py` was rejected because the engine owns canonical representation, not Windows inspection. Merging signature inspection into `file_evidence.py` was rejected because hashing and signing are distinct observations with different failure semantics.

## Decision: Use an injected inspector contract with a Windows-native default

- **Decision**: Define a narrow inspector protocol that maps one validated path to structured signature observations. Use an injected inspector for tests and a Windows-native implementation for endpoint use. The initial native implementation may delegate to PowerShell `Get-AuthenticodeSignature`, which is Windows-only and exposes signature status and signer certificate information.
- **Rationale**: The project has no dependency manifest or third-party security library, and injected inspectors make signed, unsigned, invalid, partial-metadata, inaccessible, and unsupported cases deterministic on non-Windows hosts. The native provider remains replaceable if later requirements need direct WinTrust or certificate APIs.
- **Alternatives considered**: A new package dependency was rejected under the zero-cost and minimal-dependency constraints. Direct ctypes bindings to WinTrust and Crypt32 were deferred because they increase implementation and resource-management risk without changing the evidence contract.

## Decision: Keep signature presence, validation, and metadata separate

- **Decision**: Store `signature_present`, platform-reported `validation_status`, and available certificate/signature metadata as separate fields. Record chain, revocation, expiration, and timestamp results only when supplied by the native inspector; Feature 006 defines no new certificate policy.
- **Rationale**: The clarification requires observations rather than a collector-owned trust interpretation. A valid platform status is not automatically publisher trust, authorization, malware status, or a trust-state transition.
- **Alternatives considered**: Requiring project-defined chain and revocation success was rejected because it would move policy into collection. Reporting only a Boolean signature flag was rejected because the feature explicitly requires observable signature information.

## Decision: Normalize all outcomes into canonical evidence

- **Decision**: Return `SUCCESS` evidence for an observable signature result, including signed and unsigned states, and explicit non-affirmative evidence for missing, inaccessible, unsupported, malformed, invalid, or unverifiable inspection. All results use `verified=False`, the originating observation timestamp, separate collection timestamp metadata, and deterministic evidence identity.
- **Rationale**: Requests must retain uncertainty and negative observations for downstream risk and policy evaluation. Reusing `CollectionStatus` preserves existing failure vocabulary and avoids a parallel evidence model.
- **Alternatives considered**: Dropping unsigned or failed outcomes was rejected because absence of a signature is itself an observable fact and inspection limitations must remain auditable. Marking a platform-valid signature as verified was rejected because signature observation does not establish request-specific trust.

## Decision: Keep catalog and non-Authenticode behavior explicit

- **Decision**: The adapter records the signing mechanism/source when the native inspector exposes it. Embedded Authenticode is the intended Feature 006 scope; catalog-only and unrelated signing mechanisms are reported as unsupported or unverifiable rather than silently treated as embedded Authenticode evidence.
- **Rationale**: The specification bounds the feature to Authenticode and requires unsupported mechanisms to remain explicit. The native provider must not fabricate a source when the platform result cannot distinguish it.
- **Alternatives considered**: Treating every platform signature result as equivalent was rejected because catalog and embedded signatures have different provenance and scope implications.

## Decision: Preserve the existing request and runtime boundary

- **Decision**: The caller attaches `SignatureEvidenceResult.evidence` with `SecurityRequest.add_evidence()` and invokes the existing runtime evaluator. The collector never imports or calls policy, risk, decision, trust, runtime, or Raksha modules.
- **Rationale**: This preserves `Evidence -> Request -> Risk -> Policy -> Decision -> Trust -> Raksha`, keeps authorization centralized, and maintains behavior for requests without signature evidence.
- **Alternatives considered**: Direct collector-to-runtime calls were rejected because they bypass request ownership and allow collection code to make downstream security decisions.

## External references consulted

- Microsoft Learn, `Get-AuthenticodeSignature`: Windows-only cmdlet that returns a signature object with status and signer certificate information; its documented behavior may use a Windows catalog signature when both catalog and embedded signatures exist, which is why the provider must preserve/validate signing source explicitly.
- Microsoft Learn, `WinVerifyTrust`: Windows trust-provider API and a possible future native implementation; its return code indicates provider verification status but does not replace ACHYUTA request policy.
