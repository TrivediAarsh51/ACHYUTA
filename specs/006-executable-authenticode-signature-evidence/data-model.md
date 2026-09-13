# Data Model: Executable Integrity / Authenticode Signature Evidence

## WindowsObservation

Existing immutable process observation from `platform/windows/observation.py`.

The signature adapter uses `executable_path` as its only target and preserves:

- `process_id`
- `process_name`
- `executable_path`
- `parent_process_id`
- `user_identity`
- `observed_at`

The observation is not mutated and is not replaced by a signature-specific observation model.

## SignatureInspection

Platform-local normalized result supplied by the injected or native inspector before canonical evidence creation.

| Field | Type | Meaning |
| --- | --- | --- | -- |
| `status` | `CollectionStatus` or normalized signature status | Inspection outcome such as signed, unsigned, invalid, inaccessible, unsupported, malformed, or unverifiable |
| `signature_present` | `bool | None` | Whether a signature was observed; `None` when it cannot be determined |
| `validation_status` | `str | None` | Platform-reported validation state, preserved without project trust interpretation |
| `signing_source` | `str | None` | Embedded Authenticode, catalog, or other source when the inspector identifies it |
| `signer_subject` | `str | None` | Observable signer certificate subject |
| `issuer` | `str | None` | Observable issuing certificate subject |
| `certificate_identifier` | `str | None` | Thumbprint or equivalent stable certificate identifier |
| `signature_algorithm` | `str | None` | Observable signature algorithm details |
| `chain_status` | `str | None` | Platform-reported chain result when available |
| `revocation_status` | `str | None` | Platform-reported revocation result when available |
| `reason` | `str | None` | Diagnostic reason for non-success or unavailable fields |

Unavailable fields are represented as `None` or an explicit metadata availability marker. They are never fabricated.

## SignatureEvidenceResult

Platform-local result returned by the read-only signature adapter.

| Field | Type | Meaning |
| --- | --- | --- |
| `status` | `CollectionStatus` | Overall collection/inspection status |
| `evidence` | `Evidence` | Exactly one canonical evidence item for every result |
| `observation` | `WindowsObservation` | Process observation supplying the target path |
| `collected_at` | `datetime` | Time the signature inspection result was collected |

The result contains no decision, trust transition, enforcement action, or policy result.

## Canonical Executable Signature Evidence

Existing `engine.evidence.Evidence` created with:

- `category`: `windows_executable_signature`
- `source`: `platform.windows.signature`
- `value` on an observable result: signature presence, validation status, signing source, and available certificate/signature metadata
- `value` on a non-affirmative result: explicit status and reason, with no fabricated signature fields
- `strength`: conservative existing strength selected by implementation without implying trust
- `verified`: always `False`
- `timestamp`: `WindowsObservation.observed_at`
- `metadata`: platform, process identity, executable path, observation timestamp, collection timestamp, status, and metadata availability
- `evidence_id`: deterministic from observation identity and normalized signature outcome

A platform-valid signature is an observation. It is not proof of publisher trust, malware absence, authorization, or a trust-state transition.

## SecurityRequest

Existing canonical `engine.request.SecurityRequest`. The caller attaches `SignatureEvidenceResult.evidence` through `add_evidence()`. No Windows-specific request subtype is introduced.

## Relationships and lifecycle

```text
WindowsObservation
  -> validate observed executable path
  -> SignatureInspector.inspect(path)
  -> normalize signature observation or explicit outcome
  -> canonical Evidence (verified=False)
  -> SecurityRequest.add_evidence()
  -> existing runtime evaluation
```

Lifecycle rules:

1. Unsupported runtime or malformed path stops before invoking the inspector.
2. Missing, inaccessible, unsupported, malformed, invalid, or unverifiable inspection produces explicit non-affirmative evidence.
3. Signed and unsigned are separate observable states; unsigned is not treated as inspection failure.
4. Missing certificate fields remain unavailable rather than being synthesized.
5. Collection is read-only and does not call downstream policy, risk, decision, trust, runtime, or Raksha components.
