# Data Model: Executable/File Evidence (SHA-256)

## WindowsObservation

Existing immutable process observation supplied by `platform/windows/observation.py`.

Relevant fields:

| Field | Type | Constraints |
| --- | --- | --- | --- |
| `process_id` | `int` | Positive integer |
| `process_name` | `str` | Non-empty |
| `executable_path` | `str` | Non-empty path selected by the observation source |
| `parent_process_id` | `int | None` | Positive integer when present |
| `user_identity` | `str` | Non-empty |
| `observed_at` | `datetime` | Timezone-aware |

The file adapter MUST use `executable_path` from this object and MUST preserve all relevant provenance.

## FileEvidenceResult

Platform-local result returned by the read-only file adapter.

| Field | Type | Meaning |
| --- | --- | --- |
| `status` | `CollectionStatus` | `SUCCESS`, `MISSING`, `INACCESSIBLE`, `MALFORMED`, `UNSUPPORTED`, `UNVERIFIABLE`, or another explicit non-affirmative status |
| `evidence` | `Evidence` | Exactly one canonical evidence item for success or explicit failure |
| `observation` | `WindowsObservation` | Source observation used for the attempt |
| `collected_at` | `datetime` | Time file bytes or failure status was collected |

A success contains a SHA-256 digest. A failure contains status and reason but no digest. The result never contains a decision, trust transition, or enforcement action.

## Executable File Evidence

Existing canonical `engine.evidence.Evidence` with:

- `category`: `windows_executable_sha256`
- `source`: `platform.windows.file`
- `value` on success: `{ "sha256": "<64 lowercase hex characters>" }`
- `value` on failure: `{ "status": "<CollectionStatus>", "reason": "<diagnostic text>" }`
- `strength`: conservative existing strength, selected by implementation without implying trust
- `verified`: always `False` for this feature
- `timestamp`: originating `WindowsObservation.observed_at`
- `metadata`: platform, process identity, executable path, collection timestamp, status, and `hashing_succeeded` where applicable
- `evidence_id`: deterministic from observation identity, path, outcome, and digest/status context

A successful digest is evidence that specific bytes were read and hashed. It is not evidence of signature validity, authorship, malware status, authorization, or trustworthiness.

## SecurityRequest

Existing canonical `engine.request.SecurityRequest`. The caller attaches every `FileEvidenceResult.evidence` through `add_evidence()`. No Windows-specific request subtype is introduced.

## Relationships and lifecycle

```text
WindowsObservation
  -> read-only path validation
  -> file read / SHA-256 computation
  -> canonical Evidence (success or explicit non-affirmative failure)
  -> SecurityRequest.add_evidence()
  -> existing runtime evaluation
```

Lifecycle rules:

1. Unsupported runtime or invalid observation path stops before file access.
2. Missing, inaccessible, malformed, or unstable reads produce a failure evidence item without a digest.
3. Successful reads publish one complete lowercase SHA-256 digest.
4. No result modifies endpoint state or invokes downstream decision components.
