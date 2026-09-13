# Data Model: Windows Endpoint Evidence Collection

## WindowsObservation

Platform-specific, immutable fact collected from a Windows process source.

| Field | Type | Constraints |
| --- | --- | --- |
| `process_id` | `int` | Positive integer; cannot be boolean |
| `process_name` | `str` | Non-empty after trimming |
| `executable_path` | `str` | Non-empty after trimming |
| `parent_process_id` | `int \| None` | Positive integer when present; cannot be boolean |
| `user_identity` | `str` | Non-empty after trimming |
| `observed_at` | `datetime` | Timezone-aware timestamp |

A complete observation contains only the six fields in `FR-001a`. It has no decision, policy, risk, trust, or enforcement fields.

## WindowsCollectionFailure

Platform-specific, immutable record for a collection limitation or invalid record.

| Field | Type | Constraints |
| --- | --- | --- |
| `status` | `CollectionStatus` | Any non-`SUCCESS` status |
| `source` | `str` | Non-empty source identifier |
| `message` | `str` | Non-empty diagnostic message |
| `process_id` | `int \| None` | Optional related process identifier |
| `observed_at` | `datetime \| None` | Optional timezone-aware timestamp |

Failure statuses are explicit and never convert to canonical evidence. Provider timeouts are represented as non-affirmative unavailable outcomes at the collector boundary.

## CollectionStatus

`SUCCESS`, `UNAVAILABLE`, `PERMISSION_DENIED`, `STALE`, `MALFORMED`, `UNSUPPORTED`, `UNVERIFIABLE`, `CONFLICT`, and `TIMEOUT`.

`CONFLICT` describes a result containing distinguishable complete observations that disagree. The collector preserves both records and does not resolve authorization.

## WindowsCollectionResult

Immutable aggregate returned by collection.

| Field | Type | Meaning |
| --- | --- | --- || `status` | `CollectionStatus` | Overall collection outcome |
| `observations` | `tuple[WindowsObservation, ...]` | Complete supported observations only |
| `failures` | `tuple[WindowsCollectionFailure, ...]` | Explicit limitations or invalid records |

`to_evidence()` converts observations only, using the Windows evidence adapter. Failed records produce no evidence.

## Evidence

Existing canonical `engine.evidence.Evidence` created from one complete `WindowsObservation`.

- `category`: `windows_process_observation`
- `source`: `platform.windows.process`
- `value`: the five process facts excluding the timestamp
- `timestamp`: `WindowsObservation.observed_at`
- `metadata`: platform and observation timestamp provenance
- `evidence_id`: deterministic for the observation values and timestamp

## SecurityRequest

Existing canonical `engine.request.SecurityRequest`. Windows evidence is attached through `add_evidence()` and is normalized to `Evidence`. No Windows-specific request type is introduced.

## Relationships and lifecycle

`WindowsObservation` -> `observation_to_evidence()` -> `Evidence` -> `SecurityRequest.add_evidence()` -> existing runtime evaluation.

Collection lifecycle: provider record -> validated observation or explicit failure -> optional canonical evidence conversion. Runtime evaluation remains the owner of risk, policy, decision, trust transition, and optional Raksha enforcement.
