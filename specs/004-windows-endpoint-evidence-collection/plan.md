# Implementation Plan: Windows Endpoint Evidence Collection

**Branch**: `004-windows-endpoint-evidence-collection` | **Date**: 2026-09-09 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from [spec.md](spec.md)

## Review Summary

The existing ACHYUTA engine already provides the required domain boundaries:

- `engine.evidence.Evidence` is the canonical evidence representation and already carries a timestamp and metadata.
- `engine.request.SecurityRequest` is the canonical request and normalizes evidence through `add_evidence()`.
- `engine.risk.assess_risk()` consumes a `SecurityRequest` and does not mutate trust.
- `engine.policy.evaluate_policy()` consumes a `SecurityRequest` and evaluates policy only.
- `engine.decision.resolve_decision()` resolves policy results only.
- `engine.trust.TrustEntity` owns controlled trust transitions.
- `engine.raksha.RakshaEnforcer` consumes an existing decision and records enforcement without evaluating policy or mutating trust.
- `engine.runtime.evaluate_runtime_request()` is the existing orchestration boundary.

The first implementation should therefore add a Windows collection adapter and tests without adding a second evidence or request model and without placing Windows behavior in the engine modules.

## Technical Context

**Language/Version**: Python 3.x, matching the existing dataclass-based engine

**Primary Dependencies**: Existing standard library and project dependencies; no new dependency is required by this design

**Storage**: In-memory immutable observation and result records; persistence is out of scope

**Testing**: pytest with injected provider fixtures; Windows-only integration coverage is conditional on a Windows host

**Target Platform**: Windows 11 Pro endpoint; the engine remains platform-independent

**Project Type**: Python security-model library with platform adapters

**Performance Goals**: Correctness and provenance take priority; collection must not make authorization decisions or block evaluation

**Constraints**: `platform/windows` boundary; no policy evaluation, risk calculation, trust mutation, Raksha invocation, or Windows control enforcement from the collector; existing behavior must remain unchanged

**Scope**: Process ID, process name, executable path, parent process ID, user identity, and observation timestamp only

## Design Artifacts

- [research.md](research.md): decisions, alternatives, and resolved technical unknowns.
- [data-model.md](data-model.md): entities, validation rules, relationships, and lifecycle.
- [contracts/windows-collection-contract.md](contracts/windows-collection-contract.md): provider, collector, evidence adapter, and request integration contracts.
- [quickstart.md](quickstart.md): focused, regression, and conditional Windows validation commands.

## Constitution Check

*GATE: Must pass before implementation. Re-check after implementation.*

- **Evidence-centric security**: Windows data is converted into the existing `Evidence` model; failed collection is never affirmative evidence.
- **Request-centric evaluation**: The caller attaches canonical evidence to an existing `SecurityRequest` before invoking runtime evaluation.
- **Separation of responsibilities**: The Windows boundary only observes and adapts. Risk, policy, decision, trust, and Raksha remain in their existing modules.
- **Decision and trust separation**: The collector has no decision or trust dependencies and cannot mutate either.
- **Conservative security**: Partial, unavailable, denied, stale, malformed, or unsupported records produce explicit failures and no positive evidence.
- **Explainability and auditability**: Evidence IDs, source, observation timestamp, and endpoint/process metadata remain available to the existing request and runtime audit paths.
- **Test before integration**: Unit, failure, boundary, and regression tests are required before integration.
- **Windows endpoint focus and safety**: Collection is read-only and intended for controlled, authorized endpoint research.

No constitution exception is required.

## Canonical Interfaces

### Platform-specific raw representation

Introduce `WindowsObservation` under `platform/windows/observation.py` only because the raw Windows shape is platform-specific and must not become an engine domain model.

Proposed fields:

```text
WindowsObservation
  process_id: int
  process_name: str
  executable_path: str
  parent_process_id: int | None
  user_identity: str
  observed_at: datetime
```

The representation is immutable, validates required values, requires an aware UTC timestamp, and contains no policy, risk, decision, trust, or enforcement fields.

### Explicit collection failure

Introduce `WindowsCollectionFailure` under `platform/windows/observation.py` with:

```text
WindowsCollectionFailure
  status: CollectionStatus
  source: str
  message: str
  process_id: int | None
  observed_at: datetime | None
```

`CollectionStatus` covers `SUCCESS`, `UNAVAILABLE`, `PERMISSION_DENIED`, `STALE`, `MALFORMED`, `UNSUPPORTED`, `UNVERIFIABLE`, and `CONFLICT`. `TIMEOUT` remains available for provider-specific diagnostics but maps to a non-affirmative unavailable result at the collector boundary.

### Collection result

Use a `WindowsCollectionResult` containing:

```text
WindowsCollectionResult
  observations: tuple[WindowsObservation, ...]
  failures: tuple[WindowsCollectionFailure, ...]
```

Failures are not converted to `Evidence`. A partially collected process must be represented as a failure, not as an affirmative observation with missing fields.

### Provider boundary

Define a narrow provider protocol in `platform/windows/collector.py` for reading process records. The production provider is responsible only for read-only Windows process inspection. Tests inject a fake provider so unit tests do not require a live process table, elevated permissions, or a Windows host.

The collector API should be equivalent to:

```text
WindowsProcessCollector(provider=None).collect() -> WindowsCollectionResult
```

The collector checks platform support and converts provider exceptions or invalid records into explicit failures. It does not import or call policy, risk, decision, trust, runtime, or Raksha modules.

### Canonical evidence adapter

Define a function under `platform/windows/evidence.py` with the shape:

```text
observation_to_evidence(observation: WindowsObservation) -> Evidence
```

The adapter calls the canonical evidence factory and creates one evidence item for one complete observation:

```text
category = "windows_process_observation"
source = "platform.windows.process"
value = {
  "process_id": ..., 
  "process_name": ..., 
  "executable_path": ..., 
  "parent_process_id": ..., 
  "user_identity": ...,
}
metadata = {
  "platform": "windows",
  "observation_timestamp": ...,
}
```

The evidence ID must be deterministic for the observation identity and timestamp, or be supplied by the caller, so repeated requests can distinguish fresh evidence without inventing a second identity model. The adapter must not produce evidence from `WindowsCollectionFailure`.

## Required Canonical Extension

`Evidence` already has the required `timestamp` field, but `create_evidence()` always uses its default clock value. To preserve the endpoint observation timestamp without mutating an evidence object after creation, make one backwards-compatible extension:

```text
create_evidence(..., timestamp: datetime | None = None) -> Evidence
```

When supplied, the factory passes the timestamp to `Evidence`; when omitted, current behavior remains unchanged. Add a focused engine test for both the supplied and default timestamp paths. No other engine module requires modification for this feature.

## Data Flow

```text
WindowsProcessProvider
    -> WindowsProcessCollector
    -> WindowsObservation / WindowsCollectionFailure
    -> observation_to_evidence (successful observations only)
    -> SecurityRequest.add_evidence (existing canonical request)
    -> evaluate_runtime_request (existing runtime boundary)
    -> assess_risk
    -> evaluate_policy
    -> resolve_decision
    -> TrustEntity transition when the caller explicitly supplies an entity
    -> RakshaEnforcer only when the caller explicitly requests enforcement
```

The collector must never call `evaluate_runtime_request`; the application or test harness owns attaching evidence and starting evaluation. This keeps the collector from bypassing the request boundary and makes the full flow independently testable.

The current runtime audit list is an evaluation record, not a collector pipeline. Feature 004 must not reorder or rewrite it solely to display the Windows source; it should assert that Windows evidence is present in the request and reaches the existing downstream stages.

## Failure Handling

| Condition | Collection result | Evidence result | Downstream behavior |
|---|---|---|---|
| Non-Windows host | `unsupported_platform` failure | None | Caller may skip collection; engine behavior is unchanged |
| Provider unavailable | `unavailable` failure | None | Request continues only with other evidence; no affirmative Windows claim |
| Access denied for a process or field | `access_denied` failure | No evidence for that incomplete process | Missing signal remains non-affirmative |
| Provider timeout | `timeout` failure | None for the timed-out record | No fabricated process state |
| Invalid field type or missing required field | `malformed` failure | None for that record | Invalid data cannot enter canonical evidence |
| Unsupported record/source | `unsupported` failure | None | Scope remains bounded to the six supported fields |
| Observation older than caller freshness bound | `stale` failure | None | Stale data cannot be treated as current affirmative evidence |
| Multiple complete observations disagree | Multiple observations retained | Evidence for each complete source record | Existing risk/policy layers receive both records; collector does not resolve the conflict |

Failure messages should be diagnostic but must not include secrets or attempt endpoint remediation. Exceptions from a single process should not fabricate data for that process; the result may retain successful observations from other processes.

## Test Strategy

### Unit tests

- Validate `WindowsObservation` accepts the six supported fields and rejects empty or invalid required values.
- Validate UTC-aware observation timestamps.
- Validate each `CollectionFailureCode` and immutable result contents.
- Verify a fake provider produces one complete observation per process record.
- Verify provider exceptions, unsupported hosts, malformed records, access denial, timeout, and stale records become failures.
- Verify failures never produce `Evidence`.
- Verify `observation_to_evidence()` returns the canonical `engine.evidence.Evidence` type with the expected category, source, metadata, value, and observation timestamp.
- Verify the adapter has no decision, policy, risk, trust, runtime, or Raksha side effects.

### Integration tests

- Attach converted evidence through `SecurityRequest.add_evidence()` and assert the request contains canonical `Evidence` objects.
- Pass the request to `evaluate_runtime_request()` and assert existing risk, policy, decision, trust, and optional enforcement behavior remains responsible for downstream outcomes.
- Assert a request without Windows evidence behaves exactly as before.
- Assert contradictory complete Windows observations remain separate evidence items and are visible to downstream risk comparison when supplied as current and previous requests.

### Regression validation

- Run the full existing pytest suite.
- Run the new Windows tests on a non-Windows development host using injected providers.
- Run a conditional smoke test on Windows 11 Pro that verifies read-only collection of the six fields; skip it when the host is not Windows.
- Confirm the collector module has no imports from `engine.risk`, `engine.policy`, `engine.decision`, `engine.trust`, `engine.raksha`, or `engine.runtime`.

## File-Level Changes

### New files

```text
platform/__init__.py
platform/windows/__init__.py
platform/windows/observation.py
platform/windows/collector.py
platform/windows/evidence.py
tests/test_windows_collector.py
tests/test_windows_integration.py
```

`platform/windows` is the only location for Windows-specific collection and adaptation. The production provider implementation may be split into a private module under that directory only if the first implementation needs that separation.

### Existing files requiring changes

```text
engine/evidence.py
tests/test_evidence.py
```

The only planned engine change is the optional `timestamp` argument to `create_evidence()` and its focused regression tests. No changes are planned for `engine/request.py`, `engine/risk.py`, `engine/policy.py`, `engine/decision.py`, `engine/trust.py`, `engine/raksha.py`, or `engine/runtime.py`.

### Explicit non-goals

- No second `Evidence` or `SecurityRequest` class.
- No direct collector-to-runtime or collector-to-decision call.
- No Windows policy evaluation, risk scoring, authorization, trust mutation, Raksha invocation, process termination, firewall changes, quarantine actions, or other endpoint enforcement.
- No collection outside the six first-scope process fields.
- No persistence, scheduling, event bus, service installation, or kernel/driver integration.

## Implementation Order

1. Add the platform-specific observation, failure, result, and provider protocols.
2. Add the read-only collector with injected-provider tests.
3. Add the canonical evidence adapter and failure exclusion tests.
4. Extend `create_evidence()` only to preserve an explicit observation timestamp, then run its focused regression test.
5. Add the request/runtime integration tests without changing runtime orchestration.
6. Run the full existing test suite and the conditional Windows smoke test.

## Post-Design Constitution Check

*GATE: Pass. The design artifacts preserve the constitution before implementation.*

- Evidence-centric security remains enforced because only complete observations become canonical evidence and failures remain non-affirmative.
- Request-centric evaluation remains enforced because evidence enters the existing `SecurityRequest` through `add_evidence()` before runtime evaluation.
- Separation of responsibilities remains enforced because the provider and collector do not invoke risk, policy, decision, trust, runtime, or Raksha components.
- Conservative security, explainability, and auditability are supported by explicit statuses, source provenance, observation timestamps, deterministic evidence IDs, and retained conflicts.
- Test-before-integration and no-regression requirements are covered by focused unit tests, integration tests, conditional Windows smoke coverage, and the full pytest suite.
- Windows endpoint focus and research safety are preserved through read-only process collection and controlled test environments.

No constitution exception is required.
