# Windows Collection Contract

## Scope

This internal Python adapter contract defines the boundary between a read-only Windows process provider and the canonical ACHYUTA evidence/request flow. It does not authorize access, evaluate policy, mutate trust, or enforce endpoint controls.

## Provider contract

`ProcessProvider.collect_processes() -> Iterable[Mapping[str, Any]]`

Each returned mapping is expected to contain the six supported fields:

- `process_id`
- `process_name`
- `executable_path`
- `parent_process_id`
- `user_identity`
- `observed_at`

The provider may raise `PermissionError`, `TimeoutError`, `OSError`, or `RuntimeError`. The collector maps these to explicit non-affirmative collection outcomes and does not fabricate a record.

## Collector contract

`WindowsProcessCollector.collect() -> WindowsCollectionResult`

Behavior:

- On a non-Windows runtime, return `UNSUPPORTED` without invoking the provider.
- Convert valid records to `WindowsObservation` values.
- Return invalid or incomplete records as `MALFORMED` or `UNVERIFIABLE` failures.
- Return stale records as `STALE` when a freshness bound is configured.
- Preserve complete contradictory observations and return `CONFLICT`.
- Never return an authorization decision or call runtime, risk, policy, decision, trust, or Raksha components.

## Evidence adapter contract

`observation_to_evidence(observation: WindowsObservation) -> engine.evidence.Evidence`

Only complete observations are accepted. The adapter must use the canonical evidence factory, preserve the observation timestamp, include source and platform provenance, and produce a deterministic evidence identifier. Collection failures are not accepted and never become evidence.

## Request integration contract

The caller attaches returned evidence with:

`SecurityRequest.add_evidence(evidence)`

The caller then invokes the existing runtime boundary. The collector does not invoke `evaluate_runtime_request()`.

## Compatibility guarantees

- Existing `Evidence`, `SecurityRequest`, and runtime contracts remain authoritative.
- The optional evidence timestamp argument preserves default timestamp behavior for existing callers.
- Requests without Windows evidence continue through the prior platform-independent path.
