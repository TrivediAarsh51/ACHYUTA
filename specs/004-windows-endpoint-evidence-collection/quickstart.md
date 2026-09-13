# Quickstart: Windows Endpoint Evidence Collection

## Prerequisites

- Python 3.x and the repository virtual environment.
- `pytest` installed in the project environment.
- No Windows host is required for the portable tests. A Windows 11 Pro host is required only for the native provider smoke test.

## Run focused validation

From the repository root:

```powershell
python -m pytest tests/test_windows_collector.py tests/test_windows_integration.py tests/test_evidence.py -q
```

Expected outcome: the focused collector, integration, and timestamp compatibility tests pass.

## Run full regression validation

```powershell
python -m pytest -v
```

Expected outcome: all existing tests and Feature 004 tests pass. Requests without Windows evidence retain their existing behavior.

## Validate the portable collection contract

The focused tests should cover:

1. A fake provider returning all six supported process fields produces a `WindowsObservation` and canonical `Evidence`.
2. Evidence is attached through `SecurityRequest.add_evidence()` and reaches the existing runtime flow.
3. Unsupported platform, unavailable provider, permission denial, timeout, malformed, stale, unsupported, and unverifiable records produce explicit non-affirmative statuses.
4. Contradictory complete records remain separate and retain source context.
5. The collector exposes no authorization result and does not call runtime, risk, policy, decision, trust, or Raksha components.

See [data-model.md](data-model.md) for entity constraints and [contracts/windows-collection-contract.md](contracts/windows-collection-contract.md) for the boundary contract.

## Optional Windows smoke test

On Windows 11 Pro, run the collector test module on a controlled endpoint:

```powershell
python -m pytest tests/test_windows_collector.py -q
```

The native-provider smoke case should be conditional and read-only. It must be skipped on non-Windows hosts and must not start, stop, modify, or enforce any process or endpoint control.

## Boundary review

Before integration, inspect the changed files and confirm that Windows-specific logic exists only under `platform/windows`, with the sole planned engine extension being the optional evidence timestamp parameter.
