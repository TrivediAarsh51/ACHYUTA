# Quickstart: Executable/File Evidence (SHA-256)

## Prerequisites

- Python 3.x available in the project environment.
- Repository root is `H:\Live_Projects\Hacking_projects\ACHYUTA`.
- pytest is installed for the project.
- Tests use controlled temporary files and injected readers; no elevated access or live endpoint mutation is required.

## Focused validation

Run the feature tests after implementation:

```powershell
python -m pytest tests/test_windows_file_evidence.py -q
```

Expected result: successful hashing, deterministic repeated digests, provenance/timestamp preservation, and explicit non-affirmative evidence for missing, inaccessible, unsupported, malformed, and unverifiable reads all pass.

## Existing Windows integration validation

```powershell
python -m pytest tests/test_windows_collector.py tests/test_windows_integration.py -q
```

Expected result: existing process collection behavior remains unchanged, collectors expose no authorization decision, and canonical evidence attaches through `SecurityRequest`.

## Full regression validation

```powershell
python -m pytest -q
```

Expected result: the complete existing suite passes, including requests without Windows file evidence.

## Optional Windows smoke validation

On an authorized Windows 11 Pro endpoint, run the native provider tests:

```powershell
python -m pytest tests/test_windows_collector.py -q
```

The native smoke test is conditional and may be skipped on non-Windows hosts. It must confirm read-only collection and must not terminate, modify, or launch processes.

## End-to-end flow check

A focused integration test should:

1. Build a `WindowsObservation` from a controlled fixture path.
2. Collect successful or non-affirmative file evidence.
3. Attach the canonical evidence with `SecurityRequest.add_evidence()`.
4. Invoke `evaluate_runtime_request()` from the test or caller, not from the collector.
5. Assert evidence provenance remains available to risk, policy, decision, trust, and optional Raksha audit output.
6. Assert collection itself emitted no authorization decision and no trust mutation.

See [data-model.md](data-model.md) and [contracts/windows-file-evidence-contract.md](contracts/windows-file-evidence-contract.md) for field and behavior details.
