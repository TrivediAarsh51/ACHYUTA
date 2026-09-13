# Quickstart: Executable Integrity / Authenticode Signature Evidence

## Prerequisites

- Python 3.x available in the project virtual environment.
- `pytest` installed for the project.
- Repository root is `H:\Live_Projects\Hacking_projects\ACHYUTA`.
- Portable tests use injected signature inspectors and controlled `WindowsObservation` values; they do not require a signed fixture or a live Windows endpoint.
- Optional native smoke validation runs on an authorized Windows 11 Pro endpoint with the operating system signature-inspection capability available.

## Focused validation

Run the Feature 006 unit tests after implementation:

```powershell
python -m pytest tests/test_windows_signature_evidence.py -q
```

Expected result: signed, unsigned, invalid, partial-metadata, missing, inaccessible, unsupported, malformed, and unverifiable outcomes are explicit; provenance and timestamps are preserved; no decision or trust mutation is emitted.

## Existing Windows regression validation

```powershell
python -m pytest tests/test_windows_collector.py tests/test_windows_file_evidence.py tests/test_windows_integration.py -q
```

Expected result: process observations and SHA-256 evidence retain their existing behavior, and signature evidence attaches through the canonical request boundary.

## Full regression validation

```powershell
python -m pytest -q
```

Expected result: the complete suite passes, including requests without Windows signature evidence.

## Optional Windows native smoke validation

On an authorized Windows 11 Pro endpoint, run the native-provider tests:

```powershell
python -m pytest tests/test_windows_signature_evidence.py -q
```

The native smoke test is conditional and may be skipped on non-Windows hosts. On Windows it must confirm literal observed-path inspection, explicit platform status capture, read-only behavior, and no process or certificate-store mutation.

## End-to-end flow check

A focused integration test should:

1. Build a `WindowsObservation` from a controlled executable path.
2. Inject a deterministic signed, unsigned, or failure inspection result.
3. Collect canonical signature evidence.
4. Attach it with `SecurityRequest.add_evidence()`.
5. Invoke `evaluate_runtime_request()` from the caller or test, not from the collector.
6. Assert risk, policy, decision, trust, and optional Raksha audit output retain the evidence ID.
7. Assert the collection result has no authorization decision and the endpoint fixture remains unchanged.

See [data-model.md](data-model.md) and [contracts/windows-signature-evidence-contract.md](contracts/windows-signature-evidence-contract.md) for the result fields and boundary rules.
