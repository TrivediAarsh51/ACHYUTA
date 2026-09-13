# Windows File Evidence Contract

## Scope

This contract defines the read-only adapter from an existing `WindowsObservation` to canonical ACHYUTA evidence. It does not authorize access, evaluate policy, mutate trust, enforce controls, validate signatures, or scan for malware.

## Adapter contract

`collect_file_evidence(observation: WindowsObservation) -> FileEvidenceResult`

The adapter MUST:

- use `observation.executable_path` as the only target path;
- reject malformed or empty paths without attempting unrelated path discovery;
- return `UNSUPPORTED` without file access on a non-Windows runtime when runtime support is required;
- read the file without modifying it or its owning process;
- calculate SHA-256 over the complete readable byte stream;
- preserve `observation.observed_at` and record a separate collection timestamp;
- return canonical `Evidence` with `verified=False` on both success and explicit failure;
- omit a digest for missing, inaccessible, unsupported, malformed, or unverifiable outcomes;
- never return an authorization decision or call runtime, risk, policy, decision, trust, or Raksha components.

## Success evidence contract

A successful result MUST have:

- category `windows_executable_sha256`;
- source `platform.windows.file`;
- a 64-character lowercase hexadecimal SHA-256 digest in `value.sha256`;
- `verified=False`;
- the originating observation timestamp as the evidence timestamp;
- provenance for process ID, process name, executable path, user identity, platform, and collection timestamp;
- deterministic evidence identity for the observation and digest context.

## Failure evidence contract

A failed result MUST have:

- one explicit non-affirmative status and diagnostic reason;
- `verified=False`;
- no `value.sha256` field;
- the originating observation provenance where available;
- enough metadata for downstream risk, policy, and audit handling.

Recommended statuses are the existing `CollectionStatus` values: `MISSING`, `INACCESSIBLE`, `MALFORMED`, `UNSUPPORTED`, and `UNVERIFIABLE`.

## Request integration

The caller attaches the result through:

`SecurityRequest.add_evidence(result.evidence)`

The caller then invokes the existing runtime boundary. The adapter does not invoke `evaluate_runtime_request()` and does not decide how policy or trust responds to the evidence.

## Safety and compatibility guarantees

- Existing `Evidence` and `SecurityRequest` models remain authoritative.
- Existing process observation collection remains usable without file hashing.
- Requests without Windows executable evidence retain prior behavior.
- File and process state remain unchanged by collection.
- WDAC, signature validation, malware scanning, and trust promotion remain out of scope.
