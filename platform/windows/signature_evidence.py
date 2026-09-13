"""Read-only Authenticode signature evidence for observed Windows executables."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from engine.evidence import Evidence, create_evidence
from platform.windows.observation import CollectionStatus, WindowsObservation


SOURCE = "platform.windows.signature"
CATEGORY = "windows_executable_signature"


class SignatureInspector(Protocol):
    """Inspect one literal executable path without making a security decision."""

    def inspect(self, path: Path) -> "SignatureInspection":
        ...


@dataclass(frozen=True)
class SignatureInspection:
    """Normalized platform signature facts before canonical evidence creation."""

    status: CollectionStatus
    signature_present: bool | None = None
    validation_status: str | None = None
    signing_source: str | None = None
    signer_subject: str | None = None
    issuer: str | None = None
    certificate_identifier: str | None = None
    signature_algorithm: str | None = None
    chain_status: str | None = None
    revocation_status: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        normalized = CollectionStatus(self.status)
        object.__setattr__(self, "status", normalized)
        if normalized is CollectionStatus.SUCCESS:
            if not isinstance(self.signature_present, bool):
                raise ValueError("Successful signature inspection must state presence.")
        elif not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("Non-success signature inspection requires a reason.")
        if self.signature_present is not None and not isinstance(self.signature_present, bool):
            raise ValueError("signature_present must be a boolean or None.")


@dataclass(frozen=True)
class SignatureEvidenceResult:
    """Canonical evidence and status for one observed executable."""

    status: CollectionStatus
    evidence: Evidence
    observation: WindowsObservation
    collected_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", CollectionStatus(self.status))
        if not isinstance(self.observation, WindowsObservation):
            raise TypeError("Signature evidence requires a WindowsObservation.")
        _validate_timestamp(self.collected_at, "collected_at")
        if self.evidence.verified:
            raise ValueError("Signature evidence must remain unverified.")
        if self.status is CollectionStatus.SUCCESS:
            if "signature_present" not in self.evidence.value:
                raise ValueError("Successful signature evidence must state presence.")
        elif "signature_present" in self.evidence.value:
            raise ValueError("Non-affirmative signature evidence cannot assert presence.")


def collect_signature_evidence(
    observation: WindowsObservation,
    *,
    platform_name: str | None = None,
    now: Callable[[], datetime] | None = None,
    inspector: SignatureInspector | None = None,
) -> SignatureEvidenceResult:
    """Inspect the observed executable path and return canonical evidence only."""

    if not isinstance(observation, WindowsObservation):
        raise TypeError("Signature evidence requires a WindowsObservation.")

    collected_at = (now or (lambda: datetime.now(timezone.utc)))()
    _validate_timestamp(collected_at, "collected_at")

    if not _is_windows(platform_name):
        return _failure_result(
            observation,
            collected_at,
            CollectionStatus.UNSUPPORTED,
            "Executable signature evidence requires a Windows runtime.",
        )

    try:
        path = _validated_path(observation.executable_path)
    except ValueError as error:
        return _failure_result(observation, collected_at, CollectionStatus.MALFORMED, str(error))

    try:
        if not path.exists():
            return _failure_result(
                observation,
                collected_at,
                CollectionStatus.MISSING,
                "Observed executable path does not exist.",
            )
        if not path.is_file():
            return _failure_result(
                observation,
                collected_at,
                CollectionStatus.MALFORMED,
                "Observed executable path is not a regular file.",
            )
    except OSError as error:
        return _failure_result(
            observation,
            collected_at,
            CollectionStatus.INACCESSIBLE,
            str(error) or "Unable to inspect the observed executable path.",
        )

    try:
        result = (inspector or NativeAuthenticodeInspector()).inspect(path)
        if not isinstance(result, SignatureInspection):
            raise TypeError("Signature inspector returned an invalid result.")
    except FileNotFoundError:
        return _failure_result(
            observation,
            collected_at,
            CollectionStatus.MISSING,
            "Observed executable disappeared before signature inspection.",
        )
    except PermissionError as error:
        return _failure_result(
            observation,
            collected_at,
            CollectionStatus.INACCESSIBLE,
            str(error) or "Access to the observed executable was denied.",
        )
    except (OSError, TimeoutError) as error:
        return _failure_result(
            observation,
            collected_at,
            CollectionStatus.UNVERIFIABLE,
            str(error) or "Signature inspection could not be completed reliably.",
        )
    except (TypeError, ValueError, RuntimeError) as error:
        return _failure_result(
            observation,
            collected_at,
            CollectionStatus.MALFORMED,
            str(error) or "Signature inspection returned malformed data.",
        )

    if result.status is CollectionStatus.SUCCESS:
        if result.signature_present is None:
            return _failure_result(
                observation,
                collected_at,
                CollectionStatus.UNVERIFIABLE,
                "Signature inspection did not report whether a signature is present.",
            )
        return _success_result(observation, collected_at, result)

    return _failure_result(observation, collected_at, result.status, result.reason or result.status.value)


class NativeAuthenticodeInspector:
    """Windows provider backed by PowerShell's literal-path signature inspection."""

    def __init__(self, executable: str | None = None, timeout: float = 30.0):
        self._executable = executable
        self._timeout = timeout

    def inspect(self, path: Path) -> SignatureInspection:
        executable = self._executable or shutil.which("powershell.exe") or shutil.which("pwsh")
        if executable is None:
            return SignatureInspection(
                status=CollectionStatus.UNSUPPORTED,
                reason="No Windows PowerShell signature provider is available.",
            )

        script = (
            "$signature = Get-AuthenticodeSignature -LiteralPath $args[0]; "
            "$certificate = $signature.SignerCertificate; "
            "[pscustomobject]@{ "
            "Status = [string]$signature.Status; "
            "StatusMessage = [string]$signature.StatusMessage; "
            "SignerSubject = if ($certificate) { [string]$certificate.Subject } else { $null }; "
            "Issuer = if ($certificate) { [string]$certificate.Issuer } else { $null }; "
            "Thumbprint = if ($certificate) { [string]$certificate.Thumbprint } else { $null }; "
            "SignatureAlgorithm = if ($certificate) { [string]$certificate.SignatureAlgorithm } else { $null } "
            "} | ConvertTo-Json -Compress"
        )
        completed = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", script, str(path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=self._timeout,
        )
        if completed.returncode != 0:
            raise OSError(completed.stderr.strip() or "Native signature inspection failed.")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise ValueError("Native signature provider returned invalid structured output.") from error
        if not isinstance(payload, Mapping):
            raise ValueError("Native signature provider returned a non-object result.")
        return _from_native_payload(payload)


def _from_native_payload(payload: Mapping[str, Any]) -> SignatureInspection:
    raw_status = str(payload.get("Status") or "").strip()
    status_message = str(payload.get("StatusMessage") or "").strip() or None
    if raw_status == "Valid":
        return SignatureInspection(
            status=CollectionStatus.SUCCESS,
            signature_present=True,
            validation_status=raw_status,
            signing_source="authenticode",
            signer_subject=_optional_text(payload.get("SignerSubject")),
            issuer=_optional_text(payload.get("Issuer")),
            certificate_identifier=_optional_text(payload.get("Thumbprint")),
            signature_algorithm=_optional_text(payload.get("SignatureAlgorithm")),
        )
    if raw_status == "NotSigned":
        return SignatureInspection(
            status=CollectionStatus.SUCCESS,
            signature_present=False,
            validation_status=raw_status,
            reason=status_message,
        )
    if raw_status:
        return SignatureInspection(
            status=CollectionStatus.INVALID,
            validation_status=raw_status,
            reason=status_message or f"Platform reported signature status {raw_status}.",
        )
    return SignatureInspection(
        status=CollectionStatus.UNVERIFIABLE,
        reason="Native signature provider returned no signature status.",
    )


def _success_result(
    observation: WindowsObservation,
    collected_at: datetime,
    inspection: SignatureInspection,
) -> SignatureEvidenceResult:
    value = _inspection_value(inspection)
    evidence = create_evidence(
        evidence_id=_evidence_id(observation, value),
        category=CATEGORY,
        source=SOURCE,
        value=value,
        strength="medium" if inspection.signature_present else "very_low",
        verified=False,
        timestamp=observation.observed_at,
        metadata=_metadata(observation, collected_at, inspection.status),
    )
    return SignatureEvidenceResult(CollectionStatus.SUCCESS, evidence, observation, collected_at)


def _failure_result(
    observation: WindowsObservation,
    collected_at: datetime,
    status: CollectionStatus,
    reason: str,
) -> SignatureEvidenceResult:
    value = {"status": status.value, "reason": reason}
    evidence = create_evidence(
        evidence_id=_evidence_id(observation, value),
        category=CATEGORY,
        source=SOURCE,
        value=value,
        strength="very_low",
        verified=False,
        timestamp=observation.observed_at,
        metadata=_metadata(observation, collected_at, status),
    )
    return SignatureEvidenceResult(status, evidence, observation, collected_at)


def _inspection_value(inspection: SignatureInspection) -> dict[str, object]:
    values: dict[str, object] = {"signature_present": inspection.signature_present}
    fields = {
        "validation_status": inspection.validation_status,
        "signing_source": inspection.signing_source,
        "signer_subject": inspection.signer_subject,
        "issuer": inspection.issuer,
        "certificate_identifier": inspection.certificate_identifier,
        "signature_algorithm": inspection.signature_algorithm,
        "chain_status": inspection.chain_status,
        "revocation_status": inspection.revocation_status,
    }
    values.update({key: value for key, value in fields.items() if value is not None})
    if inspection.reason:
        values["reason"] = inspection.reason
    return values


def _metadata(
    observation: WindowsObservation,
    collected_at: datetime,
    status: CollectionStatus,
) -> dict[str, object]:
    return {
        "platform": "windows",
        "process_id": observation.process_id,
        "process_name": observation.process_name,
        "executable_path": observation.executable_path,
        "parent_process_id": observation.parent_process_id,
        "user_identity": observation.user_identity,
        "observation_timestamp": observation.observed_at.isoformat(),
        "collection_timestamp": collected_at.isoformat(),
        "status": status.value,
    }


def _evidence_id(observation: WindowsObservation, value: Mapping[str, object]) -> str:
    identity = {
        "process_id": observation.process_id,
        "process_name": observation.process_name,
        "executable_path": observation.executable_path,
        "parent_process_id": observation.parent_process_id,
        "user_identity": observation.user_identity,
        "observed_at": observation.observed_at.isoformat(),
        "value": value,
    }
    serialized = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return "WIN-SIGNATURE-" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:24]


def _validated_path(raw_path: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("Observed executable path must be a non-empty string.")
    path = Path(raw_path)
    if not path.is_absolute():
        raise ValueError("Observed executable path must be absolute.")
    return path


def _is_windows(platform_name: str | None) -> bool:
    name = platform_name or sys.platform
    return name.lower() in {"windows", "win32"}


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _validate_timestamp(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware.")
