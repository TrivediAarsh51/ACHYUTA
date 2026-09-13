"""Adapter from Windows observations to canonical ACHYUTA evidence."""

from __future__ import annotations

import hashlib
import json

from engine.evidence import Evidence, create_evidence
from platform.windows.observation import WindowsObservation


def observation_to_evidence(observation: WindowsObservation) -> Evidence:
    """Convert one complete Windows observation into canonical Evidence."""

    if not isinstance(observation, WindowsObservation):
        raise TypeError("Only complete WindowsObservation values become evidence.")

    value = {
        "process_id": observation.process_id,
        "process_name": observation.process_name,
        "executable_path": observation.executable_path,
        "parent_process_id": observation.parent_process_id,
        "user_identity": observation.user_identity,
    }
    identity = json.dumps(
        {**value, "observed_at": observation.observed_at.isoformat()},
        sort_keys=True,
        separators=(",", ":"),
    )
    evidence_id = "WIN-PROC-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]

    return create_evidence(
        evidence_id=evidence_id,
        category="windows_process_observation",
        source="platform.windows.process",
        value=value,
        strength="medium",
        verified=False,
        timestamp=observation.observed_at,
        metadata={
            "platform": "windows",
            "observation_timestamp": observation.observed_at.isoformat(),
        },
    )
