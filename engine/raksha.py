"""Raksha's abstract enforcement boundary.

Raksha consumes Viveka's decision and records the action selected for a
request. It does not evaluate policies or change trust state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from engine.decision import Decision, DecisionEffect
from engine.policy import PolicyLifecycleState, PolicyRecord
from engine.request import SecurityRequest
from engine.risk import RiskAssessment, RiskLevel


class EnforcementAction(str, Enum):
    """Explicit actions available at the platform-independent boundary."""

    ALLOW = "allow"
    RESTRICT = "restrict"
    QUARANTINE = "quarantine"
    REQUIRE_VERIFICATION = "require_verification"
    DENY = "deny"


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class EnforcementRecord:
    """Immutable, traceable result of one abstract enforcement decision."""

    request_id: str
    decision_id: str
    policy_ids: tuple[str, ...]
    policy_context: Mapping[str, Any]
    evidence_ids: tuple[str, ...]
    action: EnforcementAction
    reason: str
    previous_state: EnforcementAction | None = None
    resulting_state: EnforcementAction | None = None
    decision_context: Mapping[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.request_id or not self.decision_id:
            raise ValueError("Enforcement records require request and decision identifiers.")
        object.__setattr__(self, "policy_ids", tuple(self.policy_ids))
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        object.__setattr__(self, "policy_context", _freeze(dict(self.policy_context)))
        object.__setattr__(self, "action", EnforcementAction(self.action))
        resulting_state = self.resulting_state or self.action
        object.__setattr__(self, "resulting_state", EnforcementAction(resulting_state))
        if self.previous_state is not None:
            object.__setattr__(self, "previous_state", EnforcementAction(self.previous_state))
        object.__setattr__(self, "decision_context", _freeze(dict(self.decision_context)))


class RakshaEnforcer:
    """Translate an existing decision into an auditable enforcement action."""

    def __init__(self) -> None:
        self._history: list[EnforcementRecord] = []

    @property
    def history(self) -> tuple[EnforcementRecord, ...]:
        """Return an immutable snapshot of the append-only enforcement history."""

        return tuple(self._history)

    def enforce(
        self,
        request: SecurityRequest,
        decision: Decision,
        *,
        policy_context: Mapping[str, Any] | None = None,
        policy_records: Mapping[str, PolicyRecord] | Iterable[PolicyRecord] | None = None,
        risk: RiskAssessment | None = None,
        trust_entity: Any | None = None,
    ) -> EnforcementRecord:
        """Record the action for an existing decision without mutating its inputs."""

        del trust_entity
        if not isinstance(request, SecurityRequest):
            raise TypeError("Raksha enforcement requires a SecurityRequest instance.")
        if not isinstance(decision, Decision):
            raise TypeError("Raksha requires a Decision object; raw effects cannot authorize enforcement.")

        records = self._policy_records_by_id(policy_records)
        context = dict(policy_context or {})
        lifecycle_failure = self._policy_lifecycle_failure(
            decision.matched_policy_ids,
            records,
            context,
        )
        evidence_ids = tuple(item.evidence_id for item in request.evidence)
        if lifecycle_failure is not None:
            action, reason = EnforcementAction.REQUIRE_VERIFICATION, lifecycle_failure
        else:
            action, reason = self._map_decision(
                decision,
                evidence_ids=evidence_ids,
                policy_context=context,
                risk=risk,
            )
        previous_state = self._history[-1].resulting_state if self._history else None
        record = EnforcementRecord(
            request_id=request.request_id,
            decision_id=decision.decision_id,
            policy_ids=decision.matched_policy_ids,
            policy_context=context,
            evidence_ids=evidence_ids,
            action=action,
            reason=reason,
            previous_state=previous_state,
            resulting_state=action,
            decision_context={
                "decision_id": decision.decision_id,
                "effect": DecisionEffect(decision.effect).value,
                "matched_policy_ids": tuple(decision.matched_policy_ids),
                "reason": decision.reason,
            },
        )
        self._history.append(record)
        return record

    @staticmethod
    def _policy_records_by_id(
        policy_records: Mapping[str, PolicyRecord] | Iterable[PolicyRecord] | None,
    ) -> dict[str, PolicyRecord]:
        if policy_records is None:
            return {}
        records = policy_records.values() if isinstance(policy_records, Mapping) else policy_records
        normalized: dict[str, PolicyRecord] = {}
        for record in records:
            if not isinstance(record, PolicyRecord):
                raise TypeError("Raksha requires PolicyRecord instances for enforcement.")
            if record.policy_id in normalized:
                raise ValueError(f"Duplicate PolicyRecord: {record.policy_id}")
            normalized[record.policy_id] = record
        return normalized

    @staticmethod
    def _policy_lifecycle_failure(
        policy_ids: tuple[str, ...],
        records: Mapping[str, PolicyRecord],
        policy_context: dict[str, Any],
    ) -> str | None:
        for policy_id in policy_ids:
            record = records.get(policy_id)
            if record is None:
                return "Policy lifecycle could not be validated; conservative fallback applied."

            integrity_valid = record.integrity_valid
            policy_context[policy_id] = {
                **dict(policy_context.get(policy_id, {})),
                "name": record.name,
                "version": record.version,
                "integrity_digest": record.integrity_digest,
                "lifecycle_state": record.lifecycle_state.value,
                "integrity_valid": integrity_valid,
            }
            if record.lifecycle_state is not PolicyLifecycleState.ACTIVE or not integrity_valid:
                return "Policy lifecycle is not active and integrity-valid; conservative fallback applied."
        return None

    @staticmethod
    def _map_decision(
        decision: Decision,
        *,
        evidence_ids: tuple[str, ...],
        policy_context: Mapping[str, Any],
        risk: RiskAssessment | None,
    ) -> tuple[EnforcementAction, str]:
        effect = DecisionEffect(decision.effect)

        if effect is DecisionEffect.DENY:
            return EnforcementAction.DENY, decision.reason
        if effect is DecisionEffect.QUARANTINE:
            return EnforcementAction.QUARANTINE, decision.reason
        if effect is DecisionEffect.RESTRICT:
            return EnforcementAction.RESTRICT, decision.reason
        if effect is DecisionEffect.REQUIRE_VERIFICATION:
            return EnforcementAction.REQUIRE_VERIFICATION, decision.reason

        if effect is not DecisionEffect.PERMIT:
            return EnforcementAction.RESTRICT, "Unsupported decision effect; conservative fallback applied."

        high_risk = risk is not None and risk.level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
        contradictory = risk is not None and risk.contradictory
        missing_context = not decision.decision_id or not decision.matched_policy_ids
        missing_evidence = not evidence_ids
        mismatched_risk_evidence = risk is not None and tuple(risk.evidence_ids) != evidence_ids
        missing_policy_context = any(policy_id not in policy_context for policy_id in decision.matched_policy_ids)

        if (
            high_risk
            or contradictory
            or missing_context
            or missing_evidence
            or mismatched_risk_evidence
            or missing_policy_context
        ):
            return (
                EnforcementAction.REQUIRE_VERIFICATION,
                "Permit decision lacks sufficient safe context; conservative fallback applied.",
            )

        return EnforcementAction.ALLOW, decision.reason


def enforce(
    request: SecurityRequest,
    decision: Decision,
    **kwargs: Any,
) -> EnforcementRecord:
    """Convenience entry point for one enforcement record."""

    return RakshaEnforcer().enforce(request, decision, **kwargs)
