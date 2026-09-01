"""
ACHYUTA - Trust State Engine v0.1

Responsible for representing and validating the trust state
of canonical ACHYUTA entities.

Important distinction:

    Decision  = what should happen to this request?
    TrustState = what does ACHYUTA currently believe about this entity?

Trust state is therefore not identical to authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class TrustState(str, Enum):
    UNKNOWN = "unknown"
    UNVERIFIED = "unverified"
    TRUSTED = "trusted"
    QUARANTINED = "quarantined"
    UNTRUSTED = "untrusted"


class EntityType(str, Enum):
    IDENTITY = "identity"
    SUBJECT = "subject"
    PROCESS = "process"
    RESOURCE = "resource"
    DEVICE = "device"


class RecoveryMode(str, Enum):
    AUTOMATIC = "automatic"
    STRONG_REVERIFICATION = "strong_reverification"
    HUMAN_APPROVAL = "human_approval"


@dataclass(frozen=True)
class TrustTransition:
    """
    Immutable record of a trust-state transition.
    """

    from_state: TrustState
    to_state: TrustState
    reason: str
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    evidence_ids: tuple[str, ...] = ()
    recovery_mode: RecoveryMode | None = None

    def __post_init__(self) -> None:
        try:
            from_state = TrustState(self.from_state)
            to_state = TrustState(self.to_state)
        except (TypeError, ValueError) as error:
            raise ValueError(
                "Trust transitions require supported trust states."
            ) from error

        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError(
                "Trust-state transition requires a reason."
            )

        object.__setattr__(self, "from_state", from_state)
        object.__setattr__(self, "to_state", to_state)
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        if self.recovery_mode is not None:
            try:
                recovery_mode = RecoveryMode(self.recovery_mode)
            except (TypeError, ValueError) as error:
                raise ValueError(
                    "Trust transitions require a supported recovery mode."
                ) from error
            object.__setattr__(self, "recovery_mode", recovery_mode)


@dataclass
class TrustEntity:
    """
    Current trust information for an entity.
    """

    entity_id: str
    entity_type: EntityType
    state: TrustState = TrustState.UNKNOWN
    reason: str = ""
    state_since: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    transition_history: list[TrustTransition] = field(
        default_factory=list
    )

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "state" and self.__dict__.get("_state_locked", False):
            raise AttributeError(
                "TrustEntity.state is not directly writable; use transition() or recover()."
            )
        object.__setattr__(self, name, value)

    def __post_init__(self) -> None:
        if not isinstance(self.entity_id, str) or not self.entity_id.strip():
            raise ValueError("Entity ID cannot be empty.")

        try:
            object.__setattr__(self, "entity_type", EntityType(self.entity_type))
        except (TypeError, ValueError) as error:
            raise ValueError(
                "Trust entities require a supported entity type."
            ) from error

        try:
            object.__setattr__(self, "state", TrustState(self.state))
        except (TypeError, ValueError) as error:
            raise ValueError(
                "Trust entities require a supported trust state."
            ) from error

        if self.state is TrustState.TRUSTED:
            raise ValueError(
                "Direct initialization to TRUSTED is prohibited. "
                "Use a controlled trust-promotion transition instead."
            )

        object.__setattr__(self, "_state_locked", True)

    re_evaluation_history: list["ReEvaluationRecord"] = field(
        default_factory=list
    )

    def transition(
        self,
        new_state: TrustState,
        reason: str,
        evidence_ids: tuple[str, ...] = (),
    ) -> TrustTransition:
        """
        Move the entity to a new trust state and record the transition.
        """

        try:
            validated_state = TrustState(new_state)
        except (TypeError, ValueError) as error:
            raise ValueError(
                "Trust transitions require a supported trust state."
            ) from error

        transition = TrustTransition(
            from_state=self.state,
            to_state=validated_state,
            reason=reason,
            evidence_ids=evidence_ids,
        )

        object.__setattr__(self, "state", validated_state)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "state_since", transition.timestamp)

        self.transition_history.append(transition)

        return transition

    def record_re_evaluation(
        self,
        *,
        trigger: "ReEvaluationTrigger",
        request_id: str,
        evidence_ids: tuple[str, ...] = (),
        policy_summary: str,
        decision_id: str,
        resulting_state: TrustState,
        transition_reason: str,
        previous_state: TrustState | None = None,
        previous_request_id: str | None = None,
        transition: TrustTransition | None = None,
    ) -> "ReEvaluationRecord":
        """Record the audit metadata for a distinct re-evaluation event."""

        if previous_state is None:
            if transition is not None:
                effective_previous_state = transition.from_state
            else:
                effective_previous_state = self.state
        else:
            effective_previous_state = previous_state

        if transition is None:
            next_state = TrustState(resulting_state)
            transition = self.transition(
                next_state,
                transition_reason,
                evidence_ids=evidence_ids,
            )

        record = ReEvaluationRecord(
            record_id=f"RECORD-{len(self.re_evaluation_history) + 1}",
            entity_id=self.entity_id,
            previous_state=effective_previous_state,
            trigger_id=trigger.trigger_id,
            request_id=request_id,
            previous_request_id=previous_request_id,
            evidence_ids=tuple(evidence_ids),
            policy_summary=policy_summary,
            decision_id=decision_id,
            resulting_state=TrustState(resulting_state),
            transition_reason=transition_reason,
            created_at=datetime.now(timezone.utc),
        )

        self.re_evaluation_history.append(record)
        return record

    def evaluate_re_evaluation(
        self,
        *,
        trigger: "ReEvaluationTrigger",
        request_id: str,
        evidence_ids: tuple[str, ...] = (),
        policy_summary: str,
        decision_id: str,
        current_state: TrustState | None = None,
        next_state: TrustState | None = None,
        transition_reason: str,
        previous_request_id: str | None = None,
    ) -> TrustTransition:
        """Apply a controlled re-evaluation to the entity's trust state."""

        previous_state = self.state if current_state is None else current_state
        target_state = self.state if next_state is None else next_state

        transition = self.transition(
            target_state,
            transition_reason,
            evidence_ids=evidence_ids,
        )

        self.record_re_evaluation(
            trigger=trigger,
            request_id=request_id,
            evidence_ids=evidence_ids,
            policy_summary=policy_summary,
            decision_id=decision_id,
            resulting_state=target_state,
            transition_reason=transition_reason,
            previous_state=previous_state,
            previous_request_id=previous_request_id,
            transition=transition,
        )

        return transition

    @property
    def previous_state(self) -> TrustState | None:
        """Return the most recent predecessor state for explainability."""
        if not self.transition_history:
            return None
        return self.transition_history[-1].from_state

    def recover(
        self,
        new_state: TrustState,
        reason: str,
        evidence_ids: tuple[str, ...] = (),
        recovery_mode: RecoveryMode | str | None = None,
        *,
        authorized: bool = False,
        human_approved: bool = False,
        condition: bool | None = None,
        recovery_modes: tuple[RecoveryMode | str, ...] | None = None,
    ) -> TrustTransition:
        """
        Validate and record recovery for this entity only.

        Policy evaluation and evidence collection remain outside this method.
        """

        if recovery_mode is None:
            raise ValueError("Recovery requires exactly one recovery mode.")

        if recovery_modes is not None:
            if len(recovery_modes) != 1:
                raise ValueError(
                    "Recovery requires exactly one recovery mode."
                )
            raise ValueError(
                "Recovery mode must be provided through recovery_mode only."
            )

        try:
            validated_mode = RecoveryMode(recovery_mode)
        except (TypeError, ValueError) as error:
            raise ValueError("Invalid recovery mode.") from error

        if self.state not in {
            TrustState.QUARANTINED,
            TrustState.UNVERIFIED,
        }:
            raise ValueError(
                "Recovery is only valid from QUARANTINED or UNVERIFIED."
            )

        if not evidence_ids:
            raise ValueError("Recovery requires supporting evidence.")

        if authorized is not True:
            raise PermissionError("Recovery is not authorized.")

        if validated_mode is RecoveryMode.HUMAN_APPROVAL and human_approved is not True:
            raise PermissionError(
                "Human approval is required for this recovery."
            )

        if condition is not None and condition is not True:
            raise ValueError("Recovery condition is not satisfied.")

        transition = TrustTransition(
            from_state=self.state,
            to_state=new_state,
            reason=reason,
            evidence_ids=evidence_ids,
            recovery_mode=validated_mode,
        )

        object.__setattr__(self, "state", transition.to_state)
        object.__setattr__(self, "reason", transition.reason)
        object.__setattr__(self, "state_since", transition.timestamp)
        self.transition_history.append(transition)

        return transition


@dataclass(frozen=True)
class ReEvaluationTrigger:
    """Security-relevant trigger that justifies a trust re-evaluation."""

    trigger_id: str
    entity_id: str
    trigger_type: str
    source: str
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    relevance_reason: str = ""

    def __post_init__(self) -> None:
        if not self.trigger_id:
            raise ValueError("Re-evaluation trigger requires an ID.")
        if not self.entity_id:
            raise ValueError("Re-evaluation trigger requires an entity ID.")
        if not self.trigger_type:
            raise ValueError("Re-evaluation trigger requires a trigger type.")
        if not self.source:
            raise ValueError("Re-evaluation trigger requires a source.")
        if not self.relevance_reason.strip():
            raise ValueError("Re-evaluation trigger requires a relevance reason.")


@dataclass(frozen=True)
class ReEvaluationRecord:
    """Explainable record of a distinct trust re-evaluation event."""

    record_id: str
    entity_id: str
    previous_state: TrustState
    trigger_id: str
    request_id: str
    previous_request_id: str | None = None
    evidence_ids: tuple[str, ...] = ()
    policy_summary: str = ""
    decision_id: str = ""
    resulting_state: TrustState = TrustState.UNKNOWN
    transition_reason: str = ""
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "previous_state", TrustState(self.previous_state))
        object.__setattr__(self, "resulting_state", TrustState(self.resulting_state))
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))


@dataclass(frozen=True)
class TrustExplanation:
    """
    Trace of existing request-evaluation objects and the resulting trust state.
    """

    request: Any
    evidence: tuple[Any, ...]
    policy_results: tuple[Any, ...]
    decision: Any
    trust_state: TrustState
    transition: TrustTransition | None = None
    previous_state: TrustState | None = None
    trigger: Any | None = None
    previous_request_id: str | None = None
    current_request_id: str | None = None
    trigger_id: str | None = None
    evidence_ids: tuple[str, ...] = ()
    policy_summary: str = ""
    decision_id: str = ""
    transition_reason: str = ""
    transition_timestamp: datetime | None = None


def build_trust_explanation(
    request: Any,
    policy_results: Any,
    decision: Any,
    trust_state: TrustState,
    transition: TrustTransition | None = None,
    *,
    previous_state: TrustState | None = None,
    trigger: Any | None = None,
    previous_request_id: str | None = None,
    decision_id: str | None = None,
    policy_summary: str | None = None,
    evidence_ids: tuple[str, ...] | None = None,
    transition_reason: str | None = None,
) -> TrustExplanation:
    """
    Assemble the request-to-trust trace without evaluating its components.
    """

    try:
        normalized_policy_results = tuple(policy_results)
    except TypeError:
        normalized_policy_results = (policy_results,)

    evidence_items = tuple(getattr(request, "evidence", ()))
    if evidence_ids is None:
        evidence_ids = tuple(
            getattr(item, "evidence_id", item.get("evidence_id", "unknown"))
            if hasattr(item, "evidence_id")
            else item.get("evidence_id", "unknown")
            for item in evidence_items
        )

    trigger_id = None
    if trigger is not None:
        trigger_id = getattr(trigger, "trigger_id", None)
        if trigger_id is None and isinstance(trigger, dict):
            trigger_id = trigger.get("trigger_id")
    else:
        trigger_id = getattr(request, "context", {}).get("trigger_id")

    effective_previous_state = previous_state
    if effective_previous_state is None and transition is not None:
        effective_previous_state = transition.from_state
    if effective_previous_state is None:
        effective_previous_state = getattr(request, "context", {}).get("previous_state")

    effective_previous_request_id = previous_request_id or getattr(request, "context", {}).get("previous_request_id")
    current_request_id = getattr(request, "request_id", None)
    decision_identifier = decision_id or getattr(decision, "decision_id", "")
    summary = policy_summary or "; ".join(
        f"{result.policy_id}:{result.effect or 'no-match'}" for result in normalized_policy_results if hasattr(result, "policy_id")
    )
    result_reason = transition_reason or (transition.reason if transition is not None else "")

    return TrustExplanation(
        request=request,
        evidence=evidence_items,
        policy_results=normalized_policy_results,
        decision=decision,
        trust_state=TrustState(trust_state),
        transition=transition,
        previous_state=TrustState(effective_previous_state) if effective_previous_state is not None else None,
        trigger=trigger,
        previous_request_id=effective_previous_request_id,
        current_request_id=current_request_id,
        trigger_id=trigger_id,
        evidence_ids=tuple(evidence_ids),
        policy_summary=summary,
        decision_id=decision_identifier,
        transition_reason=result_reason,
        transition_timestamp=transition.timestamp if transition is not None else None,
    )


def trust_state_from_decision(
    decision_effect: str,
    entity_type: EntityType,
) -> TrustState:
    """
    Map a Viveka decision to an initial trust-state response.

    v0.1 intentionally uses conservative behavior.

    DENY does not automatically mean UNTRUSTED.
    For a process/subject/resource, denial caused by
    suspicious evidence results in QUARANTINED.

    Permanent UNTRUSTED status requires stronger evidence
    or an explicit trust-state transition.
    """

    effect = decision_effect.lower()

    if effect == "permit":
        return TrustState.TRUSTED

    if effect == "monitor":
        return TrustState.UNVERIFIED

    if effect == "require_verification":
        return TrustState.UNVERIFIED

    if effect == "restrict":
        return TrustState.QUARANTINED

    if effect == "quarantine":
        return TrustState.QUARANTINED

    if effect == "deny":
        if entity_type in {
            EntityType.PROCESS,
            EntityType.SUBJECT,
            EntityType.RESOURCE,
        }:
            return TrustState.QUARANTINED

    raise ValueError(
        f"Unknown decision effect: {decision_effect}"
    )


def apply_re_evaluation_transition(
    entity: TrustEntity,
    *,
    decision,
    trigger: ReEvaluationTrigger,
    request_id: str,
    evidence_ids: tuple[str, ...] = (),
    policy_summary: str,
    decision_id: str,
    transition_reason: str,
) -> TrustTransition:
    """Apply a re-evaluation decision to an entity's trust state.
    
    Converts the decision effect to a target trust state, then uses
    the controlled transition mechanism to update the entity.
    
    Args:
        entity: The TrustEntity to update
        decision: The Decision object from Viveka
        trigger: The ReEvaluationTrigger that prompted this
        request_id: The fresh request ID for this re-evaluation
        evidence_ids: IDs of evidence used in the decision
        policy_summary: Summary of matched policies
        decision_id: The decision identifier
        transition_reason: Reason for the trust-state transition
    
    Returns:
        The TrustTransition record
    """
    
    # Determine target state from decision
    target_state = trust_state_from_decision(
        decision.effect.value if hasattr(decision.effect, 'value') else str(decision.effect),
        entity.entity_type,
    )
    
    # Apply controlled transition with audit recording
    return entity.evaluate_re_evaluation(
        trigger=trigger,
        request_id=request_id,
        evidence_ids=evidence_ids,
        policy_summary=policy_summary,
        decision_id=decision_id,
        current_state=entity.state,  # Preserve current state before transition
        next_state=target_state,
        transition_reason=transition_reason,
    )