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


def build_trust_explanation(
    request: Any,
    policy_results: Any,
    decision: Any,
    trust_state: TrustState,
    transition: TrustTransition | None = None,
) -> TrustExplanation:
    """
    Assemble the request-to-trust trace without evaluating its components.
    """

    try:
        normalized_policy_results = tuple(policy_results)
    except TypeError:
        normalized_policy_results = (policy_results,)

    return TrustExplanation(
        request=request,
        evidence=tuple(getattr(request, "evidence", ())),
        policy_results=normalized_policy_results,
        decision=decision,
        trust_state=TrustState(trust_state),
        transition=transition,
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

        return TrustState.UNVERIFIED

    raise ValueError(
        f"Unknown decision effect: {decision_effect}"
    )