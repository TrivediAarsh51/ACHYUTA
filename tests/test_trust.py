"""
ACHYUTA - Trust State Engine Tests
"""

import pytest

from engine.decision import Decision, DecisionEffect
from engine.evidence import create_evidence
from engine.request import SecurityRequest, create_fresh_request
from engine.trust import (
    EntityType,
    RecoveryMode,
    ReEvaluationRecord,
    ReEvaluationTrigger,
    TrustEntity,
    TrustState,
    TrustTransition,
    build_trust_explanation,
    trust_state_from_decision,
)


def test_canonical_entity_types_start_unknown():

    for entity_type in EntityType:
        entity = TrustEntity(
            entity_id=f"{entity_type.value}:test",
            entity_type=entity_type,
        )

        assert entity.state == TrustState.UNKNOWN


def test_each_supported_trust_state_can_be_reached():

    for index, state in enumerate(TrustState):
        if state is TrustState.TRUSTED:
            continue

        entity = TrustEntity(
            entity_id=f"process:state-{index}",
            entity_type=EntityType.PROCESS,
        )

        transition = entity.transition(
            state,
            f"Transitioned to {state.value} for testing.",
        )

        assert transition.from_state == TrustState.UNKNOWN
        assert transition.to_state == state
        assert entity.state == state


def test_unsupported_entity_type_is_rejected_without_mutation():

    with pytest.raises(ValueError):
        TrustEntity(
            entity_id="process:invalid-type",
            entity_type="unsupported",
        )


def test_unsupported_trust_state_is_rejected_without_mutation():

    entity = TrustEntity(
        entity_id="process:invalid-state",
        entity_type=EntityType.PROCESS,
    )
    before = (
        entity.state,
        entity.reason,
        entity.state_since,
        tuple(entity.transition_history),
    )

    with pytest.raises(ValueError):
        entity.transition(
            "unsupported",
            "Unsupported state must be rejected.",
        )

    assert (
        entity.state,
        entity.reason,
        entity.state_since,
        tuple(entity.transition_history),
    ) == before


@pytest.mark.parametrize("entity_id", ["", "   "])
def test_empty_entity_identifier_is_rejected_without_mutation(entity_id):

    with pytest.raises(ValueError):
        TrustEntity(
            entity_id=entity_id,
            entity_type=EntityType.PROCESS,
        )


def test_invalid_transition_is_rejected_without_mutation():

    entity = TrustEntity(
        entity_id="process:invalid-transition",
        entity_type=EntityType.PROCESS,
    )
    before = (
        entity.state,
        entity.reason,
        entity.state_since,
        tuple(entity.transition_history),
    )

    with pytest.raises(ValueError):
        entity.transition(
            None,
            "Invalid transition must be rejected.",
        )

    assert (
        entity.state,
        entity.reason,
        entity.state_since,
        tuple(entity.transition_history),
    ) == before


def test_existing_trust_public_contract_remains_compatible():

    assert set(TrustState) == {
        TrustState.UNKNOWN,
        TrustState.UNVERIFIED,
        TrustState.TRUSTED,
        TrustState.QUARANTINED,
        TrustState.UNTRUSTED,
    }

    assert set(EntityType) == {
        EntityType.IDENTITY,
        EntityType.SUBJECT,
        EntityType.PROCESS,
        EntityType.RESOURCE,
        EntityType.DEVICE,
    }

    transition = TrustTransition(
        from_state=TrustState.UNKNOWN,
        to_state=TrustState.UNVERIFIED,
        reason="Verification is pending.",
    )

    assert transition.evidence_ids == ()
    assert transition.timestamp.tzinfo is not None


def test_new_entity_starts_unknown():

    entity = TrustEntity(
        entity_id="process:1234",
        entity_type=EntityType.PROCESS,
    )

    assert entity.state == TrustState.UNKNOWN


def test_constructor_rejects_direct_trusted_initialization():

    entity = TrustEntity(
        entity_id="process:constructor-trusted",
        entity_type=EntityType.PROCESS,
    )
    assert entity.state == TrustState.UNKNOWN

    with pytest.raises(ValueError):
        TrustEntity(
            entity_id="process:constructor-trusted-attempt",
            entity_type=EntityType.PROCESS,
            state=TrustState.TRUSTED,
        )


def test_state_attribute_cannot_be_directly_mutated_to_trusted():

    entity = TrustEntity(
        entity_id="process:direct-mutation",
        entity_type=EntityType.PROCESS,
    )
    original_state = entity.state
    original_history = tuple(entity.transition_history)

    assert entity.state == TrustState.UNKNOWN

    with pytest.raises((AttributeError, TypeError, ValueError)):
        entity.state = TrustState.TRUSTED

    assert entity.state == original_state
    assert tuple(entity.transition_history) == original_history


def test_transition_to_trusted_is_rejected_by_the_controlled_boundary():

    entity = TrustEntity(
        entity_id="process:controlled-trusted-boundary",
        entity_type=EntityType.PROCESS,
    )

    with pytest.raises(ValueError):
        entity.transition(
            TrustState.TRUSTED,
            "Direct TRUSTED promotion is forbidden.",
            evidence_ids=("E-TRUSTED-CTRL-001",),
        )

    assert entity.state == TrustState.UNKNOWN
    assert entity.transition_history == []


def test_dedicated_trusted_promotion_api_exists():

    entity = TrustEntity(
        entity_id="process:dedicated-trusted-promotion",
        entity_type=EntityType.PROCESS,
    )

    assert hasattr(entity, "promote_to_trusted")
    assert callable(entity.promote_to_trusted)


def test_controlled_trusted_promotion_requires_valid_decision_context():

    entity = TrustEntity(
        entity_id="process:promotion-needs-decision",
        entity_type=EntityType.PROCESS,
    )

    with pytest.raises((TypeError, ValueError, PermissionError)):
        entity.promote_to_trusted(
            reason="Promotion without a valid decision should fail.",
            decision=None,
            evidence_ids=("E-TRUSTED-PROMO-001",),
        )

    assert entity.state == TrustState.UNKNOWN
    assert entity.transition_history == []


def test_controlled_trusted_promotion_requires_supporting_evidence_ids():

    entity = TrustEntity(
        entity_id="process:promotion-needs-evidence",
        entity_type=EntityType.PROCESS,
    )

    decision = Decision(
        effect=DecisionEffect.PERMIT,
        matched_policy_ids=("POL-ALLOW",),
        reason="Authorization allowed the request.",
        decision_id="DEC-ALLOW-001",
    )

    with pytest.raises((ValueError, PermissionError)):
        entity.promote_to_trusted(
            reason="Cannot promote without evidence.",
            decision=decision,
            evidence_ids=(),
        )

    assert entity.state == TrustState.UNKNOWN
    assert entity.transition_history == []


def test_raw_permit_value_is_not_sufficient_for_trusted_promotion():

    entity = TrustEntity(
        entity_id="process:permit-is-not-trust",
        entity_type=EntityType.PROCESS,
    )

    with pytest.raises((TypeError, ValueError, PermissionError)):
        entity.promote_to_trusted(
            reason="A raw permit string must not establish TRUSTED.",
            decision="permit",
            evidence_ids=("E-TRUSTED-PERMIT-001",),
        )

    assert entity.state == TrustState.UNKNOWN
    assert entity.transition_history == []


def test_valid_decision_and_evidence_preserve_immutable_audit_trail():

    entity = TrustEntity(
        entity_id="process:valid-trusted-promotion",
        entity_type=EntityType.PROCESS,
    )

    decision = Decision(
        effect=DecisionEffect.PERMIT,
        matched_policy_ids=("POL-ALLOW",),
        reason="Verified and permitted execution.",
        decision_id="DEC-ALLOW-VALID",
    )

    transition = entity.promote_to_trusted(
        reason="Verified process met the allow policy.",
        decision=decision,
        evidence_ids=("E-VALID-001", "E-VALID-002"),
    )

    assert entity.state == TrustState.TRUSTED
    assert transition.from_state == TrustState.UNKNOWN
    assert transition.to_state == TrustState.TRUSTED
    assert transition.evidence_ids == ("E-VALID-001", "E-VALID-002")
    assert entity.transition_history[-1] is transition
    assert entity.transition_history[-1].reason == "Verified process met the allow policy."

    with pytest.raises(AttributeError):
        entity.transition_history[-1].reason = "tampered reason"


def test_non_trusted_transitions_continue_to_work():

    entity = TrustEntity(
        entity_id="process:non-trusted-transition",
        entity_type=EntityType.PROCESS,
    )

    transition = entity.transition(
        TrustState.UNVERIFIED,
        "Verification remains pending.",
        evidence_ids=("E-VERIFY-001",),
    )

    assert entity.state == TrustState.UNVERIFIED
    assert transition.from_state == TrustState.UNKNOWN
    assert transition.to_state == TrustState.UNVERIFIED
    assert transition.evidence_ids == ("E-VERIFY-001",)
    assert len(entity.transition_history) == 1


def test_deny_process_results_in_quarantine():

    state = trust_state_from_decision(
        "deny",
        EntityType.PROCESS,
    )

    assert state == TrustState.QUARANTINED


def test_quarantine_decision_results_in_quarantine():

    state = trust_state_from_decision(
        "quarantine",
        EntityType.PROCESS,
    )

    assert state == TrustState.QUARANTINED


def test_require_verification_results_in_unverified():

    state = trust_state_from_decision(
        "require_verification",
        EntityType.PROCESS,
    )

    assert state == TrustState.UNVERIFIED


@pytest.mark.parametrize(
    ("decision_effect", "expected_state"),
    [
        ("deny", TrustState.QUARANTINED),
        ("restrict", TrustState.QUARANTINED),
        ("quarantine", TrustState.QUARANTINED),
        ("monitor", TrustState.UNVERIFIED),
        ("require_verification", TrustState.UNVERIFIED),
    ],
)
def test_decision_to_trust_mapping_is_conservative(
    decision_effect,
    expected_state,
):

    state = trust_state_from_decision(
        decision_effect,
        EntityType.PROCESS,
    )

    assert state == expected_state
    assert state is not TrustState.TRUSTED


def test_trusted_transition_is_recorded():

    entity = TrustEntity(
        entity_id="process:1234",
        entity_type=EntityType.PROCESS,
    )

    decision = Decision(
        effect=DecisionEffect.PERMIT,
        matched_policy_ids=("POL-TRUSTED-001",),
        reason="Process successfully verified.",
        decision_id="DEC-TRUSTED-001",
    )

    transition = entity.promote_to_trusted(
        reason="Process successfully verified.",
        decision=decision,
        evidence_ids=("E-001",),
    )

    assert entity.state == TrustState.TRUSTED
    assert transition.from_state == TrustState.UNKNOWN
    assert transition.to_state == TrustState.TRUSTED
    assert transition.evidence_ids == ("E-001",)


def test_re_evaluation_history_records_trigger_and_audit_metadata():

    entity = TrustEntity(
        entity_id="process:re-eval",
        entity_type=EntityType.PROCESS,
    )
    decision = Decision(
        effect=DecisionEffect.PERMIT,
        matched_policy_ids=("POL-RE-EVAL-INIT",),
        reason="Initial trust established.",
        decision_id="DEC-RE-EVAL-INIT",
    )
    entity.promote_to_trusted(
        reason="Initial trust established.",
        decision=decision,
        evidence_ids=("E-000",),
    )

    trigger = ReEvaluationTrigger(
        trigger_id="TRIGGER-001",
        entity_id="process:re-eval",
        trigger_type="evidence_update",
        source="mock",
        relevance_reason="New unsigned evidence is present.",
    )

    record = entity.record_re_evaluation(
        trigger=trigger,
        request_id="REQ-RE-001",
        evidence_ids=("E-001",),
        policy_summary="signature policy -> deny",
        decision_id="DEC-RE-001",
        resulting_state=TrustState.QUARANTINED,
        transition_reason="Fresh evidence contradicts previous trust.",
    )

    assert isinstance(record, ReEvaluationRecord)
    assert record.previous_state == TrustState.TRUSTED
    assert record.trigger_id == "TRIGGER-001"
    assert record.request_id == "REQ-RE-001"
    assert entity.re_evaluation_history[-1] is record


def test_re_evaluation_record_creates_append_only_transition_entry():

    entity = TrustEntity(
        entity_id="process:append-only-audit",
        entity_type=EntityType.PROCESS,
    )
    initial = entity.promote_to_trusted(
        reason="Initial trust established.",
        decision=Decision(
            effect=DecisionEffect.PERMIT,
            matched_policy_ids=("POL-APP-INIT",),
            reason="Initial trust established.",
            decision_id="DEC-APP-INIT",
        ),
        evidence_ids=("E-APP-000",),
    )

    trigger = ReEvaluationTrigger(
        trigger_id="TRIGGER-APP-001",
        entity_id="process:append-only-audit",
        trigger_type="evidence_update",
        source="mock",
        relevance_reason="Fresh evidence contradicts previous trust.",
    )

    record = entity.record_re_evaluation(
        trigger=trigger,
        request_id="REQ-RE-APP-001",
        evidence_ids=("E-APP-001",),
        policy_summary="signature policy -> deny",
        decision_id="DEC-RE-APP-001",
        resulting_state=TrustState.QUARANTINED,
        transition_reason="Fresh evidence is contradictory.",
    )

    assert isinstance(record, ReEvaluationRecord)
    assert len(entity.transition_history) == 2
    assert entity.transition_history[0] is initial
    assert entity.transition_history[0].to_state == TrustState.TRUSTED
    assert entity.transition_history[-1].from_state == TrustState.TRUSTED
    assert entity.transition_history[-1].to_state == TrustState.QUARANTINED
    assert entity.transition_history[-1].reason == "Fresh evidence is contradictory."
    assert entity.re_evaluation_history[-1] is record


def test_trusted_to_trusted_re_evaluation_still_creates_a_new_audit_event():

    entity = TrustEntity(
        entity_id="process:trusted-recheck",
        entity_type=EntityType.PROCESS,
    )
    initial = entity.promote_to_trusted(
        reason="Initial trust established.",
        decision=Decision(
            effect=DecisionEffect.PERMIT,
            matched_policy_ids=("POL-TRUSTED-INIT",),
            reason="Initial trust established.",
            decision_id="DEC-TRUSTED-INIT",
        ),
        evidence_ids=("E-TRUSTED-000",),
    )

    trigger = ReEvaluationTrigger(
        trigger_id="TRIGGER-TRUSTED-001",
        entity_id="process:trusted-recheck",
        trigger_type="request",
        source="mock",
        relevance_reason="Fresh request confirms the same trust posture remains valid.",
    )

    record = entity.record_re_evaluation(
        trigger=trigger,
        request_id="REQ-TRUSTED-RECHECK",
        previous_request_id="REQ-TRUSTED-ORIGINAL",
        evidence_ids=("E-TRUSTED-001",),
        policy_summary="signature policy -> allow",
        decision_id="DEC-TRUSTED-RECHECK",
        resulting_state=TrustState.TRUSTED,
        transition_reason="Fresh evidence validates continued trust.",
        previous_state=TrustState.TRUSTED,
    )

    assert isinstance(record, ReEvaluationRecord)
    assert record.previous_state == TrustState.TRUSTED
    assert record.resulting_state == TrustState.TRUSTED
    assert record.request_id == "REQ-TRUSTED-RECHECK"
    assert record.previous_request_id == "REQ-TRUSTED-ORIGINAL"
    assert len(entity.transition_history) == 2
    assert entity.transition_history[0] is initial
    assert entity.transition_history[-1].from_state == TrustState.TRUSTED
    assert entity.transition_history[-1].to_state == TrustState.TRUSTED
    assert len(entity.re_evaluation_history) == 1
    assert entity.state == TrustState.TRUSTED


def test_fresh_request_retains_separate_request_history():

    original = SecurityRequest(
        request_id="REQ-ORIGINAL",
        identity={"type": "local_user", "name": "alice"},
        subject={"type": "executable", "name": "trusted.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\trusted.exe"},
    )
    original.add_evidence(
        create_evidence(
            evidence_id="E-010",
            category="signature",
            source="mock",
            value="signed",
            strength="high",
            verified=True,
        )
    )

    refreshed = create_fresh_request(
        original,
        request_id="REQ-RECHECK",
        context={"origin": "re-evaluation"},
    )

    assert refreshed is not original
    assert refreshed.request_id == "REQ-RECHECK"
    assert refreshed.context["origin"] == "re-evaluation"
    assert refreshed.evidence == original.evidence
    assert refreshed.history_id == original.request_id


def test_stale_trust_re_evaluation_requires_fresh_request_context():

    original = SecurityRequest(
        request_id="REQ-ORIGINAL-TRUST",
        identity={"type": "local_user", "name": "alice"},
        subject={"type": "executable", "name": "trusted.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\trusted.exe"},
    )
    original.add_evidence(
        create_evidence(
            evidence_id="E-TRUST-ORIGINAL",
            category="signature",
            source="mock",
            value="signed",
            strength="high",
            verified=True,
        )
    )

    refreshed = create_fresh_request(
        original,
        request_id="REQ-RECHECK-TRUST",
        context={"origin": "fresh-evidence-recheck"},
    )

    assert refreshed.request_id == "REQ-RECHECK-TRUST"
    assert refreshed.history_id == original.request_id
    assert refreshed is not original


def test_quarantine_transition_is_recorded():

    entity = TrustEntity(
        entity_id="process:5678",
        entity_type=EntityType.PROCESS,
    )

    entity.transition(
        TrustState.QUARANTINED,
        "Suspicious process execution.",
        evidence_ids=("E-010", "E-011"),
    )

    assert entity.state == TrustState.QUARANTINED

    assert len(entity.transition_history) == 1

    assert entity.transition_history[0].evidence_ids == (
        "E-010",
        "E-011",
    )


def test_transition_requires_reason():

    entity = TrustEntity(
        entity_id="process:9999",
        entity_type=EntityType.PROCESS,
    )

    try:
        entity.transition(
            TrustState.QUARANTINED,
            "",
        )
        assert False
    except ValueError:
        assert True


def test_transition_metadata_is_immutable_and_complete():

    entity = TrustEntity(
        entity_id="process:metadata",
        entity_type=EntityType.PROCESS,
    )

    transition = entity.transition(
        TrustState.UNVERIFIED,
        "Verification is required.",
        evidence_ids=("E-100",),
    )

    assert transition.from_state == TrustState.UNKNOWN
    assert transition.to_state == TrustState.UNVERIFIED
    assert transition.reason == "Verification is required."
    assert transition.timestamp.tzinfo is not None
    assert transition.evidence_ids == ("E-100",)

    with pytest.raises(AttributeError):
        transition.reason = "Changed reason"


def test_evidence_identifiers_are_preserved_on_every_history_entry():

    entity = TrustEntity(
        entity_id="process:evidence-history",
        entity_type=EntityType.PROCESS,
    )

    first = entity.transition(
        TrustState.QUARANTINED,
        "Suspicious execution was observed.",
        evidence_ids=("E-101", "E-102"),
    )
    second = entity.transition(
        TrustState.UNVERIFIED,
        "Additional verification is required.",
        evidence_ids=("E-103",),
    )

    assert first.evidence_ids == ("E-101", "E-102")
    assert second.evidence_ids == ("E-103",)
    assert tuple(item.evidence_ids for item in entity.transition_history) == (
        ("E-101", "E-102"),
        ("E-103",),
    )


def test_transition_history_is_chronological_and_matches_current_state():

    entity = TrustEntity(
        entity_id="process:history",
        entity_type=EntityType.PROCESS,
    )

    first = entity.transition(
        TrustState.QUARANTINED,
        "Suspicious execution was observed.",
    )
    second = entity.promote_to_trusted(
        reason="Verification completed successfully.",
        decision=Decision(
            effect=DecisionEffect.PERMIT,
            matched_policy_ids=("POL-HISTORY-TRUSTED",),
            reason="Verification completed successfully.",
            decision_id="DEC-HISTORY-TRUSTED",
        ),
        evidence_ids=("E-HISTORY-001",),
    )

    assert entity.transition_history == [first, second]
    assert first.timestamp <= second.timestamp
    assert second.from_state == first.to_state
    assert entity.state == second.to_state
    assert entity.state_since == second.timestamp


def test_explainability_exposes_request_evidence_policy_decision_and_state():

    from engine.decision import resolve_decision
    from engine.evidence import create_evidence
    from engine.policy import evaluate_policy
    from engine.request import SecurityRequest

    evidence = create_evidence(
        evidence_id="E-EXPLAIN-001",
        category="signature",
        source="mock",
        value="unsigned",
        strength="high",
        verified=True,
    )
    request = SecurityRequest(
        request_id="REQ-EXPLAIN-001",
        identity={"type": "local_user"},
        subject={"type": "executable"},
        action={"type": "execute"},
        resource={"type": "executable"},
    )
    request.add_evidence(evidence)
    policy_result = evaluate_policy(
        {
            "id": "POL-EXPLAIN-001",
            "name": "Unsigned executable",
            "evidence": {
                "signature": {
                    "value": "unsigned",
                    "verified": True,
                }
            },
            "effect": "deny",
        },
        request,
    )
    decision = resolve_decision([policy_result])
    entity = TrustEntity(
        entity_id="process:explain",
        entity_type=EntityType.PROCESS,
    )
    transition = entity.transition(
        TrustState.QUARANTINED,
        decision.reason,
        evidence_ids=tuple(item.evidence_id for item in request.evidence),
    )

    explanation = build_trust_explanation(
        request=request,
        policy_results=[policy_result],
        decision=decision,
        trust_state=entity.state,
        transition=transition,
    )

    assert explanation.request is request
    assert explanation.evidence == (evidence,)
    assert explanation.policy_results == (policy_result,)
    assert explanation.decision is decision
    assert explanation.trust_state == TrustState.QUARANTINED
    assert explanation.transition is transition


def _quarantined_entity(entity_id, entity_type=EntityType.PROCESS):

    entity = TrustEntity(
        entity_id=entity_id,
        entity_type=entity_type,
    )
    entity.transition(
        TrustState.QUARANTINED,
        "Suspicious activity requires recovery review.",
        evidence_ids=("E-RECOVERY-001",),
    )
    return entity


def _entity_snapshot(entity):

    return (
        entity.state,
        entity.reason,
        entity.state_since,
        tuple(entity.transition_history),
    )


def test_recovery_is_scoped_to_the_selected_entity():

    selected = _quarantined_entity("process:selected")
    unrelated = _quarantined_entity("process:unrelated")
    unrelated_before = _entity_snapshot(unrelated)

    selected.recover(
        TrustState.TRUSTED,
        "Verified process evidence supports recovery.",
        evidence_ids=("E-RECOVERY-002",),
        recovery_mode=RecoveryMode.STRONG_REVERIFICATION,
        authorized=True,
    )

    assert selected.state == TrustState.TRUSTED
    assert _entity_snapshot(unrelated) == unrelated_before


@pytest.mark.parametrize("recovery_mode", RecoveryMode)
def test_recovery_records_each_explicit_recovery_mode(recovery_mode):

    entity = _quarantined_entity(f"process:{recovery_mode.value}")

    transition = entity.recover(
        TrustState.TRUSTED,
        f"Recovery completed using {recovery_mode.value}.",
        evidence_ids=(f"E-{recovery_mode.value}",),
        recovery_mode=recovery_mode,
        authorized=True,
        human_approved=True,
    )

    assert transition.recovery_mode == recovery_mode
    assert entity.state == TrustState.TRUSTED


def _assert_recovery_rejected_without_mutation(entity, **recovery_kwargs):

    before = _entity_snapshot(entity)

    with pytest.raises((PermissionError, ValueError)):
        entity.recover(
            TrustState.TRUSTED,
            "Recovery attempt should be rejected.",
            **recovery_kwargs,
        )

    assert _entity_snapshot(entity) == before


def test_recovery_without_required_evidence_is_rejected():

    _assert_recovery_rejected_without_mutation(
        _quarantined_entity("process:missing-evidence"),
        evidence_ids=(),
        recovery_mode=RecoveryMode.AUTOMATIC,
        authorized=True,
    )


def test_invalid_recovery_mode_is_rejected():

    _assert_recovery_rejected_without_mutation(
        _quarantined_entity("process:invalid-mode"),
        evidence_ids=("E-RECOVERY-INVALID",),
        recovery_mode="invalid",
        authorized=True,
    )


def test_unauthorized_recovery_is_rejected():

    _assert_recovery_rejected_without_mutation(
        _quarantined_entity("process:unauthorized"),
        evidence_ids=("E-RECOVERY-UNAUTHORIZED",),
        recovery_mode=RecoveryMode.STRONG_REVERIFICATION,
        authorized=False,
    )


def test_recovery_from_invalid_source_state_is_rejected():

    entity = TrustEntity(
        entity_id="process:unknown-source",
        entity_type=EntityType.PROCESS,
    )

    _assert_recovery_rejected_without_mutation(
        entity,
        evidence_ids=("E-RECOVERY-SOURCE",),
        recovery_mode=RecoveryMode.STRONG_REVERIFICATION,
        authorized=True,
    )


def test_human_approval_cannot_be_bypassed():

    _assert_recovery_rejected_without_mutation(
        _quarantined_entity("process:human-approval"),
        evidence_ids=("E-RECOVERY-HUMAN",),
        recovery_mode=RecoveryMode.HUMAN_APPROVAL,
        authorized=True,
        human_approved=False,
    )


def test_recovery_rejects_entity_condition_that_does_not_match():

    _assert_recovery_rejected_without_mutation(
        _quarantined_entity("device:automatic", EntityType.DEVICE),
        evidence_ids=("E-RECOVERY-DEVICE",),
        recovery_mode=RecoveryMode.AUTOMATIC,
        authorized=True,
        condition="unapproved-device-condition",
    )