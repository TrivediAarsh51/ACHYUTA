"""
ACHYUTA - Trust State Engine Tests
"""

import pytest

from engine.trust import (
    EntityType,
    RecoveryMode,
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

    transition = entity.transition(
        TrustState.TRUSTED,
        "Process successfully verified.",
        evidence_ids=("E-001",),
    )

    assert entity.state == TrustState.TRUSTED

    assert len(entity.transition_history) == 1

    assert transition.from_state == TrustState.UNKNOWN
    assert transition.to_state == TrustState.TRUSTED

    assert transition.evidence_ids == ("E-001",)


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
    second = entity.transition(
        TrustState.TRUSTED,
        "Verification completed successfully.",
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