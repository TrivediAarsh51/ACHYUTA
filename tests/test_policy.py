"""
Tests for ACHYUTA Niyama Policy Engine v0.1
"""

from engine.policy import (
    evaluate_policy,
    load_policy,
)

from engine.request import SecurityRequest, requires_re_evaluation

def test_unsigned_executable_is_denied(tmp_path):

    policy_file = tmp_path / "policy.yaml"

    policy_file.write_text(
        """
policy:
  id: P-001
  name: Block Unsigned Executables
  version: 1

  conditions:
    subject:
      signature: unsigned

    action:
      type: execute

  effect: deny
""",
        encoding="utf-8",
    )

    policy = load_policy(policy_file)

    request = SecurityRequest(
        request_id="REQ-001",

        identity={
            "type": "local_user",
            "name": "test-user",
        },

        subject={
            "type": "executable",
            "name": "unknown.exe",
            "signature": "unsigned",
        },

        action={
            "type": "execute",
        },

        resource={
            "type": "executable",
            "path": "C:\\Users\\test\\Downloads\\unknown.exe",
        },

        context={
            "origin": "internet",
        },
    )

    result = evaluate_policy(
        policy,
        request,
    )

    assert result.matched is True
    assert result.effect == "deny"
    assert result.policy_id == "P-001"


def test_signed_executable_does_not_match_unsigned_policy(tmp_path):

    policy_file = tmp_path / "policy.yaml"

    policy_file.write_text(
        """
policy:
  id: P-001
  name: Block Unsigned Executables
  version: 1

  conditions:
    subject:
      signature: unsigned

    action:
      type: execute

  effect: deny
""",
        encoding="utf-8",
    )

    policy = load_policy(policy_file)

    request = SecurityRequest(
        request_id="REQ-002",

        identity={
            "type": "local_user",
            "name": "test-user",
        },

        subject={
            "type": "executable",
            "name": "trusted.exe",
            "signature": "valid",
        },

        action={
            "type": "execute",
        },

        resource={
            "type": "executable",
            "path": "C:\\Program Files\\trusted.exe",
        },

        context={
            "origin": "trusted",
        },
    )

    result = evaluate_policy(
        policy,
        request,
    )

    assert result.matched is False


def test_contradictory_evidence_during_re_evaluation_requires_conservative_response():

    original = SecurityRequest(
        request_id="REQ-ORIGINAL-CONSERVATIVE",
        identity={"type": "local_user", "name": "operator"},
        subject={"type": "executable", "name": "trusted.exe"},
        action={"type": "execute"},
        resource={"type": "executable", "path": r"C:\trusted.exe"},
        context={"origin": "initial-evaluation"},
    )
    original.add_evidence(
        {
            "evidence_id": "E-TRUST-001",
            "category": "signature",
            "source": "mock",
            "value": "signed",
            "strength": "high",
            "verified": True,
        }
    )

    contradictory = SecurityRequest(
        request_id="REQ-RECHECK-CONSERVATIVE",
        identity=original.identity,
        subject=original.subject,
        action=original.action,
        resource=original.resource,
        context={"origin": "fresh-evidence-recheck"},
    )
    contradictory.add_evidence(
        {
            "evidence_id": "E-TRUST-001",
            "category": "signature",
            "source": "mock",
            "value": "unsigned",
            "strength": "high",
            "verified": True,
        }
    )

    assert requires_re_evaluation(contradictory, original) is True
    assert contradictory.evidence[0]["value"] == "unsigned"