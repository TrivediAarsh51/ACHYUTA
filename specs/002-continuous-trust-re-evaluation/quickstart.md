# Quickstart: Continuous Trust Re-Evaluation Validation

## Purpose

This guide describes the validation scenarios needed to prove the continuous trust re-evaluation design works without breaking the existing ACHYUTA boundaries or regression baseline.

## Prerequisites

- Python environment configured for the repository
- Existing ACHYUTA test suite available in the project
- Access to the `engine/` models and trust-state implementation

## Step 1: Activate the project environment

```powershell
Set-Location 'H:\Live_Projects\Hacking_projects\ACHYUTA'
.\venv\Scripts\Activate.ps1
```

## Step 2: Run the targeted validation suite

```powershell
python -m pytest tests/test_trust.py tests/test_decision.py tests/test_evidence_policy.py -q
```

## Expected outcomes

- Existing trust-state tests continue to pass.
- Re-evaluation scenarios preserve a distinct request history.
- A previously trusted entity does not remain elevated when fresh evidence or policy evaluation becomes more restrictive.
- Trust transitions remain auditable and controlled through the trust-state boundary.
- Authorization decisions remain distinct from trust states.

## Scenario set for implementation validation

1. Fresh evidence changes the evaluation outcome
   - Given a trusted entity and new evidence, when a fresh request is evaluated, then the reevaluation produces a new request and new decision context.

2. More restrictive policy outcome triggers a trust downgrade
   - Given a currently trusted entity, when new evidence or policy evaluation indicates restriction, then the system records a transition instead of silently preserving the prior state.

3. Inconclusive evidence triggers conservative fallback
   - Given contradictory or missing evidence, when validation is inconclusive, then the trust state defaults to verification, restriction, or quarantine.

4. Audit trail remains explainable
   - Given a reevaluation record, when a reviewer inspects it, then the previous trust state, trigger, request, evidence, policy, decision, and resulting state are traceable.

5. Regression protection
   - Given the full ACHYUTA suite, when the feature is merged, then the existing baseline must still pass unless an intentional architectural contract change is documented.

## Notes

- This guide is intentionally validation-oriented and does not include implementation bodies.
- Detailed test design for the feature will be added during the implementation phase in the task breakdown.
