"""
ACHYUTA - Request Model v0.1

A request is the central object evaluated by ACHYUTA.

This follows ADR-003:
Trust evaluation is Request-Centric.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engine.evidence import Evidence


@dataclass
class SecurityRequest:
    """
    Represents a security-relevant request.

    Example:

        A user attempts to execute a file.

    ACHYUTA evaluates the request using:
        - identity
        - subject
        - action
        - resource
        - context
        - evidence
    """

    request_id: str

    identity: dict[str, Any]

    subject: dict[str, Any]

    action: dict[str, Any]

    resource: dict[str, Any]

    context: dict[str, Any] = field(
        default_factory=dict
    )

    evidence: list[Evidence] = field(
        default_factory=list
    )

    def add_evidence(self, evidence: Evidence) -> None:
        """Attach evidence to this request."""

        self.evidence.append(evidence)

    def get_evidence(
        self,
        category: str,
    ) -> list[Evidence]:
        """Return evidence belonging to a category."""

        return [
            item
            for item in self.evidence
            if item.category == category
        ]