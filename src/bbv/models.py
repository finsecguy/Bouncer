"""Domain dataclasses and lifecycle constants."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# --- Lifecycle states ---
NEW = "new"
VALIDATING = "validating"
VALIDATED = "validated"
REJECTED = "rejected"
IN_REVIEW = "in_review"
APPROVED = "approved"
DISMISSED = "dismissed"

TERMINAL_STATES = frozenset({APPROVED, DISMISSED})

# Confidence thresholds.
SEED_CONFIDENCE = 0.3
VALIDATED_THRESHOLD = 0.80


@dataclass
class Finding:
    program: str
    target_url: str
    vuln_class: str
    request: dict[str, Any]
    id: int | None = None
    state: str = NEW
    confidence: float = SEED_CONFIDENCE
    notes: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


@dataclass
class Evidence:
    finding_id: int
    kind: str
    data: dict[str, Any]
    id: int | None = None
    created_at: str | None = None


@dataclass
class Transition:
    finding_id: int
    from_state: str
    to_state: str
    confidence_before: float
    confidence_after: float
    reason: str
    id: int | None = None
    created_at: str | None = None


@dataclass
class ValidationResult:
    """Returned by every Validator.

    confidence_delta is added to the finding's current confidence (clamped to
    [0, 1]). verdict is one of 'confirmed', 'refuted', 'inconclusive' and is
    advisory for logging; the state machine decides state purely from the
    resulting confidence.
    """

    confidence_delta: float
    verdict: str  # confirmed | refuted | inconclusive
    reason: str
    evidence: list[Evidence] = field(default_factory=list)

    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
