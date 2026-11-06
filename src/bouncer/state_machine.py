"""Finding lifecycle state machine. Transitions are explicit and gated."""
from __future__ import annotations

from . import models as m

# Allowed transitions (from -> set of to).
_ALLOWED: dict[str, frozenset[str]] = {
    m.NEW: frozenset({m.VALIDATING}),
    m.VALIDATING: frozenset({m.VALIDATED, m.REJECTED}),
    m.VALIDATED: frozenset({m.IN_REVIEW}),
    m.REJECTED: frozenset(),  # terminal for the automated pipeline
    m.IN_REVIEW: frozenset({m.APPROVED, m.DISMISSED}),
    m.APPROVED: frozenset(),
    m.DISMISSED: frozenset(),
}


class IllegalTransition(Exception):
    pass


def can_transition(from_state: str, to_state: str) -> bool:
    return to_state in _ALLOWED.get(from_state, frozenset())


def assert_transition(from_state: str, to_state: str) -> None:
    if not can_transition(from_state, to_state):
        raise IllegalTransition(f"{from_state} -> {to_state} is not allowed")


def classify_after_validation(confidence: float) -> str:
    """Decide the post-validation target state from confidence alone.

    >= VALIDATED_THRESHOLD => validated (then auto-advances to in_review).
    Anything lower => rejected. There is no 'inconclusive' resting state:
    guilty until proven exploitable, so insufficient evidence is a rejection.
    """
    return m.VALIDATED if confidence >= m.VALIDATED_THRESHOLD else m.REJECTED
