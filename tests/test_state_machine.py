import pytest

from bbv import models as m
from bbv import state_machine as sm


def test_legal_path():
    assert sm.can_transition(m.NEW, m.VALIDATING)
    assert sm.can_transition(m.VALIDATING, m.VALIDATED)
    assert sm.can_transition(m.VALIDATING, m.REJECTED)
    assert sm.can_transition(m.VALIDATED, m.IN_REVIEW)
    assert sm.can_transition(m.IN_REVIEW, m.APPROVED)
    assert sm.can_transition(m.IN_REVIEW, m.DISMISSED)


def test_illegal_transitions():
    assert not sm.can_transition(m.NEW, m.VALIDATED)
    assert not sm.can_transition(m.NEW, m.IN_REVIEW)
    assert not sm.can_transition(m.VALIDATING, m.IN_REVIEW)
    assert not sm.can_transition(m.REJECTED, m.IN_REVIEW)
    assert not sm.can_transition(m.APPROVED, m.DISMISSED)
    assert not sm.can_transition(m.IN_REVIEW, m.VALIDATING)


def test_assert_raises():
    with pytest.raises(sm.IllegalTransition):
        sm.assert_transition(m.NEW, m.APPROVED)


def test_classify_after_validation():
    assert sm.classify_after_validation(0.80) == m.VALIDATED
    assert sm.classify_after_validation(0.95) == m.VALIDATED
    assert sm.classify_after_validation(0.79) == m.REJECTED
    assert sm.classify_after_validation(0.0) == m.REJECTED
