import pytest

from bouncer import models as m
from bouncer.db import connect, init_db
from bouncer.repository import Repository
from bouncer.state_machine import IllegalTransition


@pytest.fixture
def repo(tmp_path):
    conn = connect(str(tmp_path / "t.db"))
    init_db(conn)
    return Repository(conn)


def _finding():
    return m.Finding(program="p", target_url="http://127.0.0.1/x",
                     vuln_class="reflected_xss", request={"inject_param": "q"})


def test_create_and_get(repo):
    fid = repo.create_finding(_finding())
    f = repo.get_finding(fid)
    assert f.state == m.NEW
    assert f.confidence == m.SEED_CONFIDENCE
    assert f.request["inject_param"] == "q"


def test_transition_writes_atomic_trail_and_evidence(repo):
    fid = repo.create_finding(_finding())
    repo.transition(fid, m.VALIDATING, 0.3, "start")
    repo.transition(fid, m.VALIDATED, 0.9, "confirmed",
                    evidence=[m.Evidence(fid, "diff", {"x": 1})])
    f = repo.get_finding(fid)
    assert f.state == m.VALIDATED
    assert f.confidence == 0.9
    trans = repo.list_transitions(fid)
    assert [t.to_state for t in trans] == [m.VALIDATING, m.VALIDATED]
    ev = repo.list_evidence(fid)
    assert len(ev) == 1 and ev[0].kind == "diff"


def test_illegal_transition_rolls_back(repo):
    fid = repo.create_finding(_finding())
    with pytest.raises(IllegalTransition):
        repo.transition(fid, m.APPROVED, 0.9, "nope")
    # Nothing changed, no transition row written.
    f = repo.get_finding(fid)
    assert f.state == m.NEW
    assert repo.list_transitions(fid) == []


def test_confidence_clamped(repo):
    fid = repo.create_finding(_finding())
    repo.transition(fid, m.VALIDATING, 5.0, "clamp high")
    assert repo.get_finding(fid).confidence == 1.0
