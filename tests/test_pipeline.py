from bouncer import models as m
from bouncer.db import connect, init_db
from bouncer.pipeline import validate_finding
from bouncer.repository import Repository
from bouncer.scope import Scope


def _repo(tmp_path):
    conn = connect(str(tmp_path / "p.db"))
    init_db(conn)
    return Repository(conn)


def _loopback_scope():
    return Scope.from_dict({"in_cidrs": ["127.0.0.1/32"], "in_domains": []})


def test_confirmed_finding_stops_at_in_review(mock_server, tmp_path, settings):
    repo = _repo(tmp_path)
    fid = repo.create_finding(m.Finding(
        program="demo", vuln_class="sqli_boolean",
        target_url=f"{mock_server}/item?id=1",
        request={"method": "GET", "inject_param": "id", "base_value": "1",
                 "true_payload": "1 AND 1=1", "false_payload": "1 AND 1=2"},
    ))
    created = repo.get_finding(fid)
    result = validate_finding(repo, created, _loopback_scope(), settings)

    # Pipeline hard-stops at in_review — never auto-approves.
    assert result.state == m.IN_REVIEW
    assert result.confidence >= m.VALIDATED_THRESHOLD
    states = [t.to_state for t in repo.list_transitions(fid)]
    assert states == [m.VALIDATING, m.VALIDATED, m.IN_REVIEW]


def test_weak_finding_is_rejected(mock_server, tmp_path, settings):
    repo = _repo(tmp_path)
    # /safe encodes input -> XSS refuted -> confidence drops -> rejected.
    fid = repo.create_finding(m.Finding(
        program="demo", vuln_class="reflected_xss",
        target_url=f"{mock_server}/safe?q=seed",
        request={"method": "GET", "inject_param": "q"},
    ))
    created = repo.get_finding(fid)
    result = validate_finding(repo, created, _loopback_scope(), settings)
    assert result.state == m.REJECTED
    assert result.confidence < m.VALIDATED_THRESHOLD


def test_out_of_scope_target_blocks_requests(tmp_path, settings):
    repo = _repo(tmp_path)
    # Target not in loopback scope: validator's requests get refused and logged,
    # validator errors out, finding ends rejected (never stranded in validating).
    fid = repo.create_finding(m.Finding(
        program="demo", vuln_class="sqli_boolean",
        target_url="http://8.8.8.8/item?id=1",
        request={"method": "GET", "inject_param": "id", "base_value": "1",
                 "true_payload": "1 AND 1=1", "false_payload": "1 AND 1=2"},
    ))
    created = repo.get_finding(fid)
    result = validate_finding(repo, created, _loopback_scope(), settings)
    assert result.state == m.REJECTED
