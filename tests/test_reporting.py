import json

import pytest

from bbv import models as m
from bbv.db import connect, init_db
from bbv.reporting import build_facts, get_reporter, known_platforms
from bbv.repository import Repository


@pytest.fixture
def repo(tmp_path):
    conn = connect(str(tmp_path / "rep.db"))
    init_db(conn)
    return Repository(conn)


def _approved_idor(repo):
    fid = repo.create_finding(m.Finding(
        program="demo", vuln_class="idor",
        target_url="http://127.0.0.1:8000/api/orders/1001",
        request={"method": "GET", "url_template": "http://127.0.0.1:8000/api/orders/{id}",
                 "object_id_a": "1001", "object_id_b": "1002"}))
    repo.transition(fid, m.VALIDATING, 0.3, "start")
    repo.transition(fid, m.VALIDATED, 0.9, "confirmed", evidence=[
        m.Evidence(fid, "idor_match", {
            "url_a": "http://127.0.0.1:8000/api/orders/1001",
            "url_b": "http://127.0.0.1:8000/api/orders/1002",
            "status_a_self": 200, "status_a_on_b": 200, "status_b_self": 200,
            "status_unauth": 401, "match_a_on_b_vs_b_self": 1.0,
            "diff_a_on_b_vs_a_self": 0.84, "unauth_vs_b_self": 0.373,
            "thresholds": {"match": 0.9, "differ": 0.9}})])
    repo.transition(fid, m.IN_REVIEW, 0.9, "threshold")
    repo.transition(fid, m.APPROVED, 0.9, "approved by reviewer")
    return fid


def test_report_renders_from_real_evidence(repo):
    fid = _approved_idor(repo)
    f = repo.get_finding(fid)
    facts = build_facts(f, repo.list_evidence(fid), repo.list_transitions(fid))
    md = get_reporter("intigriti").render(facts)

    # Factual claims trace to evidence rows.
    assert "CWE-639" in md
    assert "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" in md
    assert "http://127.0.0.1:8000/api/orders/1002" in md   # real URL from evidence
    assert "401" in md                                      # unauth status from evidence
    assert "not been submitted" in md.lower()


def test_every_evidence_row_appears_in_report(repo):
    fid = _approved_idor(repo)
    f = repo.get_finding(fid)
    evidence = repo.list_evidence(fid)
    md = get_reporter("intigriti").render(
        build_facts(f, evidence, repo.list_transitions(fid)))
    # No evidence silently dropped: each row's kind and raw JSON is present.
    for ev in evidence:
        assert f"`{ev.kind}`" in md
        assert json.dumps(ev.data, indent=2) in md


def _approved_xss(repo):
    fid = repo.create_finding(m.Finding(
        program="demo", vuln_class="reflected_xss",
        target_url="http://127.0.0.1:8000/xss?q=seed", request={"inject_param": "q"}))
    repo.transition(fid, m.VALIDATING, 0.3, "start")
    repo.transition(fid, m.VALIDATED, 0.9, "confirmed", evidence=[
        m.Evidence(fid, "canary_reflection", {
            "url": "http://127.0.0.1:8000/xss?q=bbvABC123%27%22", "status": 200,
            "marker": "bbvABC123", "reflected": True}),
        m.Evidence(fid, "canary_reflection", {"context": "script", "raw_special_chars": True}),
        m.Evidence(fid, "browser_exec", {
            "status": "confirmed", "url": "http://127.0.0.1:8000/xss?q=payload",
            "payload": "';window.__bbvABC123=1;//", "marker_attr": "__bbvABC123"})])
    repo.transition(fid, m.IN_REVIEW, 0.9, "threshold")
    repo.transition(fid, m.APPROVED, 0.9, "approved")
    return fid


def test_xss_steps_use_real_canary_marker_and_probe_url(repo):
    fid = _approved_xss(repo)
    f = repo.get_finding(fid)
    md = get_reporter("intigriti").render(
        build_facts(f, repo.list_evidence(fid), repo.list_transitions(fid)))
    # The marker and the real canary probe URL must appear in the steps, not be
    # lost to last-write-wins over the two canary_reflection rows.
    assert "bbvABC123" in md
    assert "q=bbvABC123" in md                       # probe URL with canary
    assert "';window.__bbvABC123=1;//" in md         # real benign exec payload


@pytest.mark.parametrize("state", [m.NEW, m.VALIDATING, m.REJECTED, m.IN_REVIEW, m.DISMISSED])
def test_report_cli_refuses_non_approved_states(repo, tmp_path, monkeypatch, settings, state):
    """Report generation must refuse on every non-approved state."""
    import bbv.cli as cli

    fid = repo.create_finding(m.Finding(
        program="demo", vuln_class="reflected_xss",
        target_url="http://127.0.0.1/x?q=1", request={"inject_param": "q"}))
    # Drive the finding to the target state via the real state machine.
    path = {
        m.NEW: [],
        m.VALIDATING: [(m.VALIDATING, 0.3)],
        m.REJECTED: [(m.VALIDATING, 0.3), (m.REJECTED, 0.2)],
        m.IN_REVIEW: [(m.VALIDATING, 0.3), (m.VALIDATED, 0.9), (m.IN_REVIEW, 0.9)],
        m.DISMISSED: [(m.VALIDATING, 0.3), (m.VALIDATED, 0.9), (m.IN_REVIEW, 0.9), (m.DISMISSED, 0.9)],
    }[state]
    for to_state, conf in path:
        ev = [m.Evidence(fid, "canary_reflection", {"context": "text", "raw_special_chars": False})] \
            if to_state == m.REJECTED else None
        repo.transition(fid, to_state, conf, "t", evidence=ev)
    assert repo.get_finding(fid).state == state

    s = settings
    s.db_path = repo.conn.execute("PRAGMA database_list").fetchone()["file"]
    monkeypatch.setattr(cli, "load_settings", lambda: s)
    rc = cli.main(["report", str(fid), "--platform", "intigriti", "--dry-run"])
    assert rc == 2  # refused


def test_unknown_platform_lists_available(repo, tmp_path, monkeypatch, settings, capsys):
    import bbv.cli as cli
    fid = _approved_idor(repo)
    s = settings
    s.db_path = repo.conn.execute("PRAGMA database_list").fetchone()["file"]
    monkeypatch.setattr(cli, "load_settings", lambda: s)
    rc = cli.main(["report", str(fid), "--platform", "bogus"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "intigriti" in err  # lists available platforms, no KeyError
    assert "intigriti" in " ".join(known_platforms())
