import pytest

from bouncer import models as m
from bouncer import signatures as sig
from bouncer.db import connect, init_db
from bouncer.repository import Repository


# ---------- pure extractor ----------

def _ev(kind, data):
    return m.Evidence(finding_id=1, kind=kind, data=data)


def test_xss_context_text_fingerprint():
    s = sig.extract("reflected_xss", [
        _ev("canary_reflection", {"reflected": True}),
        _ev("canary_reflection", {"context": "text", "raw_special_chars": False}),
    ])
    assert s.feature_key == "xss|reflected|context=text|raw=false"
    assert s.scope == sig.SCOPE_GLOBAL


def test_xss_not_reflected_is_distinct():
    s = sig.extract("reflected_xss", [_ev("canary_reflection", {"reflected": False})])
    assert s.feature_key == "xss|not_reflected"


def test_xss_different_context_discriminates():
    a = sig.extract("reflected_xss", [_ev("canary_reflection", {"context": "text", "raw_special_chars": False})])
    b = sig.extract("reflected_xss", [_ev("canary_reflection", {"context": "attribute", "raw_special_chars": False})])
    assert a.feature_key != b.feature_key


def test_idor_cause_discrimination():
    th = {"match": 0.9, "differ": 0.9}
    public = sig.extract("idor", [_ev("idor_match", {
        "status_unauth": 200, "unauth_vs_b_self": 1.0, "diff_a_on_b_vs_a_self": 0.3,
        "status_a_on_b": 200, "match_a_on_b_vs_b_self": 1.0, "thresholds": th})])
    not_obj = sig.extract("idor", [_ev("idor_match", {
        "status_unauth": 401, "unauth_vs_b_self": 0.1, "diff_a_on_b_vs_a_self": 0.99,
        "status_a_on_b": 200, "match_a_on_b_vs_b_self": 1.0, "thresholds": th})])
    no_data = sig.extract("idor", [_ev("idor_match", {
        "status_unauth": 401, "unauth_vs_b_self": 0.1, "diff_a_on_b_vs_a_self": 0.3,
        "status_a_on_b": 403, "match_a_on_b_vs_b_self": 0.2, "thresholds": th})])
    keys = {public.feature_key, not_obj.feature_key, no_data.feature_key}
    assert keys == {"idor|public_endpoint", "idor|not_object_specific", "idor|no_cross_user_data"}
    assert public.scope == sig.SCOPE_PROGRAM and no_data.scope == sig.SCOPE_GLOBAL


def test_sqli_stage_discrimination():
    unstable = sig.extract("sqli_boolean", [_ev("sqli_differential", {
        "base_stability": 0.5, "thresholds": {"stable": 0.98}})])
    diff = sig.extract("sqli_boolean", [_ev("sqli_differential", {
        "base_stability": 1.0, "true_sims": [1, 1], "false_sims": [1, 1],
        "thresholds": {"stable": 0.98, "match": 0.97, "differ": 0.95}})])
    assert unstable.feature_key == "sqli|baseline_unstable"
    assert diff.feature_key == "sqli|differential_unstable"
    assert diff.scope == sig.SCOPE_PROGRAM


def test_normalize_endpoint_collapses_numeric_ids():
    assert sig.normalize_endpoint("http://h:8000/api/orders/1001?x=1") == "h:8000/api/orders/{n}"
    assert sig.normalize_endpoint("http://h:8000/item?id=1") == "h:8000/item"


def test_no_signature_for_empty_evidence():
    assert sig.extract("reflected_xss", []) is None
    assert sig.extract("idor", []) is None
    assert sig.extract("sqli_boolean", []) is None


# ---------- repository integration ----------

@pytest.fixture
def repo(tmp_path):
    conn = connect(str(tmp_path / "sig.db"))
    init_db(conn)
    return Repository(conn)


def _reject_xss(repo, program="demo", context="text"):
    """Create a finding and drive it validating->rejected with xss evidence."""
    fid = repo.create_finding(m.Finding(
        program=program, vuln_class="reflected_xss",
        target_url="http://127.0.0.1:8000/safe?q=x", request={"inject_param": "q"}))
    repo.transition(fid, m.VALIDATING, 0.3, "start")
    repo.transition(fid, m.REJECTED, 0.2, "refuted",
                    evidence=[m.Evidence(fid, "canary_reflection",
                                         {"context": context, "raw_special_chars": False})])
    return fid


def test_same_cause_dedupes_to_one_row_times_seen_2(repo):
    _reject_xss(repo, context="text")
    _reject_xss(repo, context="text")
    sigs = repo.list_signatures(vuln_class="reflected_xss")
    assert len(sigs) == 1
    assert sigs[0]["times_seen"] == 2


def test_different_cause_distinct_rows(repo):
    _reject_xss(repo, context="text")
    _reject_xss(repo, context="attribute")
    sigs = repo.list_signatures(vuln_class="reflected_xss")
    assert len(sigs) == 2
    assert {s["times_seen"] for s in sigs} == {1}


def test_transition_links_signature(repo):
    fid = _reject_xss(repo)
    s = repo.list_signatures()[0]
    detail = repo.get_signature(s["id"])
    assert fid in detail["linked_finding_ids"]


def test_per_program_breakdown(repo):
    _reject_xss(repo, program="alpha", context="text")
    _reject_xss(repo, program="beta", context="text")
    _reject_xss(repo, program="beta", context="text")
    s = repo.list_signatures()[0]
    assert s["times_seen"] == 3  # global total across programs
    detail = repo.get_signature(s["id"])
    counts = {pb["program"]: pb["times_seen"] for pb in detail["program_breakdown"]}
    assert counts == {"alpha": 1, "beta": 2}


def _reject_sqli(repo, url, program="demo"):
    fid = repo.create_finding(m.Finding(
        program=program, vuln_class="sqli_boolean", target_url=url,
        request={"inject_param": "id"}))
    repo.transition(fid, m.VALIDATING, 0.3, "start")
    repo.transition(fid, m.REJECTED, 0.15, "no stable differential",
                    evidence=[m.Evidence(fid, "sqli_differential", {
                        "base_stability": 1.0, "true_sims": [1.0], "false_sims": [1.0],
                        "thresholds": {"stable": 0.98, "match": 0.97, "differ": 0.95}})])
    return fid


def test_precheck_annotates_only_matching_endpoint(repo):
    from bouncer.candidates import annotate_known_patterns

    # Rejected sqli on /item (program-scoped, endpoint-derivable signature).
    _reject_sqli(repo, "http://127.0.0.1:8000/item?id=1", program="demo")

    cands = [
        {"program": "demo", "vuln_class": "sqli_boolean",
         "target_url": "http://127.0.0.1:8000/item?id=1", "request": {"inject_param": "id"}},
        {"program": "demo", "vuln_class": "sqli_boolean",
         "target_url": "http://127.0.0.1:8000/other?id=1", "request": {"inject_param": "id"}},
    ]
    annotate_known_patterns(cands, repo)

    assert "known_pattern_note" in cands[0]
    assert "/item" in cands[0]["known_pattern_note"]
    # Non-matching endpoint and core fields untouched.
    assert "known_pattern_note" not in cands[1]
    assert cands[0]["request"] == {"inject_param": "id"}
    assert cands[0]["vuln_class"] == "sqli_boolean"


def test_precheck_does_not_match_global_xss_pattern(repo):
    from bouncer.candidates import annotate_known_patterns

    _reject_xss(repo, context="text")  # global signature, not endpoint-derivable
    cands = [{"program": "demo", "vuln_class": "reflected_xss",
              "target_url": "http://127.0.0.1:8000/safe?q=x", "request": {"inject_param": "q"}}]
    annotate_known_patterns(cands, repo)
    # Honest: XSS context is unknown pre-validation, so no pre-check match.
    assert "known_pattern_note" not in cands[0]


def test_backfill_from_existing_evidence(repo):
    # Simulate a pre-milestone-3 rejection: evidence present, no signature linked.
    fid = repo.create_finding(m.Finding(
        program="demo", vuln_class="reflected_xss",
        target_url="http://127.0.0.1:8000/safe?q=x", request={"inject_param": "q"}))
    repo.transition(fid, m.VALIDATING, 0.3, "start")
    # Write the rejected transition WITHOUT the signature hook by faking an old row.
    repo.conn.execute(
        "UPDATE findings SET state='rejected', confidence=0.2 WHERE id=?", (fid,))
    repo.conn.execute(
        """INSERT INTO transitions (finding_id, from_state, to_state,
           confidence_before, confidence_after, reason)
           VALUES (?, 'validating', 'rejected', 0.3, 0.2, 'old reason')""", (fid,))
    repo.add_evidence(m.Evidence(fid, "canary_reflection",
                                 {"context": "text", "raw_special_chars": False}))

    assert repo.list_signatures() == []
    n = repo.backfill_signatures()
    assert n == 1
    assert repo.list_signatures()[0]["times_seen"] == 1


def test_signature_write_failure_rolls_back_rejection(repo, monkeypatch):
    """If the signature write fails, the rejection itself must roll back — the
    finding stays in validating with no signature and no rejected transition."""
    fid = repo.create_finding(m.Finding(
        program="demo", vuln_class="reflected_xss",
        target_url="http://127.0.0.1:8000/safe?q=x", request={"inject_param": "q"}))
    repo.transition(fid, m.VALIDATING, 0.3, "start")

    def boom(*a, **k):
        raise RuntimeError("forced signature write failure")
    monkeypatch.setattr(repo, "_record_signature", boom)

    with pytest.raises(RuntimeError):
        repo.transition(fid, m.REJECTED, 0.2, "refuted",
                        evidence=[m.Evidence(fid, "canary_reflection",
                                             {"context": "text", "raw_special_chars": False})])

    f = repo.get_finding(fid)
    assert f.state == m.VALIDATING          # rejection rolled back
    assert repo.list_signatures() == []     # no signature leaked
    assert [t.to_state for t in repo.list_transitions(fid)] == [m.VALIDATING]
