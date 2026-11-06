from bouncer import models as m
from bouncer.severity import assess, compute_base_score, vector_string


def _ev(kind, data):
    return m.Evidence(finding_id=1, kind=kind, data=data)


def test_cvss_formula_known_vectors():
    # Spec reference vectors.
    xss = {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"}
    assert compute_base_score(xss) == 6.1
    idor = {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"}
    assert compute_base_score(idor) == 4.3
    sqli = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"}
    assert compute_base_score(sqli) == 7.5


def test_xss_assessment():
    f = m.Finding(id=1, program="demo", vuln_class="reflected_xss",
                  target_url="http://127.0.0.1/xss?q=x", request={"inject_param": "q"})
    a = assess(f, [
        _ev("canary_reflection", {"context": "script", "raw_special_chars": True}),
        _ev("browser_exec", {"status": "confirmed", "marker_attr": "__bouncer"}),
    ])
    assert a.cwe_id == "CWE-79"
    assert a.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    assert a.cvss_score == 6.1 and a.severity == "Medium"
    assert "C/I" in a.metric_reasoning  # reasoning is present/auditable


def test_idor_assessment_pr_from_unauth_evidence():
    f = m.Finding(id=2, program="demo", vuln_class="idor",
                  target_url="http://127.0.0.1/api/orders/1001",
                  request={"url_template": "http://127.0.0.1/api/orders/{id}"})
    a = assess(f, [_ev("idor_match", {
        "status_unauth": 401, "match_a_on_b_vs_b_self": 1.0,
        "diff_a_on_b_vs_a_self": 0.84, "thresholds": {"match": 0.9, "differ": 0.9}})])
    assert a.cwe_id == "CWE-639"
    assert a.metrics["PR"] == "L"            # account required (401 unauth)
    assert a.metrics["C"] == "L" and a.metrics["I"] == "N"  # conservative, GET-only
    assert a.cvss_score == 4.3


def test_sqli_assessment_oracle_is_confidentiality_high():
    f = m.Finding(id=3, program="demo", vuln_class="sqli_boolean",
                  target_url="http://127.0.0.1/item?id=1",
                  request={"inject_param": "id"})
    a = assess(f, [_ev("sqli_differential", {
        "base_stability": 1.0, "true_sims": [1, 1, 1], "false_sims": [0.8, 0.8, 0.8]})])
    assert a.cwe_id == "CWE-89"
    assert a.metrics["C"] == "H" and a.metrics["PR"] == "N"
    assert a.severity == "High" and a.cvss_score == 7.5


def test_sqli_pr_low_when_request_carried_credentials():
    f = m.Finding(id=4, program="demo", vuln_class="sqli_boolean",
                  target_url="http://127.0.0.1/item?id=1",
                  request={"inject_param": "id", "headers": {"Cookie": "s=1"}})
    a = assess(f, [_ev("sqli_differential", {"base_stability": 1.0, "true_sims": [1], "false_sims": [0.8]})])
    assert a.metrics["PR"] == "L"
