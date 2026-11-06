import json

from bouncer.candidate_schema import ExtractionResult
from bouncer.candidates import AI_SOURCE_TAG, CandidateGenerator, JsInput, write_candidates
from bouncer.claude_client import ReplayExtractor, _parse_and_validate
from bouncer.scope import Scope


def _scope():
    return Scope.from_dict({"in_cidrs": ["127.0.0.1/32"], "in_domains": ["example.com"]})


SAMPLE_RESPONSE = json.dumps({
    "endpoints": [
        {"url": "/xss", "params": ["q"], "suspected_vuln_class": "reflected_xss",
         "reasoning": "echoed"},
        {"url": "/item", "params": ["id"], "id_like_params": ["id"],
         "suspected_vuln_class": "sqli_boolean", "reasoning": "sql"},
        {"url": "/api/orders/1001", "params": ["order_id"], "id_like_params": ["order_id"],
         "suspected_vuln_class": "idor", "reasoning": "seq id"},
        {"url": "http://evil.com/x", "params": ["q"],
         "suspected_vuln_class": "reflected_xss", "reasoning": "out of scope"},
        {"url": "/misc", "params": [], "suspected_vuln_class": "unknown", "reasoning": "n/a"},
    ]
})


def _generate():
    extractor = ReplayExtractor(SAMPLE_RESPONSE)
    gen = CandidateGenerator("demo", _scope(), extractor)
    js = JsInput(source_url="http://127.0.0.1:8000/app.js",
                 base_url="http://127.0.0.1:8000/", text="(stub)")
    return gen.generate([js])


def test_generates_well_formed_candidates():
    cands = _generate()
    by_class = {c["vuln_class"]: c for c in cands}

    # xss, sqli, idor emitted; out-of-scope and unknown dropped.
    assert set(by_class) == {"reflected_xss", "sqli_boolean", "idor"}
    assert not any("evil.com" in c["target_url"] for c in cands)

    xss = by_class["reflected_xss"]
    assert xss["request"] == {"method": "GET", "inject_param": "q"}
    assert xss["target_url"].startswith("http://127.0.0.1:8000/xss?q=")

    sqli = by_class["sqli_boolean"]
    assert sqli["request"]["inject_param"] == "id"
    assert "true_payload" in sqli["request"] and "false_payload" in sqli["request"]

    idor = by_class["idor"]
    assert idor["request"]["url_template"].count("{id}") == 1
    assert idor["request"]["object_id_a"] == "REPLACE_A"


def test_candidates_tagged_ai_sourced():
    for c in _generate():
        assert AI_SOURCE_TAG in c["notes"]
    # No confidence field forced high — lifecycle seeds at ingest.
    assert all("confidence" not in c for c in _generate())


def test_candidates_match_milestone1_ingest_schema():
    # Every candidate must carry exactly the top-level keys ingest reads.
    for c in _generate():
        assert set(["program", "vuln_class", "target_url", "request"]).issubset(c)
        assert isinstance(c["request"], dict)


def test_write_candidates(tmp_path):
    cands = _generate()
    paths = write_candidates(cands, tmp_path / "out")
    assert len(paths) == len(cands)
    for p in paths:
        assert json.loads(p.read_text())  # valid JSON on disk


def test_malformed_claude_output_rejected():
    assert _parse_and_validate("not json at all", "x").endpoints == []
    assert _parse_and_validate('{"endpoints": "wrong type"}', "x").endpoints == []
    # Fenced JSON is tolerated.
    good = _parse_and_validate('```json\n{"endpoints": []}\n```', "x")
    assert isinstance(good, ExtractionResult)
