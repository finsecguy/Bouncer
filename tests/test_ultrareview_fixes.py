"""Regression tests for the fixes to the ultrareview findings."""
import json

import pytest

import bouncer.cli as cli
from bouncer import models as m
from bouncer.candidates import has_unfilled_placeholders
from bouncer.claude_client import OpenAIProvider, make_provider
from bouncer.config import Settings
from bouncer.db import connect, init_db
from bouncer.repository import Repository
from bouncer.scope import Scope
from bouncer import setup as st


def _repo(tmp_path):
    conn = connect(str(tmp_path / "f.db"))
    init_db(conn)
    return Repository(conn)


def _loopback():
    return Scope.from_dict({"in_cidrs": ["127.0.0.1/32"], "in_domains": []})


# 1. IDOR placeholder candidates are refused before any validation.
def test_placeholder_idor_candidate_is_refused(tmp_path):
    repo = _repo(tmp_path)
    data = {
        "program": "demo", "vuln_class": "idor",
        "target_url": "http://127.0.0.1:8000/api/orders/1001?order_id=REPLACE_A",
        "request": {"method": "GET",
                    "url_template": "http://127.0.0.1:8000/api/orders/1001?order_id={id}",
                    "object_id_a": "REPLACE_A", "object_id_b": "REPLACE_B"},
    }
    assert has_unfilled_placeholders(data) is True
    fid = cli._ingest_finding_data(repo, _loopback(), Settings(_env_file=None), data)
    assert fid is None
    assert repo.list_findings() == []   # nothing validated, nothing recorded


def test_real_idor_candidate_is_not_refused_by_placeholder_check():
    data = {"program": "demo", "vuln_class": "idor",
            "target_url": "http://127.0.0.1:8000/api/orders/1001",
            "request": {"url_template": "http://127.0.0.1:8000/api/orders/{id}",
                        "object_id_a": "1001", "object_id_b": "1002"}}
    assert has_unfilled_placeholders(data) is False


# 2. ingest-batch only ingests the named program, and skips duplicates.
def test_ingest_batch_filters_by_program_and_skips_duplicates(mock_server, tmp_path, monkeypatch):
    s = Settings(_env_file=None)
    s.db_path = str(tmp_path / "b.db")
    monkeypatch.setattr(cli, "load_settings", lambda: s)
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_cidrs": ["127.0.0.1/32"], "in_domains": []}))

    cand = tmp_path / "cands"
    cand.mkdir()
    sqli = {"method": "GET", "inject_param": "id", "base_value": "1",
            "true_payload": "1 AND 1=1", "false_payload": "1 AND 1=2", "repeats": 3}
    (cand / "demo_001_sqli_boolean.json").write_text(json.dumps(
        {"program": "demo", "vuln_class": "sqli_boolean",
         "target_url": f"{mock_server}/item?id=1", "request": sqli}))
    # A different program's candidate in the same dir must be skipped.
    (cand / "other_001_sqli_boolean.json").write_text(json.dumps(
        {"program": "other", "vuln_class": "sqli_boolean",
         "target_url": f"{mock_server}/item?id=1", "request": sqli}))

    cli.main(["ingest-batch", "demo", "--dir", str(cand), "--scope", str(scope)])
    findings = Repository(connect(s.db_path)).list_findings()
    assert [f.program for f in findings] == ["demo"]   # 'other' never ingested

    # Re-running does not duplicate the already-ingested candidate.
    cli.main(["ingest-batch", "demo", "--dir", str(cand), "--scope", str(scope)])
    findings2 = Repository(connect(s.db_path)).list_findings()
    assert len(findings2) == 1


# 3. setup IDOR session validation matches the dict[str, str] contract.
def test_idor_session_rejects_non_string_values(tmp_path):
    env = tmp_path / ".env"
    msg = st._set_idor_session("A", '{"X-User-Id": 42}', str(env))
    assert "string" in msg.lower()
    assert not env.exists() or "BOUNCER_IDOR_SESSION_A" not in env.read_text()

    # A valid all-string dict is still accepted and written.
    ok = st._set_idor_session("A", '{"Cookie": "session=abc"}', str(env))
    assert "Saved" in ok
    assert "BOUNCER_IDOR_SESSION_A" in env.read_text()


def test_idor_session_value_survives_settings_roundtrip(tmp_path, monkeypatch):
    # What setup writes must load back without raising (no bricking).
    env = tmp_path / ".env"
    st._set_idor_session("A", '{"Cookie": "session=abc"}', str(env))
    monkeypatch.chdir(tmp_path)
    assert Settings(_env_file=str(env)).idor_session_a == {"Cookie": "session=abc"}


# 4. provider=openai always uses the official endpoint, ignoring a stale base_url.
def test_openai_provider_ignores_stale_base_url():
    prov, tag = make_provider(Settings(
        _env_file=None, llm_provider="openai", openai_api_key="k",
        openai_base_url="http://leftover-selfhosted/v1", openai_model="gpt-x"))
    assert prov._base_url == "https://api.openai.com/v1"
    assert tag == "openai:gpt-x"


# 5. OpenAIProvider falls back to max_completion_tokens on the 400 that asks for it.
def test_openai_max_completion_tokens_fallback(monkeypatch):
    calls = []

    class FakeResp:
        def __init__(self, status, text="", payload=None):
            self.status_code = status
            self.text = text
            self.headers = {}
            self._payload = payload or {}

        def json(self):
            return self._payload

        def raise_for_status(self):
            if self.status_code >= 400:
                raise AssertionError(f"unexpected raise on {self.status_code}")

    def fake_post(url, json, headers, timeout):
        calls.append(json)
        if "max_tokens" in json:
            return FakeResp(400, text="Unsupported parameter: max_tokens; use "
                            "max_completion_tokens instead")
        return FakeResp(200, payload={"choices": [{"message": {"content": "ok"}}]})

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)
    prov = OpenAIProvider("k", "gpt-5-mini", "https://api.openai.com/v1", 2048)
    assert prov.complete("hi", system="s") == "ok"
    assert "max_tokens" in calls[0] and "max_completion_tokens" in calls[1]


# 6. A rate limiter passed to validate_finding is the one actually used.
def test_validate_finding_uses_shared_rate_limiter(mock_server, tmp_path):
    from bouncer.pipeline import build_rate_limiter, validate_finding

    repo = _repo(tmp_path)
    fid = repo.create_finding(m.Finding(
        program="demo", vuln_class="sqli_boolean",
        target_url=f"{mock_server}/item?id=1",
        request={"inject_param": "id", "base_value": "1",
                 "true_payload": "1 AND 1=1", "false_payload": "1 AND 1=2", "repeats": 1}))
    rl = build_rate_limiter(Settings(_env_file=None))
    seen = []
    orig = rl.acquire
    rl.acquire = lambda url: (seen.append(url), orig(url))[1]
    validate_finding(repo, repo.get_finding(fid), _loopback(), Settings(_env_file=None), rl)
    assert seen, "the shared rate limiter should have been used for requests"
