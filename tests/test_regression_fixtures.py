"""Regression tests promoted from milestone-1 manual verification."""
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from bbv import models as m
from bbv.db import connect, init_db
from bbv.http_client import ScopedHttpClient
from bbv.pipeline import validate_finding
from bbv.rate_limiter import RateLimiter
from bbv.repository import Repository
from bbv.scope import Scope, ScopeError

FIX = Path(__file__).parent / "fixtures"


def _repo(tmp_path):
    conn = connect(str(tmp_path / "r.db"))
    init_db(conn)
    return Repository(conn)


def _loopback_scope():
    return Scope.from_dict({"in_cidrs": ["127.0.0.1/32"], "in_domains": []})


def test_non_exploitable_reflection_is_rejected(mock_server, tmp_path, settings):
    data = json.loads((FIX / "negative_non_exploitable_reflection.json").read_text())
    # Bind the sentinel host to the live loopback mock server.
    host = urlsplit(mock_server).netloc
    data["target_url"] = data["target_url"].replace("TARGET", host)

    repo = _repo(tmp_path)
    fid = repo.create_finding(m.Finding(
        program=data["program"], vuln_class=data["vuln_class"],
        target_url=data["target_url"], request=data["request"],
    ))
    result = validate_finding(repo, repo.get_finding(fid), _loopback_scope(), settings)

    assert result.state == m.REJECTED
    assert result.confidence < m.SEED_CONFIDENCE  # dropped below seed (0.3)


class _SpyTransport:
    """Stand-in for the underlying httpx client that records every send."""
    def __init__(self):
        self.calls = 0

    def request(self, *a, **k):
        self.calls += 1
        raise AssertionError("an HTTP request was sent for an out-of-scope URL")

    def close(self):
        pass


def test_out_of_scope_makes_zero_http_calls():
    data = json.loads((FIX / "negative_out_of_scope.json").read_text())
    client = ScopedHttpClient(_loopback_scope(), RateLimiter(100, 100, 200, 200))
    spy = _SpyTransport()
    client._client = spy  # replace the real httpx client with the spy

    with pytest.raises(ScopeError):
        client.get(data["target_url"])
    assert spy.calls == 0
    assert client.blocked and client.blocked[0].url == data["target_url"]


def test_out_of_scope_ingest_creates_no_finding(tmp_path, monkeypatch, settings):
    """The CLI ingest path refuses an out-of-scope target before persisting."""
    import bbv.cli as cli
    data = json.loads((FIX / "negative_out_of_scope.json").read_text())
    finding_path = tmp_path / "f.json"
    finding_path.write_text(json.dumps(data))
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({"in_cidrs": ["127.0.0.1/32"], "in_domains": []}))

    s = settings
    s.db_path = str(tmp_path / "cli.db")
    monkeypatch.setattr(cli, "load_settings", lambda: s)

    rc = cli.main(["ingest", str(finding_path), "--scope", str(scope_path)])
    assert rc == 2

    repo = cli._open_repo(s)
    assert repo.list_findings() == []
