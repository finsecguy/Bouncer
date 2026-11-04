"""Milestone 5: orchestration glue (run, ingest-batch, queue). These wrappers
must add zero autonomy: run stops after generate-candidates, batch is identical
to sequential single ingests, queue changes nothing."""
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

import bbv.cli as cli
from bbv import models as m
from bbv.config import Settings
from bbv.db import connect, init_db
from bbv.repository import Repository


def _settings(tmp_path, **kw):
    s = Settings(_env_file=None)
    s.db_path = str(tmp_path / "bbv.db")
    s.candidates_dir = str(tmp_path / "candidates")
    s.reports_dir = str(tmp_path / "reports")
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def _write(path: Path, obj: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


def _scope_file(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"in_cidrs": ["127.0.0.1/32"], "in_domains": []}))
    return str(p)


# ---------------- run: chains then STOPS ----------------

def test_run_chains_recon_and_generate_then_stops(mock_server, tmp_path, monkeypatch, capsys):
    s = _settings(tmp_path)
    monkeypatch.setattr(cli, "load_settings", lambda: s)
    scope = _scope_file(tmp_path)

    rc = cli.main([
        "run", "demo", "--scope", scope,
        "--js-file", "samples/sample_app.js", "--base-url", mock_server,
        "--stub-response", "samples/claude_response.example.json",
        "--out", str(tmp_path / "candidates"),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert f"SCOPE: {scope}" in out            # scope printed loudly
    assert "Nothing was ingested, validated, or submitted." in out

    # Candidates were written...
    assert list((tmp_path / "candidates").glob("*.json"))
    # ...but run created NO findings in the DB (no ingest happened).
    repo = Repository(connect(s.db_path))
    assert repo.list_findings() == []


def test_run_refuses_without_scope(tmp_path, monkeypatch, capsys):
    s = _settings(tmp_path)
    monkeypatch.setattr(cli, "load_settings", lambda: s)
    # No --scope and no scopes/demo.json present.
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["run", "demo"])
    assert rc == 2
    assert "no --scope given" in capsys.readouterr().err


def test_default_scope_path_used_and_announced(tmp_path, monkeypatch, capsys):
    s = _settings(tmp_path)
    monkeypatch.setattr(cli, "load_settings", lambda: s)
    monkeypatch.chdir(tmp_path)
    # Provide the predictable default path.
    (tmp_path / "scopes").mkdir()
    (tmp_path / "scopes" / "demo.json").write_text(
        json.dumps({"in_cidrs": ["127.0.0.1/32"], "in_domains": []}))
    rc = cli.main(["recon", "demo"])
    assert rc == 0
    assert "SCOPE: scopes/demo.json" in capsys.readouterr().out


# ---------------- ingest-batch == sequential ----------------

def _sqli_candidate(mock_server, path_part):
    return {
        "program": "demo", "vuln_class": "sqli_boolean",
        "target_url": f"{mock_server}{path_part}",
        "request": {"method": "GET", "inject_param": "id", "base_value": "1",
                    "true_payload": "1 AND 1=1", "false_payload": "1 AND 1=2",
                    "repeats": 3},
    }


def _run_cli_with_settings(settings, monkeypatch, argv):
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    return cli.main(argv)


def test_ingest_batch_matches_sequential(mock_server, tmp_path, monkeypatch):
    scope = _scope_file(tmp_path)
    # One validating case (/item) and one rejecting case (/safe): deterministic,
    # no Chromium needed.
    c_item = _sqli_candidate(mock_server, "/item?id=1")
    c_safe = _sqli_candidate(mock_server, "/safe?id=1")

    # --- batch run in its own DB ---
    batch_dir = tmp_path / "cands"
    _write(batch_dir / "demo_001_sqli_boolean.json", c_item)
    _write(batch_dir / "demo_002_sqli_boolean.json", c_safe)
    s_batch = _settings(tmp_path / "b")
    _run_cli_with_settings(s_batch, monkeypatch,
                           ["ingest-batch", "demo", "--dir", str(batch_dir), "--scope", scope])

    # --- sequential single ingests in a separate DB ---
    s_seq = _settings(tmp_path / "s")
    f_item = tmp_path / "item.json"; f_item.write_text(json.dumps(c_item))
    f_safe = tmp_path / "safe.json"; f_safe.write_text(json.dumps(c_safe))
    _run_cli_with_settings(s_seq, monkeypatch, ["ingest", str(f_item), "--scope", scope])
    _run_cli_with_settings(s_seq, monkeypatch, ["ingest", str(f_safe), "--scope", scope])

    def digest(db_path):
        repo = Repository(connect(db_path))
        out = []
        for f in repo.list_findings():
            evs = [(e.kind, e.data) for e in repo.list_evidence(f.id)]
            out.append((f.vuln_class, f.target_url, f.state, round(f.confidence, 3), evs))
        return sorted(out, key=lambda r: r[1])

    assert digest(s_batch.db_path) == digest(s_seq.db_path)


def test_ingest_batch_prints_full_trail_plus_summary(mock_server, tmp_path, monkeypatch, capsys):
    scope = _scope_file(tmp_path)
    batch_dir = tmp_path / "cands"
    _write(batch_dir / "demo_001_sqli_boolean.json", _sqli_candidate(mock_server, "/item?id=1"))
    s = _settings(tmp_path)
    _run_cli_with_settings(s, monkeypatch,
                           ["ingest-batch", "demo", "--dir", str(batch_dir), "--scope", scope])
    out = capsys.readouterr().out
    # Full per-finding detail (evidence + transitions) AND a summary table.
    assert "sqli_differential" in out        # full evidence present
    assert "validating -> validated" in out or "validating -> rejected" in out
    assert "Batch summary" in out            # summary in addition


# ---------------- queue: read-only ----------------

SQLI_ONLY_STUB = json.dumps({"endpoints": [
    {"url": "/item", "params": ["id"], "id_like_params": ["id"],
     "suspected_vuln_class": "sqli_boolean", "reasoning": "id into lookup"}]})


def _digest_findings(db_path):
    repo = Repository(connect(db_path))
    out = []
    for f in repo.list_findings():
        evs = [(e.kind, e.data) for e in repo.list_evidence(f.id)]
        out.append((f.vuln_class, f.target_url, f.state, round(f.confidence, 3), evs))
    return sorted(out, key=lambda r: r[1])


def test_auto_chain_evidence_identical_to_manual(mock_server, tmp_path, monkeypatch):
    """Same candidate, ingested via the default manual path vs via --auto-chain,
    must produce identical evidence/confidence/final state."""
    scope = _scope_file(tmp_path)
    stub = tmp_path / "stub.json"; stub.write_text(SQLI_ONLY_STUB)

    # --- manual path: generate candidate file, then `ingest` it ---
    s_manual = _settings(tmp_path / "m")
    gen_dir = tmp_path / "m_cands"
    _run_cli_with_settings(s_manual, monkeypatch, [
        "generate-candidates", "demo", "--scope", scope,
        "--js-file", "samples/sample_app.js", "--base-url", mock_server,
        "--stub-response", str(stub), "--out", str(gen_dir)])
    cand_file = next(gen_dir.glob("*sqli_boolean.json"))
    _run_cli_with_settings(s_manual, monkeypatch,
                           ["ingest", str(cand_file), "--scope", scope])

    # --- auto-chain path: run generates the same candidate and ingests it ---
    s_auto = _settings(tmp_path / "a")
    _run_cli_with_settings(s_auto, monkeypatch, [
        "run", "demo", "--scope", scope,
        "--js-file", "samples/sample_app.js", "--base-url", mock_server,
        "--stub-response", str(stub), "--out", str(tmp_path / "a_cands"),
        "--auto-chain", "--yes"])

    assert _digest_findings(s_manual.db_path) == _digest_findings(s_auto.db_path)


def test_auto_chain_never_reaches_approved_or_report(mock_server, tmp_path, monkeypatch):
    scope = _scope_file(tmp_path)
    stub = tmp_path / "stub.json"; stub.write_text(SQLI_ONLY_STUB)
    s = _settings(tmp_path)
    _run_cli_with_settings(s, monkeypatch, [
        "run", "demo", "--scope", scope,
        "--js-file", "samples/sample_app.js", "--base-url", mock_server,
        "--stub-response", str(stub), "--out", str(tmp_path / "cands"),
        "--auto-chain", "--yes"])

    repo = Repository(connect(s.db_path))
    findings = repo.list_findings()
    assert findings, "auto-chain should have created findings"
    # The line that cannot move: nothing is approved, and no report file exists.
    assert all(f.state in ("in_review", "rejected") for f in findings)
    assert not list((tmp_path / "reports").rglob("*.md"))


def test_auto_chain_refuses_without_yes_noninteractive(mock_server, tmp_path, monkeypatch):
    scope = _scope_file(tmp_path)
    stub = tmp_path / "stub.json"; stub.write_text(SQLI_ONLY_STUB)
    s = _settings(tmp_path)
    # pytest stdin is not a tty; without --yes, auto-chain must refuse and do nothing.
    rc = _run_cli_with_settings(s, monkeypatch, [
        "run", "demo", "--scope", scope,
        "--js-file", "samples/sample_app.js", "--base-url", mock_server,
        "--stub-response", str(stub), "--auto-chain"])
    assert rc == 1
    assert Repository(connect(s.db_path)).list_findings() == []


def test_run_without_auto_chain_ingests_nothing(mock_server, tmp_path, monkeypatch):
    scope = _scope_file(tmp_path)
    stub = tmp_path / "stub.json"; stub.write_text(SQLI_ONLY_STUB)
    s = _settings(tmp_path)
    _run_cli_with_settings(s, monkeypatch, [
        "run", "demo", "--scope", scope,
        "--js-file", "samples/sample_app.js", "--base-url", mock_server,
        "--stub-response", str(stub), "--out", str(tmp_path / "cands")])
    # Default run generates candidate files but never ingests, so no findings.
    assert Repository(connect(s.db_path)).list_findings() == []


def test_queue_reports_pending_accurately(tmp_path, monkeypatch, capsys):
    s = _settings(tmp_path)
    repo = Repository(connect(s.db_path)); init_db(repo.conn)

    # in_review finding.
    fid_r = repo.create_finding(m.Finding(program="demo", vuln_class="sqli_boolean",
        target_url="http://127.0.0.1/item?id=1", request={"inject_param": "id"}))
    repo.transition(fid_r, m.VALIDATING, 0.3, "s")
    repo.transition(fid_r, m.VALIDATED, 0.9, "ok")
    repo.transition(fid_r, m.IN_REVIEW, 0.9, "thr")

    # approved finding without a report file.
    fid_a = repo.create_finding(m.Finding(program="demo", vuln_class="idor",
        target_url="http://127.0.0.1/api/orders/1001", request={}))
    repo.transition(fid_a, m.VALIDATING, 0.3, "s")
    repo.transition(fid_a, m.VALIDATED, 0.9, "ok")
    repo.transition(fid_a, m.IN_REVIEW, 0.9, "thr")
    repo.transition(fid_a, m.APPROVED, 0.9, "approved")

    # candidates dir: one pending (new URL), one already-ingested (matches fid_r).
    cand_dir = tmp_path / "candidates"
    _write(cand_dir / "pending.json", {"program": "demo", "vuln_class": "reflected_xss",
        "target_url": "http://127.0.0.1/xss?q=x"})
    _write(cand_dir / "already.json", {"program": "demo", "vuln_class": "sqli_boolean",
        "target_url": "http://127.0.0.1/item?id=1"})

    monkeypatch.setattr(cli, "load_settings", lambda: s)
    rc = cli.main(["queue", "--dir", str(cand_dir)])
    assert rc == 0
    out = capsys.readouterr().out

    # [1] in_review shows fid_r, not the approved one.
    assert f"#{fid_r}  demo  sqli_boolean" in out
    # [2] pending candidate listed; already-ingested one NOT listed.
    assert "pending.json" in out
    assert "already.json" not in out
    # [3] approved-without-report shows fid_a.
    assert f"#{fid_a}  demo  idor" in out

    # Read-only: queue changed no state.
    assert repo.get_finding(fid_r).state == m.IN_REVIEW
    assert repo.get_finding(fid_a).state == m.APPROVED
