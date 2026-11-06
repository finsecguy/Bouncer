"""Structural guard for the human-in-the-loop boundary (see DESIGN_PRINCIPLES.md).

No automation, including `bouncer run --auto-chain`, may auto-approve, auto-dismiss,
auto-generate a report, or auto-submit. These tests fail the build if that
boundary is ever crossed in code. If one fails: a feature crossed the line; fix
the feature, do not relax the test.
"""
import ast
import json
from pathlib import Path

import pytest

import bouncer.cli as cli
from bouncer import models as m
from bouncer.config import Settings
from bouncer.db import connect
from bouncer.repository import Repository

CLI_SRC = Path(cli.__file__)


# --------------------------------------------------------------------------
# Primary guard: runtime behavioral check. Wrap every forbidden sink so it
# raises if called, then run a COMPLETE --auto-chain pass (all three vuln
# classes, reaching both in_review and rejected) and assert none fired.
# --------------------------------------------------------------------------
def test_auto_chain_can_never_reach_approval_or_report(mock_server, tmp_path, monkeypatch):
    import bouncer.reporting as reporting
    import bouncer.severity as severity

    s = Settings(_env_file=None)
    s.db_path = str(tmp_path / "bouncer.db")
    s.candidates_dir = str(tmp_path / "candidates")
    s.reports_dir = str(tmp_path / "reports")
    monkeypatch.setattr(cli, "load_settings", lambda: s)

    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"in_cidrs": ["127.0.0.1/32"], "in_domains": []}))
    stub = tmp_path / "stub.json"
    stub.write_text(json.dumps({"endpoints": [
        {"url": "/xss", "params": ["q"], "suspected_vuln_class": "reflected_xss"},
        {"url": "/item", "params": ["id"], "id_like_params": ["id"],
         "suspected_vuln_class": "sqli_boolean"},
        {"url": "/api/orders/1001", "params": ["order_id"], "id_like_params": ["order_id"],
         "suspected_vuln_class": "idor"},
    ]}))

    # --- wrap the sinks ---
    orig_transition = Repository.transition

    def guarded_transition(self, finding_id, to_state, *a, **k):
        if to_state in (m.APPROVED, m.DISMISSED):
            raise AssertionError(
                "BOUNDARY VIOLATION: an auto-chain code path attempted to "
                f"transition finding {finding_id} to {to_state!r}. Approval and "
                "dismissal must only ever come from `bouncer review`. See "
                "DESIGN_PRINCIPLES.md.")
        return orig_transition(self, finding_id, to_state, *a, **k)

    def forbidden(name):
        def _raise(*a, **k):
            raise AssertionError(
                f"BOUNDARY VIOLATION: an auto-chain code path called {name}, i.e. "
                "it tried to generate a report. Reports require prior human "
                "approval via `bouncer review` and are produced only by `bouncer report`. "
                "See DESIGN_PRINCIPLES.md.")
        return _raise

    monkeypatch.setattr(Repository, "transition", guarded_transition)
    monkeypatch.setattr(reporting, "build_facts", forbidden("reporting.build_facts"))
    monkeypatch.setattr(severity, "assess", forbidden("severity.assess"))

    rc = cli.main([
        "run", "demo", "--scope", str(scope),
        "--js-file", "samples/sample_app.js", "--base-url", mock_server,
        "--stub-response", str(stub), "--out", str(tmp_path / "candidates"),
        "--auto-chain", "--yes",
    ])
    assert rc == 0

    # The run produced real findings, and every one stopped at in_review/rejected.
    findings = Repository(connect(s.db_path)).list_findings()
    assert findings, "auto-chain should have ingested and created findings"
    assert all(f.state in (m.IN_REVIEW, m.REJECTED) for f in findings), \
        [(f.id, f.state) for f in findings]
    assert not list((tmp_path / "reports").rglob("*.md"))


# --------------------------------------------------------------------------
# Defense in depth: static check. No function reachable from cmd_run within the
# CLI layer may import the reporting/severity modules or name a report/approval
# entry point. (Intra-file call-graph BFS; unambiguous, no false positives.)
# --------------------------------------------------------------------------
def _cli_run_path_functions() -> dict[str, ast.FunctionDef]:
    tree = ast.parse(CLI_SRC.read_text(encoding="utf-8"))
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}

    def local_calls(fn: ast.FunctionDef) -> set[str]:
        out = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                out.add(node.func.id)
        return out

    reach: dict[str, ast.FunctionDef] = {}
    stack = ["cmd_run"]
    while stack:
        name = stack.pop()
        if name in reach or name not in funcs:
            continue
        reach[name] = funcs[name]
        stack.extend(local_calls(funcs[name]))
    return reach


def test_run_path_does_not_wire_in_reporting_or_approval():
    reach = _cli_run_path_functions()
    assert "cmd_run" in reach
    # cmd_report must NOT be reachable from cmd_run.
    assert "cmd_report" not in reach and "cmd_review" not in reach

    forbidden_names = {"build_facts", "get_reporter", "render", "assess",
                       "cmd_review", "cmd_report"}
    violations = []
    for fname, fn in reach.items():
        for node in ast.walk(fn):
            if isinstance(node, ast.ImportFrom) and node.module and \
                    ("reporting" in node.module or "severity" in node.module):
                violations.append(f"{fname} imports {node.module}")
            if isinstance(node, ast.Name) and node.id in forbidden_names:
                violations.append(f"{fname} references {node.id}")
            if isinstance(node, ast.Attribute) and node.attr in forbidden_names:
                violations.append(f"{fname} references .{node.attr}")
    assert not violations, (
        "BOUNDARY VIOLATION: the `bouncer run` code path wired in report generation "
        "or approval: " + "; ".join(violations) + ". See DESIGN_PRINCIPLES.md.")


def test_no_submission_code_exists():
    """There is no platform-submission code in the repo, by design. Assert no
    source file defines a submit-to-platform entry point."""
    src = Path(cli.__file__).parent
    offenders = []
    for py in src.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                low = node.name.lower()
                if "submit" in low and ("platform" in low or "report" in low
                                        or "finding" in low):
                    offenders.append(f"{py.name}:{node.name}")
    assert not offenders, (
        "BOUNDARY VIOLATION: submission code appeared: " + ", ".join(offenders)
        + ". No code may submit to a platform. See DESIGN_PRINCIPLES.md.")
