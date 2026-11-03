"""bbv command line. Subcommands: ingest, review, show, list, mockserver."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import models as m
from .config import load_settings
from .db import connect, init_db
from .pipeline import validate_finding
from .repository import Repository
from .scope import Scope


def _open_repo(settings) -> Repository:
    conn = connect(settings.db_path)
    init_db(conn)
    return Repository(conn)


def _print_trail(repo: Repository, finding_id: int) -> None:
    f = repo.get_finding(finding_id)
    assert f is not None
    print(f"\nFinding #{f.id}  [{f.program}]  {f.vuln_class}")
    print(f"  target: {f.target_url}")
    print(f"  state:  {f.state}    confidence: {f.confidence:.2f}")

    print("\n  transitions:")
    for t in repo.list_transitions(finding_id):
        print(f"    {t.created_at}  {t.from_state:>10} -> {t.to_state:<10} "
              f"({t.confidence_before:.2f} -> {t.confidence_after:.2f})  {t.reason}")

    print("\n  evidence:")
    for e in repo.list_evidence(finding_id):
        print(f"    [{e.kind}] {json.dumps(e.data)}")
    print()


def cmd_ingest(args: argparse.Namespace) -> int:
    settings = load_settings()
    repo = _open_repo(settings)
    scope = Scope.load(args.scope)

    data = json.loads(Path(args.finding).read_text(encoding="utf-8"))
    finding = m.Finding(
        program=data["program"],
        target_url=data["target_url"],
        vuln_class=data["vuln_class"],
        request=data.get("request", {}),
        notes=data.get("notes"),
        confidence=float(data.get("confidence", m.SEED_CONFIDENCE)),
    )
    # Guard: the finding's target must itself be in scope before we create it.
    if not scope.is_allowed(finding.target_url):
        print(f"REFUSED: target {finding.target_url} is not in the provided scope.",
              file=sys.stderr)
        return 2

    finding_id = repo.create_finding(finding)
    print(f"ingested finding #{finding_id} ({finding.vuln_class}); validating...")

    created = repo.get_finding(finding_id)
    assert created is not None
    validate_finding(repo, created, scope, settings)

    _print_trail(repo, finding_id)
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    settings = load_settings()
    repo = _open_repo(settings)
    f = repo.get_finding(args.id)
    if f is None:
        print(f"no finding #{args.id}", file=sys.stderr)
        return 2
    if f.state != m.IN_REVIEW:
        print(f"finding #{args.id} is in state {f.state!r}; only in_review findings "
              f"can be approved/dismissed.", file=sys.stderr)
        return 2

    to_state = m.APPROVED if args.approve else m.DISMISSED
    reason = args.reason or ("approved by reviewer" if args.approve else "dismissed by reviewer")
    repo.transition(args.id, to_state, f.confidence, reason)
    _print_trail(repo, args.id)
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    settings = load_settings()
    repo = _open_repo(settings)
    if repo.get_finding(args.id) is None:
        print(f"no finding #{args.id}", file=sys.stderr)
        return 2
    _print_trail(repo, args.id)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    settings = load_settings()
    repo = _open_repo(settings)
    for f in repo.list_findings(args.state):
        print(f"#{f.id:<4} {f.state:<11} {f.confidence:.2f}  {f.vuln_class:<15} "
              f"{f.program}  {f.target_url}")
    return 0


def cmd_mockserver(args: argparse.Namespace) -> int:
    from .mockserver import serve
    serve(args.host, args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bbv", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("ingest", help="ingest a candidate finding JSON and validate it")
    pi.add_argument("finding", help="path to candidate finding JSON")
    pi.add_argument("--scope", required=True, help="path to program scope JSON")
    pi.set_defaults(func=cmd_ingest)

    pr = sub.add_parser("review", help="record your decision on an in_review finding")
    pr.add_argument("id", type=int)
    g = pr.add_mutually_exclusive_group(required=True)
    g.add_argument("--approve", action="store_true")
    g.add_argument("--dismiss", action="store_true")
    pr.add_argument("--reason", default=None)
    pr.set_defaults(func=cmd_review)

    ps = sub.add_parser("show", help="print a finding's full trail")
    ps.add_argument("id", type=int)
    ps.set_defaults(func=cmd_show)

    pl = sub.add_parser("list", help="list findings")
    pl.add_argument("--state", default=None)
    pl.set_defaults(func=cmd_list)

    pm = sub.add_parser("mockserver", help="run the local vulnerable mock server")
    pm.add_argument("--host", default="127.0.0.1")
    pm.add_argument("--port", type=int, default=8000)
    pm.set_defaults(func=cmd_mockserver)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
