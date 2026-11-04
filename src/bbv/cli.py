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


def cmd_report(args: argparse.Namespace) -> int:
    import re as _re

    from .reporting import build_facts, get_reporter, known_platforms

    settings = load_settings()
    repo = _open_repo(settings)

    reporter = get_reporter(args.platform)
    if reporter is None:
        print(f"unknown platform {args.platform!r}. Available: "
              f"{', '.join(known_platforms())}", file=sys.stderr)
        return 2

    f = repo.get_finding(args.id)
    if f is None:
        print(f"no finding #{args.id}", file=sys.stderr)
        return 2

    # CRITICAL: reports are only generated for human-approved findings.
    if f.state != m.APPROVED:
        print(f"REFUSED: finding #{args.id} is in state {f.state!r}; reports are "
              "only generated for 'approved' findings (use "
              f"`bbv review {args.id} --approve` first).", file=sys.stderr)
        return 2

    facts = build_facts(f, repo.list_evidence(args.id), repo.list_transitions(args.id))
    report = reporter.render(facts)

    if args.dry_run:
        print(report)
        return 0

    safe_program = _re.sub(r"[^A-Za-z0-9._-]", "_", f.program)
    out_dir = Path(args.out or settings.reports_dir) / safe_program
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{f.id}_{f.vuln_class}.md"
    path.write_text(report, encoding="utf-8")
    print(f"wrote {path}")
    print("NOTE: this report has NOT been submitted. Submission is a manual "
          "action you perform on the platform yourself.")
    return 0


def cmd_signatures(args: argparse.Namespace) -> int:
    settings = load_settings()
    repo = _open_repo(settings)

    if args.sig_cmd == "backfill":
        n = repo.backfill_signatures()
        print(f"backfilled {n} past rejection(s) into the signature catalog")
        return 0

    if args.sig_cmd == "show":
        s = repo.get_signature(args.id)
        if s is None:
            print(f"no signature #{args.id}", file=sys.stderr)
            return 2
        print(f"Signature #{s['id']}  [{s['vuln_class']}]  scope={s['scope']}")
        print(f"  feature_key: {s['feature_key']}")
        if s["program"]:
            print(f"  program:     {s['program']}")
        if s["endpoint"]:
            print(f"  endpoint:    {s['endpoint']}")
        print(f"  times_seen:  {s['times_seen']}  (first {s['first_seen']}, last {s['last_seen']})")
        print(f"  last_reason: {s['last_reason']}")
        print(f"  example_evidence: {json.dumps(s['example_evidence'])}")
        print("  per-program breakdown:")
        for pb in s["program_breakdown"]:
            print(f"    {pb['program']:<20} {pb['times_seen']}x  (last {pb['last_seen']})")
        print(f"  linked rejected findings: {s['linked_finding_ids']}")
        return 0

    # list
    rows = repo.list_signatures(program=args.program, vuln_class=args.vuln_class)
    if not rows:
        print("no signatures recorded yet "
              "(reject some findings, or run: bbv signatures backfill)")
        return 0
    hdr = f"{'ID':<4} {'SEEN':<5} {'SCOPE':<8} {'VULN_CLASS':<15} FEATURE_KEY"
    if args.program:
        hdr = f"{'ID':<4} {'SEEN':<5} {'HERE':<5} {'SCOPE':<8} {'VULN_CLASS':<15} FEATURE_KEY"
    print(hdr)
    for r in rows:
        if args.program:
            print(f"{r['id']:<4} {r['times_seen']:<5} {r['program_times_seen']:<5} "
                  f"{r['scope']:<8} {r['vuln_class']:<15} {r['feature_key']}")
        else:
            print(f"{r['id']:<4} {r['times_seen']:<5} {r['scope']:<8} "
                  f"{r['vuln_class']:<15} {r['feature_key']}")
    return 0


def cmd_recon(args: argparse.Namespace) -> int:
    from .recon import ReconRunner
    settings = load_settings()
    repo = _open_repo(settings)
    scope = Scope.load(args.scope)

    summary = ReconRunner(repo, scope, settings, args.program).run()

    print(f"recon for program '{args.program}':")
    print(f"  tools available: {summary.tools_available}")
    print(f"  asset counts:    {summary.counts}")
    for n in summary.notes:
        print(f"  note: {n}")
    total = len(repo.list_assets(args.program))
    in_scope = len(repo.list_assets(args.program, in_scope=True))
    print(f"  assets persisted: {total} ({in_scope} in scope)")
    return 0


def cmd_generate_candidates(args: argparse.Namespace) -> int:
    from .candidates import CandidateGenerator, JsInput, write_candidates
    from .claude_client import ClaudeExtractor, ReplayExtractor
    from .http_client import ScopedHttpClient
    from .pipeline import build_rate_limiter

    settings = load_settings()
    repo = _open_repo(settings)
    scope = Scope.load(args.scope)

    # Choose the extractor: real Claude, or a replayed saved response (offline).
    if args.stub_response:
        extractor = ReplayExtractor(
            Path(args.stub_response).read_text(encoding="utf-8"),
            source_label=args.stub_response,
        )
    else:
        try:
            extractor = ClaudeExtractor(settings)
        except RuntimeError as e:
            print(f"ERROR: {e}. Set BBV_ANTHROPIC_API_KEY, or pass --stub-response "
                  "to replay a saved Claude response offline.", file=sys.stderr)
            return 2

    # Build the JS inputs: explicit files, or in-scope JS assets fetched through
    # the scoped client (the ONLY target-traffic path here, and it is gated).
    js_inputs: list[JsInput] = []
    if args.js_file:
        base = args.base_url or ""
        for jf in args.js_file:
            text = Path(jf).read_text(encoding="utf-8")
            js_inputs.append(JsInput(source_url=jf, base_url=base, text=text))
    else:
        js_assets = repo.list_assets(args.program, kind=m.KIND_JS, in_scope=True)
        if not js_assets:
            print(f"no in-scope JS assets for '{args.program}'. Run recon first, "
                  "or pass --js-file <path> --base-url <url>.", file=sys.stderr)
            return 2
        rl = build_rate_limiter(settings)
        with ScopedHttpClient(scope, rl, timeout=settings.http_timeout,
                              user_agent=settings.user_agent) as http:
            for a in js_assets:
                try:
                    resp = http.get(a.value)
                except Exception as e:
                    print(f"  skip {a.value}: {e}", file=sys.stderr)
                    continue
                js_inputs.append(JsInput(source_url=a.value, base_url=a.value,
                                         text=resp.text))

    gen = CandidateGenerator(args.program, scope, extractor)
    candidates = gen.generate(js_inputs)
    # Advisory annotation only — never filters or alters core fields.
    from .candidates import annotate_known_patterns
    annotate_known_patterns(candidates, repo)
    paths = write_candidates(candidates, args.out or settings.candidates_dir)

    noted = sum(1 for c in candidates if "known_pattern_note" in c)
    if noted:
        print(f"({noted} candidate(s) carry an advisory known_pattern_note — "
              "still unvalidated; the validator runs on ingest)")

    print(f"generated {len(paths)} candidate(s) for '{args.program}':")
    for p in paths:
        print(f"  {p}")
    print("\nThese are UNVALIDATED candidates. Review each one, then ingest the "
          "ones you choose:\n  python -m bbv ingest <candidate.json> --scope "
          f"{args.scope}\nNothing has been validated or submitted.")
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

    prc = sub.add_parser("recon", help="passive recon: populate the assets table")
    prc.add_argument("program")
    prc.add_argument("--scope", required=True, help="path to program scope JSON")
    prc.set_defaults(func=cmd_recon)

    pg = sub.add_parser("generate-candidates",
                        help="reason over JS assets and write candidate finding JSON "
                             "(does NOT ingest or validate)")
    pg.add_argument("program")
    pg.add_argument("--scope", required=True, help="path to program scope JSON")
    pg.add_argument("--js-file", action="append",
                    help="use a local JS file instead of fetching from assets (repeatable)")
    pg.add_argument("--base-url", default=None,
                    help="base URL to resolve root-relative endpoints from --js-file")
    pg.add_argument("--stub-response", default=None,
                    help="replay a saved Claude JSON response instead of calling the API")
    pg.add_argument("--out", default=None, help="output dir (default: candidates/)")
    pg.set_defaults(func=cmd_generate_candidates)

    prep = sub.add_parser("report",
                          help="generate a platform-formatted report for an APPROVED finding")
    prep.add_argument("id", type=int)
    prep.add_argument("--platform", required=True, help="e.g. intigriti")
    prep.add_argument("--dry-run", action="store_true",
                      help="print to stdout instead of writing a file")
    prep.add_argument("--out", default=None, help="output base dir (default: reports/)")
    prep.set_defaults(func=cmd_report)

    psig = sub.add_parser("signatures",
                          help="browse the advisory false-positive signature catalog")
    sig_sub = psig.add_subparsers(dest="sig_cmd", required=True)
    sl = sig_sub.add_parser("list", help="signatures by recurrence (most-seen first)")
    sl.add_argument("--program", default=None)
    sl.add_argument("--vuln-class", default=None, dest="vuln_class")
    sl.set_defaults(func=cmd_signatures)
    ss = sig_sub.add_parser("show", help="full detail for one signature")
    ss.add_argument("id", type=int)
    ss.set_defaults(func=cmd_signatures)
    sb = sig_sub.add_parser("backfill",
                            help="derive signatures from past rejections' stored evidence")
    sb.set_defaults(func=cmd_signatures)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
