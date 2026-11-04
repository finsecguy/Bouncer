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


def _resolve_scope(explicit: str | None, program: str) -> tuple[str, Scope] | None:
    """Pick the scope file and ALWAYS announce it loudly. Explicit --scope wins;
    otherwise fall back to scopes/<program>.json. Never silently guess: if
    neither exists, print a clear error and return None (caller exits 2)."""
    path = explicit or str(Path("scopes") / f"{program}.json")
    if not Path(path).exists():
        if explicit:
            print(f"ERROR: scope file {path!r} does not exist.", file=sys.stderr)
        else:
            print(f"ERROR: no --scope given and default scopes/{program}.json not "
                  "found. Pass --scope <file>.", file=sys.stderr)
        return None
    print(f"SCOPE: {path}")
    return path, Scope.load(path)


def _ingest_finding_data(repo: Repository, scope: Scope, settings, data: dict) -> int | None:
    """Shared ingest core used by both `ingest` and `ingest-batch`, so batch
    behaves identically to a sequence of single ingests. Returns the new finding
    id, or None if the target was out of scope (refusal already printed)."""
    finding = m.Finding(
        program=data["program"],
        target_url=data["target_url"],
        vuln_class=data["vuln_class"],
        request=data.get("request", {}),
        notes=data.get("notes"),
        confidence=float(data.get("confidence", m.SEED_CONFIDENCE)),
    )
    if not scope.is_allowed(finding.target_url):
        print(f"REFUSED: target {finding.target_url} is not in the provided scope.",
              file=sys.stderr)
        return None
    finding_id = repo.create_finding(finding)
    print(f"ingested finding #{finding_id} ({finding.vuln_class}); validating...")
    validate_finding(repo, repo.get_finding(finding_id), scope, settings)
    return finding_id


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

    data = json.loads(Path(args.finding).read_text(encoding="utf-8"))
    resolved = _resolve_scope(args.scope, data["program"])
    if resolved is None:
        return 2
    _, scope = resolved

    finding_id = _ingest_finding_data(repo, scope, settings, data)
    if finding_id is None:
        return 2
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


def _run_recon(settings, repo, scope, program):
    from .recon import ReconRunner
    return ReconRunner(repo, scope, settings, program).run()


def _print_recon_summary(summary, repo, program, indent="  ") -> None:
    print(f"{indent}tools available: {summary.tools_available}")
    print(f"{indent}asset counts:    {summary.counts}")
    for n in summary.notes:
        print(f"{indent}note: {n}")
    total = len(repo.list_assets(program))
    in_scope = len(repo.list_assets(program, in_scope=True))
    print(f"{indent}assets persisted: {total}  ({in_scope} in scope, "
          f"{total - in_scope} out of scope)")


def cmd_recon(args: argparse.Namespace) -> int:
    settings = load_settings()
    repo = _open_repo(settings)
    resolved = _resolve_scope(args.scope, args.program)
    if resolved is None:
        return 2
    _, scope = resolved

    summary = _run_recon(settings, repo, scope, args.program)
    print(f"recon for program '{args.program}':")
    _print_recon_summary(summary, repo, args.program)
    return 0


def _run_generate(settings, repo, scope, program, *, js_file, base_url,
                  stub_response, out) -> tuple[list, list] | None:
    """Shared generate-candidates core. Returns (paths, candidates), or None if
    it could not proceed (message already printed). Writes files; never ingests."""
    from .candidates import (CandidateGenerator, JsInput, annotate_known_patterns,
                             write_candidates)
    from .claude_client import ReplayExtractor, make_extractor
    from .http_client import ScopedHttpClient
    from .pipeline import build_rate_limiter

    if stub_response:
        # Provider-agnostic: replay bypasses the API entirely.
        extractor = ReplayExtractor(
            Path(stub_response).read_text(encoding="utf-8"), source_label=stub_response)
    else:
        try:
            extractor = make_extractor(settings)   # picks provider from BBV_LLM_PROVIDER
        except RuntimeError as e:
            print(f"ERROR: {e}. Fix provider config (see `bbv setup`), or pass "
                  "--stub-response to replay a saved response offline.", file=sys.stderr)
            return None

    js_inputs: list[JsInput] = []
    if js_file:
        for jf in js_file:
            js_inputs.append(JsInput(source_url=jf, base_url=base_url or "",
                                     text=Path(jf).read_text(encoding="utf-8")))
    else:
        js_assets = repo.list_assets(program, kind=m.KIND_JS, in_scope=True)
        if not js_assets:
            print(f"no in-scope JS assets for '{program}'. Run recon first, or pass "
                  "--js-file <path> --base-url <url>.", file=sys.stderr)
            return None
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

    try:
        candidates = CandidateGenerator(program, scope, extractor).generate(js_inputs)
    except Exception as e:
        # A live provider call failed (auth, network, bad endpoint). Fail cleanly
        # for the right reason rather than crashing; malformed-but-parsed output
        # is handled upstream (discarded), so this is a transport/provider fault.
        print(f"ERROR: LLM provider call failed ({type(e).__name__}: {e}). "
              "Check `bbv setup`, or use --stub-response to work offline.",
              file=sys.stderr)
        return None
    annotate_known_patterns(candidates, repo)   # advisory only; never filters
    paths = write_candidates(candidates, out or settings.candidates_dir)
    return paths, candidates


def _print_candidate_results(paths, candidates, indent="  ") -> None:
    noted = [c for c in candidates if "known_pattern_note" in c]
    print(f"{indent}generated {len(paths)} candidate(s):")
    noted_names = {str(p) for c, p in zip(candidates, paths) if "known_pattern_note" in c}
    for p in paths:
        tag = "   [!] known_pattern_note" if str(p) in noted_names else ""
        print(f"{indent}  {p}{tag}")
    if noted:
        print(f"{indent}[!] {len(noted)} candidate(s) match a repeat false-positive "
              "pattern (read those first):")
        for c, p in zip(candidates, paths):
            if "known_pattern_note" in c:
                print(f"{indent}    - {Path(p).name}: {c['known_pattern_note']}")


def cmd_generate_candidates(args: argparse.Namespace) -> int:
    settings = load_settings()
    repo = _open_repo(settings)
    resolved = _resolve_scope(args.scope, args.program)
    if resolved is None:
        return 2
    scope_path, scope = resolved

    result = _run_generate(settings, repo, scope, args.program,
                           js_file=args.js_file, base_url=args.base_url,
                           stub_response=args.stub_response, out=args.out)
    if result is None:
        return 2
    paths, candidates = result
    _print_candidate_results(paths, candidates)
    print("\nThese are UNVALIDATED candidates. Review each one, then ingest the "
          f"ones you choose:\n  python -m bbv ingest <candidate.json> --scope "
          f"{scope_path}\nNothing has been validated or submitted.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Chain recon -> generate-candidates and STOP. No ingest, review, or report."""
    settings = load_settings()
    repo = _open_repo(settings)
    resolved = _resolve_scope(args.scope, args.program)
    if resolved is None:
        return 2
    scope_path, scope = resolved

    print(f"\n== bbv run: {args.program} ==")

    print("\n-- Stage 1/2: recon --")
    summary = _run_recon(settings, repo, scope, args.program)
    _print_recon_summary(summary, repo, args.program)

    print("\n-- Stage 2/2: generate-candidates --")
    result = _run_generate(settings, repo, scope, args.program,
                           js_file=args.js_file, base_url=args.base_url,
                           stub_response=args.stub_response, out=args.out)
    if result is None:
        print("\n(recon completed; no candidates were generated. Nothing was "
              "ingested, validated, or submitted.)")
        return 2
    paths, candidates = result
    _print_candidate_results(paths, candidates)

    out_dir = args.out or settings.candidates_dir
    print("\n== Done. Nothing was ingested, validated, or submitted. ==")
    print(f"Next: review the {len(paths)} file(s) in {out_dir}/, then ingest the "
          "ones worth testing:")
    print(f"  python -m bbv ingest-batch {args.program}")
    print(f"  python -m bbv ingest {out_dir}/<file>.json --scope {scope_path}")
    return 0


def cmd_ingest_batch(args: argparse.Namespace) -> int:
    """Ingest every candidate JSON in a directory, sequentially. Full per-finding
    output is printed for each (never abbreviated), plus a summary table."""
    settings = load_settings()
    repo = _open_repo(settings)

    directory = Path(args.dir or settings.candidates_dir)
    files = sorted(directory.glob("*.json"))
    if not files:
        print(f"no candidate JSON files in {directory}/", file=sys.stderr)
        return 2

    rows: list[tuple] = []
    for path in files:
        print(f"\n{'='*70}\n# {path}\n{'='*70}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"  skip {path}: not valid JSON ({e})", file=sys.stderr)
            rows.append((path.name, "-", "-", "SKIPPED (bad JSON)", "-"))
            continue

        resolved = _resolve_scope(args.scope, data.get("program", args.program))
        if resolved is None:
            rows.append((path.name, data.get("vuln_class", "-"),
                         data.get("target_url", "-"), "SKIPPED (no scope)", "-"))
            continue
        _, scope = resolved

        fid = _ingest_finding_data(repo, scope, settings, data)
        if fid is None:
            rows.append((path.name, data.get("vuln_class", "-"),
                         data.get("target_url", "-"), "REFUSED (out of scope)", "-"))
            continue
        _print_trail(repo, fid)   # identical full output to single `ingest`
        f = repo.get_finding(fid)
        rows.append((f"#{fid}", f.vuln_class, f.target_url, f.state,
                     f"{f.confidence:.2f}"))

    # Summary table IN ADDITION to the full output above, never instead of it.
    print(f"\n{'='*70}\n# Batch summary ({len(files)} file(s))\n{'='*70}")
    print(f"{'id/file':<28} {'vuln_class':<15} {'state':<22} {'conf':<5} target")
    for name, vc, target, state, conf in rows:
        ident = name if str(name).startswith("#") else name
        print(f"{ident:<28} {vc:<15} {state:<22} {conf:<5} {target}")
    return 0


def cmd_queue(args: argparse.Namespace) -> int:
    """Read-only: show everything across all programs that is waiting on you."""
    settings = load_settings()
    repo = _open_repo(settings)

    print("== bbv queue: what needs you ==  (read-only; nothing is changed)")

    # [1] findings in review.
    in_review = repo.list_findings(m.IN_REVIEW)
    print(f"\n[1] Findings in review (awaiting approve/dismiss):  {len(in_review)}")
    for f in in_review:
        print(f"  #{f.id}  {f.program}  {f.vuln_class}  conf {f.confidence:.2f}  {f.target_url}")
        print(f"      -> bbv review {f.id} --approve   |   bbv review {f.id} --dismiss")

    # [2] candidates on disk not yet ingested (exact program+vuln_class+target_url diff).
    existing = {(f.program, f.vuln_class, f.target_url) for f in repo.list_findings()}
    cand_dir = Path(args.dir or settings.candidates_dir)
    pending = []
    for path in sorted(cand_dir.glob("*.json")):
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        key = (d.get("program"), d.get("vuln_class"), d.get("target_url"))
        if key not in existing:
            pending.append((path, d))
    print(f"\n[2] Candidates on disk not yet ingested:  {len(pending)}")
    for path, d in pending:
        tag = "   [!] known_pattern_note" if "known_pattern_note" in d else ""
        print(f"  {path}  {d.get('program')}  {d.get('vuln_class')}  "
              f"{d.get('target_url')}{tag}")
    if pending:
        print("      -> review the file, then: bbv ingest <file> --scope <scope>")

    # [3] approved findings with no report file yet.
    import re as _re
    approved = repo.list_findings(m.APPROVED)
    reports_base = Path(settings.reports_dir)
    missing = []
    for f in approved:
        safe = _re.sub(r"[^A-Za-z0-9._-]", "_", f.program)
        report_path = reports_base / safe / f"{f.id}_{f.vuln_class}.md"
        if not report_path.exists():
            missing.append(f)
    print(f"\n[3] Approved findings with no report yet:  {len(missing)}")
    for f in missing:
        print(f"  #{f.id}  {f.program}  {f.vuln_class}  {f.target_url}")
        print(f"      -> bbv report {f.id} --platform intigriti")
    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    from .setup import gather_status, render_status, run_self_test, run_setup

    settings = load_settings()
    if args.check:
        # Non-interactive status report (safe for scripts/CI). Always exits 0;
        # it is informational and does not change behavior.
        print(render_status(gather_status(settings)))
        return 0

    if args.self_test:
        # Non-interactive pipeline smoke test (uses a temp DB, never the real one).
        ok = run_self_test()
        return 0 if ok else 1

    run_setup()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bbv", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("ingest", help="ingest a candidate finding JSON and validate it")
    pi.add_argument("finding", help="path to candidate finding JSON")
    pi.add_argument("--scope", default=None,
                    help="path to program scope JSON (default: scopes/<program>.json)")
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
    prc.add_argument("--scope", default=None,
                     help="path to program scope JSON (default: scopes/<program>.json)")
    prc.set_defaults(func=cmd_recon)

    prun = sub.add_parser("run",
                          help="chain recon + generate-candidates, then STOP (no ingest)")
    prun.add_argument("program")
    prun.add_argument("--scope", default=None,
                      help="path to program scope JSON (default: scopes/<program>.json)")
    prun.add_argument("--js-file", action="append",
                      help="use a local JS file instead of fetching from assets (repeatable)")
    prun.add_argument("--base-url", default=None,
                      help="base URL to resolve root-relative endpoints from --js-file")
    prun.add_argument("--stub-response", default=None,
                      help="replay a saved Claude JSON response instead of calling the API")
    prun.add_argument("--out", default=None, help="candidates output dir (default: candidates/)")
    prun.set_defaults(func=cmd_run)

    pib = sub.add_parser("ingest-batch",
                         help="ingest every candidate JSON in a directory (full output each)")
    pib.add_argument("program")
    pib.add_argument("--dir", default=None, help="candidates dir (default: candidates/)")
    pib.add_argument("--scope", default=None,
                     help="path to program scope JSON (default: scopes/<program>.json)")
    pib.set_defaults(func=cmd_ingest_batch)

    pq = sub.add_parser("queue", help="read-only: what is waiting on you, across programs")
    pq.add_argument("--dir", default=None, help="candidates dir (default: candidates/)")
    pq.set_defaults(func=cmd_queue)

    pset = sub.add_parser("setup",
                          help="show config status and fix gaps interactively")
    pset.add_argument("--check", action="store_true",
                      help="print status non-interactively and exit (no prompts)")
    pset.add_argument("--self-test", action="store_true", dest="self_test",
                      help="run a pipeline smoke test against an in-process mock "
                           "server using a temporary DB (never touches the real DB)")
    pset.set_defaults(func=cmd_setup)

    pg = sub.add_parser("generate-candidates",
                        help="reason over JS assets and write candidate finding JSON "
                             "(does NOT ingest or validate)")
    pg.add_argument("program")
    pg.add_argument("--scope", default=None,
                    help="path to program scope JSON (default: scopes/<program>.json)")
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
