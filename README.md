# bbv: bug bounty validation engine

Evidence-gated validation for **authorized** bug bounty work. A candidate
finding is *guilty until proven exploitable*: it reaches you only after a
deterministic validator produces real request/response evidence. The pipeline
hard-stops at `in_review`, and nothing in this repo ever submits to a platform.

## Pipeline at a glance

```
recon  →  generate-candidates  →  (you review)  →  ingest  →  validate  →  in_review  →  (you decide)  →  report
 M2             M2                                   M1          M1          M1            review (M1)      M4
```

1. **Recon** (M2) discovers assets by wrapping existing tools.
2. **Candidate generation** (M2) reasons over discovered JS with Claude and writes candidate finding JSON. It never auto-ingests.
3. **You** review the candidates and choose which to `ingest`.
4. **Validation** (M1) runs a deterministic validator and moves the finding to `in_review` or `rejected`.
5. **You** approve or dismiss findings in `in_review`.
6. **Reporting** (M4) turns an approved finding into a platform-formatted Markdown file. Submitting it is still your manual action.

A **false-positive signature catalog** (M3) sits over the rejected pile and makes
recurring rejection causes visible for triage. It is advisory only.

**Convenience commands** (M5) chain the *mechanical* steps so you retype less:
`run` chains recon and generate-candidates then stops, `ingest-batch` ingests a
whole directory, and `queue` shows what is waiting on you. They add zero
autonomy. Every human checkpoint that existed before (read candidates before
ingest, read evidence before approve, read the report before you submit) still
exists, unchanged.

## Install

Requires Python 3.11+ (developed on 3.14).

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m playwright install chromium   # for the XSS execution check
cp .env.example .env                     # then edit; .env is gitignored
```

Two optional pieces:

- **Recon** wraps the ProjectDiscovery tools (`subfinder`, `httpx`, `katana`) if
  they are on your `PATH`. It degrades gracefully and never crashes when they are
  absent.
- **Candidate generation** needs an LLM provider configured (see below). Without
  one you can replay a saved response offline with `--stub-response`.

Run `bbv setup` to see what is configured and fix gaps interactively, or
`bbv setup --check` for a non-interactive status report.

## Configuration and setup

`bbv setup` shows a status table (what is set, what is missing) and lets you fill
gaps. Secrets are entered hidden, written only to `.env` (mode 0600), never
committed, never logged, and shown in status masked to the last four characters.
`bbv setup --check` prints the same table non-interactively, so you can see
config problems up front instead of discovering them mid-run.

### Self-test

`bbv setup --self-test` (also menu option 5) runs a pipeline smoke test: it
starts the mock server in-process, pushes the three sample findings through
ingest against a **temporary** database, and reports pass/fail per check:

- `reflected_xss` should reach `in_review` (reported as DEGRADED, not failed, if
  Chromium is not installed, since confirmed execution needs it).
- `idor` reports "needs `BBV_IDOR_SESSION_A/B`" explicitly when those are unset,
  rather than failing silently.
- `sqli_boolean` reports whatever the mock actually produces.

It tears the mock server down afterwards and **never touches your real database**
(it points `db_path` at a throwaway temp file for the duration). The flag exits 0
if every check passed and 1 otherwise, so it is usable in CI.

### LLM provider

Candidate generation (the one reasoning step) works with any of three providers,
selected by `BBV_LLM_PROVIDER`:

| Provider | `BBV_LLM_PROVIDER` | Needs |
|----------|--------------------|-------|
| Anthropic | `anthropic` (default) | `BBV_ANTHROPIC_API_KEY` |
| OpenAI | `openai` | `BBV_OPENAI_API_KEY` (optional `BBV_OPENAI_BASE_URL`) |
| Self-hosted (Ollama, vLLM, LM Studio, ...) | `self_hosted` | `BBV_OPENAI_BASE_URL` (e.g. `http://localhost:11434/v1`); key often optional |

Self-hosted is just the OpenAI client pointed at an OpenAI-compatible endpoint,
so no separate implementation is needed. Whatever the provider, the model's
output goes through the **same** pydantic validation before anything touches
disk: malformed output from any provider is discarded and logged, never guessed
at. A candidate is still only a candidate (no trust bonus, confidence floor
unchanged), and its `notes` record which model produced it, for example
`ai-sourced:openai:gpt-4.1-mini` or `ai-sourced:replay` for `--stub-response`.
The provider endpoint is reasoning infrastructure, not a program target, so it
is not routed through `ScopedHttpClient`; keys are never logged.

## Quickstart

Start the local, deliberately-vulnerable mock server (nothing touches a real
target), then drive a finding through the gate in another shell.

```bash
python -m bbv mockserver --port 8000
```

```bash
# Ingest and validate sample findings.
python -m bbv ingest samples/finding_xss.json  --scope samples/scope.example.json
python -m bbv ingest samples/finding_sqli.json --scope samples/scope.example.json

# IDOR needs two authenticated sessions; for the mock server:
BBV_IDOR_SESSION_A='{"Cookie":"session=alice"}' \
BBV_IDOR_SESSION_B='{"Cookie":"session=bob"}' \
  python -m bbv ingest samples/finding_idor.json --scope samples/scope.example.json

# Browse, decide, and report.
python -m bbv list
python -m bbv show 1
python -m bbv review 1 --approve --reason "verified"
python -m bbv report 1 --platform intigriti
```

## Commands

| Command | What it does |
|---------|--------------|
| `recon <program> [--scope <file>]` | Passive asset discovery into the `assets` table. |
| `generate-candidates <program> [--scope <file>]` | Reason over JS, write candidate finding JSON. Never ingests. |
| `run <program> [--scope <file>]` | Chain recon + generate-candidates, then stop. Never ingests. |
| `ingest <candidate.json> [--scope <file>]` | Create a finding and run its validator. |
| `ingest-batch <program> [--dir <d>] [--scope <file>]` | Ingest every candidate JSON in a directory, sequentially. |
| `queue [--dir <d>]` | Read-only: what is waiting on you, across programs. |
| `list [--state X]` / `show <id>` | Browse findings and their full trail. |
| `review <id> --approve\|--dismiss` | Record your decision on an `in_review` finding. |
| `report <id> --platform <p> [--dry-run]` | Generate a report file for an `approved` finding. |
| `signatures list\|show\|backfill` | Browse the advisory false-positive catalog. |
| `setup [--check]` | Show config status and fix gaps interactively. |
| `mockserver [--port]` | Run the local vulnerable server for testing. |

When `--scope` is omitted, commands default to `scopes/<program>.json` and
**always print which scope file was used**. If neither an explicit `--scope` nor
the default file exists, the command refuses rather than guessing.

## Convenience commands

These reduce typing. They do not reduce review. No step past
generate-candidates ever runs without a separate, explicit, human-invoked
command, and no evidence is hidden or summarized away: if anything, batch mode
shows *more* per invocation, never less.

- **`bbv run <program>`** chains recon then generate-candidates and **stops**. It
  prints the recon summary (in-scope and out-of-scope asset counts), the
  candidate files written, and flags prominently any candidate that carries a
  `known_pattern_note` so you see repeat patterns before opening files. It does
  not ingest, validate, review, or report, and it ends by telling you the next
  manual step. `run` accepts the same `--js-file` / `--base-url` /
  `--stub-response` options as generate-candidates.
- **`bbv run <program> --auto-chain`** is an opt-in extension that also ingests
  each generated candidate (running the real validator, full per-finding
  evidence printed) before stopping. **It chains recon, candidate generation,
  and ingestion. It never approves or submits findings; `bbv review` and
  `bbv report` remain separate manual steps.** Because it fires live validation
  requests, it asks for confirmation first unless you pass `--yes` (required for
  non-interactive use). `--max-candidates N` caps how many candidates it ingests
  in one run; set it for unattended or scheduled use. Auto-chained ingestion uses
  the exact same validator path as a manual `ingest`, so the evidence it records
  is identical to ingesting the same candidate by hand. The default `run` (no
  flag) is unchanged.
- **`bbv ingest-batch <program> [--dir candidates/]`** ingests every candidate
  JSON in a directory, one at a time (sequential, so rate limiting and scope
  enforcement behave exactly as single ingests). For each file it prints the
  **same full evidence and transition trail** as a single `ingest`, then a
  summary table at the end (id, vuln_class, state, confidence, target). The
  table is in addition to the full output, never a replacement for it.
- **`bbv queue [--dir candidates/]`** is read-only and changes nothing. It shows,
  across all programs: findings in `in_review` awaiting your decision, candidate
  files not yet ingested (an exact `program + vuln_class + target_url` diff
  against the findings table), and approved findings with no report file yet.
  Run it when you sit down and want to know what needs you right now.

## Lifecycle

```
new → validating → (validated → in_review) | rejected
in_review → approved | dismissed      # your decision, via `review`
approved → (report)                   # generates a file, never submits
```

Confidence seeds at 0.30. A validator returns a confidence delta plus evidence.
At `>= 0.80` the finding becomes `validated` and auto-advances to `in_review`.
Anything lower is `rejected` (insufficient evidence counts as a rejection, not a
resting state). Every transition is stored with before/after confidence and a
reason. Each state change is one atomic SQLite transaction, so a crashed run
loses nothing already written.

## Validators

All deterministic. None of them "ask an LLM if it looks exploitable."

- **reflected_xss.** Reflects a unique canary, uses an HTML parser to decide
  whether it lands in an executable context (script, attribute, event handler)
  rather than encoded text, then confirms real execution in headless Chromium
  with a benign `window.__<marker>` payload. It reaches high confidence only on
  confirmed execution. If Chromium is unavailable it stays below threshold and
  says why.
- **idor.** Replays account A's request for account B's object using A's session
  (GET/HEAD only). It confirms only when all of these hold: A receives B's data,
  that data matches what B sees, the endpoint is object-specific, and the object
  is not publicly accessible. A bare `200 OK` is not evidence.
- **sqli_boolean.** Sends TRUE and FALSE boolean payloads. It requires a stable
  baseline first, then confirms the TRUE response matches the baseline and the
  FALSE response differs, holding across repeats to rule out jitter. Tautologies
  only; stacked, UNION, time-based, and DML payloads are refused.

## Recon and candidate generation

```bash
# 1. Passive recon. Wrapped tools only ever receive in-scope hosts; every
#    discovered asset is scope-checked before it is stored.
python -m bbv recon demo --scope samples/scope.example.json

# 2. Candidate generation. Needs BBV_ANTHROPIC_API_KEY, or replay a saved
#    Claude response offline against a sample JS file:
python -m bbv generate-candidates demo --scope samples/scope.example.json \
  --js-file samples/sample_app.js --base-url http://127.0.0.1:8000/ \
  --stub-response samples/claude_response.example.json

# 3. Review the files in candidates/ yourself, then ingest the ones you choose.
python -m bbv ingest candidates/demo_001_reflected_xss.json --scope samples/scope.example.json
```

Candidate output is unvalidated and not trustworthy on its own. Candidate
generation only turns an asset into well-formed finding JSON. It never calls a
validator or sets state beyond `new`, and AI-sourced candidates get no
confidence bonus: they seed at 0.30 like any other and are tagged
`ai-sourced:claude` in `notes` purely as a signal. Deciding whether a candidate
is real is exactly the job of the validation gate, which is why generation never
auto-ingests. Review every candidate before `ingest`.

## False-positive signatures (advisory triage)

When a finding is rejected, bbv derives a deterministic fingerprint of *why*,
from the same structured evidence the validator already wrote, and tracks how
often that exact fingerprint recurs. The goal is faster triage over time, not
noise prevention: nothing fuzzy reaches you in this architecture, because every
rejection already carries a concrete deterministic reason.

```bash
python -m bbv signatures list [--program demo] [--vuln-class sqli_boolean]
python -m bbv signatures show <id>     # feature_key, example evidence, breakdown
python -m bbv signatures backfill      # derive signatures from past rejections
```

This layer is **advisory only**. It never auto-rejects a candidate without
running the real validator, never skips or lowers the rigor of a validation
step, never changes a confidence threshold or the 0.80 boundary, and never lets
a finding bypass human review. All it does is annotate ("this matches a pattern
seen N times, last reason X") for your convenience. The full validator always
still runs. It is safe to have precisely because the validators are already
deterministic, so there is no fuzzy noise to filter; the only job here is making
repetition visible.

How it works:

- **Fingerprints** are per vuln_class, built from existing evidence fields:
  `xss|reflected|context=text|raw=false`, `idor|not_object_specific`,
  `sqli|baseline_unstable`, and so on. Same cause, same string, always. No LLM,
  no embeddings.
- **Scope.** General web-behavior patterns are `global` (for example, XSS
  landing in a text node). Patterns about a specific endpoint are `program`
  scoped (for example, "this program's `/support` ignores the SQLi payload").
  Per-program recurrence is tracked for every signature, so "this exact thing,
  on this program, 4 times" is always answerable.
- **Atomic.** The signature upsert happens in the same transaction as the
  rejection write. If it fails, the rejection rolls back too, so there is no
  silent desync.
- **Backfill vs. going forward.** New rejections are caught automatically by the
  rejection-path hook. `signatures backfill` additionally derives signatures
  from rejections recorded before this layer existed, reading only stored
  evidence.
- **Advisory pre-check** on `generate-candidates`. If a candidate targets an
  endpoint this program has rejected before (a program-scoped signature), a
  `known_pattern_note` is added to its JSON. This is the only honest
  pre-validation match. Global and response-derived patterns (such as XSS
  context) are unknown until the real probe runs, so they are deliberately not
  guessed at. The note never changes core fields, removes a candidate, or
  filters the output.

## Reports

Once you have approved a finding, turn it into a submittable write-up:

```bash
python -m bbv report <finding_id> --platform intigriti            # writes a file
python -m bbv report <finding_id> --platform intigriti --dry-run  # prints instead
```

Reports are written to `reports/<program>/<finding_id>_<vuln_class>.md`. The
command refuses any finding not in `approved` (a clear error, not a crash) and
lists the available platforms if you pass an unknown one.

**This tool never submits anything.** There is no bug-bounty-platform API code in
this repo. Generating a report produces a Markdown file; pasting or uploading it
to the platform is a manual action you perform yourself.

How reports stay honest:

- **Every factual claim is deterministic.** Titles, steps to reproduce, impact,
  CVSS, and CWE are assembled in `reporting/base.py` from the actual finding,
  evidence, and transition rows: the real canary markers, payloads, URLs, HTTP
  statuses, and similarity numbers. Steps come from the evidence trail, not a
  generic template.
- **No LLM in the report path.** The milestone's one permitted LLM use, polishing
  prose around already-assembled facts, is deliberately deferred. Routing any
  factual claim through a model risks drift, so for now nothing in a report comes
  from an LLM. This keeps every claim diffable against the evidence.
- **No evidence is dropped.** Every evidence row is reproduced verbatim in the
  report's Evidence Appendix, alongside the full validation trail.
- **Severity is derived, never guessed** (`severity.py`). A deterministic
  CVSS 3.1 and CWE mapping reads each metric off the evidence and prints its
  reasoning into the report so it is auditable. It scores conservatively: an
  IDOR's Confidentiality is set to Low rather than High because the evidence does
  not quantify the exposed data's sensitivity, and the report says so and invites
  manual adjustment. CWE mapping: XSS to CWE-79, IDOR to CWE-639, SQLi to CWE-89.
- **Formatter registry.** `reporting/` mirrors the validator registry. Intigriti
  ships today; HackerOne and Bugcrowd formatters can be added by registering
  another `Reporter`, reusing the deterministic fact-assembly unchanged.

## Safety

- **Scope.** Every outbound request, including redirects and every Playwright
  browser request, routes through one scope gate that refuses and logs anything
  out of scope. Out-of-scope beats in-scope; userinfo tricks and non-http(s)
  schemes are rejected. There is no bypass flag.
- **Rate limiting.** Conservative token buckets (global plus per-host),
  configurable per program, with 429 and `Retry-After` backoff.
- **No destructive payloads.** Validators prove exploitability with minimal
  benign evidence (canaries, diffs, differentials), never data exfiltration or
  state changes.
- **No submission, no auto-ingest.** The pipeline stops at `in_review`, and
  candidate generation never ingests what it produces.

### Recon traffic and the Claude API

The wrapped recon tools (subfinder, httpx, katana) run their own HTTP stacks, so
they cannot literally go through `ScopedHttpClient`. The scope guarantee is kept
two ways instead: they are only ever handed pre-scope-checked in-scope targets,
and all of their output is scope-checked before it is persisted (out-of-scope
assets are recorded and flagged, never silently probed or dropped). Each tool is
also passed its native rate-limit flag from config. The one target fetch bbv
does itself, pulling JS for candidate generation, does go through
`ScopedHttpClient`.

The LLM provider API (Anthropic, OpenAI, or a self-hosted OpenAI-compatible
endpoint) is reasoning infrastructure, not a program target, so it is
deliberately not routed through `ScopedHttpClient` (doing so would pollute
program scope with the provider's host). API keys come from config and are never
logged.

## Layout

```
src/bbv/
  scope.py http_client.py rate_limiter.py   # safety layer (single choke point)
  state_machine.py repository.py db.py models.py
  validators/                               # one module per vuln_class, registered
  recon.py                                  # subprocess wrappers for subfinder/httpx/katana
  claude_client.py candidate_schema.py candidates.py   # LLM providers + JS reasoning to candidate JSON
  signatures.py                             # deterministic FP fingerprints (advisory)
  severity.py                               # deterministic CVSS 3.1 / CWE mapping
  reporting/                                # formatter registry; Intigriti markdown
  setup.py                                  # config status + interactive setup
  pipeline.py cli.py mockserver.py
tests/      # scope, rate limiter, state machine, repo, validators, pipeline,
            # recon, candidates, signatures, severity, reporting, regression fixtures
samples/    # scope, one finding per validator, sample JS + replay Claude response
```

## Config

Configuration comes from `.env` (see `.env.example`) with the prefix `BBV_`:
`DB_PATH`, rate limits, HTTP timeout and user agent, IDOR session headers, recon
tool paths and flags, `CANDIDATES_DIR`, `REPORTS_DIR`, and the LLM provider
settings (`LLM_PROVIDER`, `ANTHROPIC_API_KEY`/`ANTHROPIC_MODEL`,
`OPENAI_API_KEY`/`OPENAI_MODEL`/`OPENAI_BASE_URL`). Secrets live only in `.env`,
which is gitignored. The easiest way to set these is `bbv setup`.

## Tests

```bash
pytest
```

The XSS browser routing and execution tests skip cleanly if Chromium is not
installed. No test touches a live target or the live Claude API: recon tests use
fake subprocess output, candidate tests replay a saved Claude response, and
everything else runs against the local mock server on loopback through a real
scope file that lists `127.0.0.1`.

## Not yet built (extension points)

Additional platform formatters (HackerOne and Bugcrowd, by registering a
`Reporter`) and optional LLM prose-polishing of reports (deferred, see above).
Platform submission is intentionally out of scope and remains a manual human
action. The validator registry, the `assets` table, the candidate schema, the
signature catalog, and the formatter registry are where future work plugs in.
