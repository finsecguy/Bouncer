# bbv — bug bounty validation engine

Evidence-gated validation for **authorized** bug bounty findings. A candidate
finding is *guilty until proven exploitable*: it only reaches you after a
deterministic validator produces real request/response evidence. The pipeline
hard-stops at `in_review` — there is no auto-submission anywhere in this repo.

The gate (milestone 1) is fed by a front end (milestone 2): passive recon to
discover assets, then candidate generation that reasons over discovered JS with
Claude and emits candidate finding JSON. No platform submission, no reporting
(clean extension points are left for them).

## Install

Requires Python 3.11+ (developed on 3.14).

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m playwright install chromium   # for the XSS execution check
cp .env.example .env                     # then edit; .env is gitignored
```

Recon wraps external ProjectDiscovery tools if present on `PATH`
(`subfinder`, `httpx`, `katana`); it degrades gracefully and never crashes when
they are absent. Candidate generation needs `BBV_ANTHROPIC_API_KEY` set, or you
can replay a saved response offline with `--stub-response`.

## Try it

Start the local, deliberately-vulnerable mock server (nothing touches a real
target), then ingest the sample findings in another shell:

```bash
python -m bbv mockserver --port 8000
```

```bash
python -m bbv ingest samples/finding_xss.json  --scope samples/scope.example.json
python -m bbv ingest samples/finding_sqli.json --scope samples/scope.example.json
# IDOR needs two sessions; for the mock server:
BBV_IDOR_SESSION_A='{"Cookie":"session=alice"}' \
BBV_IDOR_SESSION_B='{"Cookie":"session=bob"}' \
  python -m bbv ingest samples/finding_idor.json --scope samples/scope.example.json

python -m bbv list
python -m bbv show 1
python -m bbv review 1 --approve --reason "verified"
python -m bbv review 2 --dismiss
```

## Recon → candidates → (manual) ingest

```bash
# 1. Passive recon: discover assets into the `assets` table. Wrapped external
#    tools (subfinder/httpx/katana) only ever receive in-scope hosts; every
#    discovered asset is scope-checked before being stored.
python -m bbv recon demo --scope samples/scope.example.json

# 2. Candidate generation: reason over discovered JS with Claude and write
#    candidate finding JSON to candidates/. Needs BBV_ANTHROPIC_API_KEY — or
#    replay a saved Claude response offline against a sample JS file:
python -m bbv generate-candidates demo --scope samples/scope.example.json \
  --js-file samples/sample_app.js --base-url http://127.0.0.1:8000/ \
  --stub-response samples/claude_response.example.json

# 3. Review the files in candidates/ YOURSELF, then ingest the ones you choose.
#    This step is deliberately manual.
python -m bbv ingest candidates/demo_001_reflected_xss.json --scope samples/scope.example.json
```

> **Candidate output is unvalidated and not trustworthy on its own.** Candidate
> generation does nothing but turn an asset into well-formed finding JSON; it
> never calls a validator or sets state beyond `new`, and AI-sourced candidates
> get **no** confidence bonus (they seed at 0.30 like any other and are tagged
> `ai-sourced:claude` in `notes` purely as signal). Deciding a candidate is real
> is exactly the job of the milestone-1 gate — which is why generation never
> auto-ingests. Review every candidate before `ingest`.

## Lifecycle

```
new → validating → (validated → in_review) | rejected
in_review → approved | dismissed      # your decision, via `review`
```

Confidence seeds at 0.30. A validator returns a confidence delta plus evidence;
at `>= 0.80` the finding is `validated` and auto-advances to `in_review`.
Anything lower is `rejected` (insufficient evidence is a rejection, not a
resting state). Every transition is stored with before/after confidence and a
reason; each state change is one atomic SQLite transaction, so a crashed run
loses nothing already written.

## Validators (deterministic — no "ask an LLM if it looks exploitable")

- **reflected_xss** — reflects a unique canary, uses an HTML parser to decide
  whether it lands in an executable context (script/attribute/event handler)
  vs. encoded text, then confirms real execution in headless Chromium via a
  benign `window.__<marker>` payload. High confidence only on confirmed
  execution; if Chromium is unavailable it stays below threshold and says so.
- **idor** — replays account A's request for account B's object using A's
  session (GET/HEAD only). Confirmed only when A gets B's data **and** it
  matches what B sees **and** the endpoint is object-specific **and** the object
  is not publicly accessible. A bare `200 OK` is not evidence.
- **sqli_boolean** — sends TRUE/FALSE boolean payloads, requires a stable
  baseline first, then confirms TRUE matches baseline and FALSE differs across
  repeats (rules out jitter). Tautologies only; stacked/UNION/time-based/DML
  payloads are refused.

## Safety (baked into the architecture)

- **Scope**: every outbound request — including redirects and every Playwright
  browser request — routes through one scope gate that refuses and logs
  anything out of scope. Out-of-scope beats in-scope; userinfo tricks and
  non-http(s) schemes are rejected. No bypass flag exists.
- **Rate limiting**: conservative token buckets (global + per-host),
  configurable per program, with 429 / `Retry-After` backoff.
- **No destructive payloads**: validators prove exploitability with minimal
  benign evidence (canaries, diffs, differentials), never data exfiltration or
  state changes.
- **No submission / no auto-ingest**: the pipeline stops at `in_review`, and
  candidate generation never ingests what it produces.

### A note on recon traffic and the Claude API

The wrapped recon tools (subfinder/httpx/katana) run their own HTTP stacks, so
they can't literally go through `ScopedHttpClient`. The scope guarantee is kept
two ways: they are only ever handed **pre-scope-checked in-scope** targets, and
**all of their output is scope-checked before it is persisted** (out-of-scope
assets are recorded and flagged, never silently probed or dropped). Each tool is
also passed its native rate-limit flag from config. The one target-fetch bbv
does itself — pulling JS for candidate generation — **does** go through
`ScopedHttpClient`.

The Claude API call (`api.anthropic.com`) is reasoning infrastructure, **not a
program target**, so it is deliberately *not* routed through `ScopedHttpClient`
(doing so would mean polluting program scope with Anthropic's host). The API key
comes from config and is never logged.

## Layout

```
src/bbv/
  scope.py http_client.py rate_limiter.py   # safety layer (single choke point)
  state_machine.py repository.py db.py models.py
  validators/                               # one module per vuln_class, registered
  recon.py                                  # subprocess wrappers for subfinder/httpx/katana
  claude_client.py candidate_schema.py candidates.py   # JS reasoning -> candidate JSON
  pipeline.py cli.py mockserver.py
tests/      # scope, rate limiter, state machine, repo, validators, pipeline,
            # recon, candidates, and regression fixtures
samples/    # scope, one finding per validator, sample JS + replay Claude response
```

## Config

`.env` (see `.env.example`), prefix `BBV_`: `DB_PATH`, rate limits, HTTP
timeout/UA, IDOR session headers, recon tool paths/flags, `CANDIDATES_DIR`, and
`ANTHROPIC_API_KEY`/`ANTHROPIC_MODEL`. Secrets live only in `.env`, which is
gitignored.

## Tests

```bash
pytest
```

The XSS browser-routing/execution tests skip cleanly if Chromium isn't
installed. No test touches a live target or the live Claude API — recon tests
use fake subprocess output, candidate tests replay a saved Claude response, and
everything else runs against the local mock server on loopback through a real
scope file that lists `127.0.0.1`.

## Not yet built (extension points)

Platform submission and report generation. The validator registry, the `assets`
table, and the candidate schema are where those plug in.
