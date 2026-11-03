# bbv — bug bounty validation engine

Evidence-gated validation for **authorized** bug bounty findings. A candidate
finding is *guilty until proven exploitable*: it only reaches you after a
deterministic validator produces real request/response evidence. The pipeline
hard-stops at `in_review` — there is no auto-submission anywhere in this repo.

This is milestone 1: the validation gate. No recon, no candidate generation, no
platform submission, no reporting (clean extension points are left for them).

## Install

Requires Python 3.11+ (developed on 3.14).

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m playwright install chromium   # for the XSS execution check
cp .env.example .env                     # then edit; .env is gitignored
```

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
- **No submission**: the pipeline stops at `in_review`.

## Layout

```
src/bbv/
  scope.py http_client.py rate_limiter.py   # safety layer (single choke point)
  state_machine.py repository.py db.py models.py
  validators/                               # one module per vuln_class, registered
  pipeline.py cli.py mockserver.py
tests/      # scope, rate limiter, state machine, repo, each validator, pipeline
samples/    # scope + one candidate finding per validator
```

## Config

`.env` (see `.env.example`), prefix `BBV_`: `DB_PATH`, rate limits, HTTP
timeout/UA, and the IDOR session headers. Secrets live only in `.env`, which is
gitignored.

## Tests

```bash
pytest
```

The XSS browser-routing/execution tests skip cleanly if Chromium isn't
installed. No test touches a live target — everything runs against the local
mock server on loopback, through a real scope file that lists `127.0.0.1`.

## Not yet built (extension points)

Recon, candidate generation, the Claude reasoning seam (deliberately uncalled),
platform submission, and reporting. The validator registry and the
`validating → …` states are where those plug in.
