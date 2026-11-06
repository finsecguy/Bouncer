"""`bouncer setup`: surface what is configured, what is missing, and let the user
fix gaps interactively. Pure UX/config tooling.

It never changes validation, scope, or signature logic; never makes a safety
check optional; never guesses or generates secrets. Secrets are written ONLY to
.env (mode 0600), never committed, never logged, and never printed back in full
(status masks to the last 4 characters).
"""
from __future__ import annotations

import getpass
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import Settings, load_settings

ENV_PATH = ".env"


def _samples_dir() -> Path:
    """Locate the repo's samples/ (absolute, cwd-independent)."""
    cand = Path(__file__).resolve().parents[2] / "samples"
    return cand if cand.exists() else Path("samples")


def mask(value: str) -> str:
    """Render a secret's presence without revealing it."""
    if not value:
        return "not set"
    v = str(value)
    return f"set (****{v[-4:]})" if len(v) >= 4 else "set"


@dataclass
class StatusItem:
    label: str
    value: str
    ok: bool
    note: str = ""


def _chromium_status() -> tuple[bool, str]:
    """Best-effort check for the Playwright Chromium binary (no browser launch)."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False, "playwright not importable"
    try:
        with sync_playwright() as p:
            path = p.chromium.executable_path
        if path and os.path.exists(path):
            return True, "installed"
        return False, "not installed (run: python -m playwright install chromium)"
    except Exception:
        return False, "not installed (run: python -m playwright install chromium)"


def _llm_provider_status(settings: Settings) -> StatusItem:
    """Which provider is configured, and whether its required secret/base_url is
    set. The required field differs per provider."""
    p = (settings.llm_provider or "anthropic").strip().lower()
    if p == "anthropic":
        ok = bool(settings.anthropic_api_key)
        detail = f"anthropic (BOUNCER_ANTHROPIC_API_KEY {'set' if ok else 'not set'})"
    elif p == "openai":
        ok = bool(settings.openai_api_key)
        detail = f"openai (BOUNCER_OPENAI_API_KEY {'set' if ok else 'not set'})"
    elif p == "self_hosted":
        ok = bool(settings.openai_base_url)
        detail = (f"self_hosted (BOUNCER_OPENAI_BASE_URL "
                  f"{'set' if ok else 'not set'}; key optional)")
    else:
        ok = False
        detail = f"{p!r} (unknown; expected anthropic|openai|self_hosted)"
    return StatusItem("LLM provider", detail, ok,
                      "used by generate-candidates / run stage 2")


def gather_status(settings: Settings, env_path: str = ENV_PATH) -> list[StatusItem]:
    """Read-only snapshot of configuration. No side effects."""
    items: list[StatusItem] = []

    env_exists = Path(env_path).exists()
    items.append(StatusItem(".env file", "present" if env_exists else "missing",
                            env_exists, "secrets live here; it is gitignored"))

    items.append(_llm_provider_status(settings))
    items.append(StatusItem("  Anthropic API key", mask(settings.anthropic_api_key),
                            bool(settings.anthropic_api_key), ""))
    items.append(StatusItem("  OpenAI API key", mask(settings.openai_api_key),
                            bool(settings.openai_api_key), ""))
    items.append(StatusItem("  OpenAI base URL",
                            settings.openai_base_url or "(default: OpenAI endpoint)",
                            True, "set for self_hosted, e.g. http://localhost:11434/v1"))

    items.append(StatusItem("IDOR session A",
                            "set" if settings.idor_session_a else "not set",
                            bool(settings.idor_session_a), "needed for idor validation"))
    items.append(StatusItem("IDOR session B",
                            "set" if settings.idor_session_b else "not set",
                            bool(settings.idor_session_b), "needed for idor validation"))

    db = Path(settings.db_path)
    items.append(StatusItem("Database",
                            f"{settings.db_path} ({'exists' if db.exists() else 'will be created'})",
                            True))

    sf = shutil.which(settings.subfinder_bin)
    items.append(StatusItem("Recon: subfinder", "found" if sf else "not found",
                            bool(sf), "optional (subdomain enum)"))

    hx = shutil.which(settings.httpx_bin)
    from .recon import _is_projectdiscovery_httpx
    hx_ok = bool(hx) and _is_projectdiscovery_httpx(hx, 10)
    hx_note = "optional (liveness/fingerprint)"
    if hx and not hx_ok:
        hx_note = "PATH 'httpx' is NOT ProjectDiscovery httpx (likely the Python httpx CLI)"
    items.append(StatusItem("Recon: httpx (PD)", "found" if hx_ok else "not found",
                            hx_ok, hx_note))

    kt = shutil.which(settings.katana_bin)
    items.append(StatusItem("Recon: katana", "found" if kt else "not found",
                            bool(kt), "optional (crawl)"))

    ok, detail = _chromium_status()
    items.append(StatusItem("Playwright chromium", detail, ok,
                            "needed for confirmed XSS execution"))

    scopes_dir = Path("scopes")
    scopes = sorted(p.name for p in scopes_dir.glob("*.json")) if scopes_dir.exists() else []
    items.append(StatusItem("Scope files (scopes/)",
                            ", ".join(scopes) if scopes else "none",
                            bool(scopes), "used as the default --scope lookup"))
    return items


def render_status(items: list[StatusItem]) -> str:
    width = max(len(i.label) for i in items)
    lines = ["=== Configuration status ==="]
    for i in items:
        mark = "ok " if i.ok else " ! "
        note = f"   [{i.note}]" if i.note else ""
        lines.append(f" [{mark}] {i.label.ljust(width)} : {i.value}{note}")
    return "\n".join(lines)


def set_env_var(key: str, value: str, env_path: str = ENV_PATH) -> None:
    """Add or update KEY=value in .env, preserving every other line and comment.
    Writes with mode 0600. Never logs the value."""
    path = Path(env_path)
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    out: list[str] = []
    found = False
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith(f"{key}=") and not stripped.startswith("#"):
            out.append(f"{key}={value}")
            found = True
        else:
            out.append(line)
    if not found:
        out.append(f"{key}={value}")
    content = "\n".join(out) + "\n"
    # Atomic write with 0600 from creation: create a temp file in the same dir
    # with mode 0600, write, then os.replace over .env. This avoids a brief
    # world-readable window and avoids truncating .env on a mid-write crash.
    parent = path.parent if str(path.parent) else Path(".")
    fd, tmp = tempfile.mkstemp(dir=str(parent), prefix=".env.", suffix=".tmp")
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


_SCOPE_TEMPLATE = {
    "in_domains": [],
    "in_cidrs": [],
    "out_domains": [],
    "out_cidrs": [],
    "wildcard_matches_apex": False,
    "allowed_schemes": ["http", "https"],
}


def write_scope_template(program: str, scopes_dir: str = "scopes") -> Path | None:
    """Create scopes/<program>.json from a template. Returns the path, or None if
    it already exists (never overwrites a scope the user has edited)."""
    d = Path(scopes_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{program}.json"
    if path.exists():
        return None
    path.write_text(json.dumps(_SCOPE_TEMPLATE, indent=2) + "\n", encoding="utf-8")
    return path


def _choose_provider(env_path, inp, secret, out) -> None:
    """Pick the LLM provider and prompt for the secrets/base_url it needs. Keys
    are entered hidden (getpass) and written only to .env; the base URL is not a
    secret, so it is entered in the clear."""
    out("Providers: 1) anthropic   2) openai   3) self_hosted (OpenAI-compatible)")
    sel = inp("Provider [1/2/3]: ").strip()
    provider = {"1": "anthropic", "2": "openai", "3": "self_hosted"}.get(sel)
    if provider is None:
        out("Unrecognized provider; unchanged.")
        return

    set_env_var("BOUNCER_LLM_PROVIDER", provider, env_path)
    out(f"Set BOUNCER_LLM_PROVIDER={provider}.")

    if provider == "anthropic":
        val = secret("Anthropic API key (input hidden, blank to keep current): ").strip()
        if val:
            set_env_var("BOUNCER_ANTHROPIC_API_KEY", val, env_path)
            out("Saved Anthropic API key to .env (not shown).")
    elif provider == "openai":
        # Clear any base_url left over from a previous self_hosted config so the
        # real OpenAI key can never be sent to some other host; provider=openai
        # always uses the official endpoint.
        set_env_var("BOUNCER_OPENAI_BASE_URL", "", env_path)
        val = secret("OpenAI API key (input hidden, blank to keep current): ").strip()
        if val:
            set_env_var("BOUNCER_OPENAI_API_KEY", val, env_path)
            out("Saved OpenAI API key to .env (not shown).")
    else:  # self_hosted
        base = inp("OpenAI-compatible base URL (e.g. http://localhost:11434/v1): ").strip()
        if base:
            set_env_var("BOUNCER_OPENAI_BASE_URL", base, env_path)
            out(f"Set BOUNCER_OPENAI_BASE_URL={base}.")
        model = inp("Model name your endpoint serves (e.g. llama3; blank to keep "
                    "current): ").strip()
        if model:
            set_env_var("BOUNCER_OPENAI_MODEL", model, env_path)
            out(f"Set BOUNCER_OPENAI_MODEL={model}.")
        # The key field is shared with provider=openai. Blank CLEARS it, so a
        # real OpenAI key is never silently sent to a self-hosted/remote host.
        val = secret("API key if the server requires one (input hidden, blank to "
                     "CLEAR any stored key): ").strip()
        set_env_var("BOUNCER_OPENAI_API_KEY", val, env_path)
        out("Saved API key to .env (not shown)." if val
            else "Cleared stored OpenAI API key for self_hosted.")


def _set_idor_session(which: str, raw: str, env_path: str) -> str:
    """Validate and store an IDOR session header dict. Returns a status message
    (never echoes the value)."""
    raw = raw.strip()
    if not raw:
        return "No value entered; unchanged."
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return "Not valid JSON; unchanged. Expected e.g. {\"Cookie\": \"session=...\"}"
    if not isinstance(parsed, dict):
        return "Must be a JSON object of headers; unchanged."
    # Must match the Settings contract (dict[str, str]) exactly, or a later
    # load_settings() would raise and brick every command, including setup
    # itself. Reject non-string keys/values here instead of writing them.
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in parsed.items()):
        return ("Every header name and value must be a string, e.g. "
                '{"Cookie": "session=..."}; unchanged.')
    set_env_var(f"BOUNCER_IDOR_SESSION_{which}", json.dumps(parsed), env_path)
    return f"Saved IDOR session {which} to .env (not shown)."


def _ingest_sample(repo, scope, settings, data):
    """Create + validate one sample finding in the given (temp) repo."""
    from . import models as m
    from .pipeline import validate_finding

    finding = m.Finding(
        program=data["program"], target_url=data["target_url"],
        vuln_class=data["vuln_class"], request=data.get("request", {}),
        notes=data.get("notes"))
    fid = repo.create_finding(finding)
    return validate_finding(repo, repo.get_finding(fid), scope, settings)


def run_self_test(loader: Callable[[], Settings] = load_settings,
                  out: Callable[[str], None] = print) -> bool:
    """Smoke-test the pipeline end to end against an in-process mock server,
    using a TEMPORARY database. data/bouncer.db (or whatever db_path points at) is
    never opened or written. Returns True if no check FAILED.

    Checks: reflected_xss should reach in_review (DEGRADED if Chromium is
    missing); idor reports 'needs BOUNCER_IDOR_SESSION_A/B' when those are unset
    instead of failing silently; sqli_boolean reports what the mock produces.
    """
    from . import models as m
    from .db import connect, init_db
    from .mockserver import start_background
    from .repository import Repository
    from .scope import Scope

    settings = loader()
    samples = _samples_dir()
    failures = 0

    out("=== bouncer self-test ===")
    out("Using a temporary database; the real database is not touched.")

    with tempfile.TemporaryDirectory() as td:
        # Hard isolation: point db_path at a throwaway file, never the real db.
        settings.db_path = str(Path(td) / "selftest.db")
        server, port = start_background("127.0.0.1", 0)
        base = f"127.0.0.1:{port}"
        out(f"Mock server: http://{base}")
        try:
            conn = connect(settings.db_path)
            init_db(conn)
            repo = Repository(conn)
            scope = Scope.load(str(samples / "scope.example.json"))

            def load_sample(name: str) -> dict:
                text = (samples / name).read_text(encoding="utf-8")
                return json.loads(text.replace("127.0.0.1:8000", base))

            def last_reason(fid: int) -> str:
                ts = repo.list_transitions(fid)
                return ts[-1].reason if ts else ""

            # --- reflected_xss: should reach in_review ---
            f = _ingest_sample(repo, scope, settings, load_sample("finding_xss.json"))
            if f.state == m.IN_REVIEW:
                out(f"  [PASS] reflected_xss  -> {f.state}")
            else:
                chromium_ok, _ = _chromium_status()
                if not chromium_ok:
                    out(f"  [DEGRADED] reflected_xss -> {f.state} "
                        "(confirmed XSS needs Chromium: python -m playwright install chromium)")
                else:
                    failures += 1
                    out(f"  [FAIL] reflected_xss -> {f.state}: {last_reason(f.id)}")

            # --- idor: needs two sessions; report explicitly if unset ---
            has_sessions = bool(settings.idor_session_a and settings.idor_session_b)
            f = _ingest_sample(repo, scope, settings, load_sample("finding_idor.json"))
            if not has_sessions:
                out("  [NEEDS CONFIG] idor -> BOUNCER_IDOR_SESSION_A/B not set; "
                    "idor validation cannot run (this is expected, not a failure)")
            elif f.state == m.IN_REVIEW:
                out(f"  [PASS] idor  -> {f.state}")
            else:
                failures += 1
                out(f"  [FAIL] idor -> {f.state}: {last_reason(f.id)}")

            # --- sqli_boolean: report what the mock produces ---
            f = _ingest_sample(repo, scope, settings, load_sample("finding_sqli.json"))
            if f.state == m.IN_REVIEW:
                out(f"  [PASS] sqli_boolean  -> {f.state}")
            else:
                failures += 1
                out(f"  [FAIL] sqli_boolean -> {f.state}: {last_reason(f.id)}")
        finally:
            server.shutdown()
            server.server_close()

    out(f"Result: {'OK' if failures == 0 else f'{failures} check(s) FAILED'} "
        "(the real database was not modified).")
    return failures == 0


def run_setup(
    env_path: str = ENV_PATH,
    loader: Callable[[], Settings] = load_settings,
    inp: Callable[[str], str] = input,
    secret: Callable[[str], str] = getpass.getpass,
    out: Callable[[str], None] = print,
) -> None:
    """Interactive menu loop. I/O is injected so it is testable."""
    while True:
        settings = loader()
        out("")
        out(render_status(gather_status(settings, env_path)))
        out("")
        out("=== Actions ===")
        out(" 1) Choose LLM provider (anthropic / openai / self_hosted)")
        out(" 2) Set IDOR session A")
        out(" 3) Set IDOR session B")
        out(" 4) Create a scope file for a program")
        out(" 5) Run self-test (pipeline smoke test; uses a temp DB)")
        out(" 6) Re-scan status")
        out(" 0) Quit")
        choice = inp("Choose: ").strip()

        if choice == "1":
            _choose_provider(env_path, inp, secret, out)
        elif choice == "2":
            out(_set_idor_session("A", secret('IDOR session A as JSON headers '
                                               '(e.g. {"Cookie": "session=..."}): '), env_path))
        elif choice == "3":
            out(_set_idor_session("B", secret('IDOR session B as JSON headers '
                                              '(e.g. {"Cookie": "session=..."}): '), env_path))
        elif choice == "4":
            program = inp("Program name: ").strip()
            if not program:
                out("No program name; unchanged.")
            else:
                path = write_scope_template(program)
                if path is None:
                    out(f"scopes/{program}.json already exists; left untouched.")
                else:
                    out(f"Wrote {path} (a template; edit it to add in-scope "
                        "domains/CIDRs before using it).")
        elif choice == "5":
            run_self_test(loader=loader, out=out)
        elif choice == "6":
            continue
        elif choice == "0":
            out("Done. No runtime behavior was changed.")
            return
        else:
            out("Unrecognized choice.")
