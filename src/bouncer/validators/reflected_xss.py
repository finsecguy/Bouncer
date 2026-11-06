"""Reflected XSS validator.

Two stages:
1. Static reflection analysis with a unique canary, using a real HTML parser
   (BeautifulSoup) to decide whether the canary lands in an *executable*
   context (script body, attribute that can be broken out of, event handler)
   rather than HTML-encoded text.
2. Execution confirmation with Playwright: inject a benign payload that sets
   ``window.__bouncer_<marker>`` and check it actually ran. High confidence is
   granted ONLY on confirmed execution. If Chromium is unavailable, the
   validator stays below the validated threshold and says why.

Benign only: the proof sets a window marker. No alert(), no cookie/exfil.
"""
from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from ..models import Evidence, Finding, ValidationResult
from .base import Validator, ValidatorContext


def _inject_query(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit(parts._replace(query=urlencode(q)))


class ReflectedXssValidator(Validator):
    vuln_class = "reflected_xss"

    def validate(self, finding: Finding, ctx: ValidatorContext) -> ValidationResult:
        req = finding.request
        param = req.get("inject_param")
        if not param:
            return ValidationResult(
                -0.1, ValidationResult.INCONCLUSIVE,
                "no inject_param specified in finding.request",
            )

        marker = "bouncer" + uuid.uuid4().hex[:12]
        # Canary carries marker + the chars needed to break out of HTML/attrs.
        canary = f"{marker}'\"<>"
        url = _inject_query(finding.target_url, param, canary)

        resp = ctx.http.get(url)
        body = resp.text
        evidence: list[Evidence] = [
            Evidence(finding.id or 0, "canary_reflection", {
                "url": url, "status": resp.status_code,
                "marker": marker, "reflected": marker in body,
            })
        ]

        if marker not in body:
            return ValidationResult(
                -0.2, ValidationResult.REFUTED,
                "canary not reflected in response", evidence,
            )

        context = self._classify_context(body, marker)
        raw_breakout = self._raw_special_chars_present(body, marker)
        evidence.append(Evidence(finding.id or 0, "canary_reflection", {
            "context": context, "raw_special_chars": raw_breakout,
        }))

        executable_context = context in {"script", "event_handler", "attribute"} and raw_breakout
        if not executable_context:
            return ValidationResult(
                -0.1, ValidationResult.REFUTED,
                f"reflected but not in executable context (context={context}, "
                f"raw_special_chars={raw_breakout}); likely encoded or inert",
                evidence,
            )

        # Stage 2: confirm execution with Playwright.
        exec_result = self._confirm_execution(finding, ctx, param, marker)
        evidence.append(Evidence(finding.id or 0, "browser_exec", exec_result))

        if exec_result["status"] == "confirmed":
            return ValidationResult(
                0.6, ValidationResult.CONFIRMED,
                "canary executed in browser (window marker set)", evidence,
            )
        if exec_result["status"] == "unavailable":
            return ValidationResult(
                0.3, ValidationResult.INCONCLUSIVE,
                f"executable-context reflection, but execution unconfirmed: "
                f"{exec_result['detail']}", evidence,
            )
        return ValidationResult(
            -0.1, ValidationResult.REFUTED,
            "executable-context reflection but browser did not execute marker",
            evidence,
        )

    # --- static analysis ---
    @staticmethod
    def _classify_context(body: str, marker: str) -> str:
        soup = BeautifulSoup(body, "html.parser")

        for script in soup.find_all("script"):
            if script.string and marker in script.string:
                return "script"

        for tag in soup.find_all(True):
            for attr, val in tag.attrs.items():
                val_str = " ".join(val) if isinstance(val, list) else str(val)
                if marker in val_str:
                    if attr.lower().startswith("on"):
                        return "event_handler"
                    return "attribute"

        # Found in a text node only.
        for text in soup.find_all(string=True):
            if marker in text:
                return "text"
        return "unknown"

    @staticmethod
    def _raw_special_chars_present(body: str, marker: str) -> bool:
        """Did the breakout chars survive UN-encoded adjacent to the marker?
        If the server HTML-encoded them (&lt; &gt; &quot;) the raw chars won't
        be in the raw body next to the marker."""
        idx = body.find(marker)
        if idx < 0:
            return False
        window = body[idx: idx + len(marker) + 4]
        return ("<" in window) or (">" in window) or ('"' in window) or ("'" in window)

    # --- execution confirmation ---
    @staticmethod
    def _exec_payloads(marker: str) -> list[str]:
        """Benign break-out payloads for common reflection contexts. Each only
        sets window.__<marker>=1 — no alert, no cookie access, no exfil. We let
        the browser tell us which (if any) actually executes."""
        set_marker = f"window.__{marker}=1"
        return [
            f"';{set_marker};//",                      # break out of single-quoted JS string
            f'";{set_marker};//',                      # break out of double-quoted JS string
            f"</script><script>{set_marker}</script>",  # close JS string's script, open a new one
            f'"><script>{set_marker}</script>',         # break out of an attribute into HTML
            f'"><img src=x onerror="{set_marker}">',    # event-handler context
        ]

    def _confirm_execution(
        self, finding: Finding, ctx: ValidatorContext, param: str, marker: str
    ) -> dict[str, Any]:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:
            return {"status": "unavailable", "detail": f"playwright not importable: {e}"}

        scope = ctx.http._scope
        rl = ctx.http._rl
        tried: list[str] = []

        try:
            with sync_playwright() as p:
                try:
                    browser = p.chromium.launch(headless=True)
                except Exception as e:
                    return {"status": "unavailable",
                            "detail": f"chromium launch failed (run "
                                      f"'playwright install chromium'): {e}"}
                try:
                    for payload in self._exec_payloads(marker):
                        url = _inject_query(finding.target_url, param, payload)
                        tried.append(payload)
                        page = browser.new_page()
                        page.route("**/*", lambda route, request:
                                   _scope_route(scope, rl, route, request))
                        try:
                            page.goto(url, wait_until="load")
                            ran = page.evaluate(f"() => window.__{marker} === 1")
                        except Exception:
                            ran = False
                        finally:
                            page.close()
                        if ran:
                            return {"status": "confirmed", "url": url,
                                    "payload": payload, "marker_attr": f"__{marker}"}
                    return {"status": "not_executed", "payloads_tried": tried}
                finally:
                    browser.close()
        except Exception as e:
            return {"status": "unavailable", "detail": f"browser error: {e}"}


def _scope_route(scope: Any, rl: Any, route: Any, request: Any) -> None:
    """Playwright request interceptor: EVERY browser request (navigation,
    subresource, XHR) is scope-checked and rate-limited here, so the browser
    cannot bypass the outbound choke point. Out-of-scope requests are aborted."""
    req_url = request.url
    try:
        scope.check(req_url)
    except Exception:
        route.abort()
        return
    rl.acquire(req_url)
    route.continue_()
