import pytest

from bbv import models as m
from bbv.models import ValidationResult
from bbv.validators import get_validator
from bbv.validators.base import ValidatorContext


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True)
            b.close()
        return True
    except Exception:
        return False


def _finding(base, path):
    return m.Finding(
        id=1, program="demo", vuln_class="reflected_xss",
        target_url=f"{base}{path}", request={"method": "GET", "inject_param": "q"},
    )


def test_reflected_in_executable_context(mock_server, http, settings):
    v = get_validator("reflected_xss")
    ctx = ValidatorContext(http=http, settings=settings)
    res = v.validate(_finding(mock_server, "/xss?q=seed"), ctx)

    # Static analysis must detect script-context reflection either way.
    kinds = [e.data for e in res.evidence if e.kind == "canary_reflection"]
    assert any(d.get("context") == "script" for d in kinds)

    if _chromium_available():
        assert res.verdict == ValidationResult.CONFIRMED
        assert res.confidence_delta > 0.5
    else:
        # Execution unconfirmed must NOT reach high confidence.
        assert res.verdict == ValidationResult.INCONCLUSIVE
        assert 0.3 + res.confidence_delta < 0.80


def test_encoded_reflection_is_not_xss(mock_server, http, settings):
    v = get_validator("reflected_xss")
    ctx = ValidatorContext(http=http, settings=settings)
    res = v.validate(_finding(mock_server, "/safe?q=seed"), ctx)
    assert res.verdict == ValidationResult.REFUTED
    assert res.confidence_delta <= 0


class _FakeRoute:
    def __init__(self):
        self.aborted = False
        self.continued = False

    def abort(self):
        self.aborted = True

    def continue_(self):
        self.continued = True


class _FakeRequest:
    def __init__(self, url):
        self.url = url


def test_scope_route_aborts_out_of_scope_browser_request():
    """The Playwright interceptor must abort any browser request (subresource,
    XHR, redirect) that leaves scope — no bypass through the browser stack."""
    from bbv.rate_limiter import RateLimiter
    from bbv.scope import Scope
    from bbv.validators.reflected_xss import _scope_route

    sc = Scope.from_dict({"in_cidrs": ["127.0.0.1/32"], "in_domains": []})
    rl = RateLimiter(100, 100, 200, 200)

    allowed = _FakeRoute()
    _scope_route(sc, rl, allowed, _FakeRequest("http://127.0.0.1:9/app.js"))
    assert allowed.continued and not allowed.aborted

    blocked = _FakeRoute()
    _scope_route(sc, rl, blocked, _FakeRequest("http://evil.example/steal.js"))
    assert blocked.aborted and not blocked.continued
