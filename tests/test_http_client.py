"""ScopedHttpClient tests. Every request stays on the loopback mock transport."""
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest

from bouncer.http_client import ScopedHttpClient, _parse_retry_after
from bouncer.rate_limiter import RateLimiter
from bouncer.scope import Scope, ScopeError


def _scope() -> Scope:
    return Scope.from_dict({"in_cidrs": ["127.0.0.1/32"], "in_domains": []})


def _limiter() -> RateLimiter:
    return RateLimiter(100.0, 100, 200.0, 200)


def _client(handler, limiter=None) -> ScopedHttpClient:
    return ScopedHttpClient(
        _scope(),
        limiter or _limiter(),
        transport=httpx.MockTransport(handler),
    )


def test_parse_retry_after_seconds():
    assert _parse_retry_after("12") == 12.0
    assert _parse_retry_after("12.5") == 12.5
    assert _parse_retry_after("  0  ") == 0.0
    assert _parse_retry_after("-3") == 0.0
    assert _parse_retry_after(None) is None
    assert _parse_retry_after("   ") is None
    assert _parse_retry_after("not-a-delay") is None
    assert _parse_retry_after("inf") is None


def test_parse_retry_after_http_date():
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    future = format_datetime(now + timedelta(seconds=45), usegmt=True)
    past = format_datetime(now - timedelta(seconds=10), usegmt=True)
    assert _parse_retry_after(future, now=now) == 45.0
    assert _parse_retry_after(past, now=now) == 0.0
    # The two obsolete HTTP-date forms, fixed against the same clock.
    assert _parse_retry_after("Monday, 01-Jun-26 12:00:30 GMT", now=now) == 30.0
    assert _parse_retry_after("Mon Jun  1 12:00:15 2026", now=now) == 15.0


def test_429_delta_seconds_is_the_penalty():
    penalties = []

    class _Recording(RateLimiter):
        def penalize(self, url, retry_after_seconds):
            penalties.append((url, retry_after_seconds))
            super().penalize(url, retry_after_seconds)

    def handler(request):
        return httpx.Response(429, headers={"Retry-After": "7"})

    with _client(handler, _Recording(100.0, 100, 200.0, 200)) as client:
        resp = client.get("http://127.0.0.1/slow")
    assert resp.status_code == 429
    assert penalties == [("http://127.0.0.1/slow", 7.0)]


def test_429_http_date_is_the_penalty(monkeypatch):
    frozen = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    class _Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return frozen

    monkeypatch.setattr("bouncer.http_client.datetime", _Frozen)
    header = format_datetime(frozen + timedelta(seconds=45), usegmt=True)
    penalties = []

    class _Recording(RateLimiter):
        def penalize(self, url, retry_after_seconds):
            penalties.append(retry_after_seconds)
            super().penalize(url, retry_after_seconds)

    def handler(request):
        return httpx.Response(429, headers={"Retry-After": header})

    with _client(handler, _Recording(100.0, 100, 200.0, 200)) as client:
        client.get("http://127.0.0.1/slow")
    assert penalties == [45.0]


def test_429_missing_or_invalid_retry_after_uses_default():
    penalties = []

    class _Recording(RateLimiter):
        def penalize(self, url, retry_after_seconds):
            penalties.append(retry_after_seconds)

    def handler(request):
        if request.url.path == "/missing":
            return httpx.Response(429)
        return httpx.Response(429, headers={"Retry-After": "soon"})

    limiter = _Recording(100.0, 100, 200.0, 200)
    with _client(handler, limiter) as client:
        client.get("http://127.0.0.1/missing")
        client.get("http://127.0.0.1/bogus")
    assert penalties == [5.0, 5.0]


@pytest.mark.parametrize(
    ("status", "method", "expected"),
    [
        (301, "POST", "GET"),
        (302, "POST", "GET"),
        (302, "PUT", "GET"),
        (302, "DELETE", "GET"),
        (303, "POST", "GET"),
        (303, "OPTIONS", "GET"),
        (303, "HEAD", "HEAD"),
        (302, "GET", "GET"),
        (302, "HEAD", "HEAD"),
        (302, "OPTIONS", "OPTIONS"),
        (307, "POST", "POST"),
        (308, "PUT", "PUT"),
    ],
)
def test_redirect_downgrades_unsafe_methods(status, method, expected):
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path, request.content))
        if request.url.path == "/start":
            return httpx.Response(status, headers={"Location": "/next"})
        return httpx.Response(200, text="ok")

    with _client(handler) as client:
        resp = client.request(method, "http://127.0.0.1/start", content=b"body")
    assert resp.status_code == 200
    assert [item[0] for item in seen] == [method, expected]
    assert seen[0][2] == b"body"
    # The follow-up never resends the body, including 307/308.
    assert seen[1][2] == b""


def test_redirect_to_out_of_scope_is_blocked_before_send():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://203.0.113.50/no"})

    with _client(handler) as client:
        with pytest.raises(ScopeError):
            client.get("http://127.0.0.1/start")
    assert seen == ["http://127.0.0.1/start"]
