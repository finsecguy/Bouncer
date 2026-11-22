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


def test_connection_is_pinned_to_the_checked_address():
    scope = Scope.from_dict({
        "in_domains": ["app.test"],
        "out_cidrs": ["10.1.2.3/32"],
    })
    calls = []

    def resolver(host):
        calls.append(host)
        return ["127.0.0.1"]

    scope.resolver = resolver
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, text="ok")

    with ScopedHttpClient(scope, _limiter(), transport=httpx.MockTransport(handler)) as client:
        resp = client.get("http://app.test/path")
    assert resp.status_code == 200
    assert calls == ["app.test"]
    assert seen[0].url.host == "127.0.0.1"
    assert seen[0].headers["host"] == "app.test"
    assert seen[0].extensions["sni_hostname"] == "app.test"


def test_second_resolver_answer_is_not_used_for_the_socket():
    scope = Scope.from_dict({
        "in_domains": ["app.test"],
        "out_cidrs": ["10.9.9.9/32"],
    })
    answers = [["127.0.0.1"], ["10.9.9.9"]]

    def resolver(host):
        return answers.pop(0)

    scope.resolver = resolver
    seen = []

    def handler(request):
        seen.append(request.url.host)
        return httpx.Response(200, text="ok")

    with ScopedHttpClient(scope, _limiter(), transport=httpx.MockTransport(handler)) as client:
        resp = client.get("http://app.test/x")
    assert resp.status_code == 200
    assert seen == ["127.0.0.1"]
    assert answers == [["10.9.9.9"]]


def test_relative_redirect_is_rechecked_on_the_original_name():
    scope = Scope.from_dict({"in_domains": ["app.test"], "out_cidrs": ["10.0.0.0/8"]})
    calls = []

    def resolver(host):
        calls.append(host)
        return ["127.0.0.1"]

    scope.resolver = resolver
    seen = []

    def handler(request):
        seen.append((request.url.host, request.url.path, request.headers["host"]))
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/next"})
        return httpx.Response(200, text="ok")

    with ScopedHttpClient(scope, _limiter(), transport=httpx.MockTransport(handler)) as client:
        resp = client.get("http://app.test/start")
    assert resp.status_code == 200
    assert calls == ["app.test", "app.test"]
    assert seen == [
        ("127.0.0.1", "/start", "app.test"),
        ("127.0.0.1", "/next", "app.test"),
    ]


def test_redirect_into_excluded_cidr_is_not_sent():
    scope = Scope.from_dict({
        "in_domains": ["app.test", "bad.test"],
        "out_cidrs": ["10.1.2.3/32"],
    })

    def resolver(host):
        return {"app.test": ["127.0.0.1"], "bad.test": ["10.1.2.3"]}[host]

    scope.resolver = resolver
    seen = []

    def handler(request):
        seen.append(request.url.host)
        return httpx.Response(302, headers={"Location": "http://bad.test/secret"})

    with ScopedHttpClient(scope, _limiter(), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ScopeError, match="out of scope"):
            client.get("http://app.test/start")
    assert seen == ["127.0.0.1"]


def test_ipv6_pin_keeps_the_original_host_header():
    scope = Scope.from_dict({"in_domains": ["app.test"]})
    scope.resolver = lambda host: ["::1"]
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, text="ok")

    with ScopedHttpClient(scope, _limiter(), transport=httpx.MockTransport(handler)) as client:
        resp = client.get("http://app.test:8080/x")
    assert resp.status_code == 200
    assert seen[0].url.host == "::1"
    assert seen[0].url.port == 8080
    assert str(seen[0].url).startswith("http://[::1]:8080/")
    assert seen[0].headers["host"] == "app.test:8080"
    assert seen[0].extensions["sni_hostname"] == "app.test"


def test_trailing_dot_and_idna_pin_the_checked_address():
    scope = Scope.from_dict({
        "in_domains": ["app.test", "xn--bcher-kva.test"],
    })
    calls = []

    def resolver(host):
        calls.append(host)
        return ["127.0.0.1"]

    scope.resolver = resolver
    seen = []

    def handler(request):
        seen.append((
            request.url.host,
            request.headers["host"],
            request.extensions.get("sni_hostname"),
        ))
        return httpx.Response(200, text="ok")

    with ScopedHttpClient(scope, _limiter(), transport=httpx.MockTransport(handler)) as client:
        client.get("http://App.Test./x")
        client.get("http://bücher.test/y")
    assert calls == ["app.test", "xn--bcher-kva.test"]
    assert seen[0][0] == "127.0.0.1"
    assert seen[0][1] != "127.0.0.1"
    assert seen[0][2] == "app.test"
    assert seen[1][0] == "127.0.0.1"
    assert seen[1][2] == "xn--bcher-kva.test"


def test_redirect_to_out_of_scope_is_blocked_before_send():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://203.0.113.50/no"})

    with _client(handler) as client:
        with pytest.raises(ScopeError):
            client.get("http://127.0.0.1/start")
    assert seen == ["http://127.0.0.1/start"]
