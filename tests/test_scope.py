import ipaddress
import json
from pathlib import Path

import pytest

from bouncer.scope import Scope, ScopeError


@pytest.fixture
def scope():
    return Scope.from_dict({
        "in_domains": ["example.com", "*.api.example.com"],
        "in_cidrs": ["127.0.0.1/32", "10.0.0.0/8"],
        "out_domains": ["secret.api.example.com"],
        "out_cidrs": ["10.1.2.3/32"],
        "wildcard_matches_apex": False,
    })


def test_exact_domain_in_scope(scope):
    assert scope.is_allowed("https://example.com/path")


def test_subdomain_wildcard(scope):
    assert scope.is_allowed("https://v1.api.example.com/x")


def test_wildcard_does_not_match_apex_when_disabled(scope):
    # *.api.example.com should NOT match api.example.com here.
    assert not scope.is_allowed("https://api.example.com/x")


def test_wildcard_matches_apex_when_enabled():
    s = Scope.from_dict({"in_domains": ["*.example.com"], "wildcard_matches_apex": True})
    assert s.is_allowed("https://example.com/")
    assert s.is_allowed("https://a.example.com/")


def test_out_of_scope_beats_in_scope(scope):
    assert not scope.is_allowed("https://secret.api.example.com/x")


def test_unlisted_domain_refused(scope):
    assert not scope.is_allowed("https://evil.com/x")


def test_userinfo_trick_refused(scope):
    with pytest.raises(ScopeError):
        scope.check("http://example.com@evil.com/")


def test_scheme_restricted(scope):
    with pytest.raises(ScopeError):
        scope.check("ftp://example.com/x")
    with pytest.raises(ScopeError):
        scope.check("file:///etc/passwd")


def test_trailing_dot_and_case_normalized(scope):
    assert scope.is_allowed("https://EXAMPLE.com./path")


def test_ip_in_cidr(scope):
    assert scope.is_allowed("http://127.0.0.1:8000/x")
    assert scope.is_allowed("http://10.5.5.5/x")


def test_ip_out_of_scope_exclusion_wins(scope):
    assert not scope.is_allowed("http://10.1.2.3/x")


def test_ip_not_in_any_cidr(scope):
    assert not scope.is_allowed("http://8.8.8.8/x")


def test_wildcard_exclusion_covers_apex_when_flag_is_off():
    s = Scope.from_dict({
        "in_domains": ["example.com", "*.example.com", "example.org"],
        "out_domains": ["*.example.com"],
        "wildcard_matches_apex": False,
    })
    assert not s.is_allowed("https://a.example.com/x")
    assert not s.is_allowed("https://example.com/x")
    assert s.is_allowed("https://example.org/x")


def test_wildcard_exclusion_apex_does_not_swallow_other_names():
    s = Scope.from_dict({
        "in_domains": ["example.com", "*.example.com"],
        "out_domains": ["*.api.example.com"],
        "wildcard_matches_apex": False,
    })
    assert s.is_allowed("https://example.com/")
    assert s.is_allowed("https://www.example.com/")
    assert not s.is_allowed("https://api.example.com/")
    assert not s.is_allowed("https://v1.api.example.com/")


def test_hostname_resolving_into_out_cidr_is_refused():
    calls = []

    def resolver(host):
        calls.append(host)
        return ["10.1.2.3"]

    s = Scope.from_dict({
        "in_domains": ["app.test"],
        "in_cidrs": ["127.0.0.1/32"],
        "out_cidrs": ["10.1.2.3/32"],
    })
    s.resolver = resolver
    with pytest.raises(ScopeError, match="out of scope"):
        s.check("http://app.test/x")
    assert calls == ["app.test"]


def test_any_resolved_address_in_out_cidr_refuses_the_name():
    s = Scope.from_dict({
        "in_domains": ["app.test"],
        "out_cidrs": ["10.1.2.3/32"],
    })
    s.resolver = lambda host: ["127.0.0.1", "10.1.2.3"]
    assert not s.is_allowed("http://app.test/x")


def test_resolved_pin_is_the_first_clean_address():
    s = Scope.from_dict({
        "in_domains": ["app.test"],
        "out_cidrs": ["10.0.0.0/8"],
    })
    s.resolver = lambda host: ["127.0.0.2", "127.0.0.2", "127.0.0.3"]
    decision = s.check("http://app.test/x")
    assert decision.pin == "127.0.0.2"
    assert decision.host == "app.test"


def test_domain_allow_does_not_require_address_in_in_cidrs():
    s = Scope.from_dict({
        "in_domains": ["app.test"],
        "in_cidrs": ["127.0.0.1/32"],
        "out_cidrs": ["10.0.0.0/8"],
    })
    s.resolver = lambda host: ["127.0.0.2"]
    assert s.is_allowed("http://app.test/x")


def test_unresolved_hostname_is_refused():
    s = Scope.from_dict({"in_domains": ["app.test"]})
    s.resolver = lambda host: []
    with pytest.raises(ScopeError, match="did not resolve"):
        s.check("http://app.test/")


def test_resolver_oserror_is_scope_error():
    def resolver(host):
        raise OSError("dns down")

    s = Scope.from_dict({"in_domains": ["app.test"]})
    s.resolver = resolver
    with pytest.raises(ScopeError, match="could not resolve"):
        s.check("http://app.test/")


def test_non_ip_resolver_result_is_refused():
    s = Scope.from_dict({"in_domains": ["app.test"]})
    s.resolver = lambda host: ["not-an-ip"]
    with pytest.raises(ScopeError, match="non-ip"):
        s.check("http://app.test/")


def test_literal_ip_does_not_resolve():
    calls = []
    s = Scope.from_dict({"in_cidrs": ["127.0.0.1/32"], "out_cidrs": ["10.0.0.0/8"]})
    s.resolver = lambda host: calls.append(host) or ["10.1.1.1"]
    assert s.check("http://127.0.0.1/x").pin == "127.0.0.1"
    assert calls == []


def test_out_of_scope_name_is_not_resolved():
    calls = []
    s = Scope.from_dict({"in_domains": ["app.test"], "out_domains": ["secret.app.test"]})
    s.resolver = lambda host: calls.append(host) or ["127.0.0.1"]
    assert not s.is_allowed("http://secret.app.test/")
    assert not s.is_allowed("http://other.test/")
    assert calls == []


def test_ipv4_mapped_address_matches_out_cidr():
    s = Scope.from_dict({
        "in_domains": ["app.test"],
        "in_cidrs": ["10.0.0.0/8"],
        "out_cidrs": ["10.1.2.3/32"],
    })
    s.resolver = lambda host: ["::ffff:10.1.2.3"]
    assert not s.is_allowed("http://app.test/")
    assert not s.is_allowed("http://[::ffff:10.1.2.3]/")


def test_ipv4_mapped_literal_can_match_in_cidr():
    s = Scope.from_dict({"in_cidrs": ["127.0.0.1/32"]})
    assert s.is_allowed("http://[::ffff:127.0.0.1]/")


def test_resolve_host_reads_stubbed_getaddrinfo(monkeypatch):
    import socket

    from bouncer.scope import _addresses_from_getaddrinfo

    def fake(host, port, *args, **kwargs):
        assert host == "app.test"
        assert port is None
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    assert _addresses_from_getaddrinfo("app.test") == ["127.0.0.1", "::1"]


def test_committed_demo_scope_is_loopback_only():
    """The committed demo scope is the local mock, never a real name or address.

    Resolved-address checks pin a hostname to whatever it looks up. This file
    therefore lists no hostnames, so loading it cannot resolve or contact anything
    except the literal loopback address the mock server binds.
    """
    root = Path(__file__).resolve().parents[1]
    demo = json.loads((root / "scopes" / "demo.json").read_text(encoding="utf-8"))
    assert demo["in_domains"] == []
    assert demo["out_domains"] == []
    assert demo["in_cidrs"] == ["127.0.0.1/32"]
    assert demo["out_cidrs"] == []
    assert "example.com" not in json.dumps(demo)

    calls = []
    scope = Scope.from_dict(demo)
    scope.resolver = lambda host: calls.append(host) or ["127.0.0.1"]

    decision = scope.check("http://127.0.0.1:8000/xss")
    assert decision.pin == "127.0.0.1"
    assert decision.host == "127.0.0.1"
    mapped = scope.check("http://[::ffff:127.0.0.1]/")
    assert ipaddress.ip_address(mapped.pin).ipv4_mapped == ipaddress.ip_address("127.0.0.1")

    refused = (
        "https://example.com/",
        "https://app.example.com/x",
        "http://localhost/",
        "http://127.0.0.2/",
        "http://8.8.8.8/x",
        "http://[::1]/",
        "http://[::ffff:8.8.8.8]/",
    )
    for url in refused:
        with pytest.raises(ScopeError):
            scope.check(url)
    assert calls == []
