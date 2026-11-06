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
