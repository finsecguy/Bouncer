"""Scope enforcement. Every outbound request passes is_allowed() before it is
sent. Out-of-scope always beats in-scope. No bypass flag exists.

Hostnames are resolved before a connection is allowed. Every address is
checked against out_cidrs, and the caller must connect to the returned pin
instead of looking the name up again.
"""
from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, NamedTuple
from urllib.parse import urlsplit


class ScopeError(Exception):
    """Raised (and logged) when a request targets an out-of-scope destination."""


class ResolvedTarget(NamedTuple):
    """Address to open a socket to, and the name that stays on Host and SNI."""

    pin: str
    host: str


def _normalize_host(host: str | None) -> str | None:
    if not host:
        return None
    h = host.strip().lower().rstrip(".")
    if not h:
        return None
    try:
        # IDNA-encode unicode hostnames; ascii hosts pass through.
        h = h.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        # Leave as-is; comparison will simply fail to match a clean list.
        pass
    return h


def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _ip_forms(ip: ipaddress.IPv4Address | ipaddress.IPv6Address):
    """Address plus its IPv4 form when the value is an IPv4-mapped IPv6 address."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return (ip, ip.ipv4_mapped)
    return (ip,)


def _addresses_from_getaddrinfo(host: str) -> list[str]:
    """Unique addresses from getaddrinfo. Empty when the name does not resolve.

    This is the only function that calls getaddrinfo. Tests replace
    ``resolve_host`` and never let this run against an external name.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    found: list[str] = []
    for info in infos:
        ip = info[4][0]
        if "%" in ip:
            ip = ip.split("%", 1)[0]
        if ip not in found:
            found.append(ip)
    return found


def resolve_host(host: str) -> list[str]:
    """Resolve ``host`` to every unique address string."""
    return _addresses_from_getaddrinfo(host)


def _default_resolver(host: str) -> list[str]:
    # Look up the module global at call time so tests can replace resolve_host.
    return resolve_host(host)


@dataclass
class Scope:
    """A per-program scope.

    in_domains: exact hostnames or wildcard patterns ('*.example.com').
    in_cidrs:   networks / single IPs (as strings) that are in scope.
    out_domains / out_cidrs: explicit exclusions, which win over everything.
    wildcard_matches_apex: whether '*.example.com' also covers 'example.com'
        for inclusions. Wildcard exclusions always cover the apex.
    resolver: hostname to address list. The default uses getaddrinfo. A
        hostname is resolved only after it matches an inclusion, and every
        returned address is refused when it falls in out_cidrs.
    """

    in_domains: list[str] = field(default_factory=list)
    in_cidrs: list[str] = field(default_factory=list)
    out_domains: list[str] = field(default_factory=list)
    out_cidrs: list[str] = field(default_factory=list)
    wildcard_matches_apex: bool = False
    allowed_schemes: tuple[str, ...] = ("http", "https")
    resolver: Callable[[str], list[str]] = field(
        default=_default_resolver, repr=False, compare=False
    )

    # ---- construction ----
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Scope":
        return cls(
            in_domains=[s.strip().lower().rstrip(".") for s in d.get("in_domains", [])],
            in_cidrs=[s.strip() for s in d.get("in_cidrs", [])],
            out_domains=[s.strip().lower().rstrip(".") for s in d.get("out_domains", [])],
            out_cidrs=[s.strip() for s in d.get("out_cidrs", [])],
            wildcard_matches_apex=bool(d.get("wildcard_matches_apex", False)),
            allowed_schemes=tuple(d.get("allowed_schemes", ["http", "https"])),
        )

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    # ---- matching helpers ----
    @staticmethod
    def _domain_match(host: str, pattern: str, wildcard_matches_apex: bool) -> bool:
        if pattern.startswith("*."):
            suffix = pattern[2:]  # example.com
            if host == suffix:
                return wildcard_matches_apex
            return host.endswith("." + suffix)
        return host == pattern

    def _ip_in(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, cidrs: list[str]) -> bool:
        for form in _ip_forms(ip):
            for c in cidrs:
                try:
                    net = ipaddress.ip_network(c, strict=False)
                except ValueError:
                    continue
                if form.version != net.version:
                    continue
                if form in net:
                    return True
        return False

    def _check_literal_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        if self._ip_in(ip, self.out_cidrs):
            raise ScopeError(f"host {ip} is explicitly out of scope (ip)")
        if self._ip_in(ip, self.in_cidrs):
            return
        raise ScopeError(f"ip {ip} is not in scope")

    def _check_resolved(self, host: str, addresses: list[object]) -> list[str]:
        """Refuse when any resolved address is in out_cidrs. Return pin order.

        The hostname has already matched an inclusion. in_cidrs is a separate
        way to allow a literal address, not a second requirement on that name.
        Exclusions still win, including IPv4-mapped forms of an IPv6 answer.
        """
        if not addresses:
            raise ScopeError(f"host {host} did not resolve")
        pins: list[str] = []
        seen: set[str] = set()
        for raw in addresses:
            text = str(raw).strip()
            ip = _as_ip(text.split("%", 1)[0])
            if ip is None:
                raise ScopeError(f"resolver returned non-ip {raw!r} for {host}")
            if self._ip_in(ip, self.out_cidrs):
                raise ScopeError(
                    f"resolved address {ip} for {host} is explicitly out of scope"
                )
            key = str(ip)
            if key not in seen:
                seen.add(key)
                pins.append(key)
        return pins

    # ---- the single decision function ----
    def check(self, url: str) -> ResolvedTarget:
        """Raise ScopeError if url is not allowed.

        Returns the address the caller must connect to. For a literal IP that
        address is the IP itself. For a hostname it is the first resolved
        address that was checked, so the connection does not look the name up
        again.
        """
        parts = urlsplit(url)
        scheme = (parts.scheme or "").lower()
        if scheme not in self.allowed_schemes:
            raise ScopeError(f"scheme {scheme!r} not allowed for {url!r}")

        # Reject userinfo tricks: http://in.scope@evil.com
        if parts.username or parts.password:
            raise ScopeError(f"userinfo not allowed in url {url!r}")

        host = _normalize_host(parts.hostname)
        if host is None:
            raise ScopeError(f"no host in url {url!r}")

        ip = _as_ip(host)
        if ip is not None:
            self._check_literal_ip(ip)
            text = str(ip)
            return ResolvedTarget(pin=text, host=text)

        # Exclusions first. Wildcard exclusions cover the apex even when
        # wildcard_matches_apex is false: *.example.com excludes example.com.
        for pat in self.out_domains:
            if self._domain_match(host, pat, wildcard_matches_apex=True):
                raise ScopeError(f"host {host} is explicitly out of scope")

        matched = False
        for pat in self.in_domains:
            if self._domain_match(host, pat, self.wildcard_matches_apex):
                matched = True
                break
        if not matched:
            raise ScopeError(f"host {host} is not in scope")

        try:
            addresses = list(self.resolver(host))
        except OSError as exc:
            raise ScopeError(f"could not resolve host {host!r}") from exc
        pins = self._check_resolved(host, addresses)
        return ResolvedTarget(pin=pins[0], host=host)

    def is_allowed(self, url: str) -> bool:
        try:
            self.check(url)
            return True
        except ScopeError:
            return False
