"""Scope enforcement. Every outbound request passes is_allowed() before it is
sent. Out-of-scope always beats in-scope. No bypass flag exists."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class ScopeError(Exception):
    """Raised (and logged) when a request targets an out-of-scope destination."""


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


def _as_ip(host: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


@dataclass
class Scope:
    """A per-program scope.

    in_domains: exact hostnames or wildcard patterns ('*.example.com').
    in_cidrs:   networks / single IPs (as strings) that are in scope.
    out_domains / out_cidrs: explicit exclusions, which win over everything.
    wildcard_matches_apex: whether '*.example.com' also covers 'example.com'.
    """

    in_domains: list[str] = field(default_factory=list)
    in_cidrs: list[str] = field(default_factory=list)
    out_domains: list[str] = field(default_factory=list)
    out_cidrs: list[str] = field(default_factory=list)
    wildcard_matches_apex: bool = False
    allowed_schemes: tuple[str, ...] = ("http", "https")

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

    def _ip_in(self, ip: ipaddress._BaseAddress, cidrs: list[str]) -> bool:
        for c in cidrs:
            try:
                net = ipaddress.ip_network(c, strict=False)
            except ValueError:
                continue
            if ip in net:
                return True
        return False

    # ---- the single decision function ----
    def check(self, url: str) -> None:
        """Raise ScopeError if url is not allowed. Otherwise return None."""
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

        # Exclusions first — they always win.
        if ip is not None:
            if self._ip_in(ip, self.out_cidrs):
                raise ScopeError(f"host {host} is explicitly out of scope (ip)")
        else:
            for pat in self.out_domains:
                if self._domain_match(host, pat, self.wildcard_matches_apex):
                    raise ScopeError(f"host {host} is explicitly out of scope")

        # Inclusions.
        if ip is not None:
            if self._ip_in(ip, self.in_cidrs):
                return
            raise ScopeError(f"ip {host} is not in scope")
        else:
            for pat in self.in_domains:
                if self._domain_match(host, pat, self.wildcard_matches_apex):
                    return
            raise ScopeError(f"host {host} is not in scope")

    def is_allowed(self, url: str) -> bool:
        try:
            self.check(url)
            return True
        except ScopeError:
            return False
