"""The single outbound HTTP choke point. Nothing in bouncer may talk to a target
except through ScopedHttpClient. It enforces scope on every hop (including
redirects), rate-limits, and backs off on 429."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

from .rate_limiter import RateLimiter
from .scope import Scope, ScopeError

log = logging.getLogger("bouncer.http")

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_MAX_REDIRECTS = 5


@dataclass
class ScopeBlock:
    url: str
    reason: str


class ScopedHttpClient:
    def __init__(
        self,
        scope: Scope,
        rate_limiter: RateLimiter,
        timeout: float = 15.0,
        user_agent: str = "bouncer-validator/0.1",
        on_scope_block: Callable[[ScopeBlock], None] | None = None,
    ):
        self._scope = scope
        self._rl = rate_limiter
        self._ua = user_agent
        self._on_scope_block = on_scope_block
        self._client = httpx.Client(
            follow_redirects=False,  # we follow manually to re-check scope each hop
            timeout=timeout,
            headers={"User-Agent": user_agent},
        )
        self.blocked: list[ScopeBlock] = []

    # context manager
    def __enter__(self) -> "ScopedHttpClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def _block(self, url: str, reason: str) -> ScopeError:
        sb = ScopeBlock(url=url, reason=reason)
        self.blocked.append(sb)
        log.warning("SCOPE BLOCK: %s (%s)", url, reason)
        if self._on_scope_block:
            self._on_scope_block(sb)
        return ScopeError(reason)

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Scope-checked, rate-limited request with manual redirect handling."""
        method = method.upper()
        current_url = url
        for _hop in range(_MAX_REDIRECTS + 1):
            # 1) scope gate — refuse and log anything out of scope.
            try:
                self._scope.check(current_url)
            except ScopeError as e:
                raise self._block(current_url, str(e)) from e

            # 2) rate gate.
            self._rl.acquire(current_url)

            # 3) send (no auto-redirect).
            resp = self._client.request(method, current_url, **kwargs)

            # 4) 429 backoff honoring Retry-After.
            if resp.status_code == 429:
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                self._rl.penalize(current_url, retry_after if retry_after is not None else 5.0)
                log.warning("429 from %s; backing off %.1fs", current_url, retry_after or 5.0)
                return resp

            # 5) redirect? re-check scope on the next hop.
            if resp.is_redirect and "location" in resp.headers:
                next_url = str(resp.next_request.url) if resp.next_request else None
                if not next_url:
                    return resp
                current_url = next_url
                # Redirected requests downgrade body/params; httpx builds
                # next_request, but we re-issue via loop for the scope check.
                kwargs.pop("content", None)
                kwargs.pop("data", None)
                kwargs.pop("json", None)
                continue

            return resp

        raise self._block(current_url, f"exceeded {_MAX_REDIRECTS} redirects")

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("HEAD", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        # HTTP-date form not parsed here; fall back to caller default.
        return None
