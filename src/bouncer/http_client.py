"""The single outbound HTTP choke point. Nothing in bouncer may talk to a target
except through ScopedHttpClient. It enforces scope on every hop (including
redirects), rate-limits, backs off on 429, and pins each connection to the
address scope already checked."""
from __future__ import annotations

import ipaddress
import logging
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable

import httpx

from .rate_limiter import RateLimiter
from .scope import ResolvedTarget, Scope, ScopeError

log = logging.getLogger("bouncer.http")

# RFC 9110 safe methods. A 301/302 of anything else is retried as GET so a
# validator does not replay a state-changing method across a redirect.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_MAX_REDIRECTS = 5
_DEFAULT_RETRY_AFTER = 5.0


def _host_keys(host: str) -> tuple[str, ...]:
    """Forms of a hostname that should share one pin.

    httpx keeps a trailing dot and exposes IDNA names in Unicode, while scope
    compares the A-label with the dot stripped. Remembering every form keeps
    the pin lookup aligned with the request httpx actually sends.
    """
    keys: list[str] = []

    def add(value: str) -> None:
        if value and value not in keys:
            keys.append(value)

    add(host)
    lowered = host.lower()
    add(lowered)
    stripped = lowered.rstrip(".")
    add(stripped)
    try:
        add(stripped.encode("idna").decode("ascii"))
    except (UnicodeError, ValueError):
        pass
    try:
        add(stripped.encode("ascii").decode("idna"))
    except (UnicodeError, ValueError):
        pass
    return tuple(keys)


def _same_ip(host: str, pin: str) -> bool:
    try:
        return ipaddress.ip_address(host) == ipaddress.ip_address(pin)
    except ValueError:
        return False


class _PinningTransport(httpx.BaseTransport):
    """Send the request to a checked address without changing the URL httpx sees.

    Relative redirects are joined against the original name and scope-checked
    again. The socket is opened to the pin, with the original Host header and
    SNI left on the name that was checked.
    """

    def __init__(self, inner: httpx.BaseTransport):
        self._inner = inner
        self._pins: dict[str, tuple[str, str]] = {}

    def remember(self, host: str, pin: str, sni: str) -> None:
        for key in _host_keys(host):
            self._pins[key] = (pin, sni)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        chosen: tuple[str, str] | None = None
        for key in _host_keys(host):
            chosen = self._pins.get(key)
            if chosen is not None:
                break
        if chosen is None:
            raise ScopeError(f"refusing unpinned connection to {host!r}")
        pin, sni = chosen
        if _same_ip(host, pin):
            return self._inner.handle_request(request)
        extensions = dict(request.extensions)
        extensions["sni_hostname"] = sni
        forwarded = httpx.Request(
            method=request.method,
            url=request.url.copy_with(host=pin),
            headers=request.headers,
            stream=request.stream,
            extensions=extensions,
        )
        return self._inner.handle_request(forwarded)

    def close(self) -> None:
        self._inner.close()


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
        transport: httpx.BaseTransport | None = None,
    ):
        self._scope = scope
        self._rl = rate_limiter
        self._ua = user_agent
        self._on_scope_block = on_scope_block
        self._transport = _PinningTransport(transport or httpx.HTTPTransport())
        self._client = httpx.Client(
            follow_redirects=False,  # we follow manually to re-check scope each hop
            timeout=timeout,
            headers={"User-Agent": user_agent},
            transport=self._transport,
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
            # 1) scope gate. Hostnames are resolved here, and the pin is the
            #    only address the transport is allowed to open.
            try:
                decision: ResolvedTarget = self._scope.check(current_url)
            except ScopeError as e:
                raise self._block(current_url, str(e)) from e
            self._transport.remember(
                httpx.URL(current_url).host, decision.pin, decision.host
            )

            # 2) rate gate.
            self._rl.acquire(current_url)

            # 3) send (no auto-redirect).
            resp = self._client.request(method, current_url, **kwargs)

            # 4) 429 backoff honoring Retry-After.
            if resp.status_code == 429:
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                delay = _DEFAULT_RETRY_AFTER if retry_after is None else retry_after
                self._rl.penalize(current_url, delay)
                log.warning("429 from %s; backing off %.1fs", current_url, delay)
                return resp

            # 5) redirect? re-check scope on the next hop.
            if resp.is_redirect and "location" in resp.headers:
                next_url = str(resp.next_request.url) if resp.next_request else None
                if not next_url:
                    return resp
                current_url = next_url
                method = _method_for_redirect(method, resp.status_code)
                # Redirected requests downgrade body/params; httpx builds
                # next_request, but we re-issue via loop for the scope check.
                kwargs.pop("content", None)
                kwargs.pop("data", None)
                kwargs.pop("json", None)
                kwargs.pop("files", None)
                continue

            return resp

        raise self._block(current_url, f"exceeded {_MAX_REDIRECTS} redirects")

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("HEAD", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)


def _method_for_redirect(method: str, status_code: int) -> str:
    """Method to replay after a redirect.

    303 becomes GET, except HEAD which stays HEAD (RFC 9110). 301 and 302
    downgrade methods outside ``_SAFE_METHODS`` to GET. 307 and 308 keep the
    method the caller sent.
    """
    if status_code == 303 and method != "HEAD":
        return "GET"
    if status_code in (301, 302) and method not in _SAFE_METHODS:
        return "GET"
    return method


def _parse_retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    """Seconds to wait, from a Retry-After delta or an HTTP-date.

    Returns None when the header is missing or not understood, so the caller
    can apply its own default. A date that is already in the past returns 0.
    ``now`` is injectable so tests can pin the clock.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        seconds = float(text)
    except ValueError:
        seconds = None
    else:
        if not math.isfinite(seconds):
            return None
        return max(0.0, seconds)

    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    clock = now or datetime.now(timezone.utc)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=timezone.utc)
    return max(0.0, (parsed - clock).total_seconds())
