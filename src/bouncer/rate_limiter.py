"""Token-bucket rate limiting: a global bucket plus one bucket per host.

The clock is injectable (``now`` / ``sleep``) so tests can drive it
deterministically without real sleeps."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit


@dataclass
class _Bucket:
    rate: float          # tokens per second
    capacity: float      # max tokens (burst)
    tokens: float
    last: float          # last refill timestamp

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.last)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last = now

    def time_until_available(self, now: float) -> float:
        self._refill(now)
        if self.tokens >= 1.0:
            return 0.0
        return (1.0 - self.tokens) / self.rate

    def consume(self, now: float) -> None:
        self._refill(now)
        self.tokens -= 1.0


class RateLimiter:
    def __init__(
        self,
        per_host_rate: float,
        per_host_burst: int,
        global_rate: float,
        global_burst: int,
        now: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ):
        self._now = now or time.monotonic
        self._sleep = sleep or time.sleep
        self._lock = threading.Lock()
        self._per_host_rate = per_host_rate
        self._per_host_burst = per_host_burst
        t = self._now()
        self._global = _Bucket(global_rate, global_burst, float(global_burst), t)
        self._hosts: dict[str, _Bucket] = {}
        # Per-host cooldowns from Retry-After / 429 backoff (host -> ready-at time).
        self._cooldown: dict[str, float] = {}

    def _host_bucket(self, host: str) -> _Bucket:
        b = self._hosts.get(host)
        if b is None:
            b = _Bucket(self._per_host_rate, self._per_host_burst,
                        float(self._per_host_burst), self._now())
            self._hosts[host] = b
        return b

    @staticmethod
    def _host_of(url: str) -> str:
        return (urlsplit(url).hostname or "").lower()

    def acquire(self, url: str) -> None:
        """Block until a token is available for both the global and host buckets
        (and any active cooldown has elapsed), then consume one from each."""
        host = self._host_of(url)
        while True:
            with self._lock:
                now = self._now()
                wait = 0.0
                cd = self._cooldown.get(host, 0.0)
                if cd > now:
                    wait = cd - now
                g_wait = self._global.time_until_available(now)
                h_wait = self._host_bucket(host).time_until_available(now)
                wait = max(wait, g_wait, h_wait)
                if wait <= 0.0:
                    self._global.consume(now)
                    self._host_bucket(host).consume(now)
                    return
            self._sleep(wait)

    def penalize(self, url: str, retry_after_seconds: float) -> None:
        """Record a server-requested backoff (from a 429 Retry-After)."""
        host = self._host_of(url)
        with self._lock:
            ready = self._now() + max(0.0, retry_after_seconds)
            self._cooldown[host] = max(self._cooldown.get(host, 0.0), ready)
