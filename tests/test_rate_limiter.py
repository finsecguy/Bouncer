from bouncer.rate_limiter import RateLimiter


class FakeClock:
    """Deterministic clock. sleep() advances virtual time instead of blocking."""
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


def make(clock, **kw):
    kw.setdefault("per_host_rate", 2.0)
    kw.setdefault("per_host_burst", 2)
    kw.setdefault("global_rate", 100.0)
    kw.setdefault("global_burst", 100)
    return RateLimiter(now=clock.now, sleep=clock.sleep, **kw)


def test_per_host_burst_then_throttle():
    clock = FakeClock()
    rl = make(clock)
    url = "http://a.test/x"
    # Burst of 2 is immediate.
    rl.acquire(url); rl.acquire(url)
    assert clock.t == 0.0
    # Third must wait ~1/rate = 0.5s.
    rl.acquire(url)
    assert clock.t >= 0.5


def test_per_host_is_independent():
    clock = FakeClock()
    rl = make(clock)
    rl.acquire("http://a.test/"); rl.acquire("http://a.test/")
    # Different host has its own bucket; no wait yet.
    t0 = clock.t
    rl.acquire("http://b.test/"); rl.acquire("http://b.test/")
    assert clock.t == t0


def test_global_bucket_limits_across_hosts():
    clock = FakeClock()
    rl = make(clock, per_host_rate=1000.0, per_host_burst=1000,
              global_rate=2.0, global_burst=2)
    rl.acquire("http://a.test/"); rl.acquire("http://b.test/")
    assert clock.t == 0.0
    rl.acquire("http://c.test/")  # global exhausted -> wait
    assert clock.t >= 0.5


def test_penalize_enforces_retry_after():
    clock = FakeClock()
    rl = make(clock, per_host_rate=1000.0, per_host_burst=1000)
    url = "http://a.test/x"
    rl.penalize(url, 10.0)
    rl.acquire(url)
    assert clock.t >= 10.0
