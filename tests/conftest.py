from __future__ import annotations

import pytest

from bbv.config import Settings
from bbv.http_client import ScopedHttpClient
from bbv.mockserver import start_background
from bbv.rate_limiter import RateLimiter
from bbv.scope import Scope


@pytest.fixture(scope="session")
def mock_server():
    server, port = start_background("127.0.0.1", 0)
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def scope() -> Scope:
    # Real scope object, loopback only. No allow-all / bypass flag.
    return Scope.from_dict({
        "in_domains": ["example.com", "*.example.com"],
        "in_cidrs": ["127.0.0.1/32"],
        "out_domains": ["admin.example.com"],
        "out_cidrs": [],
        "wildcard_matches_apex": False,
    })


@pytest.fixture
def fast_limiter() -> RateLimiter:
    # Generous limits so throughput-oriented tests don't actually sleep.
    return RateLimiter(100.0, 100, 200.0, 200)


@pytest.fixture
def http(scope, fast_limiter) -> ScopedHttpClient:
    client = ScopedHttpClient(scope, fast_limiter, timeout=5.0)
    yield client
    client.close()


@pytest.fixture
def settings() -> Settings:
    # Avoid reading a developer .env during tests.
    return Settings(_env_file=None)
