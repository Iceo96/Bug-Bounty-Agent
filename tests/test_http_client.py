"""HTTP client tests: scope enforcement, required headers, method/path guards, rate limiting."""

from __future__ import annotations

import time

import httpx
import pytest

from bbagent.http.client import AuthorizedHTTPClient, RequestBlocked


def _echo_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={"seen_headers": dict(request.headers), "url": str(request.url)},
    )


@pytest.fixture
def transport():
    return httpx.MockTransport(_echo_handler)


async def test_blocks_out_of_scope(program_config, transport):
    async with AuthorizedHTTPClient(program_config, transport=transport) as client:
        with pytest.raises(RequestBlocked):
            await client.get("https://evil.com/")


async def test_blocks_excluded(program_config, transport):
    async with AuthorizedHTTPClient(program_config, transport=transport) as client:
        with pytest.raises(RequestBlocked):
            await client.get("https://secret.example.com/")


async def test_allows_in_scope_and_injects_headers(program_config, transport):
    async with AuthorizedHTTPClient(program_config, transport=transport) as client:
        ex = await client.get("https://example.com/")
    assert ex.status_code == 200
    # Required header injected on the wire.
    assert ex.request_headers.get("x-bug-bounty") == "researcher"


async def test_blocks_forbidden_method(program_config, transport):
    async with AuthorizedHTTPClient(program_config, transport=transport) as client:
        with pytest.raises(RequestBlocked):
            await client.request("DELETE", "https://example.com/x")


async def test_blocks_forbidden_path(program_config, transport):
    async with AuthorizedHTTPClient(program_config, transport=transport) as client:
        with pytest.raises(RequestBlocked):
            await client.get("https://example.com/danger/thing")


async def test_dry_run_kill_switch(program_config, transport, monkeypatch):
    monkeypatch.setenv("BBAGENT_DRY_RUN", "1")
    async with AuthorizedHTTPClient(program_config, transport=transport) as client:
        with pytest.raises(RequestBlocked):
            await client.get("https://example.com/")


async def test_passive_mode_blocks_active_methods(program_config, transport):
    program_config.restrictions.allow_active_testing = False
    async with AuthorizedHTTPClient(program_config, transport=transport) as client:
        with pytest.raises(RequestBlocked):
            await client.request("POST", "https://example.com/x")
        # GET still fine.
        ex = await client.get("https://example.com/x")
        assert ex.status_code == 200


async def test_rate_limit_throttles(program_config, transport):
    # 5 req/s, single host -> 4 requests take at least ~0.4s after the initial burst.
    program_config.rate_limit.requests_per_second = 5
    program_config.rate_limit.max_concurrent = 2
    async with AuthorizedHTTPClient(program_config, transport=transport) as client:
        start = time.perf_counter()
        for _ in range(6):
            await client.get("https://example.com/")
        elapsed = time.perf_counter() - start
    # After the initial bucket (capacity==rate==5), the 6th needs a refill (~0.2s).
    assert elapsed >= 0.15
