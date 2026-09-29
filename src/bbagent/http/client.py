"""The only sanctioned way to make outbound requests.

Every request passes, in order, through:
  1. global dry-run kill switch
  2. scope validation (fail-closed)
  3. method + forbidden-path restrictions
  4. active-testing gate (non-idempotent methods blocked in passive mode)
  5. injection of program-required headers
  6. rate limiting (throughput + concurrency)

The client returns an :class:`HTTPExchange` capturing the raw request and
response for the evidence store. No component may bypass this class.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

import httpx

from bbagent.config.models import ProgramConfig
from bbagent.logging_config import get_logger
from bbagent.scope.engine import ScopeEngine, ScopeError

log = get_logger(__name__)

# Methods considered "active" (state-changing / non-idempotent enough to require
# explicit active-testing authorization).
_ACTIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class RequestBlocked(Exception):
    """Raised when a request is blocked before it leaves the process."""


@dataclass
class HTTPExchange:
    """A captured request/response pair — the raw material for evidence."""

    exchange_id: str
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: Optional[str]
    status_code: int
    response_headers: dict[str, str]
    response_body: str
    elapsed_ms: float
    started_at: float = field(default_factory=time.time)


class AuthorizedHTTPClient:
    """Async HTTP client that refuses to touch anything out of scope."""

    def __init__(
        self,
        program: ProgramConfig,
        *,
        timeout: float = 20.0,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self._program = program
        self._scope = ScopeEngine(program.scope)
        self._rate = _make_rate_limiter(program)
        self._timeout = timeout
        # A transport may be injected for testing; production leaves it None.
        self._transport = transport
        self._client: Optional[httpx.AsyncClient] = None
        # Number of requests that actually left the process — used by budgets.
        self.request_count = 0

    async def __aenter__(self) -> "AuthorizedHTTPClient":
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=False,  # redirects can leave scope; handle explicitly.
            transport=self._transport,
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # --- guards ----------------------------------------------------------------

    def _preflight(self, method: str, url: str) -> None:
        method = method.upper()

        if os.getenv("BBAGENT_DRY_RUN", "0") == "1":
            raise RequestBlocked("BBAGENT_DRY_RUN is set — all outbound requests are blocked")
        if getattr(self._program, "dry_run_only", False):
            raise RequestBlocked("program is dry-run-only — outbound requests are permanently blocked")

        # Scope is checked first and always.
        try:
            self._scope.enforce(url)
        except ScopeError as exc:
            raise RequestBlocked(str(exc)) from exc

        r = self._program.restrictions
        if method not in r.allowed_methods:
            raise RequestBlocked(f"method {method} not permitted by program restrictions")

        from urllib.parse import urlsplit

        path = urlsplit(url).path or "/"
        for frag in r.forbidden_paths:
            if frag and frag in path:
                raise RequestBlocked(f"path matches forbidden fragment {frag!r}")

        if method in _ACTIVE_METHODS and not r.allow_active_testing:
            raise RequestBlocked(f"active method {method} blocked: program is passive-only")

    def _merge_headers(self, headers: Optional[Mapping[str, str]]) -> dict[str, str]:
        merged: dict[str, str] = dict(self._program.required_headers)
        if headers:
            merged.update(headers)
        return merged

    # --- request ---------------------------------------------------------------

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        content: Optional[str | bytes] = None,
    ) -> HTTPExchange:
        """Perform a scope-checked request and return a captured exchange."""
        if self._client is None:
            raise RuntimeError("AuthorizedHTTPClient must be used as an async context manager")

        method = method.upper()
        self._preflight(method, url)
        final_headers = self._merge_headers(headers)

        async with self._rate.slot(url):
            started = time.perf_counter()
            resp = await self._client.request(
                method, url, headers=final_headers, params=params, content=content,
            )
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            self.request_count += 1

        exchange = HTTPExchange(
            exchange_id=uuid.uuid4().hex,
            method=method,
            url=str(resp.request.url),
            request_headers={k: v for k, v in resp.request.headers.items()},
            request_body=_as_text(content),
            status_code=resp.status_code,
            response_headers={k: v for k, v in resp.headers.items()},
            response_body=resp.text,
            elapsed_ms=elapsed_ms,
        )
        log.info(
            "http.exchange",
            id=exchange.exchange_id,
            method=method,
            url=exchange.url,
            status=exchange.status_code,
            ms=round(elapsed_ms, 1),
        )
        return exchange

    async def get(self, url: str, **kw: Any) -> HTTPExchange:
        return await self.request("GET", url, **kw)


def _as_text(content: Optional[str | bytes]) -> Optional[str]:
    if content is None:
        return None
    if isinstance(content, bytes):
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError:
            return f"<{len(content)} bytes binary>"
    return content


def _make_rate_limiter(program: ProgramConfig):
    # Local import keeps the module import graph light and avoids a cycle.
    from bbagent.http.ratelimit import RateLimiter

    return RateLimiter(program.rate_limit)
