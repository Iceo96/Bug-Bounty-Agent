"""Browser navigation/network errors must not crash the research loop.

A failed goto for one in-scope origin is caught, recorded as a sanitized diagnostic,
and the origin is skipped (no retry) while remaining in-scope origins are still
explored. No real browser, no network, no Temu — a mock backend raises Playwright-
style errors.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from bbagent.browser.controller import BrowserBackend, BrowserController
from bbagent.browser.explorer import (
    AutonomousExplorer, ExplorationLimits, ExplorationSummary, _classify_nav_error,
)
from bbagent.browser.models import ObservedExchange
from bbagent.config.models import (
    ProgramConfig, ScopeConfig, ScopeKind, ScopeRule, TestingRestrictions,
)
from bbagent.program.manager import ProgramManager
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore
from bbagent.storage.db import Database


def _program(hosts=("a.test", "b.test")) -> ProgramManager:
    return ProgramManager(ProgramConfig(
        name="navtest", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value=h) for h in hosts]),
        restrictions=TestingRestrictions(allow_active_testing=False, allowed_methods=["GET"]),
        allow_unauthenticated=True))


class FlakyBackend(BrowserBackend):
    """Raises a (Playwright-style) error for configured origins; serves others."""

    def __init__(self, fail_origins, *, error="Page.goto: net::ERR_CONNECTION_RESET at {url}"):
        self._fail = set(fail_origins)
        self._err = error
        self._buf: list[ObservedExchange] = []
        self.goto_calls: list[str] = []

    async def start(self): self._buf.clear()
    async def close(self): pass

    async def goto(self, url):
        self.goto_calls.append(url)
        p = urlsplit(url)
        if f"{p.scheme}://{p.hostname}" in self._fail:
            raise RuntimeError(self._err.format(url=url))
        self._buf.append(ObservedExchange(
            "GET", url, status=200, request_headers={"cookie": ""},
            response_headers={"Content-Type": "text/html"},
            response_body="<html><body>ok</body></html>", identity_label="researcher"))

    async def click(self, s): pass
    async def type_text(self, s, t): pass
    async def scroll(self, s=None, amount=3): pass

    async def drain(self):
        out = self._buf; self._buf = []; return out


def _explorer(program, backend):
    db = Database(":memory:")
    surface = SurfaceStore(db)
    controller = BrowserController(program, surface, backend,
                                   default_identity=AuthIdentity.IDENTITY_A)
    explorer = AutonomousExplorer(controller, surface,
                                  limits=ExplorationLimits(max_no_progress=6))
    return db, surface, explorer


def _hosts(surface, program):
    return {urlsplit(e.url).hostname for e in surface.list_endpoints(program.name)}


# --- A/B/C/D: one origin fails -> continue, record, no crash --------------------

def test_connection_reset_does_not_crash_and_continues():
    program = _program(("a.test", "b.test"))
    backend = FlakyBackend({"https://a.test"})
    db, surface, explorer = _explorer(program, backend)

    summary = asyncio.run(explorer.run(["https://a.test/", "https://b.test/"]))

    assert isinstance(summary, ExplorationSummary)          # (A/D) completed, no escape
    assert "b.test" in _hosts(surface, program)             # (B) remaining origin visited
    assert "a.test" not in _hosts(surface, program)         # failed origin: no endpoint
    recs = [f for f in summary.navigation_failures if f["origin"] == "https://a.test"]
    assert recs and recs[0]["category"] == "connection_reset"   # (C) recorded
    assert recs[0]["error_type"] == "RuntimeError" and recs[0]["action"] == "goto"
    # No retry of the failed origin.
    assert backend.goto_calls.count("https://a.test/") == 1
    db.close()


# --- E: scope behavior unchanged (out-of-scope seed never explored) -------------

def test_scope_unchanged_out_of_scope_seed_not_explored():
    program = _program(("a.test",))
    backend = FlakyBackend(set())
    db, surface, explorer = _explorer(program, backend)

    summary = asyncio.run(explorer.run(["https://a.test/", "https://evil.test/"]))

    assert _hosts(surface, program) == {"a.test"}
    assert all("evil.test" not in (f.get("origin") or "") for f in summary.navigation_failures)
    assert not any("evil.test" in u for u in backend.goto_calls)   # never navigated off-scope
    db.close()


# --- TLS/security error: recorded + skipped, NOT bypassed -----------------------

def test_tls_error_recorded_and_skipped_not_bypassed():
    program = _program(("a.test", "b.test"))
    backend = FlakyBackend({"https://a.test"},
                           error="Page.goto: net::ERR_CERT_AUTHORITY_INVALID at {url}")
    db, surface, explorer = _explorer(program, backend)

    summary = asyncio.run(explorer.run(["https://a.test/", "https://b.test/"]))

    rec = [f for f in summary.navigation_failures if f["origin"] == "https://a.test"][0]
    assert rec["category"] == "tls_security"
    assert "a.test" not in _hosts(surface, program)        # not bypassed -> no data from it
    assert "b.test" in _hosts(surface, program)            # others still explored
    db.close()


# --- unrecognized error handled; message sanitized (first line only) ------------

def test_unrecognized_error_handled_and_message_sanitized():
    program = _program(("a.test", "b.test"))
    backend = FlakyBackend({"https://a.test"},
                           error="boom-weird\nSECRET-LINE-SHOULD-NOT-APPEAR")
    db, surface, explorer = _explorer(program, backend)

    summary = asyncio.run(explorer.run(["https://a.test/", "https://b.test/"]))

    rec = [f for f in summary.navigation_failures if f["origin"] == "https://a.test"][0]
    assert rec["category"] == "other"
    assert "SECRET-LINE-SHOULD-NOT-APPEAR" not in rec["message"]   # multi-line stripped
    assert "b.test" in _hosts(surface, program)
    db.close()


# --- classifier unit coverage ---------------------------------------------------

def test_classifier_categories():
    mk = RuntimeError
    assert _classify_nav_error(mk("Page.goto: net::ERR_CONNECTION_RESET")) == "connection_reset"
    assert _classify_nav_error(mk("net::ERR_CONNECTION_REFUSED")) == "connection_refused"
    assert _classify_nav_error(mk("net::ERR_TIMED_OUT")) == "timed_out"
    assert _classify_nav_error(mk("Timeout 30000ms exceeded")) == "timed_out"
    assert _classify_nav_error(mk("net::ERR_NAME_NOT_RESOLVED")) == "dns_or_network"
    assert _classify_nav_error(mk("net::ERR_CERT_DATE_INVALID")) == "tls_security"
    assert _classify_nav_error(mk("net::ERR_SOMETHING_NEW")) == "navigation_error"
