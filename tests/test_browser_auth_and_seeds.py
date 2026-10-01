"""Diagnostics for (1) authenticated-session detection and (2) multi-origin seeding.

All local: mock request/response objects, local ProgramConfigs, and a mock backend.
No real browser, no network, no Temu. No secret value is ever stored or asserted-on
except to prove it is ABSENT from what we keep.
"""

from __future__ import annotations

import asyncio
import inspect
import json

from bbagent.browser import auth_signals, seed_origins_from_scope
from bbagent.browser.controller import BrowserBackend, BrowserController, ExplorationStep
from bbagent.browser.explorer import AutonomousExplorer, ExplorationLimits
from bbagent.browser.models import ObservedExchange
from bbagent.browser import playwright_backend as pwb
from bbagent.browser.playwright_backend import PlaywrightBackend
from bbagent.config.loader import load_program
from bbagent.config.models import ProgramConfig, ScopeConfig, ScopeKind, ScopeRule
from bbagent.program.manager import ProgramManager
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore
from bbagent.storage.db import Database
from pathlib import Path

TEMU_YAML = str(Path(__file__).resolve().parents[1] / "programs" / "temu.yaml")
SECRET = "SECRET_COOKIE_VALUE_do_not_store"


# =========================================================================
# 1) AUTHENTICATION DETECTION
# =========================================================================

# --- what the classifier considers authenticated (header NAME presence) -------

def test_classifier_keys_on_header_names_only():
    assert ObservedExchange("GET", "u", request_headers={"cookie": ""}).looks_authenticated()
    assert ObservedExchange("GET", "u", request_headers={"Authorization": ""}).looks_authenticated()
    assert ObservedExchange("GET", "u", request_headers={"VerifyAuthToken": ""}).looks_authenticated()
    # No auth header name -> unauthenticated, regardless of other headers.
    assert not ObservedExchange("GET", "u", request_headers={"content-type": "x"}).looks_authenticated()
    assert not ObservedExchange("GET", "u", request_headers={}).looks_authenticated()


def test_request_is_authenticated_helper():
    assert auth_signals.request_is_authenticated(["Content-Type", "Cookie"]) is True
    assert auth_signals.request_is_authenticated(["content-type", "accept"]) is False


# --- the capture FIX: Playwright sync .headers drops Cookie; all_headers keeps it

class _FakeReq:
    def __init__(self, headers): self._h = headers; self.method = "GET"; self.url = "https://app.local.test/x"
    async def all_headers(self): return self._h


class _FakeResp:
    def __init__(self, req, headers, body="<html></html>"):
        self.request = req; self._h = headers; self.status = 200
        self.url = "https://app.local.test/x"; self._body = body
    async def all_headers(self): return self._h
    async def text(self): return self._body


def test_capture_observes_cookie_name_and_redacts_value():
    backend = PlaywrightBackend()
    backend._page = type("P", (), {"url": "https://app.local.test/x"})()
    resp = _FakeResp(
        _FakeReq({"cookie": SECRET, "content-type": "text/html"}),
        {"content-type": "text/html", "set-cookie": SECRET})
    asyncio.run(backend._on_response(resp))
    ex = backend._buffer[0]
    # The auth header NAME is now observed (the whole point of all_headers)...
    assert "cookie" in {k.lower() for k in ex.request_headers}
    assert ex.looks_authenticated() is True
    # ...and the VALUE is redacted everywhere — no secret stored.
    assert SECRET not in json.dumps(ex.request_headers)
    assert SECRET not in json.dumps(ex.response_headers)
    assert ex.request_headers["cookie"] == ""


def test_capture_unauthenticated_when_no_auth_header():
    backend = PlaywrightBackend()
    backend._page = type("P", (), {"url": "https://app.local.test/x"})()
    resp = _FakeResp(_FakeReq({"content-type": "text/html"}), {"content-type": "text/html"})
    asyncio.run(backend._on_response(resp))
    assert backend._buffer[0].looks_authenticated() is False


def test_backend_uses_all_headers_not_sync_headers():
    # Structural guard against regressing to the sync accessor that strips Cookie.
    src = inspect.getsource(pwb)
    assert "all_headers()" in src


def test_build_exchange_is_pure_and_redacts():
    ex = PlaywrightBackend()._build_exchange(
        method="GET", url="u", status=200,
        req_headers={"Cookie": SECRET}, resp_headers={"Set-Cookie": SECRET},
        body=None, source_page=None)
    assert ex.looks_authenticated() and ex.request_headers["Cookie"] == ""
    assert SECRET not in json.dumps([ex.request_headers, ex.response_headers])


# --- non-secret page/UI login signal ------------------------------------------

def test_page_login_signal():
    assert auth_signals.page_login_signal(
        "<a href='/account'>My account</a><a>Sign out</a>") == "logged_in"
    assert auth_signals.page_login_signal(
        "<form><input type='password'></form> Sign in") == "logged_out"
    assert auth_signals.page_login_signal("<div id='root'></div>") == "unknown"
    assert auth_signals.page_login_signal("") == "unknown"


# =========================================================================
# 2) MULTI-ORIGIN SEEDING
# =========================================================================

def test_seed_origins_from_temu_scope_are_the_four_web_assets():
    temu = ProgramManager(load_program(TEMU_YAML))
    origins = seed_origins_from_scope(temu)
    assert origins == [
        "https://www.temu.com/",
        "https://seller.temu.com/",
        "https://partner.temu.com/",
        "https://ads.temu.com/",
    ]
    # Never a wildcard, never a mobile/App-Store id.
    assert not any("*" in o for o in origins)
    assert not any("einnovation" in o or "1641486558" in o for o in origins)


def test_seed_origins_skip_wildcard_and_cidr():
    prog = ProgramManager(ProgramConfig(
        name="mixed", authorized=True,
        scope=ScopeConfig(in_scope=[
            ScopeRule(kind=ScopeKind.DOMAIN, value="a.example.test"),
            ScopeRule(kind=ScopeKind.WILDCARD, value="*.example.test"),
            ScopeRule(kind=ScopeKind.URL_PREFIX, value="https://api.example.test/v1/"),
            ScopeRule(kind=ScopeKind.CIDR, value="10.0.0.0/24"),
        ])))
    assert seed_origins_from_scope(prog) == [
        "https://a.example.test/", "https://api.example.test/v1/"]


class MultiOriginBackend(BrowserBackend):
    """Emits one in-scope HTML document for whatever URL it is told to visit."""

    def __init__(self) -> None:
        self._buf: list[ObservedExchange] = []

    async def start(self) -> None: self._buf.clear()
    async def close(self) -> None: self._buf.clear()

    async def goto(self, url: str) -> None:
        self._buf.append(ObservedExchange(
            "GET", url.split("#", 1)[0], status=200,
            request_headers={"cookie": ""}, response_headers={"Content-Type": "text/html"},
            response_body="<html><body>ok</body></html>", identity_label="researcher"))

    async def click(self, selector: str) -> None: return None
    async def type_text(self, selector: str, text: str) -> None: return None
    async def scroll(self, selector: str | None = None, amount: int = 3) -> None: return None

    async def drain(self) -> list[ObservedExchange]:
        out = self._buf; self._buf = []; return out


def test_explorer_visits_all_configured_origins_when_seeded():
    program = ProgramManager(ProgramConfig(
        name="four-origins", authorized=True,
        scope=ScopeConfig(in_scope=[
            ScopeRule(kind=ScopeKind.DOMAIN, value="www.site.test"),
            ScopeRule(kind=ScopeKind.DOMAIN, value="seller.site.test"),
            ScopeRule(kind=ScopeKind.DOMAIN, value="partner.site.test"),
            ScopeRule(kind=ScopeKind.DOMAIN, value="ads.site.test"),
        ])))
    db = Database(":memory:")
    surface = SurfaceStore(db)
    controller = BrowserController(program, surface, MultiOriginBackend(),
                                   default_identity=AuthIdentity.IDENTITY_A,
                                   identity_map={"researcher": AuthIdentity.IDENTITY_A})
    explorer = AutonomousExplorer(controller, surface,
                                  limits=ExplorationLimits(max_no_progress=8))
    seeds = seed_origins_from_scope(program)
    summary = asyncio.run(explorer.run(seeds))

    from urllib.parse import urlsplit
    hosts = {urlsplit(e.url).hostname for e in surface.list_endpoints(program.name)}
    assert hosts == {"www.site.test", "seller.site.test", "partner.site.test", "ads.site.test"}
    assert summary.pages_visited == 4
    assert summary.authenticated_endpoints == 4      # all observed authenticated
    db.close()
