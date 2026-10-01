"""Deterministic in-memory mock web application + browser backend for tests.

This is the local "web application" the browser-controller and autonomous-explorer
tests drive. It never opens a socket or contacts any real service: it models a
small app as a routing table and produces :class:`ObservedExchange` objects exactly
as a browser's network capture would, in response to navigate/click/type/scroll.

It deliberately exercises:
  * unauthenticated vs authenticated traffic (login sets a session cookie; the
    autonomous explorer instead assumes an already-authenticated session),
  * discoverable affordances in the page HTML (links, a form, ``data-explore``
    buttons, a search input) so the explorer can act without a fixed script,
  * in-scope JSON APIs returning id-like objects (IDOR/SQLi surface, not tested),
  * an in-scope JS asset,
  * an OUT-OF-SCOPE third-party analytics beacon (must be dropped fail-closed),
  * a secret session cookie that must NEVER be persisted.
"""

from __future__ import annotations

import json

from bbagent.browser.controller import BrowserBackend
from bbagent.browser.models import ObservedExchange
from bbagent.config.models import ProgramConfig, ScopeConfig, ScopeKind, ScopeRule
from bbagent.program.manager import ProgramManager

MOCK_HOST = "app.local.test"
MOCK_BASE = f"https://{MOCK_HOST}"
SECRET_COOKIE = "sid=MOCK_SECRET_SESSION_do_not_persist"
OUT_OF_SCOPE_BEACON = "https://analytics.example.net/collect?e=pageview"

_HOME_HTML = (
    "<html><title>Home</title>"
    "<a href='/dashboard'>dash</a>"
    "<form action='/login' method='post'>"
    "<input name='username'><input name='password'>"
    "<button data-explore='login'>Login</button></form>"
    "<input name='q'>"
    "<button data-explore='search'>Search</button>"
    "<button data-explore='orders'>Load orders</button>"
    "</html>"
)


def mock_program(name: str = "mock-webapp") -> ProgramManager:
    """A program scoped to the mock app only (exact host, fail-closed elsewhere)."""
    return ProgramManager(ProgramConfig(
        name=name, authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value=MOCK_HOST)]),
    ))


def _ex(method: str, url: str, status: int, *, ct: str | None, body: str | None,
        authed: bool, referer: str | None) -> ObservedExchange:
    req_headers: dict[str, str] = {}
    if referer:
        req_headers["Referer"] = referer
    if authed:
        req_headers["Cookie"] = SECRET_COOKIE            # secret — never persisted
    resp_headers = {"Server": "mock/1.0"}
    if ct:
        resp_headers["Content-Type"] = ct
    return ObservedExchange(
        method=method, url=url, status=status,
        request_headers=req_headers, response_headers=resp_headers,
        response_body=body, source_page=referer, identity_label="researcher",
    )


class MockBrowserBackend(BrowserBackend):
    """A browser backend that serves the mock app from memory (no sockets)."""

    def __init__(self, *, authenticated: bool = False) -> None:
        self._buf: list[ObservedExchange] = []
        self._authed = authenticated
        self._typed: dict[str, str] = {}
        self._page = MOCK_BASE + "/"

    # BrowserBackend -----------------------------------------------------------

    async def start(self) -> None:
        self._buf.clear()

    async def close(self) -> None:
        # Never persists cookies/storage — nothing to tear down.
        self._typed.clear()

    async def goto(self, url: str) -> None:
        self._page = url
        base = url.split("#", 1)[0].rstrip("/")
        if base == MOCK_BASE:  # home page
            self._buf.append(_ex("GET", MOCK_BASE + "/", 200, ct="text/html",
                                 body=_HOME_HTML, authed=self._authed, referer=None))
            self._buf.append(_ex("GET", MOCK_BASE + "/static/app.js", 200,
                                 ct="application/javascript", body="fetch('/api/orders')",
                                 authed=self._authed, referer=MOCK_BASE + "/"))
            # OUT-OF-SCOPE analytics beacon (must be dropped).
            self._buf.append(_ex("GET", OUT_OF_SCOPE_BEACON, 204, ct=None, body=None,
                                 authed=False, referer=MOCK_BASE + "/"))
        elif base == MOCK_BASE + "/dashboard":
            if self._authed:
                self._buf.append(_ex("GET", MOCK_BASE + "/dashboard", 200, ct="text/html",
                                     body="<html><title>Dashboard</title>"
                                          "<a href='/'>home</a></html>",
                                     authed=True, referer=self._page))
            else:
                self._buf.append(_ex("GET", MOCK_BASE + "/dashboard", 401, ct="text/html",
                                     body="<html>login required</html>",
                                     authed=False, referer=self._page))
        else:
            # An observed in-scope URL navigated as a document but not a real page.
            self._buf.append(_ex("GET", url.split("#", 1)[0], 404, ct="text/html",
                                 body="<html>not found</html>",
                                 authed=self._authed, referer=self._page))

    async def click(self, selector: str) -> None:
        if selector in ("login", "#login", "button[type=submit]"):
            self._authed = True
            self._buf.append(_ex("POST", MOCK_BASE + "/login", 200, ct="application/json",
                                 body=json.dumps({"ok": True}), authed=True, referer=self._page))
        elif selector in ("orders", "#load-orders"):
            if self._authed:
                body = json.dumps({"orders": [{"id": 9001, "owner_id": "u-1"},
                                              {"id": 9002, "owner_id": "u-2"}]})
                self._buf.append(_ex("GET", MOCK_BASE + "/api/orders", 200,
                                     ct="application/json", body=body,
                                     authed=True, referer=self._page))
            else:
                self._buf.append(_ex("GET", MOCK_BASE + "/api/orders", 401,
                                     ct="application/json", body=json.dumps({"error": "auth"}),
                                     authed=False, referer=self._page))
        elif selector in ("search", "#search"):
            q = self._typed.get("#q", "")
            body = json.dumps({"results": [{"id": 7001}, {"id": 7002}], "q": q})
            self._buf.append(_ex("GET", MOCK_BASE + f"/api/search?q={q}", 200,
                                 ct="application/json", body=body,
                                 authed=self._authed, referer=self._page))

    async def type_text(self, selector: str, text: str) -> None:
        # Store the typed value; it is NEVER emitted into an exchange or a log.
        self._typed[selector] = text

    async def scroll(self, selector: str | None = None, amount: int = 3) -> None:
        if self._authed:
            body = json.dumps({"orders": [{"id": 9003, "owner_id": "u-3"}], "page": 2})
            self._buf.append(_ex("GET", MOCK_BASE + "/api/orders?page=2", 200,
                                 ct="application/json", body=body,
                                 authed=True, referer=self._page))

    async def drain(self) -> list[ObservedExchange]:
        out = self._buf
        self._buf = []
        return out
