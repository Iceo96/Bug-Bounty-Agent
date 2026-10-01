"""A browser backend that OBSERVES the local vulnerable lab.

Models an authenticated user's browser session against the loopback lab: loading
the site + JS, and the XHRs the app issues as the user navigates (notes, profile,
admin, products, search). It produces :class:`ObservedExchange` objects only — it
never opens a socket. The URLs are the lab's own endpoints (observed, not invented);
the real ACTIVE tests against them run later through PolicyGatedHTTP on the
AuthorizedHTTPClient.

Authentication material is represented only so the traffic reads as authenticated
(``Authorization`` header present); its value is a placeholder and is never
persisted by the ingestor.
"""

from __future__ import annotations

import json

from bbagent.browser.controller import BrowserBackend
from bbagent.browser.models import ObservedExchange

_SITE_HTML = (
    "<!doctype html><html><head><title>Lab Portal</title>"
    "<script src='/static/app.js'></script></head><body>"
    "<a href='/site/about'>About</a><a href='/site/notes'>Notes</a>"
    "<form action='/api/search' method='get'>"
    "<input name='q'><input name='page'><input name='limit'></form>"
    "</body></html>"
)
_APP_JS = "const API='/api'; fetch('/api/notes/note-a1'); fetch('/api/profile/1001');"


class LabBrowserBackend(BrowserBackend):
    def __init__(self, base_url: str, *, identity_label: str = "researcher") -> None:
        self._base = base_url.rstrip("/")
        self._label = identity_label
        self._buf: list[ObservedExchange] = []

    def _ex(self, method: str, path: str, status: int, *, ct: str, body: str | None,
            referer: str | None) -> ObservedExchange:
        url = path if path.startswith("http") else self._base + path
        return ObservedExchange(
            method=method, url=url, status=status,
            request_headers={"Authorization": "Bearer PLACEHOLDER",
                             **({"Referer": referer} if referer else {})},
            response_headers={"Content-Type": ct, "Server": "lab"},
            response_body=body, source_page=referer, identity_label=self._label,
        )

    def _session(self) -> None:
        site = self._base + "/site"
        self._buf.append(self._ex("GET", "/site", 200, ct="text/html", body=_SITE_HTML, referer=None))
        self._buf.append(self._ex("GET", "/static/app.js", 200, ct="application/javascript",
                                  body=_APP_JS, referer=site))
        # Authenticated XHRs the app performs as the user navigates (object-scoped,
        # function-level, and query-parameter endpoints — the lab's real surface).
        self._buf.append(self._ex("GET", "/api/notes/note-a1", 200, ct="application/json",
                                  body=json.dumps({"note": {"id": "note-a1", "owner": "user_a"}}),
                                  referer=site))
        self._buf.append(self._ex("GET", "/api/profile/1001", 200, ct="application/json",
                                  body=json.dumps({"profile": {"id": "1001", "owner": "user_a"}}),
                                  referer=site))
        self._buf.append(self._ex("GET", "/api/admin/report", 200, ct="application/json",
                                  body=json.dumps({"report": "restricted"}), referer=site))
        self._buf.append(self._ex("GET", "/api/admin/settings", 200, ct="application/json",
                                  body=json.dumps({"settings": "restricted"}), referer=site))
        self._buf.append(self._ex("GET", "/api/admin/ping", 200, ct="application/json",
                                  body=json.dumps({"ok": True}), referer=site))
        self._buf.append(self._ex("GET", "/products?id=1", 200, ct="application/json",
                                  body=json.dumps({"products": [{"sku": 1}], "count": 1}), referer=site))
        self._buf.append(self._ex("GET", "/products-safe?id=1", 200, ct="application/json",
                                  body=json.dumps({"products": [{"sku": 1}], "count": 1}), referer=site))
        self._buf.append(self._ex("GET", "/whoami?id=1", 200, ct="application/json",
                                  body=json.dumps({"records": [{"echo": "1"}]}), referer=site))
        self._buf.append(self._ex("GET", "/search?q=probe", 200, ct="text/html",
                                  body="<html><body>Results for: probe</body></html>", referer=site))

    async def start(self) -> None:
        self._buf.clear()

    async def close(self) -> None:
        self._buf.clear()

    async def goto(self, url: str) -> None:
        base = url.split("#", 1)[0].rstrip("/")
        if base in (self._base, self._base + "/site"):
            self._session()
        else:
            # Any other observed in-scope URL navigated as a document.
            self._buf.append(self._ex("GET", url, 200, ct="application/json",
                                      body="{}", referer=self._base + "/site"))

    async def click(self, selector: str) -> None:  # lab session is XHR/nav-driven
        return None

    async def type_text(self, selector: str, text: str) -> None:
        return None

    async def scroll(self, selector: str | None = None, amount: int = 3) -> None:
        return None

    async def drain(self) -> list[ObservedExchange]:
        out = self._buf
        self._buf = []
        return out
