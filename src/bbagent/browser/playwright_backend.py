"""Real browser backend built on Playwright (optional dependency).

Playwright is imported lazily so the package works without it. Install with:

    pip install "bbagent[browser]"
    playwright install chromium

The backend subscribes to network *responses* and turns each into an
:class:`ObservedExchange`. Authentication material is stripped at capture time:
we keep only the *names* of auth headers (so identity can be inferred) and drop
their values — cookies/tokens/passwords never leave the browser process. The
backend never exports cookies or persists storage state.
"""

from __future__ import annotations

from bbagent.browser.controller import BrowserBackend
from bbagent.browser.models import ObservedExchange
from bbagent.logging_config import get_logger

log = get_logger(__name__)

# Header names whose VALUES must never be captured. We keep the name with an empty
# value so ObservedExchange.looks_authenticated() still works, without the secret.
_AUTH_HEADER_NAMES = {
    "authorization", "cookie", "set-cookie", "verifyauthtoken", "x-verify-auth-token",
    "x-api-key", "x-auth-token", "proxy-authorization",
}
# Response bodies are only read for these content types (avoids binary/huge assets).
_TEXTUAL = ("application/json", "text/", "application/javascript",
            "application/xml", "application/x-www-form-urlencoded")


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        out[k] = "" if k.lower() in _AUTH_HEADER_NAMES else v
    return out


def _is_textual(content_type: str | None) -> bool:
    ct = (content_type or "").lower()
    return any(t in ct for t in _TEXTUAL)


class PlaywrightBackend(BrowserBackend):
    def __init__(self, *, headless: bool = True, user_data_dir: str | None = None,
                 identity_label: str = "researcher",
                 extra_http_headers: dict[str, str] | None = None):
        self._headless = headless
        #: Context-level headers applied to EVERY browser request (e.g. the non-secret
        #: X-HackerOne-Research identifier). Must NEVER contain session/secret values
        #: (Cookie/VerifyAuthToken/Authorization/…) — those come from the profile.
        self._extra_http_headers = dict(extra_http_headers or {})
        #: Persistent Chromium profile directory. When set, the browser launches
        #: with the operator's already-authenticated profile (their manual Temu
        #: login). The agent only POINTS the browser at this directory — it never
        #: reads, copies, uploads, logs, or persists its contents.
        self._user_data_dir = user_data_dir
        self._buffer: list[ObservedExchange] = []
        self._pw = None
        self._browser = None
        self._context = None
        self._page = None
        self._identity_label: str | None = identity_label

    @property
    def uses_persistent_profile(self) -> bool:
        return bool(self._user_data_dir)

    @property
    def user_data_dir(self) -> str | None:
        return self._user_data_dir

    async def start(self) -> None:
        try:
            from playwright.async_api import async_playwright  # lazy import
        except ImportError as exc:  # pragma: no cover - exercised only without playwright
            raise RuntimeError(
                "Playwright is not installed. Install with: pip install \"bbagent[browser]\" "
                "&& playwright install chromium"
            ) from exc

        self._pw = await async_playwright().start()
        # Context-level headers (non-secret identifier only) ride every request. The
        # authenticated session still comes solely from the persistent profile.
        extra = self._extra_http_headers or None
        if self._user_data_dir:
            # Reuse the operator's persistent, pre-authenticated profile. We never
            # export storage_state or read cookies from it.
            self._context = await self._pw.chromium.launch_persistent_context(
                self._user_data_dir, headless=self._headless, extra_http_headers=extra)
            self._browser = None  # the persistent context owns the browser process
            self._page = (self._context.pages[0] if self._context.pages
                          else await self._context.new_page())
        else:
            self._browser = await self._pw.chromium.launch(headless=self._headless)
            self._context = await self._browser.new_context(extra_http_headers=extra)
            self._page = await self._context.new_page()
        self._page.on("response", self._on_response)

    async def _on_response(self, response) -> None:
        try:
            request = response.request
            # IMPORTANT: use the ASYNC all_headers(). Playwright's sync .headers
            # accessor omits security headers — notably Cookie — so the auth-header
            # NAME the classifier needs would be missing and every request would look
            # unauthenticated. all_headers() includes them; _redact_headers then keeps
            # the NAMES and blanks the VALUES, so no secret is ever stored.
            try:
                req_headers = await request.all_headers()
            except Exception:  # noqa: BLE001 - fall back to sync (still redacted)
                req_headers = dict(request.headers)
            try:
                resp_headers = await response.all_headers()
            except Exception:  # noqa: BLE001
                resp_headers = dict(response.headers)
            ct = resp_headers.get("content-type")
            body: str | None = None
            if _is_textual(ct):
                try:
                    body = await response.text()
                except Exception:  # noqa: BLE001 - body may be unavailable
                    body = None
            self._buffer.append(self._build_exchange(
                method=request.method, url=response.url, status=response.status,
                req_headers=req_headers, resp_headers=resp_headers, body=body,
                source_page=self._page.url if self._page else None,
            ))
        except Exception as exc:  # noqa: BLE001 - capture must never break the session
            log.warning("browser.capture_error", error=str(exc))

    def _build_exchange(self, *, method, url, status, req_headers, resp_headers, body,
                        source_page) -> ObservedExchange:
        """Build a redacted ObservedExchange (auth header NAMES kept, VALUES blanked).

        Pure and side-effect-free so the capture/redaction logic is unit-testable
        without a real browser. Never stores cookie/token/authorization values.
        """
        return ObservedExchange(
            method=method, url=url, status=status,
            request_headers=_redact_headers(dict(req_headers)),
            request_body=None,
            response_headers=_redact_headers(dict(resp_headers)),
            response_body=body, source_page=source_page,
            identity_label=self._identity_label,
        )

    async def goto(self, url: str) -> None:  # pragma: no cover - needs a browser
        await self._page.goto(url)

    async def goto_capture(self, url: str) -> dict | None:  # pragma: no cover - needs a browser
        """Navigate and return the Response page.goto() yields, as a sanitized dict.

        Captures the real status/body even across redirects/URL normalization. Header
        VALUES are redacted (names kept); cookies/tokens are never returned. Returns
        None if goto() produced no Response (caller falls back to captured events)."""
        resp = await self._page.goto(url)
        if resp is None:
            return None
        try:
            headers = await resp.all_headers()
        except Exception:  # noqa: BLE001 - fall back to sync headers (still redacted)
            headers = dict(getattr(resp, "headers", {}) or {})
        ct = headers.get("content-type")
        body = ""
        if _is_textual(ct):
            try:
                body = await resp.text()
            except Exception:  # noqa: BLE001 - body may be unavailable
                body = ""
        return {
            "status": resp.status,
            "body": body,
            "content_type": ct,
            "response_headers": _redact_headers(dict(headers)),   # values blanked
            "final_url": resp.url,
        }

    async def click(self, selector: str) -> None:  # pragma: no cover - needs a browser
        await self._page.click(selector)

    async def type_text(self, selector: str, text: str) -> None:  # pragma: no cover
        await self._page.fill(selector, text)

    async def scroll(self, selector: str | None = None, amount: int = 3) -> None:  # pragma: no cover
        await self._page.mouse.wheel(0, 800 * max(1, amount))

    async def drain(self) -> list[ObservedExchange]:
        out = self._buffer
        self._buffer = []
        return out

    async def close(self) -> None:  # pragma: no cover - needs a browser
        # Deliberately do NOT export cookies or storage_state.
        if self._context is not None:
            await self._context.close()
        if self._browser is not None:
            await self._browser.close()
        if self._pw is not None:
            await self._pw.stop()
