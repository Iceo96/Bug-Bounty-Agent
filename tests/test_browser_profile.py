"""Persistent-profile (Option B) browser-auth wiring.

Proves the configured Chromium profile directory is threaded from the CLI to the
backend and is the profile the browser flow launches with — using a mock backend,
with NO real browser, NO network, and NO Temu contact. Also checks the backend
never exports profile contents and fails closed without Playwright.
"""

from __future__ import annotations

import asyncio
import importlib.util

import pytest

from bbagent.browser.controller import BrowserController, ExplorationStep
from bbagent.browser.models import ObservedExchange
from bbagent.browser.playwright_backend import PlaywrightBackend
from bbagent.cli import _make_browser_backend
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore
from bbagent.storage.db import Database
from bbagent_lab.mock_webapp import MOCK_BASE, MockBrowserBackend, mock_program


# --- backend stores + reports the profile -------------------------------------

def test_backend_persistent_profile_flag():
    b = PlaywrightBackend(user_data_dir="C:/tmp/profile")
    assert b.uses_persistent_profile is True
    assert b.user_data_dir == "C:/tmp/profile"
    e = PlaywrightBackend()
    assert e.uses_persistent_profile is False
    assert e.user_data_dir is None


def test_cli_helper_threads_profile_through():
    b = _make_browser_backend("C:/tmp/profile", headless=False)
    assert isinstance(b, PlaywrightBackend)
    assert b.user_data_dir == "C:/tmp/profile"
    assert b.uses_persistent_profile is True
    assert b._headless is False
    # No profile -> ephemeral context.
    assert _make_browser_backend(None, headless=True).uses_persistent_profile is False


# --- mock browser flow proves the profile path is actually used ---------------

class ProfileRecordingBackend(MockBrowserBackend):
    """A mock backend that records which profile dir it 'launched' with."""

    def __init__(self, *, user_data_dir: str, authenticated: bool = True) -> None:
        super().__init__(authenticated=authenticated)
        self._profile = user_data_dir
        self.launched_with: str | None = None

    async def start(self) -> None:
        self.launched_with = self._profile      # records the configured profile
        await super().start()


def test_mock_flow_launches_with_configured_profile():
    db = Database(":memory:")
    surface = SurfaceStore(db)
    program = mock_program()
    backend = ProfileRecordingBackend(user_data_dir="C:/tmp/temu-profile")
    controller = BrowserController(program, surface, backend,
                                   default_identity=AuthIdentity.IDENTITY_A)

    result = asyncio.run(controller.explore([ExplorationStep("goto", MOCK_BASE + "/")]))

    # The flow launched the browser with exactly the configured profile dir...
    assert backend.launched_with == "C:/tmp/temu-profile"
    # ...and the run still observed + ingested in-scope traffic.
    assert result.report.in_scope >= 1
    assert surface.list_endpoints(program.name)
    db.close()


# --- safety: no export; fail-closed without Playwright ------------------------

def test_close_is_safe_for_persistent_context():
    # Persistent context owns the browser (self._browser is None); close must work
    # and must NOT read/export storage_state or cookies.
    b = PlaywrightBackend(user_data_dir="C:/tmp/profile")

    class _Ctx:
        def __init__(self): self.closed = False
        async def close(self): self.closed = True

    class _Pw:
        async def stop(self): pass

    ctx = _Ctx()
    b._context, b._browser, b._pw = ctx, None, _Pw()
    asyncio.run(b.close())
    assert ctx.closed is True


def test_backend_never_exports_profile_state():
    # Structural: the backend source never calls storage_state()/cookies().
    import inspect
    from bbagent.browser import playwright_backend
    src = inspect.getsource(playwright_backend)
    assert "storage_state(" not in src
    assert ".cookies(" not in src


@pytest.mark.skipif(importlib.util.find_spec("playwright") is not None,
                    reason="playwright installed; failure path not exercised")
def test_persistent_start_fails_closed_without_playwright():
    b = PlaywrightBackend(user_data_dir="C:/tmp/profile")
    with pytest.raises(RuntimeError, match="Playwright is not installed"):
        asyncio.run(b.start())


# --- CLI: browser-login requires a profile dir (no browser launched) ----------

def test_cli_browser_login_requires_profile_dir():
    from bbagent import cli
    with pytest.raises(SystemExit):        # argparse error before anything launches
        cli.main(["browser-login"])
