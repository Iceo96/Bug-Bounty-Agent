"""BrowserIdentityFetcher.fetch now uses the Response returned by page.goto() as the
primary observation (handling redirects/URL normalization that previously yielded
status=0), falling back to captured network events only when goto() returns None.
No real browser, no network, no Temu — a mock backend simulates goto_capture/drain.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path

import pytest

from bbagent.browser.controller import BrowserBackend
from bbagent.browser.models import ObservedExchange
from bbagent.browser import playwright_backend as pwb
from bbagent.config.loader import load_program
from bbagent.program.manager import ProgramManager
from bbagent.verification.browser_idor import AccessObservation, BrowserIdentityFetcher

TEMU_YAML = str(Path(__file__).resolve().parents[1] / "programs" / "temu.yaml")
URL = "https://ads.temu.com/api/phantom/xg/pfb/b"


class NavBackend(BrowserBackend):
    """Mock backend exposing goto_capture (dict|None) and captured events for drain."""

    def __init__(self, *, nav=None, captured=None):
        self._nav = nav
        self._captured = list(captured or [])
        self.started = False
        self.closed = False

    async def start(self): self.started = True
    async def close(self): self.closed = True
    async def goto_capture(self, url): return self._nav
    async def goto(self, url): pass
    async def click(self, s): pass
    async def type_text(self, s, t): pass
    async def scroll(self, s=None, amount=3): pass
    async def drain(self):
        out = self._captured; self._captured = []; return out


@pytest.fixture
def fetcher(monkeypatch, tmp_path):
    monkeypatch.setenv("BBAGENT_H1_USERNAME", "h1-handle")
    monkeypatch.setenv("BBAGENT_TEMU_PROFILE_A", str(tmp_path / "A"))
    monkeypatch.setenv("BBAGENT_TEMU_PROFILE_B", str(tmp_path / "B"))
    return BrowserIdentityFetcher(ProgramManager(load_program(TEMU_YAML)))


def _swap(fetcher, backend, label="researcher"):
    fetcher._backends[label] = backend
    fetcher._started = set()
    return fetcher


def _run(coro):
    return asyncio.run(coro)


# 1. page.goto() returns a normal response -> status/body captured ---------------

def test_goto_response_captured(fetcher):
    nav = {"status": 200, "body": json.dumps({"x": 1}),
           "content_type": "application/json",
           "response_headers": {"content-type": "application/json"}, "final_url": URL}
    _swap(fetcher, NavBackend(nav=nav))
    obs = _run(fetcher.fetch("researcher", URL))
    assert obs.status == 200 and obs.body == json.dumps({"x": 1})
    assert obs.url == URL


# 2. final URL differs (redirect/normalized) -> still captured -------------------

def test_goto_response_captured_even_when_final_url_differs(fetcher):
    nav = {"status": 200, "body": json.dumps({"x": 1}),
           "content_type": "application/json", "response_headers": {},
           "final_url": URL + "?region=us"}   # differs from requested URL
    _swap(fetcher, NavBackend(nav=nav))
    obs = _run(fetcher.fetch("researcher", URL))
    assert obs.status == 200 and obs.body == json.dumps({"x": 1})   # no exact-match needed
    assert obs.url == URL + "?region=us"


# 3. goto() returns None -> fallback to captured events --------------------------

def test_fallback_to_captured_events_when_goto_none(fetcher):
    captured = [ObservedExchange("GET", URL, status=200,
                                 response_headers={"Content-Type": "application/json"},
                                 response_body=json.dumps({"x": 2}))]
    _swap(fetcher, NavBackend(nav=None, captured=captured))
    obs = _run(fetcher.fetch("researcher", URL))
    assert obs.status == 200 and obs.body == json.dumps({"x": 2})


# 4. None + no matching captured response -> status 0 remains --------------------

def test_status_zero_when_no_response_at_all(fetcher):
    _swap(fetcher, NavBackend(nav=None, captured=[]))
    obs = _run(fetcher.fetch("researcher", URL))
    assert obs.status == 0 and obs.body == ""


# 5. sensitive headers remain redacted -------------------------------------------

def test_evidence_redacts_sensitive_headers():
    obs = AccessObservation("researcher", URL, 200, json.dumps({"x": 1}),
                            response_headers={"Set-Cookie": "sid=SECRET", "content-type": "application/json"})
    ex = obs.to_exchange()
    assert "SECRET" not in json.dumps(ex.response_headers)
    assert ex.response_headers.get("Set-Cookie") == ""


def test_goto_capture_source_redacts_headers():
    # The real backend redacts header VALUES at the source (names kept).
    src = inspect.getsource(pwb.PlaywrightBackend.goto_capture)
    assert "_redact_headers(" in src
    assert "resp.text()" in src and "resp.status" in src


# 6. Profile A/B behavior unchanged ----------------------------------------------

def test_profiles_still_isolated(fetcher):
    assert set(fetcher.identities()) == {"researcher", "researcher_b"}
    a = fetcher._backends["researcher"].user_data_dir
    b = fetcher._backends["researcher_b"].user_data_dir
    assert a and b and a != b
