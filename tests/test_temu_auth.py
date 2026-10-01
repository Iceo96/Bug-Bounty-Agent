"""Temu session-auth mismatch fix: Cookie + VerifyAuthToken (+ X-HackerOne-Research)
are injected from environment variables, cannot be overridden, fail closed when
missing, and never leak into sanitized output / evidence / reports. No network."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from bbagent.config.loader import load_program
from bbagent.config.models import (
    ProgramConfig, RateLimit, ScopeConfig, ScopeKind, ScopeRule, TestingRestrictions,
)
from bbagent.http.client import AuthorizedHTTPClient, HTTPExchange, RequestBlocked
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.tools.http_tool import HttpArgs, HttpTool
from bbagent.tools.context import ToolContext

TEMU_YAML = str(Path(__file__).resolve().parents[1] / "programs" / "temu.yaml")

COOKIE_ENV = "BBAGENT_TEMU_COOKIE"
VAT_ENV = "BBAGENT_TEMU_VERIFY_AUTH_TOKEN"
H1_ENV = "BBAGENT_H1_USERNAME"
COOKIE_VALUE = "session=SECRET_COOKIE_VALUE_do_not_leak"
VAT_VALUE = "SECRET_VERIFY_AUTH_TOKEN_do_not_leak"
H1_VALUE = "researcher-handle"


class CapturingTransport(httpx.MockTransport):
    """Records the headers of the last request that reached transport."""

    def __init__(self):
        self.calls = 0
        self.last_headers: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            self.calls += 1
            self.last_headers = {k.lower(): v for k, v in request.headers.items()}
            return httpx.Response(200, headers={"content-type": "application/json"}, text="{}")
        super().__init__(handler)


def _mirror_program():
    """A runnable loopback program mirroring Temu's session-auth required headers."""
    return ProgramConfig(
        name="temu-auth-mirror", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="127.0.0.1")]),
        restrictions=TestingRestrictions(allowed_methods=["GET"]),
        rate_limit=RateLimit(requests_per_second=100, max_concurrent=8),
        required_header_refs={
            "X-HackerOne-Research": H1_ENV,
            "Cookie": COOKIE_ENV,
            "VerifyAuthToken": VAT_ENV,
        },
    )


@pytest.fixture
def creds(monkeypatch):
    monkeypatch.setenv(COOKIE_ENV, COOKIE_VALUE)
    monkeypatch.setenv(VAT_ENV, VAT_VALUE)
    monkeypatch.setenv(H1_ENV, H1_VALUE)


# --- programs/temu.yaml declares the right env-referenced headers -------------

def test_temu_yaml_declares_session_headers():
    temu = load_program(TEMU_YAML)
    assert temu.required_header_refs == {
        "X-HackerOne-Research": "BBAGENT_H1_USERNAME",
        "Cookie": "BBAGENT_TEMU_COOKIE",
        "VerifyAuthToken": "BBAGENT_TEMU_VERIFY_AUTH_TOKEN",
    }
    # No per-account bearer token, and no reference to the old env var anywhere.
    assert all(a.secret_env is None for a in temu.test_accounts)
    assert "BBAGENT_TEMU_TOKEN" not in Path(TEMU_YAML).read_text(encoding="utf-8")


# --- injection from env -------------------------------------------------------

async def test_headers_injected_from_env(creds):
    t = CapturingTransport()
    async with AuthorizedHTTPClient(_mirror_program(), transport=t) as http:
        await http.get("http://127.0.0.1/x")
    assert t.last_headers["cookie"] == COOKIE_VALUE
    assert t.last_headers["verifyauthtoken"] == VAT_VALUE
    assert t.last_headers["x-hackerone-research"] == H1_VALUE


async def test_caller_cannot_override_auth_headers(creds):
    t = CapturingTransport()
    async with AuthorizedHTTPClient(_mirror_program(), transport=t) as http:
        # Attempt to override with different case + value; env value must win.
        await http.get("http://127.0.0.1/x", headers={"cookie": "attacker",
                                                       "VerifyAuthToken": "attacker",
                                                       "X-HackerOne-Research": "attacker"})
    assert t.last_headers["cookie"] == COOKIE_VALUE
    assert t.last_headers["verifyauthtoken"] == VAT_VALUE
    assert t.last_headers["x-hackerone-research"] == H1_VALUE
    assert "attacker" not in json.dumps(t.last_headers)


# --- fail closed when missing (before transport) ------------------------------

async def test_missing_cookie_blocks_before_transport(monkeypatch):
    monkeypatch.setenv(VAT_ENV, VAT_VALUE)
    monkeypatch.setenv(H1_ENV, H1_VALUE)
    monkeypatch.delenv(COOKIE_ENV, raising=False)
    t = CapturingTransport()
    async with AuthorizedHTTPClient(_mirror_program(), transport=t) as http:
        with pytest.raises(RequestBlocked):
            await http.get("http://127.0.0.1/x")
    assert t.calls == 0


async def test_missing_verify_auth_token_blocks_before_transport(monkeypatch):
    monkeypatch.setenv(COOKIE_ENV, COOKIE_VALUE)
    monkeypatch.setenv(H1_ENV, H1_VALUE)
    monkeypatch.delenv(VAT_ENV, raising=False)
    t = CapturingTransport()
    async with AuthorizedHTTPClient(_mirror_program(), transport=t) as http:
        with pytest.raises(RequestBlocked):
            await http.get("http://127.0.0.1/x")
    assert t.calls == 0


# --- secrets never leak into sanitized output / evidence ----------------------

async def test_http_tool_result_redacts_auth(creds):
    # The tool returns response headers only, with auth material redacted.
    t = CapturingTransport()
    program = ProgramManager(_mirror_program())
    async with AuthorizedHTTPClient(program.config, transport=t) as http:
        result = await HttpTool().execute(HttpArgs(url="http://127.0.0.1/x", method="GET"),
                                          ToolContext(program=program, http=http))
    dumped = json.dumps(result)
    assert COOKIE_VALUE not in dumped and VAT_VALUE not in dumped


def test_evidence_redacts_auth_headers(tmp_path):
    db = Database(":memory:")
    ev = EvidenceStore(db, tmp_path / "ev")
    exchange = HTTPExchange(
        exchange_id="ex", method="GET", url="http://127.0.0.1/x",
        request_headers={"Cookie": COOKIE_VALUE, "VerifyAuthToken": VAT_VALUE,
                         "X-HackerOne-Research": H1_VALUE, "Authorization": "Bearer x"},
        request_body=None, status_code=200,
        response_headers={"Set-Cookie": "session=leak", "content-type": "application/json"},
        response_body='{"ok": true}', elapsed_ms=1.0,
    )
    req_rec, resp_rec = ev.store_exchange(exchange)
    stored = (ev.read_verified(req_rec.id) + ev.read_verified(resp_rec.id)).decode("utf-8")
    for secret in (COOKIE_VALUE, VAT_VALUE, "Bearer x", "session=leak"):
        assert secret not in stored
    assert "[REDACTED]" in stored
    # Non-secret context is preserved.
    assert "X-HackerOne-Research" in stored and H1_VALUE in stored
    db.close()


# --- dry_run_only still blocks the real Temu program --------------------------

async def test_real_temu_dry_run_still_blocks(creds):
    temu = ProgramManager(load_program(TEMU_YAML))
    assert temu.config.dry_run_only is True
    t = CapturingTransport()
    async with AuthorizedHTTPClient(temu.config, transport=t) as http:
        with pytest.raises(RequestBlocked):
            await http.request("GET", "https://www.temu.com/")
    assert t.calls == 0
