"""Temu capability matrix: ALLOWED classes are still gated by every other policy
constraint; FORBIDDEN classes never reach transport; the planner only generates
ALLOWED classes; dry_run_only prevents real Temu requests."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from bbagent.config.loader import load_program
from bbagent.config.models import (
    DataScope, PolicyBudget, ProgramConfig, RateLimit, ScopeConfig, ScopeKind, ScopeRule,
    TestAccount, TestingRestrictions,
)
from bbagent.http.client import AuthorizedHTTPClient, RequestBlocked, RunBudget
from bbagent.planner import DeterministicPlanner, PlanContext, default_capabilities
from bbagent.policy.engine import ProgramPolicyEngine
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.surface.store import SurfaceStore
from bbagent.tools.gateway import PolicyGatedHTTP
from bbagent.urlutils import endpoint_key

TEMU = str(Path(__file__).resolve().parents[1] / "programs" / "temu.yaml")
H1_ENV = "BBAGENT_H1_USERNAME"


class CountingTransport(httpx.MockTransport):
    def __init__(self):
        self.calls = 0

        def handler(request):
            self.calls += 1
            return httpx.Response(200, headers={"content-type": "application/json"}, text="{}")
        super().__init__(handler)


def _runnable(allowed_classes=("idor",), *, data_ids=("1",), header_env=H1_ENV):
    """A runnable loopback program with an ALLOWED class, to show it is still gated."""
    return ProgramManager(ProgramConfig(
        name="gate", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="127.0.0.1")]),
        restrictions=TestingRestrictions(allowed_methods=["GET"]),
        rate_limit=RateLimit(requests_per_second=100, max_concurrent=8),
        test_accounts=[TestAccount(label="researcher")],
        allowed_tools=["http"],
        allowed_vulnerability_classes=list(allowed_classes),
        allow_unauthenticated=True,
        request_budget=PolicyBudget(),
        required_header_refs={"X-HackerOne-Research": header_env},
        data_scope=DataScope(enforce=True, authorized_object_ids=list(data_ids)),
    ))


async def _gateway(program, transport, *, run_budget=None, vuln_class="idor"):
    http = await AuthorizedHTTPClient(program.config, transport=transport,
                                      run_budget=run_budget).__aenter__()
    gw = PolicyGatedHTTP(program, ProgramPolicyEngine(program), http)
    gw.vuln_class = vuln_class
    return gw, http


# --- an ALLOWED class is still blocked by every other gate --------------------

async def test_allowed_class_blocked_by_scope(monkeypatch):
    monkeypatch.setenv(H1_ENV, "researcher")
    t = CountingTransport()
    gw, http = await _gateway(_runnable(), t)
    try:
        with pytest.raises(RequestBlocked):
            await gw.get("http://evil.com/x")          # out of scope
    finally:
        await http.__aexit__(None, None, None)
    assert t.calls == 0


async def test_allowed_class_blocked_by_data_scope(monkeypatch):
    monkeypatch.setenv(H1_ENV, "researcher")
    t = CountingTransport()
    gw, http = await _gateway(_runnable(data_ids=("1",)), t)
    try:
        with pytest.raises(RequestBlocked):
            await gw.get("http://127.0.0.1/api/orders/999")   # unauthorized data id
    finally:
        await http.__aexit__(None, None, None)
    assert t.calls == 0


async def test_allowed_class_blocked_by_missing_required_header(monkeypatch):
    monkeypatch.delenv(H1_ENV, raising=False)            # required header env unset
    t = CountingTransport()
    gw, http = await _gateway(_runnable(), t)
    try:
        with pytest.raises(RequestBlocked):
            await gw.get("http://127.0.0.1/api/orders/1")
    finally:
        await http.__aexit__(None, None, None)
    assert t.calls == 0


async def test_allowed_class_blocked_by_budget(monkeypatch):
    monkeypatch.setenv(H1_ENV, "researcher")
    t = CountingTransport()
    gw, http = await _gateway(_runnable(), t, run_budget=RunBudget(1))
    try:
        await gw.get("http://127.0.0.1/api/orders/1")     # first allowed -> transport
        with pytest.raises(RequestBlocked):
            await gw.get("http://127.0.0.1/api/orders/1")  # budget exhausted
    finally:
        await http.__aexit__(None, None, None)
    assert t.calls == 1


# --- a FORBIDDEN class can never reach transport ------------------------------

async def test_forbidden_class_never_reaches_transport(monkeypatch):
    monkeypatch.setenv(H1_ENV, "researcher")
    t = CountingTransport()
    # reflected_xss is NOT in allowed_vulnerability_classes -> policy denies it.
    gw, http = await _gateway(_runnable(allowed_classes=("idor",)), t, vuln_class="reflected_xss")
    try:
        with pytest.raises(RequestBlocked):
            await gw.get("http://127.0.0.1/api/x")
    finally:
        await http.__aexit__(None, None, None)
    assert t.calls == 0


# --- planner only generates ALLOWED classes for Temu --------------------------

def test_planner_generates_only_allowed_classes():
    temu = ProgramManager(load_program(TEMU))
    db = Database(":memory:")
    surface = SurfaceStore(db)
    # An object-scoped API endpoint with an id-like param on an in-scope Temu host.
    url = "https://www.temu.com/api/orders/670fa3e9ead6e49d65cc3614?id=42"
    ep = surface.upsert_endpoint(temu.name, method="GET", url=url,
                                 path="/api/orders/670fa3e9ead6e49d65cc3614",
                                 template_key=endpoint_key("GET", url), query_params=["id"],
                                 confirmed=True)
    surface.upsert_object_ref(temu.name, endpoint_id=ep.id, value="670fa3e9ead6e49d65cc3614",
                              kind="hexid", location="path")
    surface.upsert_parameter(temu.name, endpoint_id=ep.id, name="id", location="query")
    surface.record_auth_observation(temu.name, endpoint_id=ep.id, identity="unauthenticated", status_code=401)
    surface.record_auth_observation(temu.name, endpoint_id=ep.id, identity="researcher", status_code=200)
    # A reflected-XSS-shaped endpoint (query param) that must NOT be planned.
    surl = "https://www.temu.com/search?q=probe"
    sep = surface.upsert_endpoint(temu.name, method="GET", url=surl, path="/search",
                                  template_key=endpoint_key("GET", surl), query_params=["q"],
                                  confirmed=True)
    surface.upsert_parameter(temu.name, endpoint_id=sep.id, name="q", location="query")

    ctx = PlanContext(temu, surface, default_capabilities(), set())
    classes = {h.vulnerability_class for h in DeterministicPlanner().plan(ctx)}
    assert "reflected_xss" not in classes            # FORBIDDEN -> never planned
    assert "idor" in classes                         # ALLOWED
    assert "sql_injection" in classes                # ALLOWED (id param)
    db.close()


# --- dry_run_only still prevents any real Temu request ------------------------

async def test_dry_run_only_prevents_real_temu_request():
    temu = ProgramManager(load_program(TEMU))
    assert temu.config.dry_run_only is True
    t = CountingTransport()
    http = await AuthorizedHTTPClient(temu.config, transport=t).__aenter__()
    try:
        with pytest.raises(RequestBlocked):
            await http.request("GET", "https://www.temu.com/")
    finally:
        await http.__aexit__(None, None, None)
    assert t.calls == 0
