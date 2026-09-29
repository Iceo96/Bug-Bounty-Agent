"""Adversarial hardening tests for the ProgramPolicyEngine and ToolRouter.

Every DENY path is exercised THROUGH the router, and a counting transport proves
the underlying HTTP execution layer is never called on a denial. Also covers
malformed/malicious LLM tool requests and config immutability (the agent/LLM can
never modify scope, exclusions, allowed tools/classes, identities, or budgets).
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
import pytest

from bbagent.config.models import (
    PolicyBudget, ProgramConfig, RateLimit, ScopeConfig, ScopeKind, ScopeRule,
    TestAccount, TestingRestrictions,
)
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.planner import DeterministicPlanner, PlanContext, default_capabilities
from bbagent.policy import ProgramPolicyEngine
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.surface.store import SurfaceStore
from bbagent.tools import ToolContext, ToolRequest, ToolRouter, default_tools
from bbagent.tools.http_tool import HttpArgs
from bbagent.urlutils import endpoint_key
from bbagent_lab.agent_config import ENV_TOKEN_A, ENV_TOKEN_B
from bbagent_lab.data import USERS
from bbagent_lab.simulator import build_simulator_manager

IN_SCOPE = "http://127.0.0.1:8000/products?id=1"


class CountingTransport(httpx.MockTransport):
    """Counts how many requests actually reached the HTTP execution layer."""

    def __init__(self):
        self.calls = 0

        def handler(request):
            self.calls += 1
            return httpx.Response(200, headers={"content-type": "application/json",
                                                "set-cookie": "s=secret"},
                                  text='{"products":[{"sku":1}]}')
        super().__init__(handler)


@pytest.fixture
def program(monkeypatch):
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)
    return build_simulator_manager()


@asynccontextmanager
async def make_router(program, transport):
    async with AuthorizedHTTPClient(program.config, transport=transport) as http:
        yield ToolRouter(default_tools(), ProgramPolicyEngine(program),
                         ToolContext(program=program, http=http))


def _req(**kw):
    return ToolRequest(**kw)


# --- baseline: an allowed request DOES reach the client -----------------------

async def test_allowed_request_reaches_client(program):
    t = CountingTransport()
    async with make_router(program, t) as router:
        res = await router.dispatch(_req(tool="http", arguments={"url": IN_SCOPE, "method": "GET"},
                                         identity="user_a"))
    assert res.success is True and t.calls == 1
    # Secrets are redacted in the sanitized result.
    assert res.sanitized["response_headers"]["set-cookie"] == "[REDACTED]"


# --- every DENY: the HTTP execution layer is never called ---------------------

@pytest.mark.parametrize("args,identity,vuln_class", [
    ({"url": "http://example.com/x", "method": "GET"}, None, None),                 # out of scope
    ({"url": "http://127.0.0.1:8000/excluded/secret", "method": "GET"}, None, None),  # excluded path
    ({"url": IN_SCOPE, "method": "GET"}, "intruder", None),                          # bad identity
    ({"url": IN_SCOPE, "method": "GET", "headers": {"X-Research-ID": "x"}}, None, None),  # header override
    ({"url": IN_SCOPE, "method": "POST"}, None, None),                              # forbidden method
    ({"url": IN_SCOPE, "method": "GET"}, None, "rce"),                              # forbidden vuln class
])
async def test_denied_requests_never_execute(program, args, identity, vuln_class):
    t = CountingTransport()
    async with make_router(program, t) as router:
        res = await router.dispatch(_req(tool="http", arguments=args,
                                         identity=identity, vuln_class=vuln_class))
    assert res.success is False and res.denied_reason
    assert t.calls == 0


async def test_unknown_tool_never_executes(program):
    t = CountingTransport()
    async with make_router(program, t) as router:
        for name in ("shell", "os.system", "HTTP", "http ", "recon2"):
            res = await router.dispatch(_req(tool=name, arguments={}))
            assert res.success is False
    assert t.calls == 0


async def test_invalid_targets_denied(program):
    bad = [
        "http://example.com/x", "ftp://127.0.0.1/x", "http:///nohost",
        "notaurl", "javascript:alert(1)", "http://127.0.0.1@evil.com/", "file:///etc/passwd",
    ]
    t = CountingTransport()
    async with make_router(program, t) as router:
        for url in bad:
            res = await router.dispatch(_req(tool="http", arguments={"url": url, "method": "GET"}))
            assert res.success is False, url
    assert t.calls == 0


async def test_invalid_identities_denied(program):
    t = CountingTransport()
    async with make_router(program, t) as router:
        # Every non-empty identity that is not an authorized handle must be denied
        # (note "user_a " and "USER_A" are NOT "user_a" — exact match only).
        for ident in ("user_c", "admin", "' OR 1=1", "user_a ", "USER_A"):
            res = await router.dispatch(_req(tool="http", arguments={"url": IN_SCOPE, "method": "GET"},
                                             identity=ident))
            assert res.success is False, ident
    assert t.calls == 0


async def test_malformed_arguments_denied(program):
    t = CountingTransport()
    async with make_router(program, t) as router:
        # missing url, unknown arg, wrong type all rejected before execution
        for args in ({"method": "GET"}, {"url": IN_SCOPE, "evil": 1},
                     {"url": IN_SCOPE, "allowed_tools": ["x"]}, {"url": 123, "method": "GET"}):
            res = await router.dispatch(_req(tool="http", arguments=args))
            assert res.success is False and "malformed" in (res.denied_reason or "")
    assert t.calls == 0


async def test_budget_exhausted_denies_without_execution(program):
    program.config.request_budget = PolicyBudget(total=1, per_target=1, per_tool=1)
    t = CountingTransport()
    async with make_router(program, t) as router:
        first = await router.dispatch(_req(tool="http", arguments={"url": IN_SCOPE, "method": "GET"}))
        assert first.success is True and t.calls == 1
        second = await router.dispatch(_req(tool="http",
                                            arguments={"url": "http://127.0.0.1:8000/other", "method": "GET"}))
        assert second.success is False and "budget" in (second.denied_reason or "")
    assert t.calls == 1  # the denied request did not execute


async def test_dry_run_blocks_execution(program, monkeypatch):
    monkeypatch.setenv("BBAGENT_DRY_RUN", "1")
    t = CountingTransport()
    async with make_router(program, t) as router:
        res = await router.dispatch(_req(tool="http", arguments={"url": IN_SCOPE, "method": "GET"}))
    assert res.success is False and t.calls == 0  # client refused before sending


async def test_active_testing_blocked_when_method_allowed(monkeypatch):
    # A program that lists POST but is passive-only must still block POST.
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)
    prog = build_simulator_manager()
    prog.config.restrictions.allowed_methods = ["GET", "POST"]
    prog.config.restrictions.allow_active_testing = False
    t = CountingTransport()
    async with make_router(prog, t) as router:
        res = await router.dispatch(_req(tool="http", arguments={"url": IN_SCOPE, "method": "POST"}))
    assert res.success is False and "active" in (res.denied_reason or "").lower()
    assert t.calls == 0


async def test_excluded_host_rule_enforced(monkeypatch):
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)
    prog = ProgramManager(ProgramConfig(
        name="excl", authorized=True,
        scope=ScopeConfig(
            in_scope=[ScopeRule(kind=ScopeKind.WILDCARD, value="*.localhost")],
            excluded=[ScopeRule(kind=ScopeKind.DOMAIN, value="admin.localhost")],
        ),
        restrictions=TestingRestrictions(allowed_methods=["GET"]),
        allowed_tools=["http"],
        request_budget=PolicyBudget(),
    ))
    t = CountingTransport()
    async with make_router(prog, t) as router:
        excluded = await router.dispatch(_req(tool="http",
                                              arguments={"url": "http://admin.localhost/x", "method": "GET"}))
        assert excluded.success is False and "exclusion" in excluded.metadata.get("matched_rule", "")
    assert t.calls == 0


# --- malformed / malicious LLM requests: cannot smuggle fields ----------------

def test_toolrequest_rejects_extra_fields():
    for extra in ("scope", "exclusions", "allowed_tools", "allowed_vulnerability_classes",
                  "test_accounts", "request_budget", "rate_limit", "authorized"):
        with pytest.raises(Exception):
            ToolRequest(tool="http", arguments={"url": IN_SCOPE}, **{extra: "x"})


def test_http_args_rejects_extra_fields():
    with pytest.raises(Exception):
        HttpArgs(url=IN_SCOPE, scope=["*"])
    with pytest.raises(Exception):
        HttpArgs(url=IN_SCOPE, request_budget={"total": 9999})


# --- the LLM cannot modify program policy via requests ------------------------

async def test_config_immutable_across_requests(program):
    before = program.config.model_dump()
    t = CountingTransport()
    async with make_router(program, t) as router:
        # A mix of allowed and adversarial requests.
        await router.dispatch(_req(tool="http", arguments={"url": IN_SCOPE, "method": "GET"}, identity="user_a"))
        await router.dispatch(_req(tool="http", arguments={"url": "http://example.com/x", "method": "GET"}))
        await router.dispatch(_req(tool="http", arguments={"url": IN_SCOPE, "allowed_tools": ["shell"]}))
        await router.dispatch(_req(tool="recon", arguments={"action": "scope_hosts"}))
    # Scope, exclusions, allowed tools/classes, identities, budgets — all unchanged.
    assert program.config.model_dump() == before


# --- planner respects the program's allowed vulnerability classes -------------

def test_planner_filters_forbidden_classes(monkeypatch):
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)
    prog = build_simulator_manager()
    prog.config.allowed_vulnerability_classes = ["idor"]   # only IDOR permitted

    db = Database(":memory:")
    surface = SurfaceStore(db)
    # An IDOR-capable endpoint and a SQLi-capable endpoint.
    notes = "http://127.0.0.1:8000/api/notes/1"
    ep = surface.upsert_endpoint(prog.name, method="GET", url=notes, path="/api/notes/1",
                                 template_key=endpoint_key("GET", notes), confirmed=True)
    surface.upsert_object_ref(prog.name, endpoint_id=ep.id, value="1", kind="numeric", location="path")
    surface.record_auth_observation(prog.name, endpoint_id=ep.id, identity="identity_a", status_code=200)
    prods = "http://127.0.0.1:8000/products?id=1"
    ep2 = surface.upsert_endpoint(prog.name, method="GET", url=prods, path="/products",
                                  template_key=endpoint_key("GET", prods), query_params=["id"], confirmed=True)
    surface.upsert_parameter(prog.name, endpoint_id=ep2.id, name="id", location="query")

    ctx = PlanContext(prog, surface, default_capabilities(), set())
    classes = {h.vulnerability_class for h in DeterministicPlanner().plan(ctx)}
    assert classes == {"idor"}  # sql_injection forbidden -> never planned
    db.close()
