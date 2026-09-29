"""Tool layer + Program Policy Engine: registration, schema, policy decisions,
sanitization, fail-closed behavior, and the LLM boundary."""

from __future__ import annotations

import httpx
import pytest

from bbagent.config.models import ProgramConfig, ScopeConfig, ScopeKind, ScopeRule
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.policy import ProgramPolicyEngine
from bbagent.program.manager import ProgramManager
from bbagent.tools import (
    HttpTool, ReconTool, ToolContext, ToolRequest, ToolRouter, default_tools,
)
from bbagent_lab.simulator import RESEARCH_HEADER, build_simulator_manager


def _policy():
    return ProgramPolicyEngine(build_simulator_manager())


def _req(**kw):
    return ToolRequest(**kw)


# --- tool registry / schema ---------------------------------------------------

def test_tool_registration_and_describe():
    reg = default_tools()
    assert set(reg.names()) == {"http", "recon"}
    http = reg.get("http")
    assert http.version and "input_schema" in http.describe()


def test_unknown_and_malformed_arguments_rejected():
    http = HttpTool()
    with pytest.raises(Exception):
        http.validate_arguments({"method": "GET"})  # missing required 'url'


def test_toolrequest_rejects_unknown_fields():
    # The LLM cannot smuggle extra fields (e.g. to alter policy/scope).
    with pytest.raises(Exception):
        ToolRequest(tool="http", arguments={}, evil="bypass")


# --- policy decisions ---------------------------------------------------------

def test_allow_in_scope_get():
    d = _policy().evaluate(_req(tool="http", arguments={"url": "http://127.0.0.1:8000/products",
                                                        "method": "GET"}, identity="user_a"))
    assert d.allowed is True


def test_deny_out_of_scope():
    d = _policy().evaluate(_req(tool="http", arguments={"url": "http://example.com/x", "method": "GET"}))
    assert d.allowed is False and "scope" in d.matched_rule


def test_deny_excluded_path():
    d = _policy().evaluate(_req(tool="http",
                                arguments={"url": "http://127.0.0.1:8000/excluded/secret", "method": "GET"}))
    assert d.allowed is False and d.matched_rule == "exclusions"


def test_deny_forbidden_method():
    d = _policy().evaluate(_req(tool="http", arguments={"url": "http://127.0.0.1:8000/x", "method": "POST"}))
    assert d.allowed is False and d.matched_rule == "allowed_methods"


def test_deny_required_header_override():
    d = _policy().evaluate(_req(tool="http", arguments={
        "url": "http://127.0.0.1:8000/x", "method": "GET",
        "headers": {RESEARCH_HEADER: "tampered"}}))
    assert d.allowed is False and d.matched_rule == "required_headers"


def test_deny_unauthorized_identity():
    d = _policy().evaluate(_req(tool="http", arguments={"url": "http://127.0.0.1:8000/x", "method": "GET"},
                                identity="intruder"))
    assert d.allowed is False and d.matched_rule == "test_accounts"


def test_deny_unauthorized_tool():
    d = _policy().evaluate(_req(tool="shell", arguments={}))
    assert d.allowed is False and d.matched_rule == "allowed_tools"


def test_deny_forbidden_vuln_class():
    d = _policy().evaluate(_req(tool="http", arguments={"url": "http://127.0.0.1:8000/x", "method": "GET"},
                                vuln_class="rce"))
    assert d.allowed is False and d.matched_rule == "allowed_vulnerability_classes"


def test_deny_budget_exhausted():
    pol = _policy()
    pol.program.config.request_budget.total = 1
    r = _req(tool="http", arguments={"url": "http://127.0.0.1:8000/a", "method": "GET"})
    assert pol.evaluate(r).allowed is True
    pol.record(r)
    d = pol.evaluate(_req(tool="http", arguments={"url": "http://127.0.0.1:8000/b", "method": "GET"}))
    assert d.allowed is False and "budget" in d.matched_rule


def test_fail_closed_no_allowed_tools():
    prog = ProgramConfig(name="x", authorized=True,
                         scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="127.0.0.1")]))
    d = ProgramPolicyEngine(ProgramManager(prog)).evaluate(
        _req(tool="http", arguments={"url": "http://127.0.0.1/x", "method": "GET"}))
    assert d.allowed is False and "fail-closed" in d.reason


def test_deny_unauthenticated_when_required():
    prog = build_simulator_manager()
    prog.config.allow_unauthenticated = False
    d = ProgramPolicyEngine(prog).evaluate(
        _req(tool="http", arguments={"url": "http://127.0.0.1:8000/x", "method": "GET"}))
    assert d.allowed is False and d.matched_rule == "allow_unauthenticated"


# --- router: denied requests never reach the HTTP client ----------------------

class _CountingTransport(httpx.MockTransport):
    def __init__(self):
        self.calls = 0

        def handler(request):
            self.calls += 1
            return httpx.Response(200, headers={"content-type": "application/json",
                                                "set-cookie": "s=secret"},
                                  text='{"products":[{"sku":1}]}')
        super().__init__(handler)


async def test_denied_request_never_reaches_http_client():
    program = build_simulator_manager()
    transport = _CountingTransport()
    async with AuthorizedHTTPClient(program.config, transport=transport) as http:
        ctx = ToolContext(program=program, http=http)
        router = ToolRouter(default_tools(), ProgramPolicyEngine(program), ctx)
        # Out-of-scope -> denied, client untouched.
        res = await router.dispatch(_req(tool="http",
                                         arguments={"url": "http://example.com/x", "method": "GET"}))
        assert res.success is False and res.denied_reason
        assert transport.calls == 0

        # In-scope -> allowed, client called, secrets redacted in the result.
        res2 = await router.dispatch(_req(tool="http",
                                          arguments={"url": "http://127.0.0.1:8000/products?id=1",
                                                     "method": "GET"}, identity="user_a"))
        assert res2.success is True
        assert transport.calls == 1
        assert res2.sanitized["response_headers"].get("set-cookie") == "[REDACTED]"
        assert "products" in res2.sanitized["body"]


async def test_router_unknown_and_malformed():
    program = build_simulator_manager()
    async with AuthorizedHTTPClient(program.config, transport=_CountingTransport()) as http:
        router = ToolRouter(default_tools(), ProgramPolicyEngine(program),
                            ToolContext(program=program, http=http))
        r1 = await router.dispatch(_req(tool="nope", arguments={}))
        assert r1.success is False and r1.denied_reason == "unknown tool"
        r2 = await router.dispatch(_req(tool="http", arguments={"method": "GET"}))  # no url
        assert r2.success is False and "malformed" in r2.denied_reason


async def test_recon_tool_local_only():
    program = build_simulator_manager()
    async with AuthorizedHTTPClient(program.config, transport=_CountingTransport()) as http:
        router = ToolRouter(default_tools(), ProgramPolicyEngine(program),
                            ToolContext(program=program, http=http))
        hosts = await router.dispatch(_req(tool="recon", arguments={"action": "scope_hosts"}))
        assert hosts.success and "127.0.0.1" in hosts.sanitized["hosts"]
        res = await router.dispatch(_req(tool="recon", arguments={"action": "resolve", "host": "localhost"}))
        assert res.sanitized["addresses"] == ["127.0.0.1"]
        # A non-loopback host resolves to nothing (no real DNS / no network).
        ext = await router.dispatch(_req(tool="recon", arguments={"action": "resolve", "host": "example.com"}))
        assert ext.sanitized["addresses"] == [] and ext.sanitized["in_scope"] is False
