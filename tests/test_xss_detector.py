"""Unit tests for the reflected-XSS verifier and capability (MockTransport)."""

from __future__ import annotations

import html as html_mod

import httpx
import pytest

from bbagent.config.models import (
    PolicyBudget, ProgramConfig, RateLimit, ScopeConfig, ScopeKind, ScopeRule, TestingRestrictions,
)
from bbagent.detectors.base import VerificationContext
from bbagent.detectors.xss import ReflectedXSSVerifier, analyze_reflection
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.planner import DeterministicPlanner, PlanContext, default_capabilities
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.storage.models import Hypothesis
from bbagent.surface.store import SurfaceStore
from bbagent.urlutils import endpoint_key

BASE = "http://127.0.0.1/search"
TARGET = BASE + "?q=probe"


def _program():
    return ProgramManager(ProgramConfig(
        name="XSSTest", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="127.0.0.1")]),
        restrictions=TestingRestrictions(allowed_methods=["GET", "HEAD", "OPTIONS"],
                                         allow_active_testing=False),
        rate_limit=RateLimit(requests_per_second=100, max_concurrent=8),
        allowed_tools=["http"],
        allowed_vulnerability_classes=["reflected_xss"],
        allow_unauthenticated=True,
        request_budget=PolicyBudget(),
    ))


def _transport(kind: str):
    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        html_hdr = {"content-type": "text/html; charset=utf-8"}
        if kind == "vuln":               # reflect raw into HTML text
            return httpx.Response(200, headers=html_hdr, text=f"<html><body><p>{q}</p></body></html>")
        if kind == "safe":               # HTML-encode
            return httpx.Response(200, headers=html_hdr,
                                  text=f"<html><body><p>{html_mod.escape(q)}</p></body></html>")
        if kind == "attribute":          # reflect into an attribute value (breakout)
            return httpx.Response(200, headers=html_hdr,
                                  text=f'<html><body><input value="{q}"></body></html>')
        if kind == "script":             # reflect raw inside a <script> block
            return httpx.Response(200, headers=html_hdr,
                                  text=f'<html><body><script>var x="{q}";</script></body></html>')
        if kind == "plain":              # non-HTML context
            return httpx.Response(200, headers={"content-type": "text/plain"}, text=f"echo: {q}")
        if kind == "generic":            # ignores q entirely
            return httpx.Response(200, headers=html_hdr, text="<html><body>ok</body></html>")
        return httpx.Response(404)
    return httpx.MockTransport(handler)


async def _verify(kind: str, *, target=TARGET, program=None):
    program = program or _program()
    db = Database(":memory:")
    try:
        async with AuthorizedHTTPClient(program.config, transport=_transport(kind)) as http:
            ctx = VerificationContext(
                program=program, db=db, http=http,
                hypothesis=Hypothesis(program=program.name, vuln_type="reflected_xss",
                                      title="t", rationale="r", target_url=target),
            )
            return await ReflectedXSSVerifier().verify(ctx)
    finally:
        db.close()


async def test_vulnerable_reflected_xss_verified():
    res = await _verify("vuln")
    assert res.verified is True
    assert "live HTML" in res.actual_behavior
    assert len(res.exchanges) == 2


async def test_encoded_reflection_disproven():
    res = await _verify("safe")
    assert res.verified is False
    assert "encoded" in res.reason


async def test_attribute_context_verified():
    res = await _verify("attribute")
    assert res.verified is True  # attribute breakout creates real markup


async def test_script_context_inconclusive_not_verified():
    res = await _verify("script")
    assert res.verified is False
    assert "script" in res.reason


async def test_plain_text_reflection_disproven():
    res = await _verify("plain")
    assert res.verified is False
    assert "not reflected xss (non_html)" in res.reason.lower()


async def test_generic_response_disproven():
    res = await _verify("generic")
    assert res.verified is False
    assert "not reflected" in res.reason
    assert len(res.exchanges) == 1  # bailed after benign baseline (no reflection)


async def test_malformed_hypothesis_no_param():
    res = await _verify("vuln", target="http://127.0.0.1/search")  # no query param
    assert res.verified is False
    assert "malformed" in res.reason


# --- analyzer unit ------------------------------------------------------------

def test_analyzer_distinguishes_encoded_from_executable():
    tag, attr, nonce = "bbxabc", "bbxaabc", "abc"
    payload = f'{nonce}"><{tag} {attr}=x>'
    raw = f"<p>{payload}</p>"
    enc = f"<p>{html_mod.escape(payload)}</p>"
    assert analyze_reflection(raw, "text/html", tag, attr, nonce, payload).verdict == "executable"
    assert analyze_reflection(enc, "text/html", tag, attr, nonce, payload).verdict == "encoded"
    assert analyze_reflection(f"echo {payload}", "text/plain", tag, attr, nonce, payload).verdict == "non_html"
    assert analyze_reflection("<p>nothing</p>", "text/html", tag, attr, nonce, payload).verdict == "not_reflected"


# --- capability / planner -----------------------------------------------------

def test_capability_registered_and_fires_on_param():
    descr = {d["vuln_class"] for d in default_capabilities().describe()}
    assert "reflected_xss" in descr

    db = Database(":memory:")
    surface = SurfaceStore(db)
    prog = _program()
    url = "http://127.0.0.1:8000/search?q=probe"
    ep = surface.upsert_endpoint(prog.name, method="GET", url=url, path="/search",
                                 template_key=endpoint_key("GET", url), query_params=["q"],
                                 confirmed=True)
    surface.upsert_parameter(prog.name, endpoint_id=ep.id, name="q", location="query")
    ctx = PlanContext(prog, surface, default_capabilities(), set())
    xss = [h for h in DeterministicPlanner().plan(ctx) if h.vulnerability_class == "reflected_xss"]
    assert len(xss) == 1
    assert xss[0].endpoint.endswith("/search?q=")
    assert xss[0].required_inputs["param"] == "q"
    db.close()


def test_capability_no_fire_without_param():
    db = Database(":memory:")
    surface = SurfaceStore(db)
    prog = _program()
    url = "http://127.0.0.1:8000/health"
    surface.upsert_endpoint(prog.name, method="GET", url=url, path="/health",
                            template_key=endpoint_key("GET", url), confirmed=True)
    ctx = PlanContext(prog, surface, default_capabilities(), set())
    assert [h for h in DeterministicPlanner().plan(ctx) if h.vulnerability_class == "reflected_xss"] == []
    db.close()
