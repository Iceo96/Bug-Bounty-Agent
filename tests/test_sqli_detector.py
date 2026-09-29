"""Unit tests for the SQL-injection verifier and capability (MockTransport)."""

from __future__ import annotations

import json

import httpx
import pytest

from bbagent.config.models import (
    ProgramConfig, RateLimit, ScopeConfig, ScopeKind, ScopeRule, TestingRestrictions,
)
from bbagent.detectors.base import VerificationContext
from bbagent.detectors.sqli import SQLInjectionVerifier, is_sql_param, result_count
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.planner import DeterministicPlanner, PlanContext, default_capabilities
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.storage.models import Hypothesis
from bbagent.surface.store import SurfaceStore
from bbagent.urlutils import endpoint_key

BASE = "http://127.0.0.1/products"
TARGET = BASE + "?id=1"


def _program():
    return ProgramManager(ProgramConfig(
        name="SQLiTest", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="127.0.0.1")]),
        restrictions=TestingRestrictions(allowed_methods=["GET", "HEAD", "OPTIONS"],
                                         allow_active_testing=False),
        rate_limit=RateLimit(requests_per_second=100, max_concurrent=8),
    ))


def _rows(n):
    return json.dumps({"products": [{"id": i} for i in range(n)], "count": n})


def _transport(kind: str):
    def handler(request: httpx.Request) -> httpx.Response:
        idv = request.url.params.get("id", "")
        json_hdr = {"content-type": "application/json"}
        if kind == "vuln":                       # boolean interpreted as SQL
            if "OR 1=1" in idv:
                return httpx.Response(200, headers=json_hdr, text=_rows(5))
            if "AND 1=2" in idv:
                return httpx.Response(200, headers=json_hdr, text=_rows(0))
            return httpx.Response(200, headers=json_hdr, text=_rows(1))
        if kind == "safe":                       # parameterized: only exact "1" matches
            return httpx.Response(200, headers=json_hdr, text=_rows(1 if idv == "1" else 0))
        if kind == "control":                    # never touches SQL: constant count
            return httpx.Response(200, headers=json_hdr,
                                  text=json.dumps({"records": [{"echo": idv}]}))
        if kind == "error":                      # generic 500 for everything
            return httpx.Response(500, headers=json_hdr, text='{"error":"boom"}')
        if kind == "length":                     # different length, constant record count
            return httpx.Response(200, headers=json_hdr,
                                  text=json.dumps({"products": [{"id": 1}], "pad": "x" * len(idv)}))
        if kind == "reflect_nonsql":             # payload reflected, not interpreted
            return httpx.Response(200, headers=json_hdr,
                                  text=json.dumps({"products": [{"echo": idv}]}))
        return httpx.Response(404)
    return httpx.MockTransport(handler)


async def _verify(kind: str, *, target=TARGET, program=None):
    program = program or _program()
    db = Database(":memory:")
    try:
        async with AuthorizedHTTPClient(program.config, transport=_transport(kind)) as http:
            ctx = VerificationContext(
                program=program, db=db, http=http,
                hypothesis=Hypothesis(program=program.name, vuln_type="sql_injection",
                                      title="t", rationale="r", target_url=target),
            )
            return await SQLInjectionVerifier().verify(ctx)
    finally:
        db.close()


async def test_vulnerable_sqli_verified():
    res = await _verify("vuln")
    assert res.verified is True
    assert len(res.exchanges) == 3
    assert "baseline" in res.actual_behavior.lower()


async def test_secure_parameterized_disproven():
    res = await _verify("safe")
    assert res.verified is False
    assert "no deterministic SQL differential" in res.reason


async def test_control_endpoint_disproven():
    res = await _verify("control")
    assert res.verified is False  # constant count, no differential


async def test_generic_500_disproven():
    res = await _verify("error")
    assert res.verified is False
    assert "baseline" in res.reason  # no baseline result set


async def test_length_difference_without_sql_disproven():
    res = await _verify("length")
    assert res.verified is False  # record count constant despite differing body length


async def test_reflected_but_not_interpreted_disproven():
    res = await _verify("reflect_nonsql")
    assert res.verified is False


async def test_malformed_hypothesis_no_param():
    res = await _verify("vuln", target="http://127.0.0.1/products")
    assert res.verified is False
    assert "malformed" in res.reason


# --- result_count metric ------------------------------------------------------

def test_result_count_metric():
    assert result_count(json.dumps({"products": [1, 2, 3]})) == 3
    assert result_count(json.dumps({"ok": True})) == 0        # JSON, no array
    assert result_count("<html>500</html>") == -1             # not JSON
    assert result_count(json.dumps({"a": {"b": [1, 2, 3, 4]}})) == 4  # nested


def test_is_sql_param():
    assert is_sql_param("id") and is_sql_param("user_id") and is_sql_param("category")
    assert not is_sql_param("q") and not is_sql_param("search")


# --- capability / planner -----------------------------------------------------

def test_capability_registered_and_fires_on_id_param():
    descr = {d["vuln_class"] for d in default_capabilities().describe()}
    assert "sql_injection" in descr

    db = Database(":memory:")
    surface = SurfaceStore(db)
    prog = _program()
    url = "http://127.0.0.1:8000/products?id=1"
    ep = surface.upsert_endpoint(prog.name, method="GET", url=url, path="/products",
                                 template_key=endpoint_key("GET", url), query_params=["id"],
                                 confirmed=True)
    surface.upsert_parameter(prog.name, endpoint_id=ep.id, name="id", location="query")
    ctx = PlanContext(prog, surface, default_capabilities(), set())
    sqli = [h for h in DeterministicPlanner().plan(ctx) if h.vulnerability_class == "sql_injection"]
    assert len(sqli) == 1
    assert sqli[0].endpoint.endswith("/products?id=")
    db.close()


def test_capability_does_not_fire_on_non_sql_param():
    db = Database(":memory:")
    surface = SurfaceStore(db)
    prog = _program()
    url = "http://127.0.0.1:8000/search?q=x"
    ep = surface.upsert_endpoint(prog.name, method="GET", url=url, path="/search",
                                 template_key=endpoint_key("GET", url), query_params=["q"],
                                 confirmed=True)
    surface.upsert_parameter(prog.name, endpoint_id=ep.id, name="q", location="query")
    ctx = PlanContext(prog, surface, default_capabilities(), set())
    assert [h for h in DeterministicPlanner().plan(ctx) if h.vulnerability_class == "sql_injection"] == []
    db.close()
