"""Unit tests for the privilege-escalation (BFLA) verifier and capability.

No real network: an httpx.MockTransport simulates admin/regular/anon behavior.
"""

from __future__ import annotations

import json

import httpx
import pytest

from bbagent.config.models import (
    ProgramConfig, RateLimit, ScopeConfig, ScopeKind, ScopeRule, TestAccount, TestingRestrictions,
)
from bbagent.detectors.privilege import PrivilegeEscalationVerifier
from bbagent.detectors.base import VerificationContext
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.planner import DeterministicPlanner, PlanContext, default_capabilities
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.storage.models import Hypothesis
from bbagent.surface.store import SurfaceStore
from bbagent.urlutils import endpoint_key

_REPORT = {"report": {"classification": "restricted",
                      "records": [{"user": "alice", "plan": "gold"}], "total": 1}}
_SETTINGS = {"settings": {"classification": "restricted", "feature_flags": {"beta": True}}}

URL = "http://127.0.0.1/api/admin/report"


def _program(roles=("admin", "user")):
    accts = [TestAccount(label=f"user_{i}", role=r) for i, r in enumerate(roles)]
    return ProgramManager(ProgramConfig(
        name="PrivTest", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="127.0.0.1")]),
        restrictions=TestingRestrictions(allowed_methods=["GET", "HEAD", "OPTIONS"],
                                         allow_active_testing=False),
        rate_limit=RateLimit(requests_per_second=100, max_concurrent=8),
        test_accounts=accts,
    ))


def _transport(kind: str):
    def handler(request: httpx.Request) -> httpx.Response:
        ident = request.headers.get("x-test-identity")
        if kind == "public":
            return httpx.Response(200, text=json.dumps(_REPORT))
        if ident is None:
            return httpx.Response(401, text='{"error":"unauthenticated"}')
        if kind == "vuln":
            return httpx.Response(200, text=json.dumps(_REPORT))     # no role check (bug)
        if kind == "secure":
            if ident != "user_0":  # only the admin identity
                return httpx.Response(403, text='{"error":"forbidden"}')
            return httpx.Response(200, text=json.dumps(_SETTINGS))
        if kind == "generic":
            return httpx.Response(200, text='{"ok": true}')          # 200 but no privileged data
        return httpx.Response(404)
    return httpx.MockTransport(handler)


async def _verify(kind: str, *, program=None, url=URL):
    program = program or _program()
    db = Database(":memory:")
    try:
        async with AuthorizedHTTPClient(program.config, transport=_transport(kind)) as http:
            ctx = VerificationContext(
                program=program, db=db, http=http,
                hypothesis=Hypothesis(program=program.name, vuln_type="privilege_escalation",
                                      title="t", rationale="r", target_url=url),
            )
            return await PrivilegeEscalationVerifier().verify(ctx)
    finally:
        db.close()


async def test_vulnerable_case_verified():
    res = await _verify("vuln")
    assert res.verified is True
    assert len(res.exchanges) == 3          # admin baseline, anon, non-privileged
    assert "restricted" in res.actual_behavior or "privileged" in res.actual_behavior.lower()


async def test_secure_case_disproven():
    res = await _verify("secure", url="http://127.0.0.1/api/admin/settings")
    assert res.verified is False
    assert "authorization holds" in res.reason


async def test_generic_response_not_flagged():
    # Admin-like path returns a 200 with no privileged content -> not a finding.
    res = await _verify("generic", url="http://127.0.0.1/api/admin/ping")
    assert res.verified is False
    assert "no privileged baseline" in res.reason


async def test_public_endpoint_not_a_privilege_boundary():
    res = await _verify("public")
    assert res.verified is False
    assert "public" in res.reason


async def test_requires_admin_and_regular_identities():
    prog = _program(roles=("user", "user"))  # no admin identity
    res = await _verify("vuln", program=prog)
    assert res.verified is False
    assert "admin" in res.reason


# --- capability / planner integration ----------------------------------------

def test_capability_registered():
    classes = {type(c).__name__ for c in default_capabilities().all()}
    assert "PrivilegeEscalationCapability" in classes
    assert "AccessControlCapability" in classes  # idor still present
    descr = {d["vuln_class"] for d in default_capabilities().describe()}
    assert {"idor", "privilege_escalation"} <= descr


def test_planner_generates_privilege_hypothesis():
    from bbagent_lab.agent_config import build_lab_program

    db = Database(":memory:")
    surface = SurfaceStore(db)
    program = ProgramManager(build_lab_program())  # user_a=admin, user_b=user
    url = "http://127.0.0.1:8000/api/admin/report"
    surface.upsert_endpoint(program.name, method="GET", url=url, path="/api/admin/report",
                            template_key=endpoint_key("GET", url), confirmed=True)
    ctx = PlanContext(program, surface, default_capabilities(), set())
    queue = DeterministicPlanner().plan(ctx)
    priv = [h for h in queue if h.vulnerability_class == "privilege_escalation"]
    assert len(priv) == 1
    assert priv[0].required_auth_context == ["user_a", "user_b"]
    assert "/api/admin/report" in priv[0].endpoint
    db.close()


def test_capability_does_not_fire_without_admin_role():
    db = Database(":memory:")
    surface = SurfaceStore(db)
    program = _program(roles=("user", "user"))
    url = "http://127.0.0.1:8000/api/admin/report"
    surface.upsert_endpoint(program.name, method="GET", url=url, path="/api/admin/report",
                            template_key=endpoint_key("GET", url), confirmed=True)
    ctx = PlanContext(program, surface, default_capabilities(), set())
    queue = DeterministicPlanner().plan(ctx)
    assert [h for h in queue if h.vulnerability_class == "privilege_escalation"] == []
    db.close()
