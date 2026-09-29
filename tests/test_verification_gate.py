"""Priority 2: detector verification is policy-gated (no bypass path).
Priority 3: the two-identity limitation is handled safely (INCONCLUSIVE, never an
unauthorized identity)."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from bbagent.config.loader import load_program
from bbagent.config.models import (
    PolicyBudget, ProgramConfig, RateLimit, ScopeConfig, ScopeKind, ScopeRule, TestAccount,
    TestingRestrictions,
)
from bbagent.detectors.base import VerificationContext
from bbagent.detectors.idor import IDORVerifier
from bbagent.detectors.privilege import PrivilegeEscalationVerifier
from bbagent.http.client import AuthorizedHTTPClient, RequestBlocked
from bbagent.policy.engine import ProgramPolicyEngine
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import Hypothesis
from bbagent.surface.store import SurfaceStore
from bbagent.tools.base import ToolRequest
from bbagent.tools.gateway import PolicyGatedHTTP
from bbagent_lab.agent_config import ENV_TOKEN_A, ENV_TOKEN_B
from bbagent_lab.data import USERS

WOLT = str(Path(__file__).resolve().parents[1] / "programs" / "wolt.yaml")
URL = "http://127.0.0.1:8000/x"


class CountingTransport(httpx.MockTransport):
    def __init__(self):
        self.calls = 0

        def handler(request):
            self.calls += 1
            return httpx.Response(200, headers={"content-type": "application/json"}, text="{}")
        super().__init__(handler)


def _program(**over):
    kw = dict(
        name="gate", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="127.0.0.1")]),
        restrictions=TestingRestrictions(allowed_methods=["GET"]),
        rate_limit=RateLimit(requests_per_second=100, max_concurrent=8),
        test_accounts=[TestAccount(label="user_a"), TestAccount(label="user_b")],
        allowed_tools=["http"],
        allowed_vulnerability_classes=["idor", "privilege_escalation", "reflected_xss", "sql_injection"],
        allow_unauthenticated=True,
        request_budget=PolicyBudget(),
    )
    kw.update(over)
    return ProgramManager(ProgramConfig(**kw))


# --- Priority 2: every gate blocks a verification request before transport ----

@pytest.mark.parametrize("setup", [
    # (program overrides, gateway kwargs, gateway.vuln_class)
    "vuln_class", "identity", "scope", "method", "forbidden_action", "required_header_override",
])
async def test_verification_request_is_policy_gated(setup):
    overrides, get_kwargs, vuln = {}, {}, "idor"
    url = URL
    if setup == "vuln_class":
        overrides = {"allowed_vulnerability_classes": ["idor"]}
        vuln = "sql_injection"                       # not permitted
    elif setup == "identity":
        get_kwargs = {"identity": "ghost"}           # not authorized
    elif setup == "scope":
        url = "http://example.com/x"                 # out of scope
    elif setup == "method":
        get_kwargs = {"method": "POST"}
    elif setup == "forbidden_action":
        overrides = {"forbidden_actions": ["dos"]}
        get_kwargs = {"requested_action": "dos"}
    elif setup == "required_header_override":
        overrides = {"required_headers": {"X-Bug-Bounty": "r"}}
        get_kwargs = {"headers": {"X-Bug-Bounty": "tampered"}}

    program = _program(**overrides)
    t = CountingTransport()
    async with AuthorizedHTTPClient(program.config, transport=t) as http:
        gw = PolicyGatedHTTP(program, ProgramPolicyEngine(program), http)
        gw.vuln_class = vuln
        with pytest.raises(RequestBlocked):
            if get_kwargs.get("method") == "POST":
                await gw.request("POST", url)
            else:
                await gw.get(url, **{k: v for k, v in get_kwargs.items() if k != "method"})
    assert t.calls == 0   # denied verification request never reached transport


async def test_verification_budget_enforced():
    program = _program(request_budget=PolicyBudget(total=1, per_target=1, per_tool=1))
    t = CountingTransport()
    async with AuthorizedHTTPClient(program.config, transport=t) as http:
        gw = PolicyGatedHTTP(program, ProgramPolicyEngine(program), http)
        gw.vuln_class = "idor"
        await gw.get("http://127.0.0.1:8000/a")          # first allowed
        with pytest.raises(RequestBlocked):
            await gw.get("http://127.0.0.1:8000/b")      # budget exhausted
    assert t.calls == 1


async def test_allowed_verification_request_reaches_transport():
    program = _program()
    t = CountingTransport()
    async with AuthorizedHTTPClient(program.config, transport=t) as http:
        gw = PolicyGatedHTTP(program, ProgramPolicyEngine(program), http)
        gw.vuln_class = "idor"
        ex = await gw.get(URL, identity="user_a")
    assert ex.status_code == 200 and t.calls == 1


# --- Priority 3: two-identity limitation handled safely -----------------------

async def _verify_idor(program, transport):
    db = Database(":memory:")
    try:
        async with AuthorizedHTTPClient(program.config, transport=transport) as http:
            gw = PolicyGatedHTTP(program, ProgramPolicyEngine(program), http)
            gw.vuln_class = "idor"
            ctx = VerificationContext(program=program, db=db, http=gw,
                                      hypothesis=Hypothesis(program=program.name, vuln_type="idor",
                                                            title="t", rationale="r", target_url=URL))
            return await IDORVerifier().verify(ctx)
    finally:
        db.close()


async def test_idor_inconclusive_with_single_identity():
    program = _program(test_accounts=[TestAccount(label="only_one")])
    t = CountingTransport()
    res = await _verify_idor(program, t)
    assert res.verified is False
    assert "INCONCLUSIVE" in res.reason
    assert t.calls == 0   # never attempted an unauthorized second identity


async def test_bfla_inconclusive_without_admin_identity():
    program = _program(test_accounts=[TestAccount(label="c", role="user")])
    db = Database(":memory:")
    t = CountingTransport()
    try:
        async with AuthorizedHTTPClient(program.config, transport=t) as http:
            gw = PolicyGatedHTTP(program, ProgramPolicyEngine(program), http)
            gw.vuln_class = "privilege_escalation"
            ctx = VerificationContext(program=program, db=db, http=gw,
                                      hypothesis=Hypothesis(program=program.name,
                                                            vuln_type="privilege_escalation",
                                                            title="t", rationale="r", target_url=URL))
            res = await PrivilegeEscalationVerifier().verify(ctx)
    finally:
        db.close()
    assert res.verified is False and "INCONCLUSIVE" in res.reason and t.calls == 0


def test_real_wolt_cannot_select_sim_other():
    wolt = ProgramManager(load_program(WOLT))
    labels = {a.label for a in wolt.config.test_accounts}
    assert labels == {"consumer_test"}          # sim_other is NOT a Wolt identity
    d = ProgramPolicyEngine(wolt).evaluate(ToolRequest(
        tool="http", arguments={"url": "https://wolt.com/x", "method": "GET"},
        target="https://wolt.com/x", identity="sim_other"))
    assert d.allowed is False   # unauthorized identity (and program not ready) -> denied
