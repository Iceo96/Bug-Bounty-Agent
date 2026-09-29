"""Wolt-specific, policy-aware SIMULATION (local mock only — never contacts Wolt).

Exercises the full autonomous pipeline against Wolt-shaped endpoints and proves
Wolt's policy semantics: allowed actions execute against the mock, denied actions
never reach the transport, and the real Wolt policy stays NOT READY / dry-run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bbagent import cli
from bbagent.config.loader import load_program
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.orchestrator import autonomous_run
from bbagent.policy import ProgramPolicyEngine
from bbagent.policy.validation import validate_policy
from bbagent.program.manager import ProgramManager
from bbagent.review import ApprovalError
from bbagent.reviewstore import ReviewStore
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import FindingStatus
from bbagent.tools import ToolContext, ToolRequest, ToolRouter, default_tools
from bbagent_lab.wolt_sim import (
    BASE, CONSUMER_TOKEN, ENV_CONSUMER, ENV_OTHER, H1_ENV, MANIFEST_URL, OTHER_TOKEN,
    WoltMockTransport, build_wolt_sim_program, wolt_mock_transport,
)

WOLT_YAML = str(Path(__file__).resolve().parents[1] / "programs" / "wolt.yaml")


@pytest.fixture
def sim_env(monkeypatch):
    monkeypatch.setenv(ENV_CONSUMER, CONSUMER_TOKEN)
    monkeypatch.setenv(ENV_OTHER, OTHER_TOKEN)
    monkeypatch.setenv(H1_ENV, "researcher-handle")
    return build_wolt_sim_program()


# --- full autonomous pipeline over the mock -----------------------------------

async def test_full_pipeline_all_four_detectors(sim_env, tmp_path):
    program = sim_env
    db = Database(":memory:")
    evidence = EvidenceStore(db, tmp_path / "ev")
    transport = wolt_mock_transport()

    report = await autonomous_run(program, db, evidence, manifests=[MANIFEST_URL],
                                  transport=transport)

    # The mock served requests (pipeline ran locally); no real network exists.
    assert transport.calls > 0
    # One verified finding per class, from Wolt-shaped endpoints.
    assert report.verified_classes == {
        "idor", "privilege_escalation", "reflected_xss", "sql_injection"}
    by_class = {v.vuln_class: v for v in report.verified}
    assert "/sim/v1/orders/" in by_class["idor"].endpoint
    assert "/sim/admin/report" in by_class["privilege_escalation"].endpoint
    assert "/sim/search" in by_class["reflected_xss"].endpoint
    assert "/sim/catalog" in by_class["sql_injection"].endpoint

    # All targets stayed on the in-scope Wolt host; evidence is valid.
    for v in report.verified:
        assert v.endpoint.startswith(BASE)
        assert v.review_status == FindingStatus.READY_FOR_REVIEW.value
    assert evidence.verify_all() == []

    # Human review only: agent cannot approve; a human can.
    rs = ReviewStore(db, evidence)
    fid = report.verified[0].finding_id
    with pytest.raises(ApprovalError):
        rs.approve(fid, reviewer="agent")
    assert rs.approve(fid, reviewer="alice").status == FindingStatus.APPROVED_FOR_SUBMISSION.value
    db.close()


# --- Wolt policy scenarios via the tool router (denied never reach transport) -

@pytest.fixture
def router_and_transport(sim_env):
    """Returns a factory that builds a router bound to a fresh counting transport."""
    program = sim_env

    class Harness:
        def __init__(self):
            self.transport = WoltMockTransport()
            self._cm = AuthorizedHTTPClient(program.config, transport=self.transport)

        async def __aenter__(self):
            http = await self._cm.__aenter__()
            self.router = ToolRouter(default_tools(), ProgramPolicyEngine(program),
                                     ToolContext(program=program, http=http))
            return self

        async def __aexit__(self, *exc):
            await self._cm.__aexit__(*exc)

    return Harness


async def _dispatch(harness_cls, **req):
    async with harness_cls() as h:
        res = await h.router.dispatch(ToolRequest(**req))
        return res, h.transport.calls


ALLOWED = {"tool": "http", "arguments": {"url": f"{BASE}/sim/manifest", "method": "GET"}}


async def test_allowed_in_scope_request_executes(router_and_transport):
    res, calls = await _dispatch(router_and_transport, **ALLOWED, identity="consumer_test")
    assert res.success is True and calls == 1


@pytest.mark.parametrize("req,label", [
    ({"tool": "http", "arguments": {"url": "https://wolt.atlassian.net/x", "method": "GET"}},
     "excluded host"),
    ({"tool": "http", "arguments": {"url": f"{BASE}/v1/waw-api/corporate-leads", "method": "GET"}},
     "excluded path"),
    ({"tool": "http", "arguments": {"url": f"{BASE}/v1/waw-api/corporate-leads", "method": "POST"}},
     "forbidden POST endpoint"),
    ({"tool": "http", "arguments": {"url": f"{BASE}/sim/manifest", "method": "GET",
                                    "headers": {"X-HackerOne-Research": "attacker"}}},
     "override required header"),
    ({"tool": "http", "arguments": {"url": f"{BASE}/sim/manifest", "method": "GET"},
      "identity": "random_person"}, "unauthorized identity"),
    ({"tool": "http", "arguments": {"url": f"{BASE}/sim/manifest", "method": "GET"},
      "identity": "courier"}, "courier unavailable"),
    ({"tool": "http", "arguments": {"url": f"{BASE}/sim/manifest", "method": "GET"},
      "identity": "merchant"}, "merchant unavailable"),
    ({"tool": "http", "arguments": {"url": f"{BASE}/sim/manifest", "method": "GET"},
      "vuln_class": "rce"}, "forbidden vuln class"),
    ({"tool": "http", "arguments": {"url": f"{BASE}/sim/manifest", "method": "GET"},
      "requested_action": "dos"}, "forbidden action category"),
    ({"tool": "http", "arguments": {"url": f"{BASE}/sim/manifest", "method": "PUT"}},
     "undefined/forbidden method"),
    ({"tool": "shell", "arguments": {}}, "unauthorized tool"),
])
async def test_denied_never_reaches_transport(router_and_transport, req, label):
    res, calls = await _dispatch(router_and_transport, **req)
    assert res.success is False, label
    assert calls == 0, f"{label}: transport must not be called"


async def test_missing_required_header_denied(monkeypatch):
    # No H1 env set -> the required research header can't be satisfied -> DENY.
    monkeypatch.setenv(ENV_CONSUMER, CONSUMER_TOKEN)
    monkeypatch.setenv(ENV_OTHER, OTHER_TOKEN)
    monkeypatch.delenv(H1_ENV, raising=False)
    program = build_wolt_sim_program()
    t = WoltMockTransport()
    async with AuthorizedHTTPClient(program.config, transport=t) as http:
        router = ToolRouter(default_tools(), ProgramPolicyEngine(program),
                            ToolContext(program=program, http=http))
        res = await router.dispatch(ToolRequest(**ALLOWED))
    assert res.success is False and "X-HackerOne-Research" in (res.denied_reason or "")
    assert t.calls == 0


# --- LLM cannot bypass policy -------------------------------------------------

def test_llm_cannot_smuggle_policy_fields():
    for extra in ("scope", "allowed_tools", "allowed_vulnerability_classes", "request_budget"):
        with pytest.raises(Exception):
            ToolRequest(tool="http", arguments={"url": f"{BASE}/x"}, **{extra: "x"})


async def test_data_outside_authorized_entities_is_denied_or_unauthorized(router_and_transport):
    # An excluded/ineligible asset (blog.wolt.com) is denied regardless.
    res, calls = await _dispatch(
        router_and_transport,
        tool="http", arguments={"url": "https://blog.wolt.com/wp-login.php", "method": "GET"})
    assert res.success is False and calls == 0


# --- the REAL Wolt policy remains untouched -----------------------------------

def test_real_wolt_policy_still_not_ready_and_dry_run():
    wolt = ProgramManager(load_program(WOLT_YAML))
    assert wolt.config.dry_run_only is True
    assert validate_policy(wolt).ready is False


def test_real_wolt_policy_check_cli_exit_1():
    assert cli.main(["policy-check", WOLT_YAML]) == 1
