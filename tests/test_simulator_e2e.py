"""End-to-end local Bug Bounty Program Simulator run.

Ties the tool layer + policy engine to the existing detection/verification/review
pipeline, entirely against the loopback lab. Proves allowed actions execute,
denied actions never do, detectors still work, findings reach human review, and
the agent can neither approve nor submit.
"""

from __future__ import annotations

import pytest

from bbagent.http.client import AuthorizedHTTPClient
from bbagent.planner import PlanRunner
from bbagent.policy import ProgramPolicyEngine
from bbagent.recon import AttackSurfaceMapper
from bbagent.review import ApprovalError
from bbagent.reviewstore import ReviewStore
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import FindingStatus
from bbagent.surface.store import SurfaceStore
from bbagent.tools import ToolContext, ToolRequest, ToolRouter, default_tools
from bbagent_lab.agent_config import ENV_TOKEN_A, ENV_TOKEN_B
from bbagent_lab.data import USERS
from bbagent_lab.server import BackgroundLab
from bbagent_lab.simulator import build_simulator_manager


@pytest.fixture
def lab():
    with BackgroundLab() as server:
        yield server


@pytest.fixture
def program(monkeypatch):
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)
    return build_simulator_manager()


async def test_full_local_simulator_run(program, lab, tmp_path):
    base = lab.base_url.rstrip("/")
    db = Database(":memory:")
    surface = SurfaceStore(db)
    evidence = EvidenceStore(db, tmp_path / "ev")

    async with AuthorizedHTTPClient(program.config) as http:
        policy = ProgramPolicyEngine(program)
        router = ToolRouter(default_tools(), policy, ToolContext(program=program, http=http))

        # 1) Allowed recon (local, deterministic).
        hosts = await router.dispatch(ToolRequest(tool="recon", arguments={"action": "scope_hosts"}))
        assert hosts.success and "127.0.0.1" in hosts.sanitized["hosts"]

        # 2) Allowed in-scope HTTP tool call (sanitized result).
        man = await router.dispatch(ToolRequest(
            tool="http", arguments={"url": f"{base}/sqli-scope/manifest", "method": "GET"}))
        assert man.success and "products" in man.sanitized["body"]

        # 3) Denied actions never execute.
        assert (await router.dispatch(ToolRequest(
            tool="http", arguments={"url": "http://example.com/x", "method": "GET"}))).success is False
        assert (await router.dispatch(ToolRequest(
            tool="http", arguments={"url": f"{base}/excluded/secret", "method": "GET"}))).success is False
        assert (await router.dispatch(ToolRequest(tool="shell", arguments={}))).success is False

        # 4) Detection/verification pipeline under the same program (scope-enforced).
        mapper = AttackSurfaceMapper(program, http, surface)
        await mapper.map_manifest(f"{base}/sqli-scope/manifest")
        summary = await PlanRunner(program, db, surface, http, evidence).run()

    # 5) A verified SQLi finding was produced with immutable, valid evidence.
    sqli = [f for f in db.list_findings(program.name) if f.vuln_type == "sql_injection"]
    assert len(sqli) == 1 and sqli[0].status is FindingStatus.VERIFIED
    assert summary.verified >= 1
    for eid in sqli[0].evidence_ids:
        assert evidence.read_verified(eid)

    # 6) Human review: agent cannot approve; a human can. No submission path.
    rs = ReviewStore(db, evidence)
    item = rs.submit_for_review(sqli[0].id)
    assert item.status == FindingStatus.READY_FOR_REVIEW.value
    with pytest.raises(ApprovalError):
        rs.approve(sqli[0].id, reviewer="agent")
    approved = rs.approve(sqli[0].id, reviewer="alice")
    assert approved.status == FindingStatus.APPROVED_FOR_SUBMISSION.value
    # Terminal state: there is no submit() anywhere in the codebase.
    assert not hasattr(rs, "submit")
    db.close()


async def test_policy_budget_blocks_before_execution(program, lab):
    """Exhausting the policy budget denies further tool calls (client not hit)."""
    base = lab.base_url.rstrip("/")
    program.config.request_budget.total = 1
    async with AuthorizedHTTPClient(program.config) as http:
        router = ToolRouter(default_tools(), ProgramPolicyEngine(program),
                            ToolContext(program=program, http=http))
        first = await router.dispatch(ToolRequest(
            tool="http", arguments={"url": f"{base}/sqli-scope/manifest", "method": "GET"}))
        assert first.success is True
        second = await router.dispatch(ToolRequest(
            tool="recon", arguments={"action": "scope_hosts"}))
        assert second.success is False and "budget" in (second.denied_reason or "")
