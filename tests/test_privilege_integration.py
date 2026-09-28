"""End-to-end privilege-escalation run against the local lab (admin manifest).

Proves the full loop for the new detector and the negative cases, using the real
mapper -> planner -> verifier -> evidence -> review pipeline over a loopback socket.
"""

from __future__ import annotations

import pytest

from bbagent.config.models import ScopeKind, ScopeRule
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.planner import PlanRunner, RunStore, TestBudget
from bbagent.program.manager import ProgramManager
from bbagent.recon import AttackSurfaceMapper
from bbagent.reviewstore import ReviewStore
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import FindingStatus
from bbagent.surface.store import SurfaceStore
from bbagent.urlutils import endpoint_key
from bbagent_lab.agent_config import ENV_TOKEN_A, ENV_TOKEN_B, build_lab_program
from bbagent_lab.data import USERS
from bbagent_lab.server import BackgroundLab

PROG = "Local Vulnerable Lab"


@pytest.fixture
def lab():
    with BackgroundLab() as server:
        yield server


@pytest.fixture
def program(monkeypatch):
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)
    return ProgramManager(build_lab_program())


@pytest.fixture
def env():
    db = Database(":memory:")
    surface = SurfaceStore(db)
    yield db, surface
    db.close()


async def _map_admin(program, surface, lab):
    async with AuthorizedHTTPClient(program.config) as http:
        mapper = AttackSurfaceMapper(program, http, surface)
        await mapper.map_manifest(lab.base_url.rstrip("/") + "/admin-scope/manifest")


async def _run(program, db, surface, tmp_path, budget=None):
    async with AuthorizedHTTPClient(program.config) as http:
        evidence = EvidenceStore(db, tmp_path / "ev")
        runner = PlanRunner(program, db, surface, http, evidence, budget=budget)
        return await runner.run(), evidence


async def test_privilege_end_to_end(program, env, lab, tmp_path):
    db, surface = env
    await _map_admin(program, surface, lab)
    summary, evidence = await _run(program, db, surface, tmp_path)

    findings = db.list_findings(PROG)
    priv = [f for f in findings if f.vuln_type == "privilege_escalation"]
    assert len(priv) == 1
    finding = priv[0]
    assert "/api/admin/report" in finding.endpoint       # the vulnerable one
    assert finding.status is FindingStatus.VERIFIED

    # Secure + generic admin endpoints must NOT become findings.
    assert not any("/api/admin/settings" in f.endpoint for f in findings)
    assert not any("/api/admin/ping" in f.endpoint for f in findings)

    # 3 privilege hypotheses executed: 1 verified, 2 disproven.
    assert summary.executed == 3
    assert summary.verified == 1
    assert summary.disproven == 2

    # Evidence is real, hashes validate, and covers all three exchanges.
    assert len(finding.evidence_ids) >= 6   # admin + anon + non-priv, request+response each
    for eid in finding.evidence_ids:
        assert evidence.read_verified(eid)
    assert evidence.verify_all() == []


async def test_review_workflow_integration(program, env, lab, tmp_path):
    db, surface = env
    await _map_admin(program, surface, lab)
    summary, evidence = await _run(program, db, surface, tmp_path)
    finding = [f for f in db.list_findings(PROG) if f.vuln_type == "privilege_escalation"][0]

    rs = ReviewStore(db, evidence)
    item = rs.submit_for_review(finding.id)
    assert item.status == FindingStatus.READY_FOR_REVIEW.value
    assert item.quality_complete is True

    # Agent cannot approve; a human can.
    from bbagent.review import ApprovalError
    with pytest.raises(ApprovalError):
        rs.approve(finding.id, reviewer="agent")
    approved = rs.approve(finding.id, reviewer="alice")
    assert approved.status == FindingStatus.APPROVED_FOR_SUBMISSION.value


async def test_verified_not_regenerated(program, env, lab, tmp_path):
    db, surface = env
    await _map_admin(program, surface, lab)
    s1, _ = await _run(program, db, surface, tmp_path)
    assert s1.verified == 1
    s2, _ = await _run(program, db, surface, tmp_path)  # re-run
    assert s2.verified == 0
    assert s2.findings_created == 0
    assert len([f for f in db.list_findings(PROG) if f.vuln_type == "privilege_escalation"]) == 1


async def test_budget_enforced(program, env, lab, tmp_path):
    db, surface = env
    await _map_admin(program, surface, lab)
    summary, _ = await _run(program, db, surface, tmp_path, budget=TestBudget(max_requests=1))
    assert summary.executed == 1
    assert "budget" in summary.stop_reason


async def test_dry_run_makes_no_requests(program, env, lab, tmp_path):
    db, surface = env
    await _map_admin(program, surface, lab)
    async with AuthorizedHTTPClient(program.config) as http:
        evidence = EvidenceStore(db, tmp_path / "ev")
        before = http.request_count
        runner = PlanRunner(program, db, surface, http, evidence)
        summary = await runner.run(dry_run=True)
        assert http.request_count == before
    assert summary.generated >= 1 and summary.executed == 0
    assert db.list_findings(PROG) == []


async def test_out_of_scope_blocked(program, env, lab, tmp_path):
    db, surface = env
    # Inject an out-of-scope admin endpoint directly into the graph.
    url = "http://example.com/api/admin/report"
    ep = surface.upsert_endpoint(PROG, method="GET", url=url, path="/api/admin/report",
                                 template_key=endpoint_key("GET", url), confirmed=True)
    surface.record_auth_observation(PROG, endpoint_id=ep.id, identity="identity_a", status_code=200)
    async with AuthorizedHTTPClient(program.config) as http:
        evidence = EvidenceStore(db, tmp_path / "ev")
        summary = await PlanRunner(program, db, surface, http, evidence).run()
    assert summary.verified == 0
    assert summary.inconclusive >= 1
    assert db.list_findings(PROG) == []
