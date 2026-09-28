"""End-to-end reflected-XSS run against the local lab (xss manifest)."""

from __future__ import annotations

import pytest

from bbagent.http.client import AuthorizedHTTPClient
from bbagent.planner import PlanRunner, RunStore, TestBudget
from bbagent.program.manager import ProgramManager
from bbagent.recon import AttackSurfaceMapper
from bbagent.reviewstore import ReviewStore
from bbagent.review import ApprovalError
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


async def _map_xss(program, surface, lab):
    async with AuthorizedHTTPClient(program.config) as http:
        mapper = AttackSurfaceMapper(program, http, surface)
        await mapper.map_manifest(lab.base_url.rstrip("/") + "/xss-scope/manifest")


async def _run(program, db, surface, tmp_path, budget=None):
    async with AuthorizedHTTPClient(program.config) as http:
        evidence = EvidenceStore(db, tmp_path / "ev")
        runner = PlanRunner(program, db, surface, http, evidence, budget=budget)
        return await runner.run(), evidence


async def test_reflected_xss_end_to_end(program, env, lab, tmp_path):
    db, surface = env
    await _map_xss(program, surface, lab)
    summary, evidence = await _run(program, db, surface, tmp_path)

    findings = db.list_findings(PROG)
    xss = [f for f in findings if f.vuln_type == "reflected_xss"]
    assert len(xss) == 1
    assert "/search" in xss[0].endpoint and "/search-safe" not in xss[0].endpoint
    assert xss[0].status is FindingStatus.VERIFIED

    # secure + control endpoints must not be reported
    assert not any("/search-safe" in f.endpoint for f in findings)
    assert not any("/echo" in f.endpoint for f in findings)

    assert summary.verified == 1
    assert summary.disproven == 2   # search-safe (encoded) + echo (non-html)

    # Evidence: baseline + payload exchanges, hashes valid.
    assert len(xss[0].evidence_ids) >= 4
    for eid in xss[0].evidence_ids:
        assert evidence.read_verified(eid)
    assert evidence.verify_all() == []


async def test_review_workflow_integration(program, env, lab, tmp_path):
    db, surface = env
    await _map_xss(program, surface, lab)
    _summary, evidence = await _run(program, db, surface, tmp_path)
    finding = [f for f in db.list_findings(PROG) if f.vuln_type == "reflected_xss"][0]

    rs = ReviewStore(db, evidence)
    item = rs.submit_for_review(finding.id)
    assert item.status == FindingStatus.READY_FOR_REVIEW.value
    with pytest.raises(ApprovalError):
        rs.approve(finding.id, reviewer="agent")
    approved = rs.approve(finding.id, reviewer="alice")
    assert approved.status == FindingStatus.APPROVED_FOR_SUBMISSION.value


async def test_dry_run_makes_no_requests(program, env, lab, tmp_path):
    db, surface = env
    await _map_xss(program, surface, lab)
    async with AuthorizedHTTPClient(program.config) as http:
        evidence = EvidenceStore(db, tmp_path / "ev")
        before = http.request_count
        summary = await PlanRunner(program, db, surface, http, evidence).run(dry_run=True)
        assert http.request_count == before
    assert summary.generated >= 1 and summary.executed == 0
    assert db.list_findings(PROG) == []


async def test_budget_enforced(program, env, lab, tmp_path):
    db, surface = env
    await _map_xss(program, surface, lab)
    summary, _ = await _run(program, db, surface, tmp_path, budget=TestBudget(max_requests=1))
    assert summary.executed == 1
    assert "budget" in summary.stop_reason


async def test_out_of_scope_blocked(program, env, lab, tmp_path):
    db, surface = env
    url = "http://example.com/search?q=probe"
    surface.upsert_endpoint(PROG, method="GET", url=url, path="/search",
                            template_key=endpoint_key("GET", url), query_params=["q"], confirmed=True)
    async with AuthorizedHTTPClient(program.config) as http:
        evidence = EvidenceStore(db, tmp_path / "ev")
        summary = await PlanRunner(program, db, surface, http, evidence).run()
    assert summary.verified == 0
    assert summary.inconclusive >= 1
    assert db.list_findings(PROG) == []


async def test_verified_not_regenerated(program, env, lab, tmp_path):
    db, surface = env
    await _map_xss(program, surface, lab)
    s1, _ = await _run(program, db, surface, tmp_path)
    assert s1.verified == 1
    s2, _ = await _run(program, db, surface, tmp_path)
    assert s2.verified == 0 and s2.findings_created == 0
    assert len([f for f in db.list_findings(PROG) if f.vuln_type == "reflected_xss"]) == 1
