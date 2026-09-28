"""End-to-end planner run against the local lab.

Proves the full loop (map -> plan -> execute -> verify -> finding) and the
negative behaviors: no finding from a 200 alone, protected endpoint disproven,
scope enforced, no external calls, budget stops, no infinite duplication.
"""

from __future__ import annotations

import pytest

from bbagent.config.models import ScopeKind, ScopeRule
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.planner import PlanRunner, PlanStatus, RunStore, TestBudget
from bbagent.program.manager import ProgramManager
from bbagent.recon import AttackSurfaceMapper
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


async def _map(program, surface, lab):
    async with AuthorizedHTTPClient(program.config) as http:
        mapper = AttackSurfaceMapper(program, http, surface)
        await mapper.map_manifest(lab.base_url.rstrip("/") + "/")


async def test_end_to_end_verified_and_negative(program, env, lab, tmp_path):
    db, surface = env
    await _map(program, surface, lab)

    async with AuthorizedHTTPClient(program.config) as http:
        evidence = EvidenceStore(db, tmp_path / "ev")
        runner = PlanRunner(program, db, surface, http, evidence)
        summary = await runner.run()

    # The vulnerable notes endpoint produced exactly one verified finding.
    findings = db.list_findings(PROG)
    assert len(findings) == 1
    assert findings[0].vuln_type == "idor"
    assert "/api/notes/" in findings[0].endpoint
    assert findings[0].status is FindingStatus.VERIFIED

    # Both candidates were tried; the protected profile endpoint was disproven.
    assert summary.executed == 2
    assert summary.verified == 1
    assert summary.disproven == 1
    assert summary.findings_created == 1
    assert summary.stop_reason == "no useful hypotheses remain"

    # Hypothesis statuses recorded in run history.
    hyps = RunStore(db).hypotheses_for_run(summary.run_id)
    statuses = {h["endpoint"]: h["status"] for h in hyps}
    assert any("/api/notes/" in e and s == "verified" for e, s in statuses.items())
    assert any("/api/profile/" in e and s == "disproven" for e, s in statuses.items())


async def test_no_finding_without_evidence_and_not_from_status_alone(program, env, lab, tmp_path):
    # profile returns 200 to its owner, but that alone is NOT a finding.
    db, surface = env
    await _map(program, surface, lab)
    async with AuthorizedHTTPClient(program.config) as http:
        evidence = EvidenceStore(db, tmp_path / "ev")
        await PlanRunner(program, db, surface, http, evidence).run()
    for f in db.list_findings(PROG):
        assert "/api/profile/" not in f.endpoint  # protected: never reported


async def test_verified_hypothesis_not_regenerated(program, env, lab, tmp_path):
    db, surface = env
    await _map(program, surface, lab)
    async with AuthorizedHTTPClient(program.config) as http:
        evidence = EvidenceStore(db, tmp_path / "ev")
        runner = PlanRunner(program, db, surface, http, evidence)
        s1 = await runner.run()
        assert s1.verified == 1
        # Second run: the verified notes hypothesis is not regenerated; only the
        # (disproven) profile is retried. No new finding is created.
        runner2 = PlanRunner(program, db, surface, http, evidence)
        s2 = await runner2.run()
    assert s2.verified == 0
    assert s2.findings_created == 0
    assert len(db.list_findings(PROG)) == 1  # still just the one


async def test_budget_stops_run(program, env, lab, tmp_path):
    db, surface = env
    await _map(program, surface, lab)
    async with AuthorizedHTTPClient(program.config) as http:
        evidence = EvidenceStore(db, tmp_path / "ev")
        runner = PlanRunner(program, db, surface, http, evidence,
                            budget=TestBudget(max_requests=1))
        summary = await runner.run()
    assert summary.executed == 1  # stops after the first test's requests
    assert "budget" in summary.stop_reason


async def test_dry_run_makes_no_requests(program, env, lab, tmp_path):
    db, surface = env
    await _map(program, surface, lab)
    async with AuthorizedHTTPClient(program.config) as http:
        evidence = EvidenceStore(db, tmp_path / "ev")
        before = http.request_count
        runner = PlanRunner(program, db, surface, http, evidence)
        summary = await runner.run(dry_run=True)
        assert http.request_count == before  # nothing executed
    assert summary.generated >= 1 and summary.executed == 0
    assert db.list_findings(PROG) == []


async def test_scope_enforced_on_execution(program, env, lab, tmp_path):
    """An out-of-scope endpoint in the graph must never yield a finding or an
    external call; the verifier is blocked by scope and the test is inconclusive."""
    db, surface = env
    # Inject an out-of-scope endpoint directly into the graph.
    url = "http://example.com/api/notes/1"
    ep = surface.upsert_endpoint(PROG, method="GET", url=url, path="/api/notes/1",
                                 template_key=endpoint_key("GET", url), confirmed=True)
    surface.upsert_object_ref(PROG, endpoint_id=ep.id, value="1", kind="numeric", location="path")
    surface.record_auth_observation(PROG, endpoint_id=ep.id, identity="identity_a", status_code=200)

    async with AuthorizedHTTPClient(program.config) as http:
        evidence = EvidenceStore(db, tmp_path / "ev")
        runner = PlanRunner(program, db, surface, http, evidence)
        summary = await runner.run()

    assert summary.verified == 0
    assert summary.inconclusive >= 1          # blocked by scope, not a finding
    assert db.list_findings(PROG) == []
    hyps = RunStore(db).hypotheses_for_run(summary.run_id)
    assert any(h["status"] == "inconclusive" for h in hyps)


async def test_no_external_targets(program, env, lab, tmp_path):
    db, surface = env
    await _map(program, surface, lab)
    async with AuthorizedHTTPClient(program.config) as http:
        evidence = EvidenceStore(db, tmp_path / "ev")
        summary = await PlanRunner(program, db, surface, http, evidence).run()
    for h in RunStore(db).hypotheses_for_run(summary.run_id):
        host = h["endpoint"].split("//", 1)[1].split("/", 1)[0].split(":")[0]
        assert host in {"127.0.0.1", "localhost"}
