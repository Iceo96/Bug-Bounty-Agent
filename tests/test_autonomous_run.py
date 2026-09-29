"""True end-to-end autonomous run against the local Bug Bounty Program Simulator.

One run discovers the full local surface and exercises ALL FOUR existing detectors
(IDOR, BFLA, reflected XSS, SQLi), verifying one finding per class with immutable
evidence, then routes them to HUMAN review. The agent cannot approve or submit.
"""

from __future__ import annotations

import pytest

from bbagent.orchestrator import autonomous_run
from bbagent.review import ApprovalError
from bbagent.reviewstore import ReviewStore
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import FindingStatus
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


async def test_autonomous_run_all_four_detectors(program, lab, tmp_path):
    db = Database(":memory:")
    evidence = EvidenceStore(db, tmp_path / "ev")
    manifest = lab.base_url.rstrip("/") + "/full-scope/manifest"

    report = await autonomous_run(program, db, evidence, manifests=[manifest])

    # Recon + discovery happened, policy-gated.
    assert "127.0.0.1" in report.recon_hosts
    assert report.manifests_allowed == [manifest]
    assert report.endpoints_discovered >= 8

    # Exactly one verified finding per vulnerability class.
    assert report.verified_classes == {
        "idor", "privilege_escalation", "reflected_xss", "sql_injection",
    }
    by_class = {v.vuln_class: v for v in report.verified}
    assert "/api/notes/" in by_class["idor"].endpoint
    assert "/api/admin/report" in by_class["privilege_escalation"].endpoint
    assert "/search" in by_class["reflected_xss"].endpoint
    assert "/products" in by_class["sql_injection"].endpoint

    # Every verified finding is queued for HUMAN review with valid evidence.
    for v in report.verified:
        assert v.review_status == FindingStatus.READY_FOR_REVIEW.value
        finding = db.get_finding(v.finding_id)
        assert finding.evidence_ids
        for eid in finding.evidence_ids:
            assert evidence.read_verified(eid)
    assert evidence.verify_all() == []

    # The agent cannot approve; a human can. There is no submission path.
    rs = ReviewStore(db, evidence)
    target = report.verified[0].finding_id
    with pytest.raises(ApprovalError):
        rs.approve(target, reviewer="agent")
    approved = rs.approve(target, reviewer="alice")
    assert approved.status == FindingStatus.APPROVED_FOR_SUBMISSION.value
    assert not hasattr(rs, "submit") and not hasattr(autonomous_run, "submit")
    db.close()


async def test_autonomous_run_denies_out_of_scope_manifest(program, lab, tmp_path):
    db = Database(":memory:")
    evidence = EvidenceStore(db, tmp_path / "ev")
    good = lab.base_url.rstrip("/") + "/full-scope/manifest"
    bad = "http://example.com/full-scope/manifest"  # out of scope

    report = await autonomous_run(program, db, evidence, manifests=[bad, good])

    assert bad in report.manifests_denied
    assert good in report.manifests_allowed
    # Nothing from the out-of-scope host was discovered.
    from bbagent.surface.store import SurfaceStore
    for ep in SurfaceStore(db).list_endpoints(program.name):
        host = ep.url.split("//", 1)[1].split("/", 1)[0].split(":")[0]
        assert host in {"127.0.0.1", "localhost"}
    db.close()
