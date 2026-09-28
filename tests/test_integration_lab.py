"""End-to-end integration tests against the local vulnerable lab.

Demonstrates the full pipeline over a REAL localhost socket:
  local app -> discovery -> endpoint -> hypothesis -> verification
             -> immutable evidence -> verified finding -> Markdown report

No external network requests are made: the lab binds to 127.0.0.1 and the scope
engine denies anything that is not loopback.
"""

from __future__ import annotations

import pytest

from bbagent.program.manager import ProgramManager
from bbagent.report import generate_report
from bbagent.scope.engine import ScopeEngine
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import FindingStatus
from bbagent_lab.agent_config import ENV_TOKEN_A, ENV_TOKEN_B, build_lab_program
from bbagent_lab.data import USERS
from bbagent_lab.pipeline import run_pipeline
from bbagent_lab.server import BackgroundLab


@pytest.fixture
def lab():
    with BackgroundLab() as server:
        yield server


@pytest.fixture
def program(monkeypatch):
    # Supply the synthetic tokens via env, exactly as a real run would.
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)
    return ProgramManager(build_lab_program())


@pytest.fixture
def store(tmp_path):
    db = Database(":memory:")
    ev = EvidenceStore(db, tmp_path / "evidence")
    yield db, ev
    db.close()


async def _run(program, store, lab):
    db, ev = store
    return await run_pipeline(program, db, ev, lab.base_url)


async def test_lab_binds_loopback_only(lab):
    host = lab.base_url.split("//", 1)[1].split(":")[0]
    assert host in {"127.0.0.1", "localhost", "::1"}


async def test_full_pipeline_detects_vulnerable_endpoint(program, store, lab):
    result = await _run(program, store, lab)

    # Both object-scoped endpoints are discovered as hypotheses...
    assert len(result.observations) == 2
    assert {h.vuln_type for h in result.hypotheses} == {"idor"}

    # ...but exactly ONE is a verified finding (the vulnerable notes endpoint).
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.vuln_type == "idor"
    assert finding.status is FindingStatus.VERIFIED
    assert "/api/notes/" in finding.endpoint
    assert "127.0.0.1" in finding.affected_asset


async def test_protected_endpoint_is_not_reported(program, store, lab):
    result = await _run(program, store, lab)
    endpoints = [f.endpoint for f in result.findings]
    # The correctly-protected profile endpoint must never become a finding.
    assert not any("/api/profile/" in e for e in endpoints)


async def test_evidence_captured_and_hashes_valid(program, store, lab):
    db, ev = store
    result = await _run(program, store, lab)
    finding = result.findings[0]

    # Request + response for BOTH identities => at least 4 evidence blobs.
    assert len(finding.evidence_ids) >= 4
    for eid in finding.evidence_ids:
        assert ev.read_verified(eid)  # raises on hash mismatch
    assert ev.verify_all() == []  # nothing tampered

    # The captured evidence really contains both identities' exchanges.
    labels = {db.get_evidence(eid).label for eid in finding.evidence_ids}
    assert {"request", "response"} <= labels


async def test_finding_cannot_exist_without_evidence(program, store, lab):
    db, _ev = store
    await _run(program, store, lab)
    for finding in db.list_findings():
        assert finding.evidence_ids, "a finding must always carry evidence"


async def test_markdown_report_generated(program, store, lab):
    db, ev = store
    result = await _run(program, store, lab)
    report = generate_report(result.findings[0], db, ev)

    assert report.startswith("# ")
    assert "## Steps to reproduce" in report
    assert "## Evidence" in report
    assert "Severity" not in report  # no methodology provided
    assert "requires human review before submission" in report
    # Report embeds real captured data (the vulnerable note contents).
    assert "note-a1" in report


async def test_scope_rules_still_apply(program):
    engine = ScopeEngine(program.config.scope)
    assert engine.is_allowed("http://127.0.0.1/api/notes/note-a1") is True
    assert engine.is_allowed("http://localhost/x") is True
    # Anything non-loopback is denied.
    assert engine.is_allowed("http://example.com/") is False
    assert engine.is_allowed("http://169.254.169.254/latest/meta-data/") is False


async def test_no_external_targets_touched(program, store, lab):
    """Every URL the pipeline touched or recorded is loopback."""
    result = await _run(program, store, lab)
    urls = [o.data["url"] for o in result.observations]
    urls += [f.endpoint for f in result.findings]
    for url in urls:
        host = url.split("//", 1)[1].split("/", 1)[0].split(":")[0]
        assert host in {"127.0.0.1", "localhost"}, f"non-loopback target: {url}"
