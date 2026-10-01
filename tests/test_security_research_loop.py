"""Security Research Loop — complete local flow.

browser exploration -> surface discovery -> hypothesis generation -> POLICY GATE
-> test via PolicyGatedHTTP -> verification -> evidence -> HUMAN review.

Runs the real pipeline against the loopback vulnerable lab: the browser layer
observes the app's surface; the existing planner/detectors/verification/evidence
pipeline confirms IDOR/BOLA, BFLA and SQLi; findings are queued for human review.
The agent never approves or submits. No Temu, no real external target.
"""

from __future__ import annotations

import pytest

from bbagent.browser import ExplorationLimits
from bbagent.planner import TestBudget
from bbagent.research import ResearchLimits, run_security_research
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import FindingStatus
from bbagent_lab.agent_config import ENV_TOKEN_A, ENV_TOKEN_B
from bbagent_lab.data import USERS
from bbagent_lab.lab_browser import LabBrowserBackend
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


def _limits() -> ResearchLimits:
    return ResearchLimits(
        max_rounds=3, max_seconds=60.0,
        exploration=ExplorationLimits(max_actions=20, max_pages=30, max_no_progress=6),
        test=TestBudget(),
    )


async def _run(program, lab, tmp_path):
    db = Database(":memory:")
    evidence = EvidenceStore(db, tmp_path / "ev")
    backend = LabBrowserBackend(lab.base_url)
    seeds = [lab.base_url.rstrip("/") + "/site"]
    report = await run_security_research(
        program, db, evidence, browser_backend=backend, seed_urls=seeds,
        identity="researcher", limits=_limits())
    return db, evidence, report


# --- the complete flow --------------------------------------------------------

async def test_full_local_flow_discovers_and_verifies(program, lab, tmp_path):
    db, _, report = await _run(program, lab, tmp_path)

    # Surface was discovered by the BROWSER layer (no manifest, no fixed steps).
    assert report.endpoints_discovered >= 8

    # Hypotheses were generated, policy-gated, tested and VERIFIED for the three
    # target classes (a hypothesis only becomes a finding via the verifier).
    assert {"idor", "privilege_escalation", "sql_injection"} <= report.verified_classes
    by_class = {v.vuln_class: v for v in report.verified}
    assert "/api/notes/" in by_class["idor"].endpoint
    assert "/api/admin/report" in by_class["privilege_escalation"].endpoint
    assert "/products" in by_class["sql_injection"].endpoint

    # Every verified finding is queued for HUMAN review — never auto-approved.
    for v in report.verified:
        assert v.review_status == FindingStatus.READY_FOR_REVIEW.value
    # The agent never approves/submits: nothing reaches the approved terminal state.
    assert all(f.status is not FindingStatus.APPROVED_FOR_SUBMISSION
               for f in db.list_findings(program.name))
    db.close()


async def test_active_tests_consumed_shared_budget(program, lab, tmp_path):
    db, _, report = await _run(program, lab, tmp_path)
    # Active verification requests flowed through the single shared RunBudget.
    assert 0 < report.request_budget_used <= report.request_budget_max
    db.close()


async def test_only_in_scope_endpoints(program, lab, tmp_path):
    db, _, report = await _run(program, lab, tmp_path)
    for v in report.verified:
        assert "127.0.0.1" in v.endpoint or "localhost" in v.endpoint
    db.close()


async def test_loop_terminates_with_reason(program, lab, tmp_path):
    db, _, report = await _run(program, lab, tmp_path)
    assert report.stop_reason
    assert report.rounds_completed >= 1
    # A static app is exhausted within the round cap (it does not loop forever).
    assert report.rounds_completed <= 3
    db.close()


async def test_returns_to_exploration_then_stops_when_exhausted(program, lab, tmp_path):
    db, _, report = await _run(program, lab, tmp_path)
    # The loop explored, tested, then re-explored; it stops once a round adds no
    # new surface and generates no new hypotheses.
    assert report.stop_reason in ("surface and hypotheses exhausted", "max_rounds reached",
                                  "request budget exhausted", "max_seconds reached")
    # The first round did the productive work (grew surface + generated hypotheses).
    assert report.rounds[0].hypotheses_generated > 0
    assert report.rounds[0].endpoints_after > report.rounds[0].endpoints_before
    db.close()


async def test_max_rounds_one_is_respected(program, lab, tmp_path):
    db = Database(":memory:")
    evidence = EvidenceStore(db, tmp_path / "ev")
    backend = LabBrowserBackend(lab.base_url)
    seeds = [lab.base_url.rstrip("/") + "/site"]
    limits = ResearchLimits(max_rounds=1, exploration=ExplorationLimits(max_actions=20),
                            test=TestBudget())
    report = await run_security_research(program, db, evidence, browser_backend=backend,
                                         seed_urls=seeds, limits=limits)
    assert report.rounds_completed == 1
    # Even one round discovers and verifies the surface from the browser session.
    assert {"idor", "privilege_escalation", "sql_injection"} <= report.verified_classes
    db.close()


# --- Temu stays disabled ------------------------------------------------------

def test_cli_research_refuses_temu(tmp_path, capsys):
    from pathlib import Path
    from bbagent import cli
    temu = str(Path(__file__).resolve().parents[1] / "programs" / "temu.yaml")
    rc = cli.main(["--db", str(tmp_path / "r.db"), "research", temu,
                   "--seed", "https://www.temu.com/", "--live"])
    assert rc == 2
    assert "REFUSING real browser session" in capsys.readouterr().err
