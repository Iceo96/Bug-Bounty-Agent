"""Task 1: one shared, run-level request budget across recon + verification.

Uses the local Wolt mock (MockTransport) as a runnable pipeline; no real network.
"""

from __future__ import annotations

import pytest

from bbagent.http.client import RequestBlocked, RunBudget
from bbagent.orchestrator import autonomous_run
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.tools.base import ToolRequest
from bbagent_lab.wolt_sim import (
    CONSUMER_TOKEN, ENV_CONSUMER, ENV_OTHER, H1_ENV, MANIFEST_URL, OTHER_TOKEN,
    build_wolt_sim_program, wolt_mock_transport,
)


@pytest.fixture
def sim(monkeypatch):
    monkeypatch.setenv(ENV_CONSUMER, CONSUMER_TOKEN)
    monkeypatch.setenv(ENV_OTHER, OTHER_TOKEN)
    monkeypatch.setenv(H1_ENV, "researcher-handle")
    return build_wolt_sim_program()


# --- RunBudget unit -----------------------------------------------------------

def test_runbudget_consume_and_no_reset():
    b = RunBudget(2)
    b.consume(); b.consume()
    assert b.used == 2 and b.remaining() == 0
    with pytest.raises(RequestBlocked):
        b.consume()               # exhausted -> raises (before any transport)
    assert not hasattr(b, "reset")   # nothing can reset the counter
    assert b.used == 2               # count only ever grows


def test_toolrequest_cannot_carry_a_budget():
    with pytest.raises(Exception):
        ToolRequest(tool="http", arguments={"url": "http://x/"}, request_budget={"total": 1})


# --- shared budget across the whole run ---------------------------------------

async def test_recon_and_verification_share_one_budget(sim, tmp_path):
    db = Database(":memory:")
    evidence = EvidenceStore(db, tmp_path / "ev")
    transport = wolt_mock_transport()
    rb = RunBudget(500)
    report = await autonomous_run(sim, db, evidence, manifests=[MANIFEST_URL],
                                  transport=transport, run_budget=rb)
    # Every request (recon/discovery + verification) drew from the ONE counter.
    assert report.request_budget_used == transport.calls == rb.used
    assert rb.used > 10                       # recon + verification both consumed
    assert report.verified_classes == {       # verification ran within the budget
        "idor", "privilege_escalation", "reflected_xss", "sql_injection"}
    db.close()


async def test_budget_exhaustion_prevents_transport(sim, tmp_path):
    db = Database(":memory:")
    evidence = EvidenceStore(db, tmp_path / "ev")
    transport = wolt_mock_transport()
    rb = RunBudget(3)                          # far fewer than a full run needs
    report = await autonomous_run(sim, db, evidence, manifests=[MANIFEST_URL],
                                  transport=transport, run_budget=rb)
    assert transport.calls == 3                # stopped exactly at the budget
    assert rb.used == 3 and report.request_budget_used == 3
    assert report.verified == []               # verification was starved -> no findings
    db.close()


async def test_fresh_budget_per_run(sim, tmp_path):
    db = Database(":memory:")
    evidence = EvidenceStore(db, tmp_path / "ev")
    # Two runs, each with its own fresh budget (default from program.request_budget).
    r1 = await autonomous_run(sim, db, evidence, manifests=[MANIFEST_URL],
                              transport=wolt_mock_transport())
    r2 = await autonomous_run(sim, db, evidence, manifests=[MANIFEST_URL],
                              transport=wolt_mock_transport())
    assert r1.request_budget_max == r2.request_budget_max == 500
    assert r1.request_budget_used > 0 and r2.request_budget_used > 0   # each got a fresh budget
    db.close()


async def test_verification_starved_when_budget_barely_covers_recon(sim, tmp_path):
    # A budget that covers discovery but not verification proves verification draws
    # from the SAME (now-limited) budget rather than a separate one.
    db = Database(":memory:")
    evidence = EvidenceStore(db, tmp_path / "ev")
    transport = wolt_mock_transport()
    # First measure recon-only cost by discovering with a generous budget.
    probe_db = Database(":memory:")
    probe_ev = EvidenceStore(probe_db, tmp_path / "probe_ev")
    full = await autonomous_run(sim, probe_db, probe_ev, manifests=[MANIFEST_URL],
                                transport=wolt_mock_transport())
    probe_db.close()
    verified_full = len(full.verified)

    rb = RunBudget(6)   # enough for some discovery, not the full verification set
    limited = await autonomous_run(sim, db, evidence, manifests=[MANIFEST_URL],
                                   transport=transport, run_budget=rb)
    assert transport.calls <= 6
    assert len(limited.verified) < verified_full   # shared budget throttled verification
    db.close()
