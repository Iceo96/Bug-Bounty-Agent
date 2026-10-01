"""Temu dry-run milestone: start from programs/temu.yaml, discover the attack
surface, generate IDOR/BFLA/SQLi hypotheses, prioritize, and run them through the
policy-gated verification pipeline — with ZERO real Temu network requests.

The real programs/temu.yaml stays dry_run_only=true and NOT READY. The pipeline is
exercised against a local MockTransport Temu simulation derived from it (same
scope, capability matrix, exclusions, required header, data-scope).
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import pytest

from bbagent.config.loader import load_program
from bbagent.http.client import AuthorizedHTTPClient, RequestBlocked, RunBudget
from bbagent.orchestrator import autonomous_run
from bbagent.policy.engine import ProgramPolicyEngine
from bbagent.program.manager import ProgramManager
from bbagent.scope.engine import ScopeEngine
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.tools.gateway import PolicyGatedHTTP
from bbagent_lab.temu_sim import (
    BASE, ENV_OTHER, ENV_RESEARCHER, H1_ENV, MANIFEST_URL, OBJECT_ID, OTHER_TOKEN,
    RESEARCHER_TOKEN, TemuMockTransport, build_temu_sim_program, temu_mock_transport,
)

TEMU_YAML = str(Path(__file__).resolve().parents[1] / "programs" / "temu.yaml")
TEMU_HOSTS = {"www.temu.com", "seller.temu.com", "partner.temu.com", "ads.temu.com"}


@pytest.fixture
def sim(monkeypatch):
    monkeypatch.setenv(ENV_RESEARCHER, RESEARCHER_TOKEN)
    monkeypatch.setenv(ENV_OTHER, OTHER_TOKEN)
    monkeypatch.setenv(H1_ENV, "researcher-handle")
    return build_temu_sim_program()


async def _run(sim, tmp_path, transport, run_budget=None):
    db = Database(":memory:")
    evidence = EvidenceStore(db, tmp_path / "ev")
    report = await autonomous_run(sim, db, evidence, manifests=[MANIFEST_URL],
                                  transport=transport, run_budget=run_budget)
    return report, db, evidence


# --- the full scope-driven dry-run ---------------------------------------------

async def test_temu_dry_run_full_pipeline(sim, tmp_path):
    transport = temu_mock_transport()
    report, db, evidence = await _run(sim, tmp_path, transport)

    # Scope-driven discovery happened from the seed manifest alone (no manual URLs).
    assert any(h in TEMU_HOSTS for h in report.recon_hosts)
    assert report.endpoints_discovered >= 5

    # ALLOWED classes reached planning; FORBIDDEN reflected XSS did not.
    assert set(report.hypotheses_by_class) >= {"idor", "privilege_escalation", "sql_injection"}
    assert "reflected_xss" not in report.hypotheses_by_class

    # The three allowed classes verified against the local mock (candidates only).
    assert report.verified_classes == {"idor", "privilege_escalation", "sql_injection"}
    assert "reflected_xss" not in report.verified_classes

    # Every discovered/tested URL stayed within the EXACT Temu scope.
    from bbagent.surface.store import SurfaceStore
    for ep in SurfaceStore(db).list_endpoints(sim.name):
        host = urlsplit(ep.url).hostname
        assert host in TEMU_HOSTS, ep.url

    # Findings are SIMULATION candidates, never confirmed real Temu findings.
    for f in db.list_findings(sim.name):
        assert "SIMULATION" in f.program and f.program != "temu-bug-bounty"
    assert evidence.verify_all() == []
    db.close()


async def test_temu_dry_run_report_contents(sim, tmp_path):
    report, db, _ = await _run(sim, tmp_path, temu_mock_transport())
    text = report.render()
    for section in ("discovered assets", "discovered endpoints", "capability matrix",
                    "enabled classes", "blocked classes", "hypotheses generated",
                    "eligible-if-live", "budget", "final status"):
        assert section in text
    assert "SIMULATION" in text
    assert "hypotheses are NOT findings" in text
    assert "reflected_xss=FORBIDDEN" in text
    db.close()


async def test_temu_capability_matrix_in_report(sim, tmp_path):
    report, db, _ = await _run(sim, tmp_path, temu_mock_transport())
    assert report.capability_matrix["reflected_xss"] == "FORBIDDEN"
    assert report.capability_matrix["idor"] == "ALLOWED"
    assert report.capability_matrix["privilege_escalation"] == "ALLOWED"
    assert report.capability_matrix["sql_injection"] == "ALLOWED"
    assert report.blocked_classes == ["reflected_xss"]
    db.close()


# --- scope cannot be expanded by discovery ------------------------------------

def test_scope_not_expandable():
    temu = ProgramManager(load_program(TEMU_YAML))
    scope = ScopeEngine(temu.config.scope)
    assert scope.is_allowed("https://www.temu.com/x") is True
    for url in ("https://api.temu.com/x", "https://cdn.temu.com/x",
                "https://temu.com/x", "https://evil.com/x"):
        assert scope.is_allowed(url) is False   # unknown/unscoped never allowed


# --- allowed class is still gated (PolicyGatedHTTP path) ----------------------

async def test_verification_is_policy_gated(sim):
    # A forbidden class cannot pass the gateway; an unauthorized data id is denied;
    # both before any transport. (This is the same gateway the engine uses.)
    t = TemuMockTransport()
    async with AuthorizedHTTPClient(sim.config, transport=t) as http:
        gw = PolicyGatedHTTP(sim, ProgramPolicyEngine(sim), http)
        gw.vuln_class = "reflected_xss"                      # FORBIDDEN
        with pytest.raises(RequestBlocked):
            await gw.get(f"{BASE}/sim/search?q=x")
        gw.vuln_class = "idor"                               # ALLOWED, but...
        with pytest.raises(RequestBlocked):
            await gw.get(f"{BASE}/sim/v1/orders/9999999999999999")  # unauthorized id -> DataScope
    assert t.calls == 0


async def test_required_header_still_enforced(monkeypatch, sim):
    monkeypatch.delenv(H1_ENV, raising=False)   # H1 username env missing
    t = TemuMockTransport()
    async with AuthorizedHTTPClient(sim.config, transport=t) as http:
        gw = PolicyGatedHTTP(sim, ProgramPolicyEngine(sim), http)
        gw.vuln_class = "idor"
        with pytest.raises(RequestBlocked):
            await gw.get(f"{BASE}/sim/v1/orders/{OBJECT_ID}")
    assert t.calls == 0


# --- global budget across recon + verification --------------------------------

async def test_budget_is_global_and_shared(sim, tmp_path):
    transport = temu_mock_transport()
    rb = RunBudget(4)
    report, db, _ = await _run(sim, tmp_path, transport, run_budget=rb)
    assert transport.calls == 4 and report.request_budget_used == 4   # recon+verify share it
    assert report.verified == []                                      # starved before findings
    db.close()


# --- dry_run_only blocks transport for the REAL program -----------------------

async def test_real_temu_dry_run_blocks_transport(tmp_path):
    temu = ProgramManager(load_program(TEMU_YAML))
    assert temu.config.dry_run_only is True
    transport = TemuMockTransport()
    # Running the real (NOT READY, dry-run) program discovers nothing and sends nothing.
    db = Database(":memory:")
    evidence = EvidenceStore(db, tmp_path / "ev")
    report = await autonomous_run(temu, db, evidence, manifests=[MANIFEST_URL], transport=transport)
    assert transport.calls == 0                     # zero real Temu requests
    assert report.endpoints_discovered == 0
    assert report.verified == []
    db.close()

    # Even a direct client call is blocked before transport by dry_run_only.
    t2 = TemuMockTransport()
    async with AuthorizedHTTPClient(temu.config, transport=t2) as http:
        with pytest.raises(RequestBlocked):
            await http.request("GET", "https://www.temu.com/")
    assert t2.calls == 0


async def test_no_manual_temu_endpoints_required(sim, tmp_path):
    # The ONLY input is the program + a discovery seed manifest; no attack endpoints
    # are hand-fed. The pipeline discovers them and still verifies allowed classes.
    report, db, _ = await _run(sim, tmp_path, temu_mock_transport())
    assert report.endpoints_discovered >= 5
    assert report.verified_classes == {"idor", "privilege_escalation", "sql_injection"}
    db.close()
