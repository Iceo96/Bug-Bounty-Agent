"""Regression: an INCONCLUSIVE IDOR candidate is preserved (not disproven/verified),
kept for human review, and NOT regenerated across research rounds while its
prerequisite (a second authorized identity) is unchanged — but IS revisited once a
second identity becomes available. No live network (in-process MockTransport).
"""

from __future__ import annotations

import httpx
import pytest

from bbagent.browser.models import ObservedExchange
from bbagent.browser.observe import NetworkObservationIngestor
from bbagent.config.models import (
    PolicyBudget, ProgramConfig, ScopeConfig, ScopeKind, ScopeRule, TestAccount,
    TestingRestrictions,
)
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.planner import PlanRunner
from bbagent.planner.history import RunStore
from bbagent.planner.models import PlannedHypothesis, PlanStatus
from bbagent.policy import ProgramPolicyEngine
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore

HOST = "app.local.test"
URL = f"https://{HOST}/api/phantom/xg/pfb/b"
UUID = "d22a0000-0000-4000-8000-0000000000d5"


def _program(n_identities: int) -> ProgramManager:
    accts = [TestAccount(label="researcher")]
    if n_identities >= 2:
        accts.append(TestAccount(label="researcher_b"))
    return ProgramManager(ProgramConfig(
        name="dedup-prog", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value=HOST)]),
        restrictions=TestingRestrictions(allow_active_testing=False, allowed_methods=["GET"]),
        test_accounts=accts, allowed_tools=["http", "recon"],
        allowed_vulnerability_classes=["idor", "privilege_escalation", "sql_injection"],
        allow_unauthenticated=True,
        request_budget=PolicyBudget(total=50, per_target=50, per_tool=50),
    ))


def _seed_surface(program, surface) -> None:
    ing = NetworkObservationIngestor(
        program, surface, default_identity=AuthIdentity.IDENTITY_A,
        identity_map={"researcher": AuthIdentity.IDENTITY_A})
    body = '{"b": "%s"}' % UUID
    ing.ingest([
        ObservedExchange("GET", URL, status=200, request_headers={},
                         response_headers={"Content-Type": "application/json"},
                         response_body=body, identity_label="researcher"),
        ObservedExchange("GET", URL, status=200, request_headers={"cookie": ""},
                         response_headers={"Content-Type": "application/json"},
                         response_body=body, identity_label="researcher"),
    ])


def _handler_per_identity(request: httpx.Request) -> httpx.Response:
    # Distinct body per identity -> NOT identical -> a proper authz boundary (so the
    # 2-identity run does not falsely confirm IDOR). Only reached when 2 identities.
    who = request.headers.get("x-test-identity", "?")
    return httpx.Response(200, headers={"content-type": "application/json"},
                          text='{"b":"%s","who":"%s"}' % (UUID, who))


async def _run_once(program, db, surface, evidence) -> "object":
    async with AuthorizedHTTPClient(program.config,
                                    transport=httpx.MockTransport(_handler_per_identity)) as http:
        runner = PlanRunner(program, db, surface, http, evidence,
                            policy=ProgramPolicyEngine(program))
        return await runner.run()


@pytest.fixture
def env(tmp_path):
    db = Database(":memory:")
    surface = SurfaceStore(db)
    evidence = EvidenceStore(db, tmp_path / "ev")
    program = _program(1)
    _seed_surface(program, surface)
    yield db, surface, evidence, program
    db.close()


# --- round 1: generated once, INCONCLUSIVE, zero requests ---------------------

async def test_first_round_is_inconclusive_not_disproven(env):
    db, surface, evidence, program = env
    s1 = await _run_once(program, db, surface, evidence)
    assert s1.generated == 1
    assert s1.inconclusive == 1
    assert s1.verified == 0 and s1.disproven == 0
    assert s1.requests_used == 0            # verifier returns before any request

    runs = RunStore(db)
    inc = runs.inconclusive_hypotheses(program.name)
    assert len(inc) == 1
    assert inc[0]["vulnerability_class"] == "idor"
    assert inc[0]["endpoint"] == URL
    assert "two authorized" in inc[0]["status_reason"].lower()
    assert inc[0]["prereq_identities"] == 1
    # It is NOT a finding and NOT disproven/verified.
    assert len(list(db.connection.execute(
        "SELECT 1 FROM findings WHERE program=?", (program.name,)))) == 0


# --- round 2+: the SAME candidate is not regenerated --------------------------

async def test_not_regenerated_across_rounds(env):
    db, surface, evidence, program = env
    await _run_once(program, db, surface, evidence)          # round 1
    s2 = await _run_once(program, db, surface, evidence)     # round 2
    s3 = await _run_once(program, db, surface, evidence)     # round 3
    assert s2.generated == 0 and s3.generated == 0           # suppressed, not re-planned
    assert s2.inconclusive == 0 and s3.inconclusive == 0
    # Still preserved + reviewable after the extra rounds.
    assert len(RunStore(db).inconclusive_hypotheses(program.name)) == 1


# --- revisited only when the prerequisite changes (a 2nd identity) ------------

async def test_revisited_when_second_identity_added(env):
    db, surface, evidence, program = env
    await _run_once(program, db, surface, evidence)          # inconclusive w/ 1 identity
    # A second authorized identity becomes available -> prerequisite changed.
    program2 = _program(2)
    s = await _run_once(program2, db, surface, evidence)
    assert s.generated == 1                                  # candidate revisited
    # With two identities it is now actually evaluated (not inconclusive); the mock
    # returns distinct bodies per identity, so it is a proper boundary -> disproven.
    assert s.inconclusive == 0
    assert s.verified == 0


# --- unit: known_plan_keys identity-awareness ---------------------------------

def test_known_plan_keys_identity_gating(tmp_path):
    db = Database(":memory:")
    runs = RunStore(db)
    run = runs.start_run("p", __import__("bbagent.planner.models", fromlist=["TestBudget"]).TestBudget())
    ph = PlannedHypothesis(target="h", endpoint=URL, method="GET", vulnerability_class="idor",
                           reasoning="r", plan_key="KEY1", priority_score=50,
                           status=PlanStatus.INCONCLUSIVE, status_reason="x", prereq_identities=1)
    runs.save_hypothesis(run.run_id, "p", ph)
    # Same identity count -> suppressed; more identities -> eligible again.
    assert "KEY1" in runs.known_plan_keys("p", current_identities=1)
    assert "KEY1" not in runs.known_plan_keys("p", current_identities=2)
    db.close()
