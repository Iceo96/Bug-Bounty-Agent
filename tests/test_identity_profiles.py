"""Second authorized identity via a SEPARATE persistent browser profile.

Proves: each identity maps to its own profile; profiles are never shared and cannot
share session state; the IDOR verifier only counts explicitly configured identities
(unauthenticated context is never a second identity) and stays INCONCLUSIVE with < 2;
and the IDOR candidate becomes eligible for reconsideration only once a second
authorized identity is configured. No browser launch, no network, no Temu contact.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path

import httpx
import pytest

from bbagent.browser import ProfileConflict, build_identity_backends, identity_profiles
from bbagent.browser import playwright_backend as pwb
from bbagent.config.loader import load_program
from bbagent.config.models import (
    PolicyBudget, ProgramConfig, ScopeConfig, ScopeKind, ScopeRule, TestAccount,
    TestingRestrictions,
)
from bbagent.detectors.base import VerificationContext
from bbagent.detectors.idor import IDORVerifier
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.planner.history import RunStore
from bbagent.planner.models import PlannedHypothesis, PlanStatus, TestBudget
from bbagent.policy import ProgramPolicyEngine
from bbagent.policy.validation import validate_policy
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.storage.models import Hypothesis
from bbagent.tools.gateway import PolicyGatedHTTP

TEMU_YAML = str(Path(__file__).resolve().parents[1] / "programs" / "temu.yaml")
URL = "https://app.local.test/api/phantom/xg/pfb/b"


# --- each identity maps to its OWN persistent profile -------------------------

def test_two_identities_use_separate_profiles(tmp_path, monkeypatch):
    a, b = str(tmp_path / "profA"), str(tmp_path / "profB")
    monkeypatch.setenv("BBAGENT_H1_USERNAME", "h1-handle")
    monkeypatch.setenv("BBAGENT_TEMU_PROFILE_A", a)
    monkeypatch.setenv("BBAGENT_TEMU_PROFILE_B", b)
    temu = ProgramManager(load_program(TEMU_YAML))

    profiles = identity_profiles(temu)
    assert profiles == {"researcher": a, "researcher_b": b}

    backends = build_identity_backends(temu)
    assert set(backends) == {"researcher", "researcher_b"}
    assert backends["researcher"].user_data_dir == a
    assert backends["researcher_b"].user_data_dir == b
    assert backends["researcher"]._identity_label == "researcher"
    assert backends["researcher_b"]._identity_label == "researcher_b"
    # Separate, persistent, and NOT shared.
    assert backends["researcher"].uses_persistent_profile
    assert backends["researcher"].user_data_dir != backends["researcher_b"].user_data_dir


def test_shared_profile_dir_is_rejected(tmp_path, monkeypatch):
    same = str(tmp_path / "shared")
    monkeypatch.setenv("BBAGENT_H1_USERNAME", "h1-handle")
    monkeypatch.setenv("BBAGENT_TEMU_PROFILE_A", same)
    monkeypatch.setenv("BBAGENT_TEMU_PROFILE_B", same)      # both point at one dir
    temu = ProgramManager(load_program(TEMU_YAML))
    with pytest.raises(ProfileConflict):
        build_identity_backends(temu)


def test_shared_profile_env_is_a_policy_conflict():
    prog = ProgramManager(ProgramConfig(
        name="shared", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="app.local.test")]),
        restrictions=TestingRestrictions(allowed_methods=["GET"]),
        test_accounts=[TestAccount(label="a", profile_dir_env="ENV_X"),
                       TestAccount(label="b", profile_dir_env="ENV_X")],   # shared!
        allowed_tools=["http"], allowed_vulnerability_classes=["idor"],
        allow_unauthenticated=True, request_budget=PolicyBudget(total=10)))
    report = validate_policy(prog)
    assert report.ready is False
    assert any("must not be shared" in c for c in report.conflicts)


def test_backends_never_export_session_state():
    # Structural: the backend never reads/exports cookies or storage_state, so two
    # separate profiles cannot leak session state into each other.
    src = inspect.getsource(pwb)
    assert "storage_state(" not in src and ".cookies(" not in src


# --- verifier counts only CONFIGURED identities ------------------------------

def _program(n: int) -> ProgramManager:
    accts = [TestAccount(label="researcher", secret_env="ENV_A" if n else None)]
    if n >= 2:
        accts.append(TestAccount(label="researcher_b", secret_env="ENV_B"))
    return ProgramManager(ProgramConfig(
        name="idp", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="app.local.test")]),
        restrictions=TestingRestrictions(allow_active_testing=False, allowed_methods=["GET"]),
        test_accounts=accts, allowed_tools=["http", "recon"],
        allowed_vulnerability_classes=["idor"], allow_unauthenticated=True,
        request_budget=PolicyBudget(total=20, per_target=20, per_tool=20)))


class _NoHTTP:
    calls = 0
    async def get(self, *a, **k):
        _NoHTTP.calls += 1
        raise AssertionError("verifier must not issue a request with < 2 identities")


def test_one_identity_stays_inconclusive_ignoring_unauth_context():
    _NoHTTP.calls = 0
    ctx = VerificationContext(
        program=_program(1), db=None, http=_NoHTTP(),
        hypothesis=Hypothesis(program="idp", vuln_type="idor", title="idor", rationale="",
                              target_url=URL, detector="planner"))
    res = asyncio.run(IDORVerifier().verify(ctx))
    assert res.verified is False and res.inconclusive is True
    assert "two authorized" in res.reason.lower()
    assert _NoHTTP.calls == 0            # unauthenticated context does NOT upgrade it


def test_two_identities_are_actually_evaluated(monkeypatch):
    monkeypatch.setenv("ENV_A", "tokA")
    monkeypatch.setenv("ENV_B", "tokB")
    program = _program(2)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        who = request.headers.get("authorization", "")
        # Distinct bodies per identity -> a proper boundary (not IDOR), and crucially
        # NOT the "requires two identities" INCONCLUSIVE path.
        return httpx.Response(200, headers={"content-type": "application/json"},
                              text=json.dumps({"who": who[-4:]}))

    async def _run():
        async with AuthorizedHTTPClient(program.config,
                                        transport=httpx.MockTransport(handler)) as client:
            gw = PolicyGatedHTTP(program, ProgramPolicyEngine(program), client)
            gw.vuln_class = "idor"
            ctx = VerificationContext(
                program=program, db=None, http=gw,
                hypothesis=Hypothesis(program="idp", vuln_type="idor", title="idor",
                                      rationale="", target_url=URL, detector="planner"))
            return await IDORVerifier().verify(ctx)

    res = asyncio.run(_run())
    assert getattr(res, "inconclusive", False) is False     # no longer inconclusive
    assert "requires two" not in res.reason.lower()
    assert calls["n"] == 2                                   # both identities fetched


# --- eligibility flips only when the 2nd identity is configured ---------------

def test_idor_eligible_only_with_second_identity(tmp_path):
    db = Database(":memory:")
    runs = RunStore(db)
    run = runs.start_run("idp", TestBudget())
    ph = PlannedHypothesis(target="app.local.test", endpoint=URL, method="GET",
                           vulnerability_class="idor", reasoning="r", plan_key="K",
                           priority_score=50, status=PlanStatus.INCONCLUSIVE,
                           status_reason="requires two authorized test identities",
                           prereq_identities=1)
    runs.save_hypothesis(run.run_id, "idp", ph)
    # One identity -> suppressed (not reconsidered).
    assert "K" in runs.known_plan_keys("idp", current_identities=1)
    # Second identity configured -> eligible for reconsideration.
    assert "K" not in runs.known_plan_keys("idp", current_identities=2)
    db.close()
