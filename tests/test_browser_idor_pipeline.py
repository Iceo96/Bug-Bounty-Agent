"""Integration: the browser-profile IDOR mode wired into the VerificationEngine.

Local mocks/fixtures only — NO browser launch, NO real network (an httpx
MockTransport that fails if the HTTP path is ever used), NO Temu. Proves the gated
flow: hypothesis -> capability/policy + identity check -> A fetch -> B fetch ->
AccessObservation -> redacted HTTPExchange -> existing engine evidence rules ->
immutable EvidenceStore -> human review (VERIFIED, awaiting approval; no auto-submit).
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from bbagent.config.models import (
    DataScope, PolicyBudget, ProgramConfig, ScopeConfig, ScopeKind, ScopeRule,
    TestAccount, TestingRestrictions,
)
from bbagent.http.client import AuthorizedHTTPClient, RunBudget
from bbagent.policy import ProgramPolicyEngine
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import FindingStatus, Hypothesis, HypothesisStatus
from bbagent.verification.browser_idor import (
    AccessObservation, BrowserIDORMode, IdentityFetcher,
)
from bbagent.verification.engine import VerificationEngine

URL = "https://app.local.test/api/phantom/xg/pfb/b"
OBJECT = json.dumps({"b": "d22a0000-0000-4000-8000-0000000000d5", "owner": "A"})


def _program(*, identities: int = 2, share_profile: bool = False,
             data_scope: DataScope | None = None) -> ProgramManager:
    accts = [TestAccount(label="researcher", profile_dir_env="ENV_A")]
    if identities >= 2:
        accts.append(TestAccount(label="researcher_b",
                                 profile_dir_env="ENV_A" if share_profile else "ENV_B"))
    return ProgramManager(ProgramConfig(
        name="bpipe", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="app.local.test")]),
        restrictions=TestingRestrictions(allow_active_testing=False, allowed_methods=["GET"]),
        test_accounts=accts, allowed_tools=["http", "recon"],
        allowed_vulnerability_classes=["idor"], allow_unauthenticated=True,
        request_budget=PolicyBudget(total=50, per_target=50, per_tool=50),
        data_scope=data_scope))


class MockFetcher(IdentityFetcher):
    def __init__(self, responses: dict[str, tuple[int, str]]):
        self._r = responses
        self.calls: list[tuple[str, str]] = []

    async def fetch(self, identity_label: str, url: str) -> AccessObservation:
        self.calls.append((identity_label, url))
        status, body = self._r[identity_label]
        return AccessObservation(identity_label, url, status, body,
                                 content_type="application/json")


def _fail_transport(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"unexpected HTTP transport request: {request.url}")


async def _process(program, fetcher, tmp_path, *, enabled=True, live=True, budget=50,
                   url=URL):
    import os
    # Two distinct, resolvable profile dirs (the browser path requires this; the
    # engine returns INCONCLUSIVE otherwise — never an HTTP fallback).
    os.environ["ENV_A"] = str(tmp_path / "profA")
    os.environ["ENV_B"] = str(tmp_path / "profB")
    db = Database(":memory:")
    ev = EvidenceStore(db, tmp_path / "ev")
    try:
        async with AuthorizedHTTPClient(program.config,
                                        transport=httpx.MockTransport(_fail_transport),
                                        run_budget=RunBudget(budget)) as http:
            mode = BrowserIDORMode(enabled=enabled, live=live, fetcher=fetcher)
            engine = VerificationEngine(program, db, http, ev,
                                        policy=ProgramPolicyEngine(program), browser_idor=mode)
            hyp = Hypothesis(program=program.name, vuln_type="idor", title="t",
                             rationale="", target_url=url, detector="planner")
            db.add_hypothesis(hyp)
            finding = await engine.process(hyp)
        return db, ev, finding, hyp
    finally:
        os.environ.pop("ENV_A", None)
        os.environ.pop("ENV_B", None)


def _run(coro):
    return asyncio.run(coro)


# --- A/B successful authorization violation -> candidate promoted + evidence ---

def test_violation_promotes_with_evidence_awaiting_review(tmp_path):
    f = MockFetcher({"researcher": (200, OBJECT), "researcher_b": (200, OBJECT)})
    db, ev, finding, hyp = _run(_process(_program(), f, tmp_path))
    assert finding is not None and finding.vuln_type == "idor"
    # Only the two DISTINCT configured identities were used (never unauth, never dup).
    assert f.calls == [("researcher", URL), ("researcher_b", URL)]
    # Immutable evidence reached the store (request+response per exchange).
    n = db.connection.execute("SELECT count(*) FROM evidence WHERE finding_id=?",
                              (finding.id,)).fetchone()[0]
    assert n == 4
    assert ev.verify_all() == []                      # evidence integrity holds
    # Candidate awaiting HUMAN review — VERIFIED, never auto-approved/submitted.
    assert finding.status is FindingStatus.VERIFIED
    assert db.get_hypothesis(hyp.id).status is HypothesisStatus.VERIFIED
    db.close()


# --- A/B proper authorization -> no finding -----------------------------------

def test_proper_authorization_no_finding(tmp_path):
    f = MockFetcher({"researcher": (200, OBJECT),
                     "researcher_b": (403, json.dumps({"error": "forbidden"}))})
    db, ev, finding, hyp = _run(_process(_program(), f, tmp_path))
    assert finding is None
    assert db.get_hypothesis(hyp.id).status is HypothesisStatus.DISCARDED
    db.close()


# --- insufficient identities -> INCONCLUSIVE, zero requests -------------------

def test_insufficient_identities_inconclusive_zero_requests(tmp_path):
    f = MockFetcher({"researcher": (200, OBJECT)})
    db, ev, finding, hyp = _run(_process(_program(identities=1), f, tmp_path))
    assert finding is None
    assert f.calls == []                              # browser path not applicable
    assert db.get_hypothesis(hyp.id).status is HypothesisStatus.INCONCLUSIVE
    db.close()


# --- same identity cannot satisfy (shared profile is not two identities) ------

def test_shared_profile_is_not_two_identities(tmp_path):
    # Two accounts sharing ONE profile env is not two distinct-profile identities,
    # so the browser mode does not apply (it never runs A-vs-A).
    mode = BrowserIDORMode(enabled=True, live=True, fetcher=MockFetcher({}))
    assert mode.applies_to(_program(share_profile=True),
                           Hypothesis(program="bpipe", vuln_type="idor", title="t",
                                      rationale="", target_url=URL)) is False
    assert mode.applies_to(_program(),
                           Hypothesis(program="bpipe", vuln_type="idor", title="t",
                                      rationale="", target_url=URL)) is True


# --- out-of-scope target refused without any fetch ----------------------------

def test_out_of_scope_target_refused(tmp_path):
    f = MockFetcher({"researcher": (200, OBJECT), "researcher_b": (200, OBJECT)})
    db, ev, finding, hyp = _run(_process(_program(), f, tmp_path,
                                         url="https://evil.example.com/x"))
    assert finding is None
    assert f.calls == []                              # scope fail-closed before fetch
    db.close()


# --- DataScope still applies (deny-all object ids) ----------------------------

def test_datascope_denies_before_fetch(tmp_path):
    # A URL-embedded object id with a deny-all DataScope allow-list must be denied by
    # the existing policy gate BEFORE any browser fetch.
    ds = DataScope(enforce=True, authorized_object_ids=[], authorized_url_prefixes=[])
    f = MockFetcher({"researcher": (200, OBJECT), "researcher_b": (200, OBJECT)})
    db, ev, finding, hyp = _run(_process(_program(data_scope=ds), f, tmp_path,
                                         url="https://app.local.test/api/orders/1001"))
    assert finding is None
    assert f.calls == []                              # DataScope denied the object id
    db.close()


# --- request budget exhaustion -> fail closed, no finding ---------------------

def test_budget_exhaustion_fails_closed(tmp_path):
    f = MockFetcher({"researcher": (200, OBJECT), "researcher_b": (200, OBJECT)})
    db, ev, finding, hyp = _run(_process(_program(), f, tmp_path, budget=1))
    assert finding is None
    assert len(f.calls) == 1                          # only the first fetch consumed budget
    db.close()


# --- live gate disabled -> INCONCLUSIVE, zero requests ------------------------

def test_live_gate_disabled_no_requests(tmp_path):
    f = MockFetcher({"researcher": (200, OBJECT), "researcher_b": (200, OBJECT)})
    db, ev, finding, hyp = _run(_process(_program(), f, tmp_path, live=False))
    assert finding is None
    assert f.calls == []                              # never fetched with the gate off
    assert db.get_hypothesis(hyp.id).status is HypothesisStatus.INCONCLUSIVE
    db.close()


# --- mode disabled -> existing HTTP verifier path is used (not replaced) ------

def test_mode_disabled_falls_back_to_http_verifier(tmp_path):
    # With the mode disabled, the engine must NOT use the browser fetcher at all.
    f = MockFetcher({"researcher": (200, OBJECT), "researcher_b": (200, OBJECT)})
    # HTTP verifier with 2 no-secret identities returns before any request (the mock
    # transport would raise if hit); here it proceeds to fetch via the gateway, so to
    # keep it request-free we assert only that the BROWSER fetcher was never called.
    db = Database(":memory:")
    ev = EvidenceStore(db, tmp_path / "ev")

    async def _go():
        async with AuthorizedHTTPClient(_program().config,
                                        transport=httpx.MockTransport(
                                            lambda r: httpx.Response(403, text="{}")),
                                        run_budget=RunBudget(50)) as http:
            prog = _program()
            engine = VerificationEngine(prog, db, http, ev,
                                        policy=ProgramPolicyEngine(prog),
                                        browser_idor=BrowserIDORMode(enabled=False, live=True,
                                                                     fetcher=f))
            hyp = Hypothesis(program=prog.name, vuln_type="idor", title="t",
                             rationale="", target_url=URL, detector="planner")
            db.add_hypothesis(hyp)
            await engine.process(hyp)

    _run(_go())
    assert f.calls == []                              # browser mode was NOT used
    db.close()
