"""Browser-profile IDOR mode wired into the VerificationEngine + research loop.

Local mocks only — NO browser launch, NO real network (an httpx MockTransport that
FAILS if the HTTP verifier path is ever used for profile-only identities), NO Temu.
Proves: profile-only IDOR uses the browser verifier or returns INCONCLUSIVE and NEVER
falls back to shared HTTP credentials; credentialed identities still use HTTP; the
research loop wires the mode; sanitized debug observations are retained without secrets.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from bbagent.browser.controller import BrowserBackend
from bbagent.browser.models import ObservedExchange
from bbagent.config.models import (
    PolicyBudget, ProgramConfig, ScopeConfig, ScopeKind, ScopeRule, TestAccount,
    TestingRestrictions,
)
from bbagent.http.client import AuthorizedHTTPClient, RunBudget
from bbagent.policy import ProgramPolicyEngine
from bbagent.program.manager import ProgramManager
from bbagent.research import ResearchLimits, run_security_research
from bbagent.browser import ExplorationLimits
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import FindingStatus, Hypothesis, HypothesisStatus
from bbagent.verification.browser_idor import (
    AccessObservation, BrowserIDORMode, IdentityFetcher,
)
from bbagent.verification.engine import VerificationEngine

URL = "https://app.local.test/api/x/obj"
OBJ = json.dumps({"b": "d22a0000-0000-4000-8000-0000000000d5", "owner": "A"})


def _profile_program():
    return ProgramManager(ProgramConfig(
        name="wire", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="app.local.test")]),
        restrictions=TestingRestrictions(allow_active_testing=False, allowed_methods=["GET"]),
        test_accounts=[TestAccount(label="researcher", profile_dir_env="ENV_PA"),
                       TestAccount(label="researcher_b", profile_dir_env="ENV_PB")],
        allowed_tools=["http", "recon"], allowed_vulnerability_classes=["idor"],
        allow_unauthenticated=True, request_budget=PolicyBudget(total=50)))


def _cred_program():
    return ProgramManager(ProgramConfig(
        name="wire-cred", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="app.local.test")]),
        restrictions=TestingRestrictions(allow_active_testing=False, allowed_methods=["GET"]),
        test_accounts=[TestAccount(label="researcher", secret_env="ENV_SA"),
                       TestAccount(label="researcher_b", secret_env="ENV_SB")],
        allowed_tools=["http", "recon"], allowed_vulnerability_classes=["idor"],
        allow_unauthenticated=True, request_budget=PolicyBudget(total=50)))


class MockFetcher(IdentityFetcher):
    def __init__(self, per, response_headers=None):
        self._per = per
        self.calls = []
        self._headers = response_headers or {}

    async def fetch(self, identity_label, url):
        self.calls.append((identity_label, url))
        st, body = self._per[identity_label]
        return AccessObservation(identity_label, url, st, body,
                                 content_type="application/json",
                                 response_headers=dict(self._headers))


def _fail(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"HTTP verifier must NOT be used here: {request.url}")


def _profiles(monkeypatch, tmp_path):
    monkeypatch.setenv("ENV_PA", str(tmp_path / "A"))
    monkeypatch.setenv("ENV_PB", str(tmp_path / "B"))


async def _process(program, mode, tmp_path, *, budget=50, transport=None, url=URL):
    db = Database(":memory:")
    ev = EvidenceStore(db, tmp_path / "ev")
    t = transport or httpx.MockTransport(_fail)
    async with AuthorizedHTTPClient(program.config, transport=t, run_budget=RunBudget(budget)) as http:
        eng = VerificationEngine(program, db, http, ev,
                                 policy=ProgramPolicyEngine(program), browser_idor=mode)
        hyp = Hypothesis(program=program.name, vuln_type="idor", title="t",
                         rationale="", target_url=url, detector="planner")
        db.add_hypothesis(hyp)
        finding = await eng.process(hyp)
    return db, ev, finding, hyp


def _run(coro):
    return asyncio.run(coro)


# --- (c + no silent fallback) profile-only + no/disabled mode -> INCONCLUSIVE, no HTTP

def test_profile_only_without_mode_is_inconclusive_never_http(tmp_path, monkeypatch):
    _profiles(monkeypatch, tmp_path)
    db, ev, finding, hyp = _run(_process(_profile_program(), None, tmp_path))
    assert finding is None
    assert db.get_hypothesis(hyp.id).status is HypothesisStatus.INCONCLUSIVE
    db.close()


def test_profile_only_mode_disabled_is_inconclusive_no_fetch(tmp_path, monkeypatch):
    _profiles(monkeypatch, tmp_path)
    f = MockFetcher({"researcher": (200, OBJ), "researcher_b": (200, OBJ)})
    mode = BrowserIDORMode(enabled=False, live=True, fetcher=f)
    db, ev, finding, hyp = _run(_process(_profile_program(), mode, tmp_path))
    assert finding is None and f.calls == []
    assert db.get_hypothesis(hyp.id).status is HypothesisStatus.INCONCLUSIVE
    db.close()


# --- (b) profile-only + enabled mode -> browser verifier, two separate identities

def test_profile_only_uses_browser_verifier_and_promotes(tmp_path, monkeypatch):
    _profiles(monkeypatch, tmp_path)
    f = MockFetcher({"researcher": (200, OBJ), "researcher_b": (200, OBJ)})
    mode = BrowserIDORMode(enabled=True, live=True, fetcher=f)
    db, ev, finding, hyp = _run(_process(_profile_program(), mode, tmp_path))
    assert finding is not None and finding.vuln_type == "idor"
    assert f.calls == [("researcher", URL), ("researcher_b", URL)]   # two separate identities
    assert finding.status is FindingStatus.VERIFIED                   # candidate awaiting review
    assert ev.verify_all() == []
    db.close()


def test_profile_only_different_object_no_finding(tmp_path, monkeypatch):
    _profiles(monkeypatch, tmp_path)
    f = MockFetcher({"researcher": (200, OBJ),
                     "researcher_b": (200, json.dumps({"b": "other", "owner": "B"}))})
    mode = BrowserIDORMode(enabled=True, live=True, fetcher=f)
    db, ev, finding, hyp = _run(_process(_profile_program(), mode, tmp_path))
    assert finding is None
    assert f.calls == [("researcher", URL), ("researcher_b", URL)]
    db.close()


# --- (d) missing second profile -> INCONCLUSIVE, never HTTP, no fetch

def test_missing_second_profile_is_inconclusive(tmp_path, monkeypatch):
    monkeypatch.setenv("ENV_PA", str(tmp_path / "A"))
    monkeypatch.delenv("ENV_PB", raising=False)          # B unresolved
    f = MockFetcher({"researcher": (200, OBJ), "researcher_b": (200, OBJ)})
    mode = BrowserIDORMode(enabled=True, live=True, fetcher=f)
    db, ev, finding, hyp = _run(_process(_profile_program(), mode, tmp_path))
    assert finding is None and f.calls == []             # no fetch, no HTTP fallback
    assert db.get_hypothesis(hyp.id).status is HypothesisStatus.INCONCLUSIVE
    db.close()


# --- (c) credentialed identities still use the HTTP verifier (browser NOT used) ---

def test_credentialed_identities_use_http_not_browser(tmp_path, monkeypatch):
    monkeypatch.setenv("ENV_SA", "tokA"); monkeypatch.setenv("ENV_SB", "tokB")
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        who = request.headers.get("authorization", "")[-4:]
        return httpx.Response(200, headers={"content-type": "application/json"},
                              text=json.dumps({"who": who}))   # distinct bodies -> not IDOR

    f = MockFetcher({"researcher": (200, OBJ), "researcher_b": (200, OBJ)})
    mode = BrowserIDORMode(enabled=True, live=True, fetcher=f)
    db, ev, finding, hyp = _run(_process(_cred_program(), mode, tmp_path,
                                         transport=httpx.MockTransport(handler)))
    assert f.calls == []            # browser mode NOT used for credentialed identities
    assert calls["n"] == 2          # HTTP verifier fetched both identities
    assert finding is None
    db.close()


# --- (e/f) PolicyGatedFetcher + shared RunBudget in the browser path --------------

def test_budget_shared_and_enforced_in_browser_path(tmp_path, monkeypatch):
    _profiles(monkeypatch, tmp_path)
    f = MockFetcher({"researcher": (200, OBJ), "researcher_b": (200, OBJ)})
    mode = BrowserIDORMode(enabled=True, live=True, fetcher=f)
    db, ev, finding, hyp = _run(_process(_profile_program(), mode, tmp_path, budget=1))
    assert finding is None              # second fetch blocked by the shared RunBudget
    assert len(f.calls) == 1
    db.close()


# --- (g) sanitized debug observation retained; no secrets/bodies -----------------

def test_verify_debug_is_sanitized(tmp_path, monkeypatch):
    _profiles(monkeypatch, tmp_path)
    secret_body = json.dumps({"b": "X", "owner": "A"})
    other_body = json.dumps({"b": "Y", "owner": "B"})
    f = MockFetcher({"researcher": (200, secret_body), "researcher_b": (200, other_body)},
                    response_headers={"Set-Cookie": "sid=SUPERSECRET", "content-type": "application/json"})
    mode = BrowserIDORMode(enabled=True, live=True, fetcher=f)
    db, ev, finding, hyp = _run(_process(_profile_program(), mode, tmp_path))
    assert finding is None
    rows = list(db.connection.execute(
        "SELECT summary, data FROM observations WHERE program='wire' AND kind='verify_debug'"))
    assert rows, "a sanitized verify_debug observation should be recorded"
    blob = rows[-1]["data"]
    data = json.loads(blob)
    # Per-exchange metadata present, but NO raw body and NO secret value.
    assert all("body_sha256" in o and "body_len" in o for o in data["observations"])
    assert "SUPERSECRET" not in blob
    assert secret_body not in blob and other_body not in blob     # bodies not stored
    # Secret header names are redacted in the record.
    names = data["observations"][0]["response_header_names"]
    assert "[redacted]" in names and not any(n.lower() == "set-cookie" for n in names)
    db.close()


# --- (a) the research loop wires the browser-profile IDOR mode -------------------

class _ExploreBackend(BrowserBackend):
    """Minimal exploration backend: surfaces ONE in-scope endpoint with a json ref."""

    def __init__(self, url): self._url = url; self._buf = []
    async def start(self): self._buf.clear()
    async def close(self): pass
    async def goto(self, url):
        self._buf.append(ObservedExchange(
            "GET", self._url, status=200, request_headers={"cookie": ""},
            response_headers={"Content-Type": "application/json"},
            response_body=json.dumps({"b": "d22a0000-0000-4000-8000-0000000000d5"}),
            identity_label="researcher"))
    async def click(self, s): pass
    async def type_text(self, s, t): pass
    async def scroll(self, s=None, amount=3): pass
    async def drain(self):
        out = self._buf; self._buf = []; return out


def test_research_loop_wires_browser_idor(tmp_path, monkeypatch):
    _profiles(monkeypatch, tmp_path)
    program = _profile_program()
    db = Database(":memory:")
    ev = EvidenceStore(db, tmp_path / "ev")
    f = MockFetcher({"researcher": (200, OBJ), "researcher_b": (200, OBJ)})
    mode = BrowserIDORMode(enabled=True, live=True, fetcher=f)

    async def _go():
        return await run_security_research(
            program, db, ev, browser_backend=_ExploreBackend(URL), seed_urls=[URL],
            transport=httpx.MockTransport(_fail),     # HTTP verifier must never run
            browser_idor=mode, live=True,
            limits=ResearchLimits(max_rounds=1,
                                  exploration=ExplorationLimits(max_actions=4, max_no_progress=2)))

    report = _run(_go())
    # IDOR was verified via the BROWSER fetcher (two identities), not HTTP.
    assert ("researcher", URL) in f.calls and ("researcher_b", URL) in f.calls
    assert "idor" in report.verified_classes
    db.close()
