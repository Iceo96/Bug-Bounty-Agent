"""Browser-profile-based two-identity IDOR verification (local, mock fetcher only).

No real browser, no network, no Temu. Proves: A and B use different profiles; A and
B make isolated requests; the same identity cannot satisfy the two-identity rule;
an unauthenticated context can never be Identity B; an A/B comparison yields a
CANDIDATE result without auto-creating a finding; and insufficient identities stays
INCONCLUSIVE with zero active fetches. Also that no session state is ever exported.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path

import pytest

from bbagent.config.loader import load_program
from bbagent.config.models import (
    PolicyBudget, ProgramConfig, ScopeConfig, ScopeKind, ScopeRule, TestAccount,
    TestingRestrictions,
)
from bbagent.detectors.base import VerificationResult
from bbagent.program.manager import ProgramManager
from bbagent.verification import browser_idor as bi
from bbagent.verification.browser_idor import (
    AccessObservation, BrowserIdentityFetcher, IdentityFetcher, verify_idor_two_identity,
)

TEMU_YAML = str(Path(__file__).resolve().parents[1] / "programs" / "temu.yaml")
URL = "https://app.local.test/api/phantom/xg/pfb/b"
OBJECT = json.dumps({"b": "d22a0000-0000-4000-8000-0000000000d5", "owner": "A"})


def _program(n: int) -> ProgramManager:
    accts = [TestAccount(label="researcher")]
    if n >= 2:
        accts.append(TestAccount(label="researcher_b"))
    return ProgramManager(ProgramConfig(
        name="bidp", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="app.local.test")]),
        restrictions=TestingRestrictions(allow_active_testing=False, allowed_methods=["GET"]),
        test_accounts=accts, allowed_tools=["http", "recon"],
        allowed_vulnerability_classes=["idor"], allow_unauthenticated=True,
        request_budget=PolicyBudget(total=20)))


class MockFetcher(IdentityFetcher):
    """Records fetches; returns a canned observation per identity. Optionally fails
    if called at all (to prove zero active requests)."""

    def __init__(self, per_identity: dict[str, AccessObservation] | None = None,
                 *, fail_if_called: bool = False):
        self._resp = per_identity or {}
        self.calls: list[tuple[str, str]] = []
        self._fail = fail_if_called

    async def fetch(self, identity_label: str, url: str) -> AccessObservation:
        if self._fail:
            raise AssertionError("fetch must not be called")
        self.calls.append((identity_label, url))
        o = self._resp.get(identity_label, AccessObservation(identity_label, url, 200, OBJECT))
        return AccessObservation(identity_label, url, o.status, o.body, o.content_type)


def _run(coro):
    return asyncio.run(coro)


# --- (12a) A and B use different profiles -------------------------------------

def test_a_and_b_use_different_profiles(tmp_path, monkeypatch):
    monkeypatch.setenv("BBAGENT_H1_USERNAME", "h1-handle")
    monkeypatch.setenv("BBAGENT_TEMU_PROFILE_A", str(tmp_path / "A"))
    monkeypatch.setenv("BBAGENT_TEMU_PROFILE_B", str(tmp_path / "B"))
    temu = ProgramManager(load_program(TEMU_YAML))
    fetcher = BrowserIdentityFetcher(temu)
    assert fetcher.identities() == ["researcher", "researcher_b"]
    a = fetcher._backends["researcher"].user_data_dir
    b = fetcher._backends["researcher_b"].user_data_dir
    assert a and b and a != b                       # own, distinct profiles
    assert fetcher._backends["researcher"]._identity_label == "researcher"
    assert fetcher._backends["researcher_b"]._identity_label == "researcher_b"


# --- (12b) A and B make isolated requests -------------------------------------

def test_a_and_b_make_isolated_requests():
    f = MockFetcher()
    res = _run(verify_idor_two_identity(_program(2), URL, f))
    assert f.calls == [("researcher", URL), ("researcher_b", URL)]   # one each, same object
    assert isinstance(res, VerificationResult)


# --- (12c) same identity cannot satisfy the two-identity requirement ----------

def test_same_identity_cannot_satisfy():
    f = MockFetcher()
    res = _run(verify_idor_two_identity(_program(2), URL, f,
                                        owner_label="researcher", other_label="researcher"))
    assert res.inconclusive is True and res.verified is False
    assert "distinct" in res.reason.lower()
    assert f.calls == []                             # no fetch when the rule can't be met


# --- (12d) unauthenticated context cannot become Identity B -------------------

def test_unauthenticated_cannot_be_identity_b():
    f = MockFetcher()
    res = _run(verify_idor_two_identity(_program(2), URL, f, other_label="unauthenticated"))
    assert res.inconclusive is True and res.verified is False
    assert f.calls == []


# --- (12e) A/B comparison yields a CANDIDATE result, never an auto-finding -----

def test_broken_access_is_candidate_not_finding():
    # B receives A's object contents -> candidate IDOR (verified True) but this call
    # returns only a VerificationResult; it has no DB and creates NO finding.
    f = MockFetcher({
        "researcher": AccessObservation("researcher", URL, 200, OBJECT),
        "researcher_b": AccessObservation("researcher_b", URL, 200, OBJECT),
    })
    res = _run(verify_idor_two_identity(_program(2), URL, f))
    assert isinstance(res, VerificationResult)
    assert res.verified is True and res.inconclusive is False
    assert len(res.exchanges) == 2                   # evidence for the engine to store
    assert not hasattr(res, "finding")               # no finding auto-created


def test_authorization_difference_is_not_a_finding():
    # A sees the object, B is denied -> a difference, NOT IDOR -> verified False.
    f = MockFetcher({
        "researcher": AccessObservation("researcher", URL, 200, OBJECT),
        "researcher_b": AccessObservation("researcher_b", URL, 403, json.dumps({"error": "forbidden"})),
    })
    res = _run(verify_idor_two_identity(_program(2), URL, f))
    assert res.verified is False and res.inconclusive is False
    assert len(res.exchanges) == 2                   # still a candidate result with evidence


# --- (12f) insufficient identities -> INCONCLUSIVE with ZERO active requests ---

def test_insufficient_identities_inconclusive_zero_requests():
    f = MockFetcher(fail_if_called=True)
    res = _run(verify_idor_two_identity(_program(1), URL, f))
    assert res.inconclusive is True and res.verified is False
    assert "two authorized" in res.reason.lower()
    assert f.calls == []                             # zero active requests


# --- scope fail-closed + no secret export -------------------------------------

def test_out_of_scope_target_refused_without_fetch():
    f = MockFetcher(fail_if_called=True)
    res = _run(verify_idor_two_identity(_program(2), "https://evil.example.com/x", f))
    assert res.verified is False
    assert "out of the configured" in res.reason.lower()
    assert f.calls == []


def test_evidence_redacts_auth_headers_and_no_storage_export():
    obs = AccessObservation("researcher", URL, 200, OBJECT,
                            response_headers={"Set-Cookie": "sid=SECRET", "Content-Type": "application/json"})
    ex = obs.to_exchange()
    assert "SECRET" not in json.dumps(ex.response_headers)
    assert ex.response_headers.get("Set-Cookie") == ""
    # The module never reads/exports browser session state.
    src = inspect.getsource(bi)
    assert "storage_state(" not in src and ".cookies(" not in src
