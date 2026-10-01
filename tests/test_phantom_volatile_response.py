"""Establish (do NOT change) how the current IDOR verifier classifies a
/phantom-style volatile response: the SAME logical object returned to A and B but
with differing volatile fields (timestamps/request-ids).

Finding we are documenting: exact-match `_same_object()` returns False on volatile
bodies, so the verifier classifies such a response as DISPROVEN — i.e. it CANNOT
confirm IDOR on a volatile endpoint. That is a SAFE under-report (never a false
positive), so there is no correctness bug to fix here. We deliberately do not change
`_same_object()` or introduce a volatility-tolerant comparator.
"""

from __future__ import annotations

import asyncio
import json

from bbagent.config.models import (
    PolicyBudget, ProgramConfig, ScopeConfig, ScopeKind, ScopeRule, TestAccount,
    TestingRestrictions,
)
from bbagent.detectors.idor import _same_object
from bbagent.program.manager import ProgramManager
from bbagent.verification.browser_idor import (
    AccessObservation, IdentityFetcher, verify_idor_two_identity,
)

URL = "https://app.local.test/api/phantom/xg/pfb/b"
_CORE = {"id": "obj-1", "data": "owner-A-note"}


def _program():
    return ProgramManager(ProgramConfig(
        name="volatile", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="app.local.test")]),
        restrictions=TestingRestrictions(allow_active_testing=False, allowed_methods=["GET"]),
        test_accounts=[TestAccount(label="researcher"), TestAccount(label="researcher_b")],
        allowed_tools=["http", "recon"], allowed_vulnerability_classes=["idor"],
        allow_unauthenticated=True, request_budget=PolicyBudget(total=20)))


class _MockFetcher(IdentityFetcher):
    def __init__(self, per): self._per = per; self.calls = []
    async def fetch(self, identity_label, url):
        self.calls.append((identity_label, url))
        st, body = self._per[identity_label]
        return AccessObservation(identity_label, url, st, body, content_type="application/json")


# --- what _same_object() actually does -----------------------------------------

def test_same_object_true_only_on_identical_bodies():
    b = json.dumps(_CORE)
    assert _same_object(b, b) is True
    # Order-insensitive JSON equality still holds for identical logical content.
    assert _same_object(json.dumps({"a": 1, "b": 2}), json.dumps({"b": 2, "a": 1})) is True


def test_same_object_false_on_volatile_fields():
    a = json.dumps({**_CORE, "ts": 1000, "request_id": "rid-A", "nonce": "n1"})
    b = json.dumps({**_CORE, "ts": 1001, "request_id": "rid-B", "nonce": "n2"})
    # Same logical object, different volatile fields -> exact equality is False.
    assert _same_object(a, b) is False


def test_same_object_empty_never_matches():
    assert _same_object("", "") is False
    assert _same_object("{}", "") is False


# --- verifier-level: volatile same-object -> DISPROVEN (safe), never VERIFIED ---

def test_verifier_cannot_confirm_idor_on_volatile_response():
    a_body = json.dumps({**_CORE, "ts": 1000, "request_id": "A"})
    b_body = json.dumps({**_CORE, "ts": 1001, "request_id": "B"})   # volatile differs
    f = _MockFetcher({"researcher": (200, a_body), "researcher_b": (200, b_body)})
    res = asyncio.run(verify_idor_two_identity(
        _program(), URL, f, owner_label="researcher", other_label="researcher_b"))

    # Classified as DISPROVEN (not verified, not inconclusive): exact match failed.
    assert res.verified is False
    assert getattr(res, "inconclusive", False) is False
    assert "same_object=False" in res.reason
    # SAFETY: a volatile difference NEVER yields a (false-positive) verified IDOR.
    assert res.verified is not True
    # Both identities were still fetched, and evidence is available for debugging.
    assert f.calls == [("researcher", URL), ("researcher_b", URL)]
    assert len(res.exchanges) == 2


def test_verifier_confirms_only_on_byte_identical_object():
    # Control: if the endpoint were NOT volatile (identical bodies), B reading A's
    # object WOULD verify — proving the verifier still works on stable objects.
    body = json.dumps(_CORE)
    f = _MockFetcher({"researcher": (200, body), "researcher_b": (200, body)})
    res = asyncio.run(verify_idor_two_identity(
        _program(), URL, f, owner_label="researcher", other_label="researcher_b"))
    assert res.verified is True and "read the first identity's object" in res.reason
