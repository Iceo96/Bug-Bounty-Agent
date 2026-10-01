"""Reproduces the live Temu outcome: an IDOR candidate is GENERATED (object-ref +
observed under >=2 identity contexts) with only ONE authorized identity, then the
verifier returns INCONCLUSIVE and makes ZERO active requests. No network, no Temu.
"""

from __future__ import annotations

import asyncio

from bbagent.browser.observe import NetworkObservationIngestor
from bbagent.browser.models import ObservedExchange
from bbagent.config.models import (
    ProgramConfig, ScopeConfig, ScopeKind, ScopeRule, TestAccount, TestingRestrictions,
)
from bbagent.detectors.base import VerificationContext
from bbagent.detectors.idor import IDORVerifier
from bbagent.planner.runner import PlanRunner
from bbagent.program.manager import ProgramManager
from bbagent.storage.models import Hypothesis
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore
from bbagent.storage.db import Database

HOST = "app.local.test"
URL = f"https://{HOST}/api/phantom/xg/pfb/b"
UUID = "d22a0000-0000-4000-8000-0000000000d5"   # 36-char UUID-like json_id (like Temu's)


def _one_account_program() -> ProgramManager:
    return ProgramManager(ProgramConfig(
        name="one-id", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value=HOST)]),
        restrictions=TestingRestrictions(allow_active_testing=False, allowed_methods=["GET"]),
        test_accounts=[TestAccount(label="researcher")],      # exactly ONE identity
        allowed_tools=["http", "recon"],
        allowed_vulnerability_classes=["idor", "privilege_escalation", "sql_injection"],
        allow_unauthenticated=True,
    ))


def _ingest_two_contexts(program, surface) -> None:
    """Same endpoint observed UNAUTHENTICATED and AUTHENTICATED, with a json_id ref."""
    ing = NetworkObservationIngestor(
        program, surface, default_identity=AuthIdentity.IDENTITY_A,
        identity_map={"researcher": AuthIdentity.IDENTITY_A})
    body = '{"b": "%s"}' % UUID
    unauth = ObservedExchange("GET", URL, status=200, request_headers={},
                              response_headers={"Content-Type": "application/json"},
                              response_body=body, identity_label="researcher")
    authed = ObservedExchange("GET", URL, status=200, request_headers={"cookie": ""},
                              response_headers={"Content-Type": "application/json"},
                              response_body=body, identity_label="researcher")
    ing.ingest([unauth, authed])


def test_planner_generates_idor_from_objref_and_two_contexts_with_one_account():
    db = Database(":memory:")
    surface = SurfaceStore(db)
    program = _one_account_program()
    _ingest_two_contexts(program, surface)

    # Concrete object-ref evidence is present (a json_id at body key "b").
    ep = surface.list_endpoints(program.name)[0]
    refs = surface.object_refs_for(ep.id)
    assert any(r.kind == "json_id" and r.location == "json:b" for r in refs)
    idents = {o.identity for o in surface.auth_observations_for(ep.id)}
    assert idents == {AuthIdentity.UNAUTHENTICATED.value, AuthIdentity.IDENTITY_A.value}

    # The planner PROPOSES an IDOR candidate even with one account, because the
    # endpoint was observed under >= 2 identity CONTEXTS (unauth + authenticated).
    queue = PlanRunner(program, db, surface).generate()
    idor = [h for h in queue if h.vulnerability_class == "idor"]
    assert idor and idor[0].endpoint == URL
    # Concrete (not generic): the candidate cites an observed object reference.
    assert "object reference" in idor[0].reasoning
    assert "multiple identity contexts" in idor[0].reasoning
    db.close()


def test_verifier_is_inconclusive_and_makes_zero_requests_with_one_identity():
    program = _one_account_program()

    class _NoHTTP:
        calls = 0
        async def get(self, *a, **k):        # must never be called
            _NoHTTP.calls += 1
            raise AssertionError("verifier issued a request with < 2 authorized identities")

    ctx = VerificationContext(
        program=program, db=None, http=_NoHTTP(),
        hypothesis=Hypothesis(program=program.name, vuln_type="idor",
                              title="idor", rationale="", target_url=URL, detector="planner"))
    result = asyncio.run(IDORVerifier().verify(ctx))

    assert result.verified is False
    assert "two authorized" in result.reason.lower()
    assert _NoHTTP.calls == 0                 # ZERO active requests — gate returns first
