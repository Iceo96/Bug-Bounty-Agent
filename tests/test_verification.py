"""Verification engine, authorization-boundary detection, dedup, and no-fabrication."""

from __future__ import annotations

import httpx
import pytest

import bbagent.detectors.idor  # noqa: F401 — registers detector/verifier
from bbagent.detectors.base import (
    VerificationContext,
    VerificationResult,
    Verifier,
    registry,
)
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.storage.models import (
    Finding,
    FindingStatus,
    Hypothesis,
    HypothesisStatus,
)
from bbagent.verification.dedup import compute_dedup_key
from bbagent.verification.engine import VerificationEngine


def _vulnerable_handler(request: httpx.Request) -> httpx.Response:
    # Vulnerable: returns the same object regardless of identity.
    return httpx.Response(200, text='{"account":"a","balance":100}')


def _safe_handler(request: httpx.Request) -> httpx.Response:
    identity = request.headers.get("x-test-identity")
    if identity == "user_a":
        return httpx.Response(200, text='{"account":"a"}')
    return httpx.Response(403, text="forbidden")


def _hypothesis(program_manager) -> Hypothesis:
    return Hypothesis(
        program=program_manager.name,
        vuln_type="idor",
        title="Possible IDOR",
        rationale="object id in path",
        target_url="https://api.example.com/v1/accounts/1",
        detector="idor-detector",
    )


async def test_verified_finding_has_real_evidence(program_manager, db, evidence_store):
    transport = httpx.MockTransport(_vulnerable_handler)
    hyp = db.add_hypothesis(_hypothesis(program_manager))
    async with AuthorizedHTTPClient(program_manager.config, transport=transport) as http:
        engine = VerificationEngine(program_manager, db, http, evidence_store)
        finding = await engine.process(hyp)

    assert finding is not None
    assert finding.status is FindingStatus.VERIFIED
    # Evidence really exists and verifies.
    assert finding.evidence_ids
    for eid in finding.evidence_ids:
        assert evidence_store.read_verified(eid)
    assert db.get_hypothesis(hyp.id).status is HypothesisStatus.VERIFIED


async def test_non_vulnerable_is_discarded(program_manager, db, evidence_store):
    transport = httpx.MockTransport(_safe_handler)
    hyp = db.add_hypothesis(_hypothesis(program_manager))
    async with AuthorizedHTTPClient(program_manager.config, transport=transport) as http:
        engine = VerificationEngine(program_manager, db, http, evidence_store)
        finding = await engine.process(hyp)

    assert finding is None
    assert db.get_hypothesis(hyp.id).status is HypothesisStatus.DISCARDED
    assert db.list_findings() == []


async def test_verified_without_evidence_is_rejected(program_manager, db, evidence_store):
    """A verifier that claims success but cites no exchanges must NOT create a finding."""

    @registry.register_verifier
    class LyingVerifier(Verifier):
        vuln_type = "lie"

        async def verify(self, ctx: VerificationContext) -> VerificationResult:
            return VerificationResult(verified=True, reason="trust me", exchanges=[])

    hyp = db.add_hypothesis(
        Hypothesis(
            program=program_manager.name, vuln_type="lie", title="fabricated",
            rationale="none", target_url="https://example.com/x",
        )
    )
    transport = httpx.MockTransport(lambda r: httpx.Response(200))
    async with AuthorizedHTTPClient(program_manager.config, transport=transport) as http:
        engine = VerificationEngine(program_manager, db, http, evidence_store)
        finding = await engine.process(hyp)

    assert finding is None
    assert db.list_findings() == []
    assert db.get_hypothesis(hyp.id).status is HypothesisStatus.DISCARDED


async def test_deduplication(program_manager, db, evidence_store):
    transport = httpx.MockTransport(_vulnerable_handler)
    async with AuthorizedHTTPClient(program_manager.config, transport=transport) as http:
        engine = VerificationEngine(program_manager, db, http, evidence_store)
        h1 = db.add_hypothesis(_hypothesis(program_manager))
        f1 = await engine.process(h1)
        # A different object id on the same endpoint template -> same dedup key.
        h2 = db.add_hypothesis(_hypothesis(program_manager))
        h2.target_url = "https://api.example.com/v1/accounts/2"
        db.connection.execute(
            "UPDATE hypotheses SET target_url=? WHERE id=?", (h2.target_url, h2.id)
        )
        f2 = await engine.process(db.get_hypothesis(h2.id))

    assert f1 is not None
    assert f2 is None  # deduplicated
    assert len(db.list_findings()) == 1


def test_dedup_key_collapses_ids():
    k1 = compute_dedup_key("idor", "https://api.example.com/v1/accounts/1", "GET")
    k2 = compute_dedup_key("idor", "https://api.example.com/v1/accounts/999", "GET")
    k3 = compute_dedup_key("idor", "https://api.example.com/v1/orders/1", "GET")
    assert k1 == k2
    assert k1 != k3
