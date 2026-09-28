"""Human-approval workflow and report generation tests."""

from __future__ import annotations

import httpx
import pytest

import bbagent.detectors.idor  # noqa: F401
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.report import generate_report
from bbagent.review import ApprovalError, transition
from bbagent.storage.models import FindingStatus, Hypothesis
from bbagent.verification.engine import VerificationEngine


async def _make_finding(program_manager, db, evidence_store):
    transport = httpx.MockTransport(lambda r: httpx.Response(200, text='{"a":1}'))
    hyp = db.add_hypothesis(
        Hypothesis(
            program=program_manager.name, vuln_type="idor", title="IDOR",
            rationale="x", target_url="https://api.example.com/v1/accounts/1",
        )
    )
    async with AuthorizedHTTPClient(program_manager.config, transport=transport) as http:
        engine = VerificationEngine(program_manager, db, http, evidence_store)
        return await engine.process(hyp)


async def test_approval_flow(program_manager, db, evidence_store):
    finding = await _make_finding(program_manager, db, evidence_store)
    assert finding.status is FindingStatus.VERIFIED

    # Agent can only mark ready for review.
    transition(db, finding.id, FindingStatus.READY_FOR_REVIEW, actor="agent")
    assert db.get_finding(finding.id).status is FindingStatus.READY_FOR_REVIEW

    # Agent must NOT be able to approve for submission.
    with pytest.raises(ApprovalError):
        transition(db, finding.id, FindingStatus.APPROVED_FOR_SUBMISSION, actor="agent")

    # A human can.
    transition(db, finding.id, FindingStatus.APPROVED_FOR_SUBMISSION, actor="human:alice")
    assert db.get_finding(finding.id).status is FindingStatus.APPROVED_FOR_SUBMISSION


async def test_illegal_transition_rejected(program_manager, db, evidence_store):
    finding = await _make_finding(program_manager, db, evidence_store)
    with pytest.raises(ApprovalError):
        # Cannot jump straight from VERIFIED to APPROVED.
        transition(db, finding.id, FindingStatus.APPROVED_FOR_SUBMISSION, actor="human:bob")


async def test_report_contains_evidence_and_no_severity_by_default(program_manager, db, evidence_store):
    finding = await _make_finding(program_manager, db, evidence_store)
    md = generate_report(finding, db, evidence_store)
    assert "# IDOR" in md
    assert "## Evidence" in md
    assert "Severity" not in md  # no methodology provided -> no severity
    assert "requires human review before submission" in md


async def test_report_includes_severity_when_provided(program_manager, db, evidence_store):
    finding = await _make_finding(program_manager, db, evidence_store)
    md = generate_report(finding, db, evidence_store, severity="High")
    assert "**Severity:** High" in md
