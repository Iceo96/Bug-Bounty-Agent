"""Tests for the human-review and reporting workflow."""

from __future__ import annotations

from pathlib import Path

import pytest

from bbagent import cli
from bbagent.http.client import HTTPExchange
from bbagent.report import generate_report
from bbagent.review import ApprovalError
from bbagent.reviewstore import ReviewError, ReviewStore
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import Finding, FindingStatus
from bbagent.validation import report_quality, validate_evidence
from bbagent.verification.dedup import compute_dedup_key

ENDPOINT = "http://127.0.0.1:8000/api/notes/note-a1"


def _exchange(url=ENDPOINT, body='{"note":{"id":"note-a1","owner":"user_a"}}'):
    return HTTPExchange(
        exchange_id="ex", method="GET", url=url, request_headers={"x-bug-bounty": "r"},
        request_body=None, status_code=200,
        response_headers={"content-type": "application/json"}, response_body=body, elapsed_ms=1.0,
    )


def _make_finding(db, evidence, *, endpoint=ENDPOINT, complete=True, with_evidence=True,
                  program="P", fid=None) -> Finding:
    finding = Finding(
        program=program, hypothesis_id="h", vuln_type="idor",
        title="IDOR at notes endpoint",
        affected_asset="127.0.0.1", endpoint=endpoint, http_method="GET",
        test_identity="user_b (non-owner)",
        expected_behavior="user_b should receive 403/404" if complete else "",
        actual_behavior="user_b received 200 with user_a's object" if complete else "",
        impact="Broken object-level authorization allows reading others' objects.",
        reproduction="1. Auth as user_a. 2. Auth as user_b. 3. GET the object as user_b.",
        status=FindingStatus.VERIFIED,
        dedup_key=compute_dedup_key("idor", endpoint, "GET"),
    )
    if fid:
        finding.id = fid
    db.add_finding(finding)
    if with_evidence:
        ids = []
        for _ in range(2):  # owner + other exchanges
            req, resp = evidence.store_exchange(_exchange(endpoint), finding_id=finding.id)
            ids += [req.id, resp.id]
        db.attach_finding_evidence(finding.id, ids)
    return db.get_finding(finding.id)


@pytest.fixture
def env_tmp(tmp_path):
    db = Database(":memory:")
    ev = EvidenceStore(db, tmp_path / "ev")
    yield db, ev, ReviewStore(db, ev)
    db.close()


# --- queue --------------------------------------------------------------------

def test_verified_finding_enters_review_queue(env_tmp):
    db, ev, rs = env_tmp
    f = _make_finding(db, ev)
    item = rs.submit_for_review(f.id)
    assert item.status == FindingStatus.READY_FOR_REVIEW.value
    assert db.get_finding(f.id).status is FindingStatus.READY_FOR_REVIEW
    assert item.quality_complete is True
    assert rs.list_queue("P")[0].finding_id == f.id


def test_invalid_evidence_prevents_report(env_tmp):
    db, ev, rs = env_tmp
    f = _make_finding(db, ev, with_evidence=False)  # no evidence
    with pytest.raises(ReviewError):
        rs.submit_for_review(f.id)
    # Not enqueued; finding stays VERIFIED.
    assert db.get_finding(f.id).status is FindingStatus.VERIFIED


def test_corrupted_evidence_is_rejected(env_tmp):
    db, ev, rs = env_tmp
    f = _make_finding(db, ev)
    rec = db.get_evidence(f.evidence_ids[0])
    p = Path(rec.blob_path)
    try:
        p.chmod(0o600)
    except OSError:
        pass
    p.write_bytes(b"tampered")
    with pytest.raises(ReviewError):
        rs.submit_for_review(f.id)


def test_missing_fields_prevent_approval(env_tmp):
    db, ev, rs = env_tmp
    f = _make_finding(db, ev, complete=False)  # no expected/actual behavior
    item = rs.submit_for_review(f.id)          # enqueues, but incomplete
    assert item.quality_complete is False
    with pytest.raises(ReviewError):
        rs.approve(f.id, reviewer="alice")
    assert db.get_finding(f.id).status is FindingStatus.READY_FOR_REVIEW  # not approved


def test_human_approval_succeeds(env_tmp):
    db, ev, rs = env_tmp
    f = _make_finding(db, ev)
    rs.submit_for_review(f.id)
    item = rs.approve(f.id, reviewer="alice")
    assert item.status == FindingStatus.APPROVED_FOR_SUBMISSION.value
    assert db.get_finding(f.id).status is FindingStatus.APPROVED_FOR_SUBMISSION


def test_agent_cannot_approve(env_tmp):
    db, ev, rs = env_tmp
    f = _make_finding(db, ev)
    rs.submit_for_review(f.id)
    with pytest.raises(ApprovalError):
        rs.approve(f.id, reviewer="agent")
    assert db.get_finding(f.id).status is FindingStatus.READY_FOR_REVIEW


def test_rejected_finding_cannot_be_submitted(env_tmp):
    db, ev, rs = env_tmp
    f = _make_finding(db, ev)
    rs.submit_for_review(f.id)
    rs.reject(f.id, reviewer="alice", note="dup")
    assert db.get_finding(f.id).status is FindingStatus.REJECTED
    with pytest.raises((ApprovalError, ReviewError)):
        rs.approve(f.id, reviewer="alice")


def test_edited_report_preserves_original(env_tmp):
    db, ev, rs = env_tmp
    f = _make_finding(db, ev)
    item = rs.submit_for_review(f.id)
    original = item.generated_report
    edited = rs.set_edited_report(f.id, "# My edited report\nCustom text.", reviewer="alice")
    assert edited.generated_report == original          # immutable
    assert edited.edited_report == "# My edited report\nCustom text."
    assert edited.current_report == edited.edited_report
    assert edited.reviewer == "alice"


def test_duplicate_candidates_surfaced(env_tmp):
    db, ev, rs = env_tmp
    f1 = _make_finding(db, ev, fid="find_dup_1")
    f2 = _make_finding(db, ev, fid="find_dup_2")  # same endpoint + vuln class
    item = rs.submit_for_review(f1.id)
    assert f2.id in item.duplicates  # surfaced, not discarded


def test_report_contains_only_verified_evidence(env_tmp):
    db, ev, rs = env_tmp
    f = _make_finding(db, ev)
    report = generate_report(f, db, ev)
    assert "## Evidence" in report
    assert "note-a1" in report                 # real captured body
    assert "INCOMPLETE" not in report          # complete finding
    # Every evidence id in the report belongs to the finding.
    for eid in f.evidence_ids:
        assert eid in report


def test_incomplete_report_is_marked_not_guessed(env_tmp):
    db, ev, rs = env_tmp
    f = _make_finding(db, ev, complete=False)
    report = generate_report(f, db, ev)
    assert "INCOMPLETE REPORT" in report
    q = report_quality(f, db, ev)
    assert not q.complete
    assert "expected_behavior_exists" in q.issues


def test_changes_requested_roundtrip_keeps_original(env_tmp):
    db, ev, rs = env_tmp
    f = _make_finding(db, ev)
    item = rs.submit_for_review(f.id)
    original = item.generated_report
    rs.request_changes(f.id, reviewer="alice", note="clarify impact")
    assert db.get_finding(f.id).status is FindingStatus.CHANGES_REQUESTED
    again = rs.submit_for_review(f.id)  # allowed from CHANGES_REQUESTED
    assert again.status == FindingStatus.READY_FOR_REVIEW.value
    assert again.generated_report == original  # generated report immutable


# --- CLI ----------------------------------------------------------------------

def test_cli_review_and_approve(tmp_path, monkeypatch, capsys):
    dbfile = str(tmp_path / "wf.db")
    evdir = str(tmp_path / "evdir")
    monkeypatch.setenv("BBAGENT_EVIDENCE_DIR", evdir)

    # Seed a verified finding using the same db file + evidence dir the CLI uses.
    db = Database(dbfile)
    ev = EvidenceStore(db, evdir)
    f = _make_finding(db, ev)
    fid = f.id
    db.close()

    assert cli.main(["--db", dbfile, "findings"]) == 0
    assert fid in capsys.readouterr().out

    assert cli.main(["--db", dbfile, "review", fid]) == 0
    out = capsys.readouterr().out
    assert "READY_FOR_REVIEW" in out.upper()
    assert "## Evidence" in out

    # Wrong confirmation aborts.
    monkeypatch.setattr("builtins.input", lambda *_: "not-the-id")
    assert cli.main(["--db", dbfile, "approve", fid]) == 1

    # Correct confirmation approves.
    monkeypatch.setattr("builtins.input", lambda *_: fid)
    assert cli.main(["--db", dbfile, "approve", fid, "--reviewer", "alice"]) == 0
    out = capsys.readouterr().out
    assert "APPROVED_FOR_SUBMISSION" in out.upper()

    db = Database(dbfile)
    try:
        assert db.get_finding(fid).status is FindingStatus.APPROVED_FOR_SUBMISSION
    finally:
        db.close()


def test_cli_approve_never_runs_as_agent(tmp_path, monkeypatch, capsys):
    dbfile = str(tmp_path / "wf2.db")
    evdir = str(tmp_path / "evdir2")
    monkeypatch.setenv("BBAGENT_EVIDENCE_DIR", evdir)
    db = Database(dbfile)
    ev = EvidenceStore(db, evdir)
    f = _make_finding(db, ev)
    fid = f.id
    db.close()

    cli.main(["--db", dbfile, "review", fid])
    capsys.readouterr()
    # Even if someone passes --reviewer agent, it is coerced to a human operator.
    monkeypatch.setattr("builtins.input", lambda *_: fid)
    assert cli.main(["--db", dbfile, "approve", fid, "--reviewer", "agent", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "reviewer: operator" in out
