"""Persistent human-review queue for verified findings.

Flow:
  verified finding -> validate evidence -> generate (immutable) report
                   -> surface duplicate candidates -> READY_FOR_REVIEW
                   -> [operator edits] -> APPROVED_FOR_SUBMISSION | CHANGES_REQUESTED | REJECTED

Guarantees:
  * A finding with invalid/corrupt evidence never enters the queue (no report).
  * The generated report is stored immutably; operator edits are stored separately.
  * Only a human actor can approve; approval also requires complete report quality.
  * Nothing is auto-submitted — the terminal state is APPROVED_FOR_SUBMISSION.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from bbagent.logging_config import get_logger
from bbagent.report import generate_report
from bbagent.review import ApprovalError, transition
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import Finding, FindingStatus
from bbagent.urlutils import endpoint_key
from bbagent.validation import EvidenceValidation, report_quality, validate_evidence

log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
    finding_id TEXT PRIMARY KEY,
    program TEXT NOT NULL,
    status TEXT NOT NULL,
    generated_report TEXT NOT NULL,
    edited_report TEXT,
    generated_at REAL NOT NULL,
    edited_at REAL,
    reviewer TEXT,
    last_action TEXT,
    action_at REAL,
    duplicates TEXT NOT NULL DEFAULT '[]',
    quality_complete INTEGER NOT NULL DEFAULT 0,
    notes TEXT NOT NULL DEFAULT ''
);
"""


class ReviewError(Exception):
    pass


@dataclass
class ReviewItem:
    finding_id: str
    program: str
    status: str
    generated_report: str
    edited_report: str | None
    generated_at: float
    edited_at: float | None
    reviewer: str | None
    last_action: str | None
    action_at: float | None
    duplicates: list[str]
    quality_complete: bool
    notes: str

    @property
    def current_report(self) -> str:
        """The edited report if present, else the immutable generated one."""
        return self.edited_report if self.edited_report else self.generated_report


class ReviewStore:
    def __init__(self, db: Database, evidence: EvidenceStore):
        self._db = db
        self._evidence = evidence
        self._c = db.connection
        self._c.executescript(_SCHEMA)
        self._c.commit()

    # --- duplicate awareness --------------------------------------------------

    def find_duplicate_candidates(self, finding: Finding) -> list[str]:
        """Return ids of existing findings that may be the same issue.

        Matches on shared dedup_key, or on same vuln class + endpoint template.
        Nothing is discarded — these are surfaced to the reviewer.
        """
        candidates: set[str] = set()
        target_key = endpoint_key(finding.http_method, finding.endpoint)
        for other in self._db.list_findings(finding.program):
            if other.id == finding.id:
                continue
            if finding.dedup_key and other.dedup_key == finding.dedup_key:
                candidates.add(other.id)
                continue
            if (other.vuln_type == finding.vuln_type
                    and endpoint_key(other.http_method, other.endpoint) == target_key):
                candidates.add(other.id)
        return sorted(candidates)

    # --- queue entry ----------------------------------------------------------

    def submit_for_review(self, finding_id: str) -> ReviewItem:
        """Validate evidence, generate the report, surface duplicates, enqueue.

        Raises :class:`ReviewError` if evidence is missing/corrupt — such a
        finding never enters the queue and no report is generated.
        """
        finding = self._db.get_finding(finding_id)
        if finding is None:
            raise ReviewError(f"no such finding: {finding_id}")
        if finding.status not in (FindingStatus.VERIFIED, FindingStatus.CHANGES_REQUESTED):
            raise ReviewError(
                f"finding {finding_id} is {finding.status.value}; only VERIFIED or "
                f"CHANGES_REQUESTED findings can be (re)submitted for review"
            )

        ev = validate_evidence(finding, self._db, self._evidence)
        if not ev.ok:
            raise ReviewError(f"evidence validation failed: {'; '.join(ev.errors)}")

        report = generate_report(finding, self._db, self._evidence)
        quality = report_quality(finding, self._db, self._evidence)
        duplicates = self.find_duplicate_candidates(finding)
        now = time.time()

        existing = self._get_row(finding_id)
        if existing is None:
            self._c.execute(
                "INSERT INTO reviews(finding_id, program, status, generated_report, generated_at,"
                " duplicates, quality_complete) VALUES(?,?,?,?,?,?,?)",
                (finding_id, finding.program, FindingStatus.READY_FOR_REVIEW.value, report, now,
                 _json(duplicates), 1 if quality.complete else 0),
            )
        else:
            # Re-submission after CHANGES_REQUESTED: keep the ORIGINAL generated
            # report immutable; only refresh status/duplicates/quality.
            self._c.execute(
                "UPDATE reviews SET status=?, duplicates=?, quality_complete=? WHERE finding_id=?",
                (FindingStatus.READY_FOR_REVIEW.value, _json(duplicates),
                 1 if quality.complete else 0, finding_id),
            )
        self._c.commit()

        transition(self._db, finding_id, FindingStatus.READY_FOR_REVIEW, actor="agent")
        log.info("review.enqueued", finding=finding_id, duplicates=len(duplicates),
                 complete=quality.complete)
        return self.get(finding_id)

    # --- operator editing -----------------------------------------------------

    def set_edited_report(self, finding_id: str, text: str, *, reviewer: str) -> ReviewItem:
        """Store an operator-edited report. The generated report stays immutable."""
        if self._get_row(finding_id) is None:
            raise ReviewError(f"no review item for finding {finding_id}")
        now = time.time()
        self._c.execute(
            "UPDATE reviews SET edited_report=?, edited_at=?, reviewer=?, last_action=?,"
            " action_at=? WHERE finding_id=?",
            (text, now, reviewer, "edited", now, finding_id),
        )
        self._c.commit()
        log.info("review.edited", finding=finding_id, reviewer=reviewer)
        return self.get(finding_id)

    # --- reviewer actions -----------------------------------------------------

    def request_changes(self, finding_id: str, *, reviewer: str, note: str = "") -> ReviewItem:
        transition(self._db, finding_id, FindingStatus.CHANGES_REQUESTED, actor=reviewer)
        self._set_action(finding_id, FindingStatus.CHANGES_REQUESTED, reviewer, "request_changes", note)
        return self.get(finding_id)

    def reject(self, finding_id: str, *, reviewer: str, note: str = "") -> ReviewItem:
        transition(self._db, finding_id, FindingStatus.REJECTED, actor=reviewer)
        self._set_action(finding_id, FindingStatus.REJECTED, reviewer, "reject", note)
        return self.get(finding_id)

    def approve(self, finding_id: str, *, reviewer: str) -> ReviewItem:
        """Approve for submission. Human-only, and only if the report is complete.

        Does NOT submit anything — the terminal state is APPROVED_FOR_SUBMISSION.
        """
        if reviewer == "agent":
            raise ApprovalError("the agent may not approve findings for submission; a human must")
        finding = self._db.get_finding(finding_id)
        if finding is None:
            raise ReviewError(f"no such finding: {finding_id}")

        # Re-validate at the moment of approval (evidence + completeness).
        ev = validate_evidence(finding, self._db, self._evidence)
        if not ev.ok:
            raise ReviewError(f"cannot approve: evidence invalid ({'; '.join(ev.errors)})")
        quality = report_quality(finding, self._db, self._evidence)
        if not quality.complete:
            raise ReviewError(f"cannot approve incomplete report; missing: {', '.join(quality.issues)}")

        transition(self._db, finding_id, FindingStatus.APPROVED_FOR_SUBMISSION, actor=reviewer)
        self._set_action(finding_id, FindingStatus.APPROVED_FOR_SUBMISSION, reviewer, "approve", "")
        log.info("review.approved", finding=finding_id, reviewer=reviewer)
        return self.get(finding_id)

    # --- queries --------------------------------------------------------------

    def get(self, finding_id: str) -> ReviewItem:
        row = self._get_row(finding_id)
        if row is None:
            raise ReviewError(f"no review item for finding {finding_id}")
        return _to_item(row)

    def list_queue(self, program: str | None = None,
                   status: FindingStatus | None = None) -> list[ReviewItem]:
        q = "SELECT * FROM reviews"
        clauses, args = [], []
        if program:
            clauses.append("program=?")
            args.append(program)
        if status:
            clauses.append("status=?")
            args.append(status.value)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY generated_at DESC"
        return [_to_item(r) for r in self._c.execute(q, tuple(args)).fetchall()]

    # --- internals ------------------------------------------------------------

    def _get_row(self, finding_id: str):
        return self._c.execute("SELECT * FROM reviews WHERE finding_id=?", (finding_id,)).fetchone()

    def _set_action(self, finding_id: str, status: FindingStatus, reviewer: str,
                    action: str, note: str) -> None:
        now = time.time()
        self._c.execute(
            "UPDATE reviews SET status=?, reviewer=?, last_action=?, action_at=?, notes=? "
            "WHERE finding_id=?",
            (status.value, reviewer, action, now, note, finding_id),
        )
        self._c.commit()


def _json(values: list[str]) -> str:
    import json
    return json.dumps(values)


def _to_item(row) -> ReviewItem:
    import json
    return ReviewItem(
        finding_id=row["finding_id"], program=row["program"], status=row["status"],
        generated_report=row["generated_report"], edited_report=row["edited_report"],
        generated_at=row["generated_at"], edited_at=row["edited_at"], reviewer=row["reviewer"],
        last_action=row["last_action"], action_at=row["action_at"],
        duplicates=json.loads(row["duplicates"]), quality_complete=bool(row["quality_complete"]),
        notes=row["notes"],
    )
