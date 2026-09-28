"""SQLite connection management and schema.

Uses the stdlib ``sqlite3`` module with a small typed access layer. WAL mode and
foreign keys are enabled. The schema stores the attack-surface map, the findings
lifecycle, and evidence metadata.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Optional

from bbagent.storage.models import (
    EvidenceRecord,
    Finding,
    FindingStatus,
    Hypothesis,
    HypothesisStatus,
    Observation,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    hostname TEXT NOT NULL,
    technologies TEXT DEFAULT '[]',
    created_at REAL NOT NULL,
    UNIQUE(program, hostname)
);

CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    params TEXT DEFAULT '[]',
    auth_boundary TEXT,
    notes TEXT,
    created_at REAL NOT NULL,
    UNIQUE(program, method, url)
);

CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    program TEXT NOT NULL,
    kind TEXT NOT NULL,
    summary TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}',
    exchange_id TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    program TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    title TEXT NOT NULL,
    rationale TEXT NOT NULL,
    target_url TEXT NOT NULL,
    status TEXT NOT NULL,
    detector TEXT NOT NULL,
    observation_ids TEXT NOT NULL DEFAULT '[]',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    program TEXT NOT NULL,
    hypothesis_id TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    title TEXT NOT NULL,
    affected_asset TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    http_method TEXT NOT NULL,
    test_identity TEXT NOT NULL,
    expected_behavior TEXT NOT NULL,
    actual_behavior TEXT NOT NULL,
    impact TEXT NOT NULL,
    preconditions TEXT NOT NULL DEFAULT '',
    reproduction TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    dedup_key TEXT,
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    created_at REAL NOT NULL
);

-- Evidence metadata is append-only; enforced by triggers below.
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    finding_id TEXT,
    hypothesis_id TEXT,
    label TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    blob_path TEXT NOT NULL,
    exchange_id TEXT,
    created_at REAL NOT NULL
);

CREATE TRIGGER IF NOT EXISTS evidence_no_update
BEFORE UPDATE ON evidence
BEGIN
    SELECT RAISE(ABORT, 'evidence rows are immutable');
END;

CREATE TRIGGER IF NOT EXISTS evidence_no_delete
BEFORE DELETE ON evidence
BEGIN
    SELECT RAISE(ABORT, 'evidence rows cannot be deleted');
END;

CREATE INDEX IF NOT EXISTS ix_findings_dedup ON findings(program, dedup_key);
CREATE INDEX IF NOT EXISTS ix_hyp_program ON hypotheses(program, status);
"""


class Database:
    """Thin typed wrapper over a SQLite connection."""

    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON;")
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL;")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    def close(self) -> None:
        self._conn.close()

    # --- observations ----------------------------------------------------------

    def add_observation(self, obs: Observation) -> Observation:
        self._conn.execute(
            "INSERT INTO observations(id, program, kind, summary, data, exchange_id, created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (obs.id, obs.program, obs.kind, obs.summary, json.dumps(obs.data), obs.exchange_id, obs.created_at),
        )
        self._conn.commit()
        return obs

    # --- hypotheses ------------------------------------------------------------

    def add_hypothesis(self, hyp: Hypothesis) -> Hypothesis:
        self._conn.execute(
            "INSERT INTO hypotheses(id, program, vuln_type, title, rationale, target_url,"
            " status, detector, observation_ids, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                hyp.id, hyp.program, hyp.vuln_type, hyp.title, hyp.rationale, hyp.target_url,
                hyp.status.value, hyp.detector, json.dumps(hyp.observation_ids), hyp.created_at,
            ),
        )
        self._conn.commit()
        return hyp

    def set_hypothesis_status(self, hypothesis_id: str, status: HypothesisStatus) -> None:
        self._conn.execute(
            "UPDATE hypotheses SET status=? WHERE id=?", (status.value, hypothesis_id)
        )
        self._conn.commit()

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Hypothesis]:
        row = self._conn.execute("SELECT * FROM hypotheses WHERE id=?", (hypothesis_id,)).fetchone()
        return _row_to_hypothesis(row) if row else None

    # --- findings --------------------------------------------------------------

    def add_finding(self, finding: Finding) -> Finding:
        self._conn.execute(
            "INSERT INTO findings(id, program, hypothesis_id, vuln_type, title, affected_asset,"
            " endpoint, http_method, test_identity, expected_behavior, actual_behavior, impact,"
            " preconditions, reproduction, status, dedup_key, evidence_ids, created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                finding.id, finding.program, finding.hypothesis_id, finding.vuln_type, finding.title,
                finding.affected_asset, finding.endpoint, finding.http_method, finding.test_identity,
                finding.expected_behavior, finding.actual_behavior, finding.impact, finding.preconditions,
                finding.reproduction, finding.status.value, finding.dedup_key,
                json.dumps(finding.evidence_ids), finding.created_at,
            ),
        )
        self._conn.commit()
        return finding

    def set_finding_status(self, finding_id: str, status: FindingStatus) -> None:
        self._conn.execute("UPDATE findings SET status=? WHERE id=?", (status.value, finding_id))
        self._conn.commit()

    def attach_finding_evidence(self, finding_id: str, evidence_ids: list[str]) -> None:
        self._conn.execute(
            "UPDATE findings SET evidence_ids=? WHERE id=?", (json.dumps(evidence_ids), finding_id)
        )
        self._conn.commit()

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        row = self._conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return _row_to_finding(row) if row else None

    def find_findings_by_dedup(self, program: str, dedup_key: str) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE program=? AND dedup_key=?", (program, dedup_key)
        ).fetchall()
        return [_row_to_finding(r) for r in rows]

    def list_findings(self, program: Optional[str] = None) -> list[Finding]:
        if program:
            rows = self._conn.execute("SELECT * FROM findings WHERE program=?", (program,)).fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM findings").fetchall()
        return [_row_to_finding(r) for r in rows]

    # --- evidence metadata (append-only) --------------------------------------

    def add_evidence(self, record: EvidenceRecord) -> EvidenceRecord:
        self._conn.execute(
            "INSERT INTO evidence(id, finding_id, hypothesis_id, label, sha256, blob_path,"
            " exchange_id, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                record.id, record.finding_id, record.hypothesis_id, record.label, record.sha256,
                record.blob_path, record.exchange_id, record.created_at,
            ),
        )
        self._conn.commit()
        return record

    def get_evidence(self, evidence_id: str) -> Optional[EvidenceRecord]:
        row = self._conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        return _row_to_evidence(row) if row else None


# --- row mappers ---------------------------------------------------------------

def _row_to_hypothesis(r: sqlite3.Row) -> Hypothesis:
    return Hypothesis(
        id=r["id"], program=r["program"], vuln_type=r["vuln_type"], title=r["title"],
        rationale=r["rationale"], target_url=r["target_url"], status=HypothesisStatus(r["status"]),
        detector=r["detector"], observation_ids=json.loads(r["observation_ids"]), created_at=r["created_at"],
    )


def _row_to_finding(r: sqlite3.Row) -> Finding:
    return Finding(
        id=r["id"], program=r["program"], hypothesis_id=r["hypothesis_id"], vuln_type=r["vuln_type"],
        title=r["title"], affected_asset=r["affected_asset"], endpoint=r["endpoint"],
        http_method=r["http_method"], test_identity=r["test_identity"],
        expected_behavior=r["expected_behavior"], actual_behavior=r["actual_behavior"], impact=r["impact"],
        preconditions=r["preconditions"], reproduction=r["reproduction"], status=FindingStatus(r["status"]),
        dedup_key=r["dedup_key"], evidence_ids=json.loads(r["evidence_ids"]), created_at=r["created_at"],
    )


def _row_to_evidence(r: sqlite3.Row) -> EvidenceRecord:
    return EvidenceRecord(
        id=r["id"], finding_id=r["finding_id"], hypothesis_id=r["hypothesis_id"], label=r["label"],
        sha256=r["sha256"], blob_path=r["blob_path"], exchange_id=r["exchange_id"], created_at=r["created_at"],
    )
