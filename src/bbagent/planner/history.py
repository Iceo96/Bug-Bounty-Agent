"""Persistence for planner runs and the planned hypotheses they produced."""

from __future__ import annotations

import json
import time
import uuid

from bbagent.planner.models import PlannedHypothesis, RunSummary, TestBudget
from bbagent.storage.db import Database

_SCHEMA = """
CREATE TABLE IF NOT EXISTS planner_runs (
    run_id TEXT PRIMARY KEY,
    program TEXT NOT NULL,
    started_at REAL NOT NULL,
    ended_at REAL,
    status TEXT NOT NULL,
    stop_reason TEXT NOT NULL DEFAULT '',
    generated INTEGER NOT NULL DEFAULT 0,
    executed INTEGER NOT NULL DEFAULT 0,
    disproven INTEGER NOT NULL DEFAULT 0,
    inconclusive INTEGER NOT NULL DEFAULT 0,
    verified INTEGER NOT NULL DEFAULT 0,
    requests_used INTEGER NOT NULL DEFAULT 0,
    findings_created INTEGER NOT NULL DEFAULT 0,
    budget TEXT NOT NULL DEFAULT '{}',
    dry_run INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS planner_hypotheses (
    id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    program TEXT NOT NULL,
    plan_key TEXT NOT NULL,
    vulnerability_class TEXT NOT NULL,
    target TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    reasoning TEXT NOT NULL,
    required_auth_context TEXT NOT NULL DEFAULT '[]',
    required_inputs TEXT NOT NULL DEFAULT '{}',
    expected_signal TEXT NOT NULL DEFAULT '',
    priority_score INTEGER NOT NULL DEFAULT 0,
    priority_band TEXT NOT NULL DEFAULT 'LOW',
    status TEXT NOT NULL,
    status_reason TEXT NOT NULL DEFAULT '',
    prereq_identities INTEGER NOT NULL DEFAULT 0,
    parent_observation TEXT,
    storage_hypothesis_id TEXT,
    finding_id TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (run_id, id)
);

CREATE INDEX IF NOT EXISTS ix_planner_hyp_run ON planner_hypotheses(run_id);
CREATE INDEX IF NOT EXISTS ix_planner_hyp_key ON planner_hypotheses(program, plan_key);
"""


class RunStore:
    def __init__(self, db: Database):
        self._db = db
        self._c = db.connection
        self._c.executescript(_SCHEMA)
        # Additive migration for databases created before the INCONCLUSIVE-state
        # columns existed. Each ADD COLUMN is a no-op if the column already exists.
        for ddl in (
            "ALTER TABLE planner_hypotheses ADD COLUMN status_reason TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE planner_hypotheses ADD COLUMN prereq_identities INTEGER NOT NULL DEFAULT 0",
        ):
            try:
                self._c.execute(ddl)
            except Exception:  # noqa: BLE001 - column already present
                pass
        self._c.commit()

    # --- runs -----------------------------------------------------------------

    def start_run(self, program: str, budget: TestBudget, *, dry_run: bool = False) -> RunSummary:
        run_id = f"run_{uuid.uuid4().hex[:12]}"
        now = time.time()
        self._c.execute(
            "INSERT INTO planner_runs(run_id, program, started_at, status, budget, dry_run)"
            " VALUES(?,?,?,?,?,?)",
            (run_id, program, now, "running", json.dumps(budget.to_dict()), 1 if dry_run else 0),
        )
        self._c.commit()
        return RunSummary(run_id=run_id, program=program, started_at=now)

    def finish_run(self, summary: RunSummary) -> None:
        summary.ended_at = summary.ended_at or time.time()
        summary.status = summary.status if summary.status != "running" else "completed"
        self._c.execute(
            "UPDATE planner_runs SET ended_at=?, status=?, stop_reason=?, generated=?, executed=?,"
            " disproven=?, inconclusive=?, verified=?, requests_used=?, findings_created=?"
            " WHERE run_id=?",
            (summary.ended_at, summary.status, summary.stop_reason, summary.generated,
             summary.executed, summary.disproven, summary.inconclusive, summary.verified,
             summary.requests_used, summary.findings_created, summary.run_id),
        )
        self._c.commit()

    def get_run(self, run_id: str) -> dict | None:
        r = self._c.execute("SELECT * FROM planner_runs WHERE run_id=?", (run_id,)).fetchone()
        return dict(r) if r else None

    def list_runs(self, program: str | None = None) -> list[dict]:
        if program:
            rows = self._c.execute(
                "SELECT * FROM planner_runs WHERE program=? ORDER BY started_at DESC", (program,)
            ).fetchall()
        else:
            rows = self._c.execute("SELECT * FROM planner_runs ORDER BY started_at DESC").fetchall()
        return [dict(r) for r in rows]

    # --- hypotheses -----------------------------------------------------------

    def save_hypothesis(self, run_id: str, program: str, ph: PlannedHypothesis) -> None:
        now = time.time()
        exists = self._c.execute(
            "SELECT 1 FROM planner_hypotheses WHERE run_id=? AND id=?", (run_id, ph.hypothesis_id)
        ).fetchone()
        if exists:
            self._c.execute(
                "UPDATE planner_hypotheses SET status=?, status_reason=?, prereq_identities=?,"
                " storage_hypothesis_id=?, finding_id=?, updated_at=? WHERE run_id=? AND id=?",
                (ph.status.value, ph.status_reason, ph.prereq_identities,
                 ph.storage_hypothesis_id, ph.finding_id, now, run_id, ph.hypothesis_id),
            )
        else:
            self._c.execute(
                "INSERT INTO planner_hypotheses(id, run_id, program, plan_key, vulnerability_class,"
                " target, endpoint, method, reasoning, required_auth_context, required_inputs,"
                " expected_signal, priority_score, priority_band, status, status_reason,"
                " prereq_identities, parent_observation, storage_hypothesis_id, finding_id,"
                " created_at, updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ph.hypothesis_id, run_id, program, ph.plan_key,
                 ph.vulnerability_class, ph.target, ph.endpoint, ph.method, ph.reasoning,
                 json.dumps(ph.required_auth_context), json.dumps(ph.required_inputs),
                 ph.expected_signal, ph.priority_score, ph.priority.value, ph.status.value,
                 ph.status_reason, ph.prereq_identities,
                 ph.parent_observation, ph.storage_hypothesis_id, ph.finding_id, now, now),
            )
        self._c.commit()

    def known_plan_keys(self, program: str, *, current_identities: int | None = None) -> set[str]:
        """Plan keys that must NOT be regenerated.

        * VERIFIED and DISPROVEN keys are always suppressed: that exact candidate was
          already evaluated in a prior round, so it is not re-tested (this stops the
          budget churn from regenerating disproven candidates every round). Materially
          new evidence changes the ``plan_key`` (it encodes class+endpoint+object-refs)
          and so is re-planned regardless — the suppression is per exact candidate.
        * INCONCLUSIVE keys are suppressed while their prerequisite is unchanged. The
          prerequisite tracked here is the number of authorized identities: an
          INCONCLUSIVE candidate is re-eligible only once MORE identities are available
          than when it was evaluated (``current_identities`` exceeds the stored
          ``prereq_identities``).
        """
        keys = {
            r["plan_key"] for r in self._c.execute(
                "SELECT DISTINCT plan_key FROM planner_hypotheses WHERE program=?"
                " AND status IN ('verified','disproven')",
                (program,),
            ).fetchall()
        }
        for r in self._c.execute(
            "SELECT plan_key, prereq_identities FROM planner_hypotheses"
            " WHERE program=? AND status=?", (program, "inconclusive"),
        ).fetchall():
            if current_identities is None or current_identities <= r["prereq_identities"]:
                keys.add(r["plan_key"])           # prerequisite unchanged -> suppress
        return keys

    def inconclusive_hypotheses(self, program: str) -> list[dict]:
        """INCONCLUSIVE candidates preserved for HUMAN review (latest row per key)."""
        rows = self._c.execute(
            "SELECT * FROM planner_hypotheses WHERE program=? AND status='inconclusive'"
            " ORDER BY updated_at DESC", (program,),
        ).fetchall()
        seen: dict[str, dict] = {}
        for r in rows:
            seen.setdefault(r["plan_key"], dict(r))
        return list(seen.values())

    def hypotheses_for_run(self, run_id: str) -> list[dict]:
        rows = self._c.execute(
            "SELECT * FROM planner_hypotheses WHERE run_id=? ORDER BY priority_score DESC, plan_key",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]
