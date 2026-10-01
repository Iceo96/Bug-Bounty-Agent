"""Secondary fix: a DISPROVEN candidate (same plan_key) is not re-tested in later
research rounds; a materially different plan_key (new evidence) is still eligible."""

from __future__ import annotations

from bbagent.planner.history import RunStore
from bbagent.planner.models import PlannedHypothesis, PlanStatus, TestBudget
from bbagent.storage.db import Database


def test_disproven_is_suppressed_but_new_evidence_is_not():
    db = Database(":memory:")
    runs = RunStore(db)
    run = runs.start_run("p", TestBudget())
    ph = PlannedHypothesis(target="h", endpoint="https://x/y", method="GET",
                           vulnerability_class="idor", reasoning="r", plan_key="DKEY",
                           priority_score=10, status=PlanStatus.DISPROVEN)
    runs.save_hypothesis(run.run_id, "p", ph)

    keys = runs.known_plan_keys("p", current_identities=2)
    assert "DKEY" in keys            # disproven -> not regenerated in a later round
    assert "NEWKEY" not in keys      # a different plan_key (new evidence) is NOT suppressed
    db.close()
