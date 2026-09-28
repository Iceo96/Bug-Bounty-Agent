"""The autonomous (but bounded and deterministic) test-execution loop.

    OBSERVE -> GENERATE HYPOTHESES -> PRIORITIZE -> EXECUTE
            -> RECORD OBSERVATION -> VERIFY -> UPDATE GRAPH -> REPLAN

The runner never performs HTTP itself. It translates a planned hypothesis into a
storage ``Hypothesis`` and hands it to the existing ``VerificationEngine``, which
invokes the registered detector/verifier. Only that engine, backed by real
captured evidence, can create a finding. The loop stops when no useful
hypotheses remain, the budget is exhausted, program rules forbid the next test,
or the operator stops it.
"""

from __future__ import annotations

import time
from typing import Callable

# Import for its side effect: registers the IDOR/access-control detector+verifier
# in the verification registry so the engine can find it during execution.
import bbagent.detectors.idor  # noqa: F401
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.logging_config import get_logger
from bbagent.planner.capabilities import CapabilityRegistry, default_capabilities
from bbagent.planner.history import RunStore
from bbagent.planner.models import PlannedHypothesis, PlanStatus, RunSummary, TestBudget
from bbagent.planner.planner import DeterministicPlanner, PlanContext, Planner
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import Hypothesis, Observation
from bbagent.urlutils import templatize_path, host_port
from bbagent.verification.dedup import compute_dedup_key
from bbagent.verification.engine import VerificationEngine

log = get_logger(__name__)


class PlanRunner:
    def __init__(
        self,
        program: ProgramManager,
        db: Database,
        surface,
        http: AuthorizedHTTPClient | None = None,
        evidence: EvidenceStore | None = None,
        *,
        planner: Planner | None = None,
        capabilities: CapabilityRegistry | None = None,
        budget: TestBudget | None = None,
        run_store: RunStore | None = None,
    ):
        self.program = program
        self.db = db
        self.surface = surface
        # http + evidence are only required for real execution (not plan/dry-run).
        self.http = http
        self.evidence = evidence
        self.planner = planner or DeterministicPlanner()
        self.capabilities = capabilities or default_capabilities()
        self.budget = budget or TestBudget()
        self.runs = run_store or RunStore(db)
        self.engine = (
            VerificationEngine(program, db, http, evidence)
            if http is not None and evidence is not None else None
        )

    # --- planning only (no execution) ----------------------------------------

    def generate(self) -> list[PlannedHypothesis]:
        """OBSERVE + GENERATE + PRIORITIZE against the current graph snapshot."""
        ctx = PlanContext(
            program=self.program, surface=self.surface, capabilities=self.capabilities,
            known_plan_keys=self.runs.known_plan_keys(self.program.name),
        )
        return self.planner.plan(ctx)

    async def run(
        self, *, dry_run: bool = False, stop: Callable[[], bool] | None = None,
    ) -> RunSummary:
        stop = stop or (lambda: False)
        summary = self.runs.start_run(self.program.name, self.budget, dry_run=dry_run)
        started = time.monotonic()

        done_keys: set[str] = set()
        per_endpoint: dict[str, int] = {}
        per_host: dict[str, int] = {}

        # DRY RUN: generate + persist the queue, execute nothing.
        if dry_run:
            queue = self.generate()
            for ph in queue:
                self.runs.save_hypothesis(summary.run_id, self.program.name, ph)
            summary.generated = len(queue)
            summary.stop_reason = "dry-run (no execution)"
            summary.status = "completed"
            self.runs.finish_run(summary)
            self._dry_queue = queue  # exposed for the CLI/tests
            return summary

        # Real execution requires the scope-enforcing client + evidence store.
        if self.http is None or self.engine is None or self.evidence is None:
            raise RuntimeError("PlanRunner.run requires http + evidence for non-dry-run execution")
        base_requests = self.http.request_count

        # EXECUTION LOOP.
        while True:
            if stop():
                summary.stop_reason = "operator stop"
                break
            if (time.monotonic() - started) > self.budget.max_runtime_seconds:
                summary.stop_reason = "runtime budget exhausted"
                break
            if (self.http.request_count - base_requests) >= self.budget.max_requests:
                summary.stop_reason = "request budget exhausted"
                break

            # OBSERVE / GENERATE / PRIORITIZE (re-plan each iteration).
            known = self.runs.known_plan_keys(self.program.name) | done_keys
            ctx = PlanContext(self.program, self.surface, self.capabilities, known)
            queue = [h for h in self.planner.plan(ctx) if h.plan_key not in done_keys]
            if not queue:
                summary.stop_reason = summary.stop_reason or "no useful hypotheses remain"
                break

            ph = queue[0]
            summary.generated += 1
            done_keys.add(ph.plan_key)  # each plan_key attempted at most once per run

            # Program-rule gate: never execute an active (state-changing) test
            # unless the program explicitly allows active testing.
            if self._is_active(ph) and not self.program.config.restrictions.allow_active_testing:
                ph.status = PlanStatus.SKIPPED
                self.runs.save_hypothesis(summary.run_id, self.program.name, ph)
                continue

            # Cross-run dedup: if a finding already exists for this signature, skip.
            dedup = compute_dedup_key(ph.vulnerability_class, ph.endpoint, ph.method)
            if self.db.find_findings_by_dedup(self.program.name, dedup):
                ph.status = PlanStatus.DUPLICATE
                self.runs.save_hypothesis(summary.run_id, self.program.name, ph)
                continue

            # Per-endpoint / per-host budget.
            ep_key = templatize_path(ph.endpoint)
            host = host_port(ph.endpoint)
            if per_endpoint.get(ep_key, 0) >= self.budget.max_tests_per_endpoint:
                ph.status = PlanStatus.SKIPPED
                self.runs.save_hypothesis(summary.run_id, self.program.name, ph)
                continue
            if per_host.get(host, 0) >= self.budget.max_tests_per_host:
                summary.stop_reason = "per-host test budget exhausted"
                self.runs.save_hypothesis(summary.run_id, self.program.name, ph)
                break

            per_endpoint[ep_key] = per_endpoint.get(ep_key, 0) + 1
            per_host[host] = per_host.get(host, 0) + 1

            await self._execute(ph, summary)
            self.runs.save_hypothesis(summary.run_id, self.program.name, ph)

        summary.requests_used = self.http.request_count - base_requests
        self.runs.finish_run(summary)
        log.info("planner.run_done", **summary.to_dict())
        return summary

    # --- execution ------------------------------------------------------------

    def _is_active(self, ph: PlannedHypothesis) -> bool:
        for cap in self.capabilities.all():
            if cap.vuln_class == ph.vulnerability_class:
                return cap.active
        return ph.method.upper() not in ("GET", "HEAD", "OPTIONS")

    async def _execute(self, ph: PlannedHypothesis, summary: RunSummary) -> None:
        """EXECUTE one hypothesis through the verification engine; record results."""
        storage_hyp = Hypothesis(
            program=self.program.name,
            vuln_type=ph.vulnerability_class,
            title=f"{ph.vulnerability_class.upper()} candidate at {ph.endpoint}",
            rationale=ph.reasoning,
            target_url=ph.endpoint,
            detector="planner",
        )
        self.db.add_hypothesis(storage_hyp)
        ph.storage_hypothesis_id = storage_hyp.id
        summary.executed += 1

        try:
            finding = await self.engine.process(storage_hyp)
        except Exception as exc:  # noqa: BLE001 — a failed test is inconclusive, not fatal
            ph.status = PlanStatus.INCONCLUSIVE
            summary.inconclusive += 1
            self._record_observation(ph, outcome="inconclusive", detail=str(exc))
            log.warning("planner.execute_error", plan=ph.hypothesis_id, error=str(exc))
            return

        # VERIFY feedback + UPDATE GRAPH (record the outcome as an observation).
        if finding is not None:
            ph.status = PlanStatus.VERIFIED
            ph.finding_id = finding.id
            summary.verified += 1
            summary.findings_created += 1
            self._record_observation(ph, outcome="verified", detail=finding.id)
        else:
            ph.status = PlanStatus.DISPROVEN
            summary.disproven += 1
            self._record_observation(ph, outcome="disproven", detail="verification returned no finding")

    def _record_observation(self, ph: PlannedHypothesis, *, outcome: str, detail: str) -> None:
        self.db.add_observation(Observation(
            program=self.program.name,
            kind="test_result",
            summary=f"{ph.vulnerability_class} {outcome} at {ph.endpoint}",
            data={
                "plan_key": ph.plan_key, "outcome": outcome, "detail": detail,
                "endpoint": ph.endpoint, "vulnerability_class": ph.vulnerability_class,
            },
        ))
