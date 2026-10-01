"""The bounded, policy-governed Security Research Loop (implementation)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from bbagent.browser import (
    AutonomousExplorer, BrowserBackend, BrowserController, ExplorationLimits,
)
from bbagent.http.client import AuthorizedHTTPClient, RunBudget
from bbagent.logging_config import get_logger
from bbagent.orchestrator import VerifiedFinding
from bbagent.planner import PlanRunner, Planner, TestBudget
from bbagent.policy import ProgramPolicyEngine
from bbagent.program.manager import ProgramManager
from bbagent.report import generate_report
from bbagent.reviewstore import ReviewStore
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import FindingStatus
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore

log = get_logger(__name__)


def _idor_identities_are_profile_only(program: ProgramManager) -> bool:
    """True when the two IDOR identities are profile-based (own browser profile, no
    per-account HTTP credential) — the case that must use browser verification."""
    accts = program.config.test_accounts
    if len(accts) < 2:
        return False
    a, b = accts[0], accts[1]
    return bool(a.profile_dir_env and b.profile_dir_env
                and not a.secret_env and not b.secret_env)


@dataclass
class ResearchLimits:
    """Bounds on the whole research loop (every one terminates it)."""

    max_rounds: int = 3
    max_seconds: float = 120.0
    exploration: ExplorationLimits = field(default_factory=ExplorationLimits)
    test: TestBudget = field(default_factory=TestBudget)


@dataclass
class RoundResult:
    round: int
    endpoints_before: int
    endpoints_after: int
    explore_actions: int
    hypotheses_generated: int
    verified: int
    disproven: int
    inconclusive: int


@dataclass
class ResearchReport:
    program: str
    simulation: bool = False
    rounds_completed: int = 0
    endpoints_discovered: int = 0
    hypotheses_generated: int = 0
    verified: list[VerifiedFinding] = field(default_factory=list)
    rounds: list[RoundResult] = field(default_factory=list)
    request_budget_max: int = 0
    request_budget_used: int = 0
    stop_reason: str = ""

    @property
    def verified_classes(self) -> set[str]:
        return {v.vuln_class for v in self.verified}

    def render(self) -> str:
        lines = [
            "# Security Research Loop" + (" — SIMULATION" if self.simulation else ""),
            f"program:              {self.program}",
            f"rounds completed:     {self.rounds_completed}",
            f"endpoints discovered: {self.endpoints_discovered}",
            f"hypotheses generated: {self.hypotheses_generated}",
            f"verified (candidate findings, NOT confirmed real): {len(self.verified)} "
            f"[{', '.join(sorted(self.verified_classes)) or '-'}]",
        ]
        for v in self.verified:
            lines.append(f"  - {v.vuln_class}: {v.endpoint} -> {v.review_status}")
        for r in self.rounds:
            lines.append(
                f"  round {r.round}: endpoints {r.endpoints_before}->{r.endpoints_after}, "
                f"explore_actions={r.explore_actions}, generated={r.hypotheses_generated}, "
                f"verified={r.verified}, disproven={r.disproven}, inconclusive={r.inconclusive}")
        lines.append(f"budget:               {self.request_budget_used}/{self.request_budget_max} requests used")
        lines.append(f"stop reason:          {self.stop_reason}")
        lines.append("final status:         hypotheses are NOT findings; verified candidates await "
                     "HUMAN review; the agent never approves or submits.")
        return "\n".join(lines)


async def run_security_research(
    program: ProgramManager,
    db: Database,
    evidence: EvidenceStore,
    *,
    browser_backend: BrowserBackend,
    seed_urls: list[str],
    transport=None,
    run_budget: RunBudget | None = None,
    planner: Planner | None = None,
    chooser=None,
    identity: str = "researcher",
    limits: ResearchLimits | None = None,
    live: bool = False,
    browser_idor=None,
) -> ResearchReport:
    """Run the bounded explore<->test research loop and return a structured report.

    ``browser_backend`` drives discovery (passive observation). ``transport`` is an
    optional httpx transport for the ACTIVE verification client (e.g. a loopback
    lab); active testing always flows through PolicyGatedHTTP on that client.

    ``browser_idor`` is the browser-profile IDOR verification mode threaded into the
    verification engine. When not supplied and the program's IDOR identities are
    profile-only, one is constructed (a real ``BrowserIdentityFetcher``; it opens no
    browser until a verification actually runs) so profile-only IDOR candidates are
    verified via their OWN browser contexts and NEVER fall back to shared HTTP
    credentials. ``live`` reflects the caller's resolved live gate (--live AND
    BBAGENT_BROWSER_LIVE=1).
    """
    limits = limits or ResearchLimits()
    surface = SurfaceStore(db)
    review = ReviewStore(db, evidence)
    report = ResearchReport(program=program.name)
    report.simulation = "SIMULATION" in program.name.upper() or transport is not None

    # ONE shared run budget + ONE shared policy engine for the whole loop.
    total = program.config.request_budget.total if program.config.request_budget else 100_000
    rb = run_budget or RunBudget(total)
    report.request_budget_max = rb.max_requests
    policy = ProgramPolicyEngine(program)

    started = time.monotonic()
    async with AuthorizedHTTPClient(program.config, transport=transport, run_budget=rb) as http:
        controller = BrowserController(
            program, surface, browser_backend,
            default_identity=AuthIdentity.IDENTITY_A,
            identity_map={identity: AuthIdentity.IDENTITY_A},
        )
        explorer = AutonomousExplorer(controller, surface, chooser=chooser,
                                      limits=limits.exploration)

        # Wire the browser-profile IDOR mode. If the program's IDOR identities are
        # profile-only and no mode was injected, construct one. A real
        # BrowserIdentityFetcher is built only when the live gate is open (it opens no
        # browser until a verification actually runs). The engine uses this mode for
        # profile-only IDOR; without a fetcher such candidates return INCONCLUSIVE —
        # they NEVER fall back to shared-credential HTTP verification.
        if browser_idor is None and _idor_identities_are_profile_only(program):
            from bbagent.verification.browser_idor import BrowserIDORMode, BrowserIdentityFetcher
            fetcher = None
            if live:
                try:
                    fetcher = BrowserIdentityFetcher(program)
                except Exception as exc:  # noqa: BLE001 - unresolved/shared profiles
                    log.info("research.browser_idor_fetcher_unavailable", error=str(exc))
            browser_idor = BrowserIDORMode(enabled=True, live=live, fetcher=fetcher)

        # PlanRunner owns the existing plan -> policy -> PolicyGatedHTTP -> verify ->
        # evidence pipeline; it shares the SAME policy engine and client budget.
        runner = PlanRunner(program, db, surface, http, evidence,
                            planner=planner, budget=limits.test, policy=policy,
                            browser_idor=browser_idor)

        for rnd in range(1, limits.max_rounds + 1):
            if time.monotonic() - started >= limits.max_seconds:
                report.stop_reason = "max_seconds reached"
                break
            if rb.remaining() <= 0:
                report.stop_reason = "request budget exhausted"
                break

            before = len(surface.list_endpoints(program.name))

            # 1) EXPLORE: discover/extend attack surface via the browser.
            explore_summary = await explorer.run(seed_urls)
            after = len(surface.list_endpoints(program.name))

            # 2) TEST: generate -> prioritize -> POLICY GATE -> PolicyGatedHTTP ->
            #    verify -> evidence. (Only ALLOWED classes; every request gated.)
            run_summary = await runner.run()

            report.rounds.append(RoundResult(
                round=rnd, endpoints_before=before, endpoints_after=after,
                explore_actions=explore_summary.actions_performed,
                hypotheses_generated=run_summary.generated,
                verified=run_summary.verified, disproven=run_summary.disproven,
                inconclusive=run_summary.inconclusive,
            ))
            report.rounds_completed = rnd
            report.hypotheses_generated += run_summary.generated

            # 3) RETURN TO EXPLORATION WHEN USEFUL: stop once a round neither grew
            #    the surface nor produced any new hypotheses to test.
            if after == before and run_summary.generated == 0:
                report.stop_reason = "surface and hypotheses exhausted"
                break
        else:
            report.stop_reason = report.stop_reason or "max_rounds reached"

        report.endpoints_discovered = len(surface.list_endpoints(program.name))
        report.request_budget_used = rb.used

    # Enqueue every VERIFIED finding for HUMAN review (agent never approves/submits).
    for finding in db.list_findings(program.name):
        if finding.status is not FindingStatus.VERIFIED:
            continue
        item = review.submit_for_review(finding.id)
        excerpt = generate_report(finding, db, evidence).splitlines()[0]
        report.verified.append(VerifiedFinding(
            finding_id=finding.id, vuln_class=finding.vuln_type, endpoint=finding.endpoint,
            review_status=item.status, report_excerpt=excerpt,
        ))

    if not report.stop_reason:
        report.stop_reason = "completed"
    log.info("research.done", program=program.name, rounds=report.rounds_completed,
             verified=len(report.verified), classes=sorted(report.verified_classes))
    return report
