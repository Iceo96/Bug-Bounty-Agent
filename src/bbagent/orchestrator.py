"""Autonomous run orchestrator.

Ties the whole pipeline together for a single, bounded, policy-governed run:

  read program rules
    → policy-gated recon (via the tool router)
    → policy-gated surface discovery (each manifest ALLOW-checked before mapping)
    → plan + prioritize (deterministic; optional LLM reorder)
    → execute the four existing detectors through the verification engine
    → immutable evidence
    → generate reports + enqueue verified findings for HUMAN review

The orchestrator never approves or submits. Recon and discovery pass through the
Program Policy Engine; detector verification runs on the same scope/rate/budget-
enforced AuthorizedHTTPClient. It adds no new detectors and no new tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from bbagent.http.client import AuthorizedHTTPClient, RequestBlocked, RunBudget
from bbagent.logging_config import get_logger
from bbagent.planner import PlanRunner, Planner, RunSummary, TestBudget
from bbagent.policy import ProgramPolicyEngine
from bbagent.program.manager import ProgramManager
from bbagent.recon import AttackSurfaceMapper
from bbagent.report import generate_report
from bbagent.reviewstore import ReviewStore
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import FindingStatus
from bbagent.surface.store import SurfaceStore
from bbagent.tools import ToolContext, ToolRequest, ToolRouter, default_tools

log = get_logger(__name__)


@dataclass
class VerifiedFinding:
    finding_id: str
    vuln_class: str
    endpoint: str
    review_status: str
    report_excerpt: str


@dataclass
class AutoRunReport:
    program: str
    recon_hosts: list[str] = field(default_factory=list)
    manifests_allowed: list[str] = field(default_factory=list)
    manifests_denied: list[str] = field(default_factory=list)
    endpoints_discovered: int = 0
    hypotheses_generated: int = 0
    verified: list[VerifiedFinding] = field(default_factory=list)
    run: RunSummary | None = None
    request_budget_max: int = 0
    request_budget_used: int = 0
    # class -> ALLOWED/FORBIDDEN/UNKNOWN (capability matrix)
    capability_matrix: dict = field(default_factory=dict)
    # class -> number of hypotheses generated (planned)
    hypotheses_by_class: dict = field(default_factory=dict)
    simulation: bool = False

    @property
    def verified_classes(self) -> set[str]:
        return {v.vuln_class for v in self.verified}

    @property
    def blocked_classes(self) -> list[str]:
        return sorted(c for c, s in self.capability_matrix.items() if s != "ALLOWED")

    @property
    def enabled_classes(self) -> list[str]:
        return sorted(c for c, s in self.capability_matrix.items() if s == "ALLOWED")

    def render(self) -> str:
        lines = ["# Autonomous DRY-RUN report" if self.simulation else "# Autonomous run",
                 f"program:              {self.program}"]
        if self.simulation:
            lines.append("mode:                 SIMULATION (local mock; NOT a real target)")
        lines += [
            f"discovered assets:    {', '.join(self.recon_hosts) or '-'}",
            f"discovered endpoints: {self.endpoints_discovered}",
            f"capability matrix:    " + ", ".join(f"{c}={s}" for c, s in sorted(self.capability_matrix.items())),
            f"enabled classes:      {', '.join(self.enabled_classes) or '(none)'}",
            f"blocked classes:      {', '.join(self.blocked_classes) or '(none)'}",
            f"hypotheses generated: {self.hypotheses_generated} "
            + "{" + ", ".join(f"{c}:{n}" for c, n in sorted(self.hypotheses_by_class.items())) + "}",
        ]
        if self.run:
            lines.append(f"outcomes:             verified={self.run.verified} "
                         f"disproven={self.run.disproven} inconclusive={self.run.inconclusive}")
        lines.append(f"verified (candidate findings, NOT confirmed real): {len(self.verified)} "
                     f"[{', '.join(sorted(self.verified_classes)) or '-'}]")
        for v in self.verified:
            lines.append(f"  - {v.vuln_class}: {v.endpoint} -> {v.review_status}")
        lines.append(f"eligible-if-live:     {', '.join(self.enabled_classes) or '(none)'} "
                     f"(only ALLOWED classes; verification still policy-gated)")
        lines.append(f"budget:               {self.request_budget_used}/{self.request_budget_max} requests used")
        lines.append("final status:         hypotheses are NOT findings; verified candidates await HUMAN "
                     "review; the agent never approves or submits.")
        return "\n".join(lines)


async def autonomous_run(
    program: ProgramManager,
    db: Database,
    evidence: EvidenceStore,
    *,
    manifests: list[str],
    planner: Planner | None = None,
    budget: TestBudget | None = None,
    transport=None,
    run_budget: RunBudget | None = None,
) -> AutoRunReport:
    """Perform one autonomous, policy-governed run and return a structured report.

    ``transport`` is an optional httpx transport for local simulation (e.g. a
    MockTransport). ``run_budget`` is the single shared run-level request budget;
    when omitted it is created from ``program.request_budget.total`` (or a high
    default). Recon, discovery, tool execution, and verification all draw from it.
    """
    surface = SurfaceStore(db)
    review = ReviewStore(db, evidence)
    report = AutoRunReport(program=program.name)
    report.simulation = "SIMULATION" in program.name.upper() or transport is not None

    # ONE shared budget + ONE shared policy engine for the whole run.
    total = program.config.request_budget.total if program.config.request_budget else 100_000
    rb = run_budget or RunBudget(total)
    report.request_budget_max = rb.max_requests
    policy = ProgramPolicyEngine(program)

    async with AuthorizedHTTPClient(program.config, transport=transport, run_budget=rb) as http:
        router = ToolRouter(default_tools(), policy, ToolContext(program=program, http=http))

        # 1) Read rules implicitly (program) + policy-gated local recon.
        recon = await router.dispatch(ToolRequest(tool="recon", arguments={"action": "scope_hosts"}))
        if recon.success:
            report.recon_hosts = recon.sanitized.get("hosts", [])

        # 2) Policy-gated surface discovery: each manifest must be ALLOWed first.
        #    Discovery consumes the same shared budget and never expands scope.
        mapper = AttackSurfaceMapper(program, http, surface)
        for manifest in manifests:
            decision = policy.evaluate(
                ToolRequest(tool="http", arguments={"url": manifest, "method": "GET"}, target=manifest)
            )
            if not decision.allowed:
                report.manifests_denied.append(manifest)
                log.info("autorun.manifest_denied", url=manifest, reason=decision.reason)
                continue
            report.manifests_allowed.append(manifest)
            try:
                await mapper.map_manifest(manifest)
            except RequestBlocked as exc:  # e.g. shared budget exhausted during discovery
                log.info("autorun.discovery_blocked", url=manifest, reason=str(exc))

        report.endpoints_discovered = len(surface.list_endpoints(program.name))

        # 3-7) Plan → execute the four detectors → verify → immutable evidence.
        #      The verification path shares the same policy engine AND client budget.
        runner = PlanRunner(program, db, surface, http, evidence, planner=planner,
                            budget=budget, policy=policy)
        summary = await runner.run()
        report.run = summary
        report.hypotheses_generated = summary.generated
        report.request_budget_used = rb.used

        # Capability matrix + per-class hypothesis counts for the dry-run report.
        from collections import Counter

        from bbagent.planner import build_capability_matrix
        from bbagent.planner.capabilities import default_capabilities

        report.capability_matrix = {
            r.vulnerability_class: r.status.value
            for r in build_capability_matrix(program, default_capabilities())
        }
        counts: Counter = Counter()
        for h in runner.runs.hypotheses_for_run(summary.run_id):
            counts[h["vulnerability_class"]] += 1
        report.hypotheses_by_class = dict(counts)

    # 8-9) Generate reports + enqueue verified findings for HUMAN review.
    for finding in db.list_findings(program.name):
        if finding.status is not FindingStatus.VERIFIED:
            continue
        item = review.submit_for_review(finding.id)          # -> READY_FOR_REVIEW
        excerpt = generate_report(finding, db, evidence).splitlines()[0]
        report.verified.append(VerifiedFinding(
            finding_id=finding.id, vuln_class=finding.vuln_type, endpoint=finding.endpoint,
            review_status=item.status, report_excerpt=excerpt,
        ))

    log.info("autorun.done", program=program.name, verified=len(report.verified),
             classes=sorted(report.verified_classes))
    return report
