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

from bbagent.http.client import AuthorizedHTTPClient
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

    @property
    def verified_classes(self) -> set[str]:
        return {v.vuln_class for v in self.verified}

    def render(self) -> str:
        lines = [f"# Autonomous run: {self.program}",
                 f"recon hosts: {', '.join(self.recon_hosts) or '-'}",
                 f"manifests allowed: {len(self.manifests_allowed)}  denied: {len(self.manifests_denied)}",
                 f"endpoints discovered: {self.endpoints_discovered}",
                 f"hypotheses: {self.hypotheses_generated}",
                 f"verified findings: {len(self.verified)} "
                 f"[{', '.join(sorted(self.verified_classes)) or '-'}]"]
        for v in self.verified:
            lines.append(f"  - {v.vuln_class}: {v.endpoint} -> {v.review_status} ({v.finding_id})")
        if self.run:
            lines.append(f"run: executed={self.run.executed} verified={self.run.verified} "
                         f"disproven={self.run.disproven} requests={self.run.requests_used}")
        lines.append("All verified findings await HUMAN review. The agent did not approve or submit.")
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
) -> AutoRunReport:
    """Perform one autonomous, policy-governed run and return a structured report.

    ``transport`` is an optional httpx transport for local simulation (e.g. a
    MockTransport). It is passed straight to the scope-enforcing HTTP client, so
    the full pipeline runs without any real network. Production leaves it None.
    """
    surface = SurfaceStore(db)
    review = ReviewStore(db, evidence)
    report = AutoRunReport(program=program.name)

    async with AuthorizedHTTPClient(program.config, transport=transport) as http:
        policy = ProgramPolicyEngine(program)
        router = ToolRouter(default_tools(), policy, ToolContext(program=program, http=http))

        # 1) Read rules implicitly (program) + policy-gated local recon.
        recon = await router.dispatch(ToolRequest(tool="recon", arguments={"action": "scope_hosts"}))
        if recon.success:
            report.recon_hosts = recon.sanitized.get("hosts", [])

        # 2) Policy-gated surface discovery: each manifest must be ALLOWed first.
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
            await mapper.map_manifest(manifest)

        report.endpoints_discovered = len(surface.list_endpoints(program.name))

        # 3-7) Plan → execute the four detectors → verify → immutable evidence.
        runner = PlanRunner(program, db, surface, http, evidence, planner=planner, budget=budget)
        summary = await runner.run()
        report.run = summary
        report.hypotheses_generated = summary.generated

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
