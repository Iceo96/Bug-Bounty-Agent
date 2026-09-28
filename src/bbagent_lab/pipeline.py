"""End-to-end pipeline glue for the lab.

Wires together the *existing* agent components without bypassing any of them:
recon discovery -> detector -> verification engine -> immutable evidence -> findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import bbagent.detectors.idor  # noqa: F401 — registers the IDOR detector/verifier
from bbagent.detectors.base import DetectionContext
from bbagent.detectors.idor import IDORDetector
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.program.manager import ProgramManager
from bbagent.recon import discover_from_manifest
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import Finding, Hypothesis, Observation
from bbagent.verification.engine import VerificationEngine


@dataclass
class PipelineResult:
    observations: list[Observation] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


async def run_pipeline(
    program: ProgramManager,
    db: Database,
    evidence: EvidenceStore,
    base_url: str,
) -> PipelineResult:
    """Run discovery -> detect -> verify against a running lab at ``base_url``."""
    result = PipelineResult()
    manifest_url = base_url.rstrip("/") + "/"

    async with AuthorizedHTTPClient(program.config) as http:
        # 1) Discovery (scope-enforced).
        result.observations = await discover_from_manifest(http, program, db, manifest_url)

        # 2) Detection -> hypotheses.
        detector = IDORDetector()
        ctx = DetectionContext(program=program, db=db, http=http, observations=result.observations)
        hypotheses = await detector.detect(ctx)

        # 3) Verification -> findings (evidence stored immutably by the engine).
        engine = VerificationEngine(program, db, http, evidence)
        for hyp in hypotheses:
            db.add_hypothesis(hyp)
            result.hypotheses.append(hyp)
            finding = await engine.process(hyp)
            if finding is not None:
                result.findings.append(finding)

    return result
