"""Verification engine — the gate between a hypothesis and a finding.

Lifecycle enforced here:

    proposed -> investigating -> verifying -> verified (Finding) | discarded

Invariants:
* A finding is created ONLY from a VerificationResult whose ``verified`` is True.
* A verified result MUST carry at least one real HTTP exchange; otherwise the
  engine rejects it and discards the hypothesis. This makes it structurally
  impossible to produce a finding without reproducible evidence.
* Every cited exchange is written to the immutable evidence store, and its id is
  attached to the finding.
* Deduplication runs before persistence; duplicates are discarded.
"""

from __future__ import annotations

from bbagent.detectors.base import (
    VerificationContext,
    VerificationResult,
    Verifier,
    registry,
)
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.logging_config import get_logger
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import (
    Finding,
    FindingStatus,
    Hypothesis,
    HypothesisStatus,
)
from bbagent.verification.dedup import compute_dedup_key

log = get_logger(__name__)


class VerificationError(Exception):
    pass


class VerificationEngine:
    def __init__(
        self,
        program: ProgramManager,
        db: Database,
        http: AuthorizedHTTPClient,
        evidence: EvidenceStore,
        *,
        policy=None,
    ):
        from bbagent.policy.engine import ProgramPolicyEngine
        from bbagent.tools.gateway import PolicyGatedHTTP

        self._program = program
        self._db = db
        self._http = http
        self._evidence = evidence
        # Every verification request is policy-gated through this single path.
        self._policy = policy or (ProgramPolicyEngine(program) if http is not None else None)
        self._gateway = (
            PolicyGatedHTTP(program, self._policy, http) if http is not None else None
        )

    async def process(self, hypothesis: Hypothesis) -> Finding | None:
        """Run a hypothesis through verification. Returns a Finding or None."""
        self._db.set_hypothesis_status(hypothesis.id, HypothesisStatus.INVESTIGATING)

        verifier_cls = registry.verifier_for(hypothesis.vuln_type)
        if verifier_cls is None:
            log.info("verify.no_verifier", vuln_type=hypothesis.vuln_type, hyp=hypothesis.id)
            self._db.set_hypothesis_status(hypothesis.id, HypothesisStatus.DISCARDED)
            return None

        verifier: Verifier = verifier_cls()
        self._db.set_hypothesis_status(hypothesis.id, HypothesisStatus.VERIFYING)
        # Gate every verification request for this hypothesis's vulnerability class.
        if self._gateway is not None:
            self._gateway.vuln_class = hypothesis.vuln_type
        ctx = VerificationContext(
            program=self._program, db=self._db, http=self._gateway or self._http,
            hypothesis=hypothesis,
        )
        result = await verifier.verify(ctx)

        if not self._result_is_valid(result):
            log.info("verify.discarded", hyp=hypothesis.id, reason=result.reason)
            self._db.set_hypothesis_status(hypothesis.id, HypothesisStatus.DISCARDED)
            return None

        return self._promote(hypothesis, result)

    def _result_is_valid(self, result: VerificationResult) -> bool:
        """A verified result must be backed by real evidence."""
        if not result.verified:
            return False
        if not result.exchanges:
            # verified=True but no evidence => reject. Evidence is mandatory.
            log.warning("verify.rejected_no_evidence")
            return False
        return True

    def _promote(self, hypothesis: Hypothesis, result: VerificationResult) -> Finding | None:
        dedup_key = result.dedup_key or compute_dedup_key(
            hypothesis.vuln_type, hypothesis.target_url,
            result.exchanges[0].method if result.exchanges else "GET",
        )

        # Deduplicate against existing findings for this program.
        if self._db.find_findings_by_dedup(hypothesis.program, dedup_key):
            log.info("verify.duplicate", hyp=hypothesis.id, dedup_key=dedup_key)
            self._db.set_hypothesis_status(hypothesis.id, HypothesisStatus.DISCARDED)
            return None

        first = result.exchanges[0]
        finding = Finding(
            program=hypothesis.program,
            hypothesis_id=hypothesis.id,
            vuln_type=hypothesis.vuln_type,
            title=hypothesis.title,
            affected_asset=_host(first.url),
            endpoint=first.url,
            http_method=first.method,
            test_identity=result.test_identity,
            expected_behavior=result.expected_behavior,
            actual_behavior=result.actual_behavior,
            impact=result.impact,
            reproduction=result.reproduction,
            status=FindingStatus.VERIFIED,
            dedup_key=dedup_key,
        )
        self._db.add_finding(finding)

        # Persist every cited exchange to the immutable evidence store.
        evidence_ids: list[str] = []
        for ex in result.exchanges:
            req_rec, resp_rec = self._evidence.store_exchange(ex, finding_id=finding.id)
            evidence_ids.extend([req_rec.id, resp_rec.id])
        self._db.attach_finding_evidence(finding.id, evidence_ids)

        self._db.set_hypothesis_status(hypothesis.id, HypothesisStatus.VERIFIED)
        log.info("verify.finding", finding=finding.id, vuln_type=finding.vuln_type, evidence=len(evidence_ids))
        return self._db.get_finding(finding.id)


def _host(url: str) -> str:
    from urllib.parse import urlsplit

    return (urlsplit(url).hostname or url).lower()
