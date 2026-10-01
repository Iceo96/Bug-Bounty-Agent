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
        browser_idor=None,
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
        # Optional, EXPLICIT browser-profile IDOR verification mode (separate from the
        # registered HTTP IDOR verifier, which is never replaced or bypassed).
        self._browser_idor = browser_idor

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

        mode = self._browser_idor
        if hypothesis.vuln_type == "idor" and self._idor_is_profile_only():
            # PROFILE-ONLY IDOR identities cannot be driven by the HTTP client (they
            # have no per-account credential; the client would inject the single
            # program-level session for BOTH, i.e. an A-vs-A test). There is NO silent
            # fallback: use the browser-profile verifier, or return INCONCLUSIVE.
            if mode is not None and mode.enabled:
                result = await self._verify_browser_idor(hypothesis)
            else:
                result = VerificationResult(
                    verified=False, inconclusive=True,
                    reason=("INCONCLUSIVE: IDOR identities are profile-only (separate browser "
                            "profiles); browser-profile verification is required and HTTP "
                            "verification with shared program credentials is refused "
                            "(no silent fallback)"))
        elif (mode is not None and mode.enabled
              and mode.applies_to(self._program, hypothesis)):
            result = await self._verify_browser_idor(hypothesis)
        else:
            # Gate every verification request for this hypothesis's vulnerability class.
            if self._gateway is not None:
                self._gateway.vuln_class = hypothesis.vuln_type
            ctx = VerificationContext(
                program=self._program, db=self._db, http=self._gateway or self._http,
                hypothesis=hypothesis,
            )
            result = await verifier.verify(ctx)

        # INCONCLUSIVE: a prerequisite was missing (e.g. a second authorized
        # identity). Preserve the state + reason; do NOT mark verified or disproven,
        # and do NOT discard. The candidate remains available for human review.
        if not result.verified and getattr(result, "inconclusive", False):
            self._db.set_hypothesis_status(hypothesis.id, HypothesisStatus.INCONCLUSIVE)
            # Surface the reason to the caller via the in-memory hypothesis object.
            try:
                hypothesis.inconclusive_reason = result.reason  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001 - best-effort annotation only
                pass
            self._record_verification_debug(hypothesis, result, outcome="inconclusive")
            log.info("verify.inconclusive", hyp=hypothesis.id, reason=result.reason)
            return None

        if not self._result_is_valid(result):
            log.info("verify.discarded", hyp=hypothesis.id, reason=result.reason)
            self._record_verification_debug(hypothesis, result, outcome="disproven")
            self._db.set_hypothesis_status(hypothesis.id, HypothesisStatus.DISCARDED)
            return None

        return self._promote(hypothesis, result)

    def _idor_is_profile_only(self) -> bool:
        """True when the two identities an IDOR test would use are profile-based
        (own browser profile, NO per-account HTTP credential) — meaning the HTTP
        verifier cannot distinguish them and must never be used."""
        accts = self._program.config.test_accounts
        if len(accts) < 2:
            return False
        a, b = accts[0], accts[1]
        return bool(a.profile_dir_env and b.profile_dir_env
                    and not a.secret_env and not b.secret_env)

    async def _verify_browser_idor(self, hypothesis: Hypothesis) -> VerificationResult:
        """Browser-profile two-identity IDOR path. Gated; fail-closed; zero requests
        unless the live gate is open AND two DISTINCT profiles resolve. Never falls
        back to HTTP/shared credentials. Produces only a CANDIDATE result — promotion
        (evidence + dedup) and human review remain the engine's job."""
        from bbagent.http.client import RequestBlocked
        from bbagent.verification.browser_idor import (
            PolicyGatedFetcher, verify_idor_two_identity,
        )

        mode = self._browser_idor
        if not mode.gate_open():
            return VerificationResult(
                verified=False, inconclusive=True,
                reason=("INCONCLUSIVE: browser-profile IDOR mode is not live-enabled "
                        "(needs the live gate + a fetcher); zero requests made"))

        # Two DISTINCT profiles must resolve, or we return INCONCLUSIVE — never an
        # HTTP verification with shared credentials (requirement: no silent fallback).
        profiled = [a.label for a in self._program.config.test_accounts if a.profile_dir_env]
        if len(profiled) < 2:
            return VerificationResult(verified=False, inconclusive=True,
                reason="INCONCLUSIVE: fewer than two profile identities are configured")
        owner_label, other_label = profiled[0], profiled[1]
        dir_a = self._program.resolve_profile_dir(owner_label)
        dir_b = self._program.resolve_profile_dir(other_label)
        if not dir_a or not dir_b or dir_a == dir_b:
            return VerificationResult(verified=False, inconclusive=True,
                reason=("INCONCLUSIVE: two distinct browser profiles could not be resolved "
                        "for the identities; refusing HTTP verification with shared credentials"))

        run_budget = getattr(self._http, "_run_budget", None)
        gated = PolicyGatedFetcher(
            mode.fetcher, self._program, self._policy,
            run_budget=run_budget, vuln_class="idor")
        try:
            return await verify_idor_two_identity(
                self._program, hypothesis.target_url, gated,
                owner_label=owner_label, other_label=other_label)
        except RequestBlocked as exc:
            # Budget exhausted or policy denied mid-flight -> fail closed, no finding.
            return VerificationResult(
                verified=False,
                reason=f"browser IDOR blocked by policy/budget: {exc}")
        except Exception as exc:  # noqa: BLE001 - e.g. a profile could not be opened
            # Fail closed to INCONCLUSIVE; never fall back to shared-credential HTTP.
            return VerificationResult(
                verified=False, inconclusive=True,
                reason=f"INCONCLUSIVE: browser-profile verification could not run: {exc}")

    def _record_verification_debug(self, hypothesis: Hypothesis, result: VerificationResult,
                                   *, outcome: str) -> None:
        """Retain SANITIZED A/B observations for INCONCLUSIVE/DISPROVEN debugging.

        Stores ONLY non-secret metadata: method, url, status, content-type, response
        body SHA-256 + length, and redacted response-header NAMES. Never stores cookies,
        Authorization/token values, or raw bodies."""
        import hashlib

        from bbagent.storage.models import Observation

        _SECRET = {"authorization", "cookie", "set-cookie", "verifyauthtoken",
                   "x-verify-auth-token", "x-api-key", "x-auth-token", "proxy-authorization"}
        obs = []
        for ex in (result.exchanges or []):
            body = ex.response_body or ""
            header_names = sorted(ex.response_headers.keys()) if ex.response_headers else []
            obs.append({
                "method": ex.method, "url": ex.url, "status": ex.status_code,
                "content_type": (ex.response_headers or {}).get("content-type", ""),
                "body_sha256": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
                "body_len": len(body),
                # NAMES only; values never recorded. Secret header names flagged redacted.
                "response_header_names": [("[redacted]" if n.lower() in _SECRET else n)
                                          for n in header_names],
            })
        try:
            self._db.add_observation(Observation(
                program=hypothesis.program, kind="verify_debug",
                summary=f"{hypothesis.vuln_type} {outcome} at {hypothesis.target_url}",
                data={"outcome": outcome, "reason": result.reason,
                      "same_object_note": "exact-equality comparison (unchanged)",
                      "observations": obs}))
        except Exception as exc:  # noqa: BLE001 - diagnostics must never break verification
            log.warning("verify.debug_record_failed", error=str(exc))

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
