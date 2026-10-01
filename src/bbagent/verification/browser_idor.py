"""Browser-profile-based two-identity IDOR verification.

Temu's Identity A and Identity B authenticate ONLY through their own separate,
persistent Playwright profiles (no per-account HTTP credential). The HTTP IDOR
verifier cannot drive those distinct sessions, so a browser-profile path is needed:
fetch the SAME in-scope object with A's authenticated browser context and with B's,
then apply the EXISTING IDOR comparison (``_same_object``) and evidence rules.

Guarantees:
  * Each identity uses its OWN persistent profile/context — never shared (built via
    :func:`bbagent.browser.build_identity_backends`, which fails closed on a shared
    directory).
  * The verifier explicitly selects two DISTINCT, explicitly-configured authorized
    identities. It never treats an unauthenticated context as Identity B, and with
    fewer than two authorized identities it stays INCONCLUSIVE and issues ZERO
    fetches.
  * Scope is fail-closed (the unchanged ScopeEngine) and only GET is performed.
  * No cookie/token/password/storage_state/localStorage/sessionStorage value is ever
    read, printed, exported, or persisted (headers are redacted; sessions live only
    inside each profile directory).
  * It returns a CANDIDATE :class:`VerificationResult` only. It never creates a
    finding: the existing verification-engine evidence rules and the human-review /
    no-submission workflow still decide, exactly as for the HTTP path. A mere
    difference between A and B never by itself yields ``verified=True`` — that
    requires B receiving A's object contents (positive evidence).
"""

from __future__ import annotations

import abc
import time
import uuid
from dataclasses import dataclass, field

from bbagent.detectors.base import VerificationResult
from bbagent.detectors.idor import _same_object
from bbagent.http.client import HTTPExchange
from bbagent.logging_config import get_logger
from bbagent.program.manager import ProgramManager
from bbagent.scope.engine import ScopeEngine
from bbagent.verification.dedup import compute_dedup_key

log = get_logger(__name__)

# Header names whose values must never be captured (kept as names only, blanked).
_AUTH_HEADER_NAMES = {
    "authorization", "cookie", "set-cookie", "verifyauthtoken", "x-verify-auth-token",
    "x-api-key", "x-auth-token", "proxy-authorization",
}


def _redact(headers: dict[str, str]) -> dict[str, str]:
    return {k: ("" if k.lower() in _AUTH_HEADER_NAMES else v) for k, v in (headers or {}).items()}


@dataclass
class AccessObservation:
    """What one identity's browser observed for a GET of the object. No secrets."""

    identity_label: str
    url: str
    status: int
    body: str = ""
    content_type: str | None = None
    elapsed_ms: float = 0.0
    response_headers: dict[str, str] = field(default_factory=dict)

    def to_exchange(self) -> HTTPExchange:
        """An evidence-compatible exchange (auth material already redacted)."""
        return HTTPExchange(
            exchange_id=f"bx_{uuid.uuid4().hex[:12]}",
            method="GET", url=self.url,
            request_headers={"X-Browser-Identity": self.identity_label},
            request_body=None, status_code=self.status,
            response_headers=_redact(self.response_headers),
            response_body=self.body, elapsed_ms=self.elapsed_ms,
        )


class IdentityFetcher(abc.ABC):
    """Fetches a URL using a specific authorized identity's isolated browser context."""

    @abc.abstractmethod
    async def fetch(self, identity_label: str, url: str) -> AccessObservation: ...


class PolicyGatedFetcher(IdentityFetcher):
    """Wraps an :class:`IdentityFetcher` and runs EVERY browser fetch through the
    existing program policy engine (scope, GET-only, DataScope, required-header
    availability, vuln-class, identity) and the shared RunBudget — before the fetch.
    A denied/over-budget fetch raises ``RequestBlocked`` and never reaches the base
    fetcher. This is the same gate the HTTP verifier uses; nothing is bypassed."""

    def __init__(self, base: IdentityFetcher, program, policy, *, run_budget=None,
                 vuln_class: str = "idor"):
        self._base = base
        self._program = program
        self._policy = policy
        self._run_budget = run_budget
        self._vuln_class = vuln_class

    async def fetch(self, identity_label: str, url: str) -> AccessObservation:
        from bbagent.http.client import RequestBlocked
        from bbagent.tools.base import ToolRequest

        req = ToolRequest(tool="http", arguments={"url": url, "method": "GET"},
                          target=url, identity=identity_label, vuln_class=self._vuln_class)
        decision = self._policy.evaluate(req)
        if not decision.allowed:
            raise RequestBlocked(f"policy denied [{decision.matched_rule}]: {decision.reason}")
        self._policy.record(req)
        if self._run_budget is not None:
            self._run_budget.consume()        # shared RunBudget; raises when exhausted
        return await self._base.fetch(identity_label, url)


@dataclass
class BrowserIDORMode:
    """An EXPLICIT, separate verification mode. The HTTP IDOR verifier is never
    replaced; the engine chooses this path only when it is enabled AND the IDOR
    hypothesis has two explicitly-configured identities with DISTINCT profiles."""

    enabled: bool = False
    live: bool = False
    fetcher: IdentityFetcher | None = None

    def applies_to(self, program, hypothesis) -> bool:
        if getattr(hypothesis, "vuln_type", None) != "idor":
            return False
        profiled = [a for a in program.config.test_accounts if a.profile_dir_env]
        envs = {a.profile_dir_env for a in profiled}
        return len(profiled) >= 2 and len(envs) == len(profiled)   # ≥2 DISTINCT profiles

    def gate_open(self) -> bool:
        """Real execution requires the mode enabled, the live gate on, and a fetcher."""
        return bool(self.enabled and self.live and self.fetcher is not None)


class BrowserIdentityFetcher(IdentityFetcher):
    """Real fetcher: one isolated persistent Playwright context per identity.

    Lazily starts each identity's OWN backend (its own profile directory) and reuses
    it ONLY for that identity. Contexts/profiles are never shared. Use as an async
    context manager so every context is closed; storage state is never exported.
    """

    def __init__(self, program: ProgramManager, *, headless: bool = True):
        from bbagent.browser.identities import build_identity_backends

        # Distinct backend (own profile) per identity; raises on a shared directory.
        self._backends = build_identity_backends(program, headless=headless)
        self._started: set[str] = set()

    def identities(self) -> list[str]:
        return list(self._backends)

    async def __aenter__(self) -> "BrowserIdentityFetcher":
        return self

    async def __aexit__(self, *exc) -> None:
        for label in list(self._started):
            try:
                await self._backends[label].close()
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass
        self._started.clear()

    async def fetch(self, identity_label: str, url: str) -> AccessObservation:
        backend = self._backends.get(identity_label)
        if backend is None:
            raise KeyError(f"no browser profile configured for identity {identity_label!r}")
        if identity_label not in self._started:
            await backend.start()
            self._started.add(identity_label)
        started = time.monotonic()

        # PRIMARY: use the Response returned directly by page.goto() when the backend
        # can provide it. This captures the real status/body even when the navigation
        # was redirected or the final URL was normalized (the case that previously
        # produced status=0). The navigation still happens inside the identity's OWN
        # isolated persistent profile; headers are redacted at the backend.
        capture = getattr(backend, "goto_capture", None)
        if capture is not None:
            nav = await capture(url)                     # navigates; returns a dict or None
            if nav is not None:
                return AccessObservation(
                    identity_label=identity_label, url=nav.get("final_url") or url,
                    status=int(nav.get("status") or 0), body=nav.get("body") or "",
                    content_type=nav.get("content_type"),
                    elapsed_ms=(time.monotonic() - started) * 1000,
                    response_headers=dict(nav.get("response_headers") or {}))
            # goto() provided no Response -> fall back to events captured DURING it.
            exchanges = await backend.drain()
        else:
            # Backend without goto_capture: navigate, then use captured events.
            await backend.goto(url)
            exchanges = await backend.drain()

        # FALLBACK: match a captured response by URL (exact, then path-level).
        target = url.split("#", 1)[0]
        match = next((e for e in exchanges if e.url.split("#", 1)[0] == target), None)
        if match is None:
            return AccessObservation(identity_label, url, status=0, body="",
                                     elapsed_ms=(time.monotonic() - started) * 1000)
        return AccessObservation(
            identity_label=identity_label, url=match.url, status=match.status or 0,
            body=match.response_body or "", content_type=match.response_content_type,
            elapsed_ms=(time.monotonic() - started) * 1000,
            response_headers=dict(match.response_headers),
        )


def _authorized_labels(program: ProgramManager) -> list[str]:
    return [a.label for a in program.config.test_accounts]


async def verify_idor_two_identity(
    program: ProgramManager,
    url: str,
    fetcher: IdentityFetcher,
    *,
    owner_label: str | None = None,
    other_label: str | None = None,
) -> VerificationResult:
    """Confirm/deny an IDOR candidate via two identities' own browser contexts.

    Returns a CANDIDATE result; it never creates a finding (engine + human review do).
    """
    labels = _authorized_labels(program)

    # (8) Fewer than two explicitly authorized identities -> INCONCLUSIVE, ZERO fetches.
    if len(labels) < 2:
        return VerificationResult(
            verified=False, inconclusive=True,
            reason=("INCONCLUSIVE / NEEDS_HUMAN_REVIEW: IDOR requires two authorized "
                    f"test identities; only {len(labels)} configured"))

    owner_label = owner_label or labels[0]
    other_label = other_label or labels[1]

    # (7) Identity B must be an explicitly-configured authorized identity — NEVER an
    # unauthenticated context — and (4) must be DISTINCT from Identity A.
    if other_label not in labels or owner_label not in labels:
        return VerificationResult(
            verified=False, inconclusive=True,
            reason="INCONCLUSIVE: both identities must be explicitly configured authorized identities")
    if owner_label == other_label:
        return VerificationResult(
            verified=False, inconclusive=True,
            reason="INCONCLUSIVE: two DISTINCT authorized identities are required (got the same one)")

    # (10/11) Fail-closed scope + GET-only. Scope engine unchanged; no wildcard.
    if not ScopeEngine(program.config.scope).is_allowed(url):
        return VerificationResult(
            verified=False,
            reason=f"refused: target is out of the configured Temu scope: {url}")

    # (5) Fetch the SAME object with each identity's OWN browser context.
    owner = await fetcher.fetch(owner_label, url)
    other = await fetcher.fetch(other_label, url)
    owner_ex, other_ex = owner.to_exchange(), other.to_exchange()

    # Baseline: the owner must actually see a real object.
    if owner.status != 200 or not owner.body.strip():
        return VerificationResult(
            verified=False, reason=f"no owner baseline (owner status={owner.status})",
            exchanges=[owner_ex, other_ex])

    # (6/9) Positive evidence ONLY: B received A's object contents (identical body).
    # A difference alone (e.g. B denied) is NOT a finding.
    same = _same_object(owner.body, other.body)
    broken = other.status == 200 and same
    if not broken:
        return VerificationResult(
            verified=False,
            reason=(f"authorization holds: owner={owner.status}, other={other.status}, "
                    f"same_object={same}"),
            exchanges=[owner_ex, other_ex])

    # Candidate confirmation — still subject to engine evidence rules + HUMAN review.
    return VerificationResult(
        verified=True,
        reason="second identity's browser read the first identity's object contents",
        exchanges=[owner_ex, other_ex],
        expected_behavior=(f"'{other_label}' should receive 403/404 when requesting "
                           f"'{owner_label}'s object at {url}."),
        actual_behavior=(f"'{other_label}' received HTTP {other.status} returning the identical "
                         f"object contents that '{owner_label}' sees."),
        impact=("Broken object-level authorization (IDOR/BOLA): a different authenticated "
                "user can read another user's object."),
        test_identity=f"{other_label} (non-owner, own browser profile)",
        reproduction=(f"1. In Identity A's browser profile, GET {url} — note the object.\n"
                      f"2. In Identity B's SEPARATE browser profile (distinct account), GET {url}.\n"
                      f"3. Observe B receiving A's object contents (HTTP {other.status})."),
        dedup_key=compute_dedup_key("idor", url, "GET"))
