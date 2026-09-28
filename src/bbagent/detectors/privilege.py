"""Second access-control detector: privilege escalation / broken function-level
authorization (BFLA).

Distinct from IDOR (object-level): here a *non-privileged* authenticated identity
reaches a *privileged function* and receives privileged data it must not see.

Verification is deliberately concrete and never based on a status code alone:

  1. Baseline — a privileged (admin) identity calls the endpoint and must receive
     200 with identifiable *privileged content* (a marker under a sensitive key).
     No privileged baseline ⇒ nothing to prove ⇒ DISPROVEN.
  2. Access control — an unauthenticated request must be denied (non-200);
     otherwise the resource is simply public, not a privilege boundary ⇒ DISPROVEN.
  3. Escalation — the non-privileged identity must receive 200 AND its body must
     actually disclose the privileged marker(s) from the baseline. A matching 200
     with no privileged content (a generic response) is NOT a finding ⇒ DISPROVEN.

Every exchange (privileged baseline, unauthenticated, non-privileged) is captured
so the finding carries reproducible evidence. Read-only (GET); no state change.
"""

from __future__ import annotations

import json
import re

from bbagent.detectors.base import (
    Detector,
    DetectionContext,
    VerificationContext,
    VerificationResult,
    Verifier,
    registry,
)
from bbagent.program.manager import ProgramManager
from bbagent.storage.models import Hypothesis
from bbagent.verification.dedup import compute_dedup_key

ADMIN_ROLES = {"admin", "administrator", "superuser", "privileged", "root"}

# Path shapes that suggest a privileged/administrative function.
ADMIN_PATH = re.compile(r"(?i)/(admin|administrator|internal|manage|management|privileged|superuser)(/|$)")

# Keys whose values indicate genuinely privileged/sensitive content.
_SENSITIVE_KEY = re.compile(
    r"(?i)(classification|records|secret|ssn|salary|confidential|internal|"
    r"privileged|feature_flags|all_users|audit)"
)


def resolve_admin_regular(program: ProgramManager) -> tuple[str | None, str | None]:
    """Return (admin_label, regular_label) from the program's test accounts."""
    admin = None
    regular = None
    for acct in program.config.test_accounts:
        if acct.role.lower() in ADMIN_ROLES and admin is None:
            admin = acct.label
        elif acct.role.lower() not in ADMIN_ROLES and regular is None:
            regular = acct.label
    return admin, regular


def _identity_headers(program: ProgramManager, label: str | None) -> dict[str, str]:
    if label is None:
        return {}
    token = program.resolve_account_secret(label)
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {"X-Test-Identity": label}


def _privileged_markers(body: str) -> set[str]:
    """Extract privileged marker values (scalars under sensitive keys)."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return set()

    markers: set[str] = set()

    def walk(node, key_ctx: str | None):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    walk(v, k)
                elif key_ctx and _SENSITIVE_KEY.search(key_ctx) or _SENSITIVE_KEY.search(k):
                    s = str(v)
                    if len(s) >= 4:
                        markers.add(s)
        elif isinstance(node, list):
            for item in node:
                walk(item, key_ctx)

    walk(obj, None)
    return markers


@registry.register_detector
class PrivilegeEscalationDetector(Detector):
    vuln_type = "privilege_escalation"
    name = "privilege-escalation-detector"

    async def detect(self, ctx: DetectionContext) -> list[Hypothesis]:
        """Propose a privilege hypothesis for admin-like endpoints.

        Observation-driven path (parallel to the planner/capability path). Does
        no HTTP and asserts nothing.
        """
        admin, regular = resolve_admin_regular(ctx.program)
        if admin is None or regular is None:
            return []
        hyps: list[Hypothesis] = []
        for obs in ctx.observations:
            if obs.kind != "endpoint":
                continue
            url = obs.data.get("url", "")
            if not ADMIN_PATH.search(url):
                continue
            hyps.append(Hypothesis(
                program=ctx.program.name,
                vuln_type=self.vuln_type,
                title=f"Possible privilege escalation at {url}",
                rationale="Administrative/privileged endpoint; function-level authorization must be enforced.",
                target_url=url,
                detector=self.name,
                observation_ids=[obs.id],
            ))
        return hyps


@registry.register_verifier
class PrivilegeEscalationVerifier(Verifier):
    vuln_type = "privilege_escalation"

    async def verify(self, ctx: VerificationContext) -> VerificationResult:
        url = ctx.hypothesis.target_url
        admin_label, regular_label = resolve_admin_regular(ctx.program)
        if admin_label is None or regular_label is None:
            return VerificationResult(
                verified=False,
                reason="need one admin-role and one non-admin test identity to verify",
            )

        # (1) Privileged baseline, (2) unauthenticated control, (3) non-privileged test.
        admin = await ctx.http.get(url, headers=_identity_headers(ctx.program, admin_label))
        anon = await ctx.http.get(url, headers={})
        other = await ctx.http.get(url, headers=_identity_headers(ctx.program, regular_label))
        exchanges = [admin, anon, other]

        markers = _privileged_markers(admin.response_body) if admin.status_code == 200 else set()
        if admin.status_code != 200 or not markers:
            return VerificationResult(
                verified=False,
                reason=(f"no privileged baseline (admin status={admin.status_code}, "
                        f"privileged_markers={len(markers)})"),
                exchanges=exchanges,
            )

        if anon.status_code == 200:
            return VerificationResult(
                verified=False,
                reason="endpoint is publicly accessible (unauthenticated 200); not a privilege boundary",
                exchanges=exchanges,
            )

        disclosed = other.status_code == 200 and any(m in other.response_body for m in markers)
        if not disclosed:
            return VerificationResult(
                verified=False,
                reason=(f"authorization holds: non-privileged status={other.status_code}, "
                        f"privileged_content_disclosed=False"),
                exchanges=exchanges,
            )

        return VerificationResult(
            verified=True,
            reason="non-privileged identity received privileged content from an admin-only function",
            exchanges=exchanges,
            expected_behavior=(
                f"'{regular_label}' (non-admin) should be denied (401/403) and must never "
                f"receive the restricted content that '{admin_label}' (admin) sees at {url}."
            ),
            actual_behavior=(
                f"'{regular_label}' received HTTP {other.status_code} disclosing privileged "
                f"content (markers: {sorted(markers)[:3]}) from an admin-only function."
            ),
            impact=(
                "Broken function-level authorization (privilege escalation): a lower-privileged "
                "authenticated user can invoke a privileged function and read restricted data."
            ),
            test_identity=f"{regular_label} (non-privileged)",
            reproduction=(
                f"1. Authenticate as '{admin_label}' (admin) and GET {url} — note the restricted content.\n"
                f"2. Confirm an unauthenticated GET {url} is denied (HTTP {anon.status_code}).\n"
                f"3. Authenticate as '{regular_label}' (non-admin) and GET {url}.\n"
                f"4. Observe HTTP {other.status_code} disclosing the same restricted content."
            ),
            dedup_key=compute_dedup_key("privilege_escalation", url, "GET"),
        )
