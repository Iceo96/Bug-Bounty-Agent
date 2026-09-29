"""Example detector/verifier: IDOR / broken object-level authorization (BOLA).

Non-destructive: uses only GET requests via the authorized client, comparing
what two different test identities can read. This module also demonstrates the
pluggable registration pattern — import it to register with the framework.

The verifier confirms a hypothesis only from REAL exchanges. It cannot fabricate
requests or responses; if the comparison doesn't demonstrate the issue, it
returns ``verified=False`` and the engine discards the hypothesis.
"""

from __future__ import annotations

import json

from bbagent.detectors.base import (
    Detector,
    DetectionContext,
    VerificationContext,
    VerificationResult,
    Verifier,
    registry,
)
from bbagent.storage.models import Hypothesis
from bbagent.verification.dedup import compute_dedup_key


@registry.register_detector
class IDORDetector(Detector):
    vuln_type = "idor"
    name = "idor-detector"

    async def detect(self, ctx: DetectionContext) -> list[Hypothesis]:
        """Propose an IDOR hypothesis for endpoints that expose object ids.

        This example scans observations tagged as ``endpoint`` whose data marks
        them ``object_scoped`` (i.e. a per-user resource with an id in the path).
        Real detectors would derive these from the attack-surface map.
        """
        hyps: list[Hypothesis] = []
        for obs in ctx.observations:
            if obs.kind != "endpoint":
                continue
            if not obs.data.get("object_scoped"):
                continue
            url = obs.data.get("url", "")
            hyps.append(
                Hypothesis(
                    program=ctx.program.name,
                    vuln_type=self.vuln_type,
                    title=f"Possible IDOR at {url}",
                    rationale=(
                        "Endpoint exposes a per-object identifier in the path; "
                        "authorization must be checked per object."
                    ),
                    target_url=url,
                    detector=self.name,
                    observation_ids=[obs.id],
                )
            )
        return hyps


def _same_object(body_a: str, body_b: str) -> bool:
    """True if two response bodies represent the same object contents.

    Compares parsed JSON when possible (order-insensitive), else exact bytes.
    Empty bodies never count as a match — a match must be positive evidence.
    """
    if not body_a.strip() or not body_b.strip():
        return False
    try:
        return json.loads(body_a) == json.loads(body_b)
    except json.JSONDecodeError:
        return body_a == body_b


@registry.register_verifier
class IDORVerifier(Verifier):
    """Confirm IDOR/BOLA by comparing two identities' access to the SAME object.

    Method:
      1. Identify the object reference (``hypothesis.target_url``, owned by A).
      2. Establish a baseline: fetch the object as the legitimate owner (A).
      3. Fetch the same object as a second authorized identity (B).
      4. Compare. Unauthorized access is proven only when B receives the *same
         object contents* as A — a matching status code alone is NOT sufficient.

    A finding is produced only when that comparison holds; otherwise the result
    is ``verified=False`` and the engine discards the hypothesis. Both exchanges
    are always returned so the engine can persist immutable evidence; if either
    request cannot be made, verification fails (no fabricated evidence).
    """

    vuln_type = "idor"

    async def verify(self, ctx: VerificationContext) -> VerificationResult:
        url = ctx.hypothesis.target_url

        # Requires TWO explicitly authorized identities. If the program authorizes
        # fewer, mark INCONCLUSIVE rather than using an unauthorized identity.
        accounts = ctx.program.config.test_accounts
        if len(accounts) < 2:
            return VerificationResult(
                verified=False,
                reason=("INCONCLUSIVE / NEEDS_HUMAN_REVIEW: IDOR requires two authorized "
                        f"test identities; only {len(accounts)} configured"),
            )
        owner_label, other_label = accounts[0].label, accounts[1].label

        # (2) Baseline as the legitimate owner; (3) same object as identity B.
        # Identities are passed as handles; the policy-gated client injects the
        # credential server-side after the policy check.
        owner = await ctx.http.get(url, identity=owner_label)
        other = await ctx.http.get(url, identity=other_label)

        # The owner must actually see a real object, or there is no baseline to
        # compare against and we cannot claim anything.
        if owner.status_code != 200 or not owner.response_body.strip():
            return VerificationResult(
                verified=False,
                reason=f"no owner baseline (owner status={owner.status_code})",
                exchanges=[owner, other],
            )

        # (4) Evidence of unauthorized access: B receives A's object contents.
        same = _same_object(owner.response_body, other.response_body)
        broken = other.status_code == 200 and same

        if not broken:
            return VerificationResult(
                verified=False,
                reason=(
                    f"authorization holds: owner={owner.status_code}, "
                    f"other={other.status_code}, same_object={same}"
                ),
                exchanges=[owner, other],
            )

        return VerificationResult(
            verified=True,
            reason="second identity read the first identity's object contents",
            exchanges=[owner, other],
            expected_behavior=(
                f"'{other_label}' should receive 403/404 when requesting "
                f"'{owner_label}'s object at {url}."
            ),
            actual_behavior=(
                f"'{other_label}' received HTTP {other.status_code} returning the "
                f"identical object contents that '{owner_label}' sees."
            ),
            impact=(
                "Broken object-level authorization (IDOR/BOLA): any authenticated "
                "user can read other users' objects by changing the object id."
            ),
            test_identity=f"{other_label} (non-owner)",
            reproduction=(
                f"1. Authenticate as '{owner_label}' and GET {url} — note the object.\n"
                f"2. Authenticate as '{other_label}' (who does not own it).\n"
                f"3. GET {url} again as '{other_label}'.\n"
                f"4. Observe HTTP {other.status_code} returning '{owner_label}'s object."
            ),
            dedup_key=compute_dedup_key("idor", url, "GET"),
        )
