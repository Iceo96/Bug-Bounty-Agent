"""Example detector/verifier: IDOR / broken object-level authorization (BOLA).

Non-destructive: uses only GET requests via the authorized client, comparing
what two different test identities can read. This module also demonstrates the
pluggable registration pattern — import it to register with the framework.

The verifier confirms a hypothesis only from REAL exchanges. It cannot fabricate
requests or responses; if the comparison doesn't demonstrate the issue, it
returns ``verified=False`` and the engine discards the hypothesis.
"""

from __future__ import annotations

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


@registry.register_verifier
class IDORVerifier(Verifier):
    vuln_type = "idor"

    async def verify(self, ctx: VerificationContext) -> VerificationResult:
        """Confirm IDOR by comparing two identities' access to the same object.

        Expects the hypothesis ``target_url`` to be the object owned by identity
        A. We fetch it as A (owner) and as B (other user). If B receives the
        same object contents, object-level authorization is broken.

        Identities are conveyed via headers here for the example; a real verifier
        would use authenticated sessions from the program's test accounts.
        """
        url = ctx.hypothesis.target_url

        owner = await ctx.http.get(url, headers={"X-Test-Identity": "user_a"})
        other = await ctx.http.get(url, headers={"X-Test-Identity": "user_b"})

        broken = (
            owner.status_code == 200
            and other.status_code == 200
            and owner.response_body == other.response_body
            and owner.response_body.strip() != ""
        )

        if not broken:
            return VerificationResult(
                verified=False,
                reason=(
                    f"no cross-user access: owner={owner.status_code}, "
                    f"other={other.status_code}, bodies_match="
                    f"{owner.response_body == other.response_body}"
                ),
                exchanges=[owner, other],
            )

        return VerificationResult(
            verified=True,
            reason="second identity read the first identity's object",
            exchanges=[owner, other],
            expected_behavior=(
                "user_b should receive 403/404 when requesting user_a's object."
            ),
            actual_behavior=(
                "user_b received HTTP 200 with user_a's object contents."
            ),
            impact=(
                "Broken object-level authorization allows any authenticated user "
                "to read other users' objects (IDOR/BOLA)."
            ),
            test_identity="user_b (non-owner)",
            reproduction=(
                f"1. Authenticate as user_b.\n"
                f"2. GET {url} (an object owned by user_a).\n"
                f"3. Observe HTTP 200 returning user_a's data."
            ),
            dedup_key=compute_dedup_key("idor", url, "GET"),
        )
