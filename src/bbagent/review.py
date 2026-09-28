r"""Human approval workflow.

The agent may reach VERIFIED and produce a report, but it may NOT submit.
Only a human moves a finding forward through review. Submission itself is
deliberately out of scope for this tool.

    VERIFIED -> READY_FOR_REVIEW -> APPROVED_FOR_SUBMISSION
                              \-> REJECTED
"""

from __future__ import annotations

from bbagent.logging_config import get_logger
from bbagent.storage.db import Database
from bbagent.storage.models import FindingStatus

log = get_logger(__name__)

# Allowed manual transitions. The agent can only ever set READY_FOR_REVIEW
# (marking its own work done); APPROVED/REJECTED require a human caller.
_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.VERIFIED: {FindingStatus.READY_FOR_REVIEW},
    FindingStatus.READY_FOR_REVIEW: {
        FindingStatus.APPROVED_FOR_SUBMISSION,
        FindingStatus.REJECTED,
    },
    FindingStatus.APPROVED_FOR_SUBMISSION: set(),
    FindingStatus.REJECTED: set(),
}


class ApprovalError(Exception):
    pass


def transition(db: Database, finding_id: str, target: FindingStatus, *, actor: str) -> None:
    """Move a finding to ``target`` if the transition is allowed.

    ``actor`` is recorded for audit. Approving for submission requires a human
    actor (any actor other than the literal string 'agent').
    """
    finding = db.get_finding(finding_id)
    if finding is None:
        raise ApprovalError(f"no such finding: {finding_id}")

    allowed = _TRANSITIONS.get(finding.status, set())
    if target not in allowed:
        raise ApprovalError(f"illegal transition {finding.status.value} -> {target.value}")

    if target is FindingStatus.APPROVED_FOR_SUBMISSION and actor == "agent":
        raise ApprovalError("the agent may not approve findings for submission; a human must")

    db.set_finding_status(finding_id, target)
    log.info("review.transition", finding=finding_id, to=target.value, actor=actor)
