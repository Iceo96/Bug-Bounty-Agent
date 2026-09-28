"""Domain models for the attack surface and findings lifecycle.

These are plain dataclasses/enums decoupled from the SQLite layer so callers
never hand-write SQL. The lifecycle enums encode the core safety invariant:
a hypothesis is NOT a finding until it has been verified with real evidence.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    INVESTIGATING = "investigating"
    VERIFYING = "verifying"
    VERIFIED = "verified"     # promoted to a finding
    DISCARDED = "discarded"


class FindingStatus(str, Enum):
    # A finding only exists after verification succeeded.
    VERIFIED = "verified"
    READY_FOR_REVIEW = "ready_for_review"
    CHANGES_REQUESTED = "changes_requested"
    APPROVED_FOR_SUBMISSION = "approved_for_submission"
    REJECTED = "rejected"


@dataclass
class Observation:
    """A neutral, factual record of something seen during recon/testing."""

    program: str
    kind: str                      # e.g. "endpoint", "header", "status", "diff"
    summary: str
    data: dict = field(default_factory=dict)
    exchange_id: Optional[str] = None
    id: str = field(default_factory=lambda: _new_id("obs"))
    created_at: float = field(default_factory=time.time)


@dataclass
class Hypothesis:
    """A detector's *suspicion*. Never itself a finding."""

    program: str
    vuln_type: str                 # e.g. "idor", "xss", "ssrf"
    title: str
    rationale: str
    target_url: str
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    detector: str = "unknown"
    observation_ids: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: _new_id("hyp"))
    created_at: float = field(default_factory=time.time)


@dataclass
class EvidenceRecord:
    """Metadata row pointing at an immutable evidence blob on disk."""

    finding_id: Optional[str]
    hypothesis_id: Optional[str]
    label: str                     # e.g. "request", "response", "baseline"
    sha256: str
    blob_path: str
    exchange_id: Optional[str] = None
    id: str = field(default_factory=lambda: _new_id("ev"))
    created_at: float = field(default_factory=time.time)


@dataclass
class Finding:
    """A *verified* vulnerability with reproducible evidence."""

    program: str
    hypothesis_id: str
    vuln_type: str
    title: str
    affected_asset: str
    endpoint: str
    http_method: str
    test_identity: str
    expected_behavior: str
    actual_behavior: str
    impact: str
    preconditions: str = ""
    reproduction: str = ""
    status: FindingStatus = FindingStatus.VERIFIED
    dedup_key: Optional[str] = None
    evidence_ids: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: _new_id("find"))
    created_at: float = field(default_factory=time.time)
