"""Planner data models.

A ``PlannedHypothesis`` is the planner's unit of work. It is a *candidate test*,
never a finding. It is translated into a storage ``Hypothesis`` and run through
the existing ``VerificationEngine``; only that engine, backed by real evidence,
can produce a finding.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum


class Priority(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @classmethod
    def from_score(cls, score: int) -> "Priority":
        if score >= 70:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        return cls.LOW


class PlanStatus(str, Enum):
    PLANNED = "planned"
    EXECUTED = "executed"
    VERIFIED = "verified"
    DISPROVEN = "disproven"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"        # e.g. active test not permitted
    DUPLICATE = "duplicate"    # equivalent to an existing finding/hypothesis


def _plan_id() -> str:
    return f"plan_{uuid.uuid4().hex[:12]}"


def compute_plan_key(vuln_class: str, host: str, endpoint_template: str, object_refs: list[str]) -> str:
    """Stable dedup key: target + endpoint + vuln class + relevant object refs."""
    refs = ",".join(sorted(set(object_refs)))
    sig = f"{vuln_class.lower()}|{host.lower()}|{endpoint_template}|{refs}"
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()[:16]


@dataclass
class PlannedHypothesis:
    target: str                         # affected asset / host
    endpoint: str                       # concrete URL to test
    method: str
    vulnerability_class: str
    reasoning: str
    plan_key: str
    priority_score: int
    required_auth_context: list[str] = field(default_factory=list)
    required_inputs: dict = field(default_factory=dict)
    expected_signal: str = ""
    parent_observation: str | None = None   # e.g. surface endpoint id / object ref
    status: PlanStatus = PlanStatus.PLANNED
    hypothesis_id: str = field(default_factory=_plan_id)
    # Filled in after execution:
    storage_hypothesis_id: str | None = None
    finding_id: str | None = None
    created_at: float = field(default_factory=time.time)

    @property
    def priority(self) -> Priority:
        return Priority.from_score(self.priority_score)

    def to_public_dict(self) -> dict:
        """JSON-serializable view (safe for a future LLM / operator UI)."""
        return {
            "hypothesis_id": self.hypothesis_id,
            "target": self.target,
            "endpoint": self.endpoint,
            "method": self.method,
            "vulnerability_class": self.vulnerability_class,
            "reasoning": self.reasoning,
            "required_auth_context": self.required_auth_context,
            "required_inputs": self.required_inputs,
            "expected_signal": self.expected_signal,
            "priority": self.priority.value,
            "priority_score": self.priority_score,
            "status": self.status.value,
            "parent_observation": self.parent_observation,
            "plan_key": self.plan_key,
            "finding_id": self.finding_id,
        }


@dataclass
class TestBudget:
    """Hard limits the run must not exceed."""

    __test__ = False  # not a pytest test class

    max_requests: int = 200
    max_tests_per_endpoint: int = 2
    max_tests_per_host: int = 100
    max_runtime_seconds: float = 120.0
    concurrency: int = 1

    def to_dict(self) -> dict:
        return {
            "max_requests": self.max_requests,
            "max_tests_per_endpoint": self.max_tests_per_endpoint,
            "max_tests_per_host": self.max_tests_per_host,
            "max_runtime_seconds": self.max_runtime_seconds,
            "concurrency": self.concurrency,
        }


@dataclass
class RunSummary:
    run_id: str
    program: str
    started_at: float
    ended_at: float | None = None
    status: str = "running"
    stop_reason: str = ""
    generated: int = 0
    executed: int = 0
    disproven: int = 0
    inconclusive: int = 0
    verified: int = 0
    requests_used: int = 0
    findings_created: int = 0

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id, "program": self.program, "started_at": self.started_at,
            "ended_at": self.ended_at, "status": self.status, "stop_reason": self.stop_reason,
            "generated": self.generated, "executed": self.executed, "disproven": self.disproven,
            "inconclusive": self.inconclusive, "verified": self.verified,
            "requests_used": self.requests_used, "findings_created": self.findings_created,
        }
