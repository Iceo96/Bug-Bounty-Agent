"""Security Research Loop.

Integrates the autonomous browser exploration layer with the existing hypothesis
planner + verification pipeline into one bounded, policy-governed loop:

  explore (browser) -> update attack-surface -> plan + prioritize -> POLICY GATE
  -> test via PolicyGatedHTTP -> verify -> evidence/findings -> HUMAN review,
  returning to exploration when the current surface is insufficient.

It reuses AutonomousExplorer, BrowserController, the SurfaceStore, PlanRunner (the
planner + detectors + VerificationEngine + PolicyGatedHTTP + DataScope + RunBudget +
EvidenceStore), and the review workflow. It builds no new detectors, no new gate,
and never approves or submits.
"""

from bbagent.research.loop import (
    ResearchLimits,
    ResearchReport,
    run_security_research,
)
from bbagent.research.preflight import (
    Check,
    ResearchPreflightReport,
    research_preflight,
)

__all__ = [
    "ResearchLimits",
    "ResearchReport",
    "run_security_research",
    "research_preflight",
    "ResearchPreflightReport",
    "Check",
]
