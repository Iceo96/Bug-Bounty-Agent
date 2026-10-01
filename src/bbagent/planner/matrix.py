"""Policy-aware capability matrix.

Classifies each registered detector capability against a program's rules as:

  ALLOWED   — the class is explicitly permitted (in allowed_vulnerability_classes)
  FORBIDDEN — the class is explicitly excluded (matched in forbidden_actions)
  UNKNOWN   — neither permitted nor excluded

Only ALLOWED capabilities may run. The absence of a prohibition is NEVER treated
as permission: an unlisted class is UNKNOWN and stays disabled. FORBIDDEN always
wins over ALLOWED.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from bbagent.planner.capabilities import CapabilityRegistry
from bbagent.program.manager import ProgramManager

# Known detector vulnerability classes.
_KNOWN_CLASSES = {"idor", "privilege_escalation", "reflected_xss", "sql_injection"}

# forbidden_actions slugs that map to a detector class.
_FORBIDDEN_ALIASES = {
    "reflected-xss": "reflected_xss", "reflected_xss": "reflected_xss",
    "sql-injection": "sql_injection", "sqli": "sql_injection", "sql_injection": "sql_injection",
    "idor": "idor", "bola": "idor",
    "privilege-escalation": "privilege_escalation", "bfla": "privilege_escalation",
    "privilege_escalation": "privilege_escalation",
}

# Which classes need two identities / data scoping (informational for the matrix).
_NEEDS_IDENTITY = {"idor", "privilege_escalation"}
_NEEDS_DATA_SCOPE = {"idor", "sql_injection"}


class CapabilityStatus(str, Enum):
    ALLOWED = "ALLOWED"
    FORBIDDEN = "FORBIDDEN"
    UNKNOWN = "UNKNOWN"


@dataclass
class CapabilityRow:
    detector: str
    vulnerability_class: str
    status: CapabilityStatus
    requires_active_testing: bool
    requires_identity: bool
    requires_data_scope: bool
    reason: str


def _forbidden_classes(program: ProgramManager) -> set[str]:
    forbidden: set[str] = set()
    for action in program.config.forbidden_actions:
        a = action.lower()
        if a in _FORBIDDEN_ALIASES:
            forbidden.add(_FORBIDDEN_ALIASES[a])
        if a in _KNOWN_CLASSES:
            forbidden.add(a)
    return forbidden


def build_capability_matrix(program: ProgramManager,
                            capabilities: CapabilityRegistry) -> list[CapabilityRow]:
    allowed = set(program.config.allowed_vulnerability_classes)
    forbidden = _forbidden_classes(program)
    rows: list[CapabilityRow] = []
    for cap in capabilities.all():
        cls = cap.vuln_class
        if cls in forbidden:
            status, reason = CapabilityStatus.FORBIDDEN, "explicitly excluded by program"
        elif cls in allowed:
            status, reason = CapabilityStatus.ALLOWED, "explicitly permitted by program"
        else:
            status, reason = CapabilityStatus.UNKNOWN, "not explicitly permitted (absence != permission)"
        rows.append(CapabilityRow(
            detector=cap.title, vulnerability_class=cls, status=status,
            requires_active_testing=cap.active,
            requires_identity=cls in _NEEDS_IDENTITY,
            requires_data_scope=cls in _NEEDS_DATA_SCOPE,
            reason=reason,
        ))
    return rows


def allowed_classes(program: ProgramManager, capabilities: CapabilityRegistry) -> set[str]:
    """The set of vulnerability classes permitted to run for this program."""
    return {r.vulnerability_class for r in build_capability_matrix(program, capabilities)
            if r.status is CapabilityStatus.ALLOWED}
