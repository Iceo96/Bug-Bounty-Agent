"""Detector and verifier interfaces.

Contract:
* A :class:`Detector` inspects observations/attack surface and emits
  :class:`Hypothesis` objects. It performs NO destructive actions and, by
  convention, only reasons over already-captured data or issues safe,
  scope-checked read requests through the provided client.
* A :class:`Verifier` attempts to confirm a single hypothesis by gathering
  *real* evidence via the authorized HTTP client. It returns a
  :class:`VerificationResult`. It can never fabricate requests or responses —
  every exchange it cites must come from the client.

Detectors and verifiers are registered by ``vuln_type`` so the framework is
pluggable: add a module, register it, done.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Sequence

from bbagent.http.client import AuthorizedHTTPClient, HTTPExchange
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.storage.models import Hypothesis, Observation


@dataclass
class DetectionContext:
    """Everything a detector may read from and the (scope-enforced) client."""

    program: ProgramManager
    db: Database
    http: AuthorizedHTTPClient
    observations: Sequence[Observation] = ()


@dataclass
class VerificationContext:
    """Inputs available to a verifier for one hypothesis."""

    program: ProgramManager
    db: Database
    http: AuthorizedHTTPClient
    hypothesis: Hypothesis


@dataclass
class VerificationResult:
    """Outcome of a verification attempt.

    ``verified`` may only be True when ``exchanges`` contains the real HTTP
    exchanges that demonstrate the issue. The verification engine enforces this.
    """

    verified: bool
    reason: str
    exchanges: list[HTTPExchange] = field(default_factory=list)
    expected_behavior: str = ""
    actual_behavior: str = ""
    impact: str = ""
    test_identity: str = "unauthenticated"
    dedup_key: Optional[str] = None
    reproduction: str = ""


class Detector(ABC):
    """Base class for pluggable, non-destructive detectors."""

    #: short, stable identifier, e.g. "idor", "xss".
    vuln_type: str = "generic"
    name: str = "detector"

    @abstractmethod
    async def detect(self, ctx: DetectionContext) -> list[Hypothesis]:
        """Return zero or more hypotheses. MUST NOT create findings or evidence."""
        raise NotImplementedError


class Verifier(ABC):
    """Base class for verifiers that confirm a hypothesis with real evidence."""

    vuln_type: str = "generic"

    @abstractmethod
    async def verify(self, ctx: VerificationContext) -> VerificationResult:
        """Attempt to confirm the hypothesis. Cite only real HTTP exchanges."""
        raise NotImplementedError


class _Registry:
    """Maps ``vuln_type`` -> detector/verifier classes."""

    def __init__(self) -> None:
        self._detectors: dict[str, type[Detector]] = {}
        self._verifiers: dict[str, type[Verifier]] = {}

    def register_detector(self, cls: type[Detector]) -> type[Detector]:
        self._detectors[cls.vuln_type] = cls
        return cls

    def register_verifier(self, cls: type[Verifier]) -> type[Verifier]:
        self._verifiers[cls.vuln_type] = cls
        return cls

    def detectors(self) -> list[type[Detector]]:
        return list(self._detectors.values())

    def verifier_for(self, vuln_type: str) -> Optional[type[Verifier]]:
        return self._verifiers.get(vuln_type)


registry = _Registry()
