"""Authenticated browser controller.

Drives a browser session (navigate / click / type / scroll) and feeds the network
traffic those actions generate into the existing
:class:`bbagent.browser.observe.NetworkObservationIngestor` — which records it into
the same :class:`SurfaceStore` the planner already reads.

Design:
  * The controller is backend-agnostic. A :class:`BrowserBackend` performs the
    actual actions and yields the :class:`ObservedExchange` objects its traffic
    produced. The real backend is :class:`PlaywrightBackend`; tests drive a
    deterministic in-memory mock backend. This keeps the full control flow testable
    with no browser binaries and no sockets.
  * Scope is fail-closed and is the single source of truth. The controller refuses
    to *navigate* to an out-of-scope URL, and the ingestor independently drops any
    out-of-scope traffic that a page generated on its own.
  * It is DISCOVERY ONLY. It performs no vulnerability testing, sends no direct HTTP
    outside the browser, and never persists cookies/tokens/passwords. Active testing
    of anything found here still flows through the existing PolicyGatedHTTP path.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

from bbagent.browser.models import IngestReport, ObservedExchange
from bbagent.browser.observe import NetworkObservationIngestor
from bbagent.logging_config import get_logger
from bbagent.program.manager import ProgramManager
from bbagent.scope.engine import ScopeEngine
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore

log = get_logger(__name__)


class BrowserLaunchRefused(Exception):
    """Raised when a real browser session is refused (e.g. dry-run/not-live)."""


@dataclass
class ExplorationStep:
    """One controlled action for the browser to perform."""

    action: str                      # "goto" | "click" | "type" | "scroll"
    target: str | None = None        # URL for goto; selector for click/type/scroll
    text: str | None = None          # text for "type" (never logged)
    # For a password/secret field, the caller sets secret=True so the value is never
    # echoed into logs or reports (the value itself still comes from the caller/env).
    secret: bool = False
    amount: int = 3                  # scroll ticks


@dataclass
class ActOutcome:
    """Result of a single controlled browser action."""

    performed: bool
    refused_out_of_scope: bool
    exchanges: list[ObservedExchange] = field(default_factory=list)


@dataclass
class ExploreResult:
    report: IngestReport
    steps_executed: int = 0
    navigations_refused: int = 0
    exchanges_captured: int = 0

    def render(self) -> str:
        lines = [
            f"# Browser exploration — {self.report.program}",
            f"steps executed:        {self.steps_executed}",
            f"navigations refused:   {self.navigations_refused} (out-of-scope, fail-closed)",
            f"exchanges captured:    {self.exchanges_captured}",
            "",
            self.report.render(),
        ]
        return "\n".join(lines)


class BrowserBackend(abc.ABC):
    """Abstract browser driver. Implementations perform actions and buffer the
    :class:`ObservedExchange` objects their traffic produced (drained per step)."""

    @abc.abstractmethod
    async def start(self) -> None: ...

    @abc.abstractmethod
    async def goto(self, url: str) -> None: ...

    @abc.abstractmethod
    async def click(self, selector: str) -> None: ...

    @abc.abstractmethod
    async def type_text(self, selector: str, text: str) -> None: ...

    @abc.abstractmethod
    async def scroll(self, selector: str | None = None, amount: int = 3) -> None: ...

    @abc.abstractmethod
    async def drain(self) -> list[ObservedExchange]:
        """Return and clear the exchanges captured since the last drain."""

    @abc.abstractmethod
    async def close(self) -> None: ...


class BrowserController:
    """Runs a controlled exploration and ingests the observed traffic."""

    def __init__(
        self,
        program: ProgramManager,
        surface: SurfaceStore,
        backend: BrowserBackend,
        *,
        default_identity: AuthIdentity = AuthIdentity.IDENTITY_A,
        identity_map: dict[str, AuthIdentity] | None = None,
    ):
        self.program = program
        self.surface = surface
        self.backend = backend
        self._scope = ScopeEngine(program.config.scope)
        self._ingestor = NetworkObservationIngestor(
            program, surface, default_identity=default_identity,
            identity_map=identity_map,
        )

    # --- single-step control (reused by the autonomous loop) ------------------

    def in_scope(self, url: str) -> bool:
        return self._scope.is_allowed(url)

    async def start(self) -> None:
        await self.backend.start()

    async def close(self) -> None:
        await self.backend.close()

    async def act(self, step: ExplorationStep) -> ActOutcome:
        """Perform ONE action and return the traffic it generated.

        A ``goto`` to an out-of-scope URL is refused fail-closed (no navigation).
        The backend must already be started.
        """
        if step.action == "goto":
            url = step.target or ""
            if not self._scope.is_allowed(url):
                log.info("browser.goto_refused_out_of_scope", url=url)
                return ActOutcome(performed=False, refused_out_of_scope=True)
            await self.backend.goto(url)
        elif step.action == "click":
            await self.backend.click(step.target or "")
        elif step.action == "type":
            # The text value is never logged (secret-safe by construction).
            await self.backend.type_text(step.target or "", step.text or "")
        elif step.action == "scroll":
            await self.backend.scroll(step.target, step.amount)
        else:
            log.warning("browser.unknown_action", action=step.action)
            return ActOutcome(performed=False, refused_out_of_scope=False)
        return ActOutcome(performed=True, refused_out_of_scope=False,
                          exchanges=await self.backend.drain())

    def ingest_exchanges(self, exchanges: list[ObservedExchange]) -> IngestReport:
        """Ingest already-captured exchanges into the surface (scope enforced)."""
        return self._ingestor.ingest(exchanges)

    async def explore(self, steps: list[ExplorationStep]) -> ExploreResult:
        captured: list[ObservedExchange] = []
        executed = 0
        refused = 0

        await self.start()
        try:
            for step in steps:
                outcome = await self.act(step)
                if outcome.refused_out_of_scope:
                    refused += 1
                    continue
                if not outcome.performed:
                    continue
                executed += 1
                captured.extend(outcome.exchanges)
        finally:
            await self.close()

        report = self.ingest_exchanges(captured)
        return ExploreResult(report=report, steps_executed=executed,
                             navigations_refused=refused, exchanges_captured=len(captured))


def ensure_live_allowed(program: ProgramManager, *, live: bool) -> None:
    """Gate for launching a REAL browser against a program.

    A real session is refused while the program is dry-run/NOT-READY, or unless the
    operator has explicitly opted into a live browser session. This keeps real Temu
    execution disabled: programs/temu.yaml is dry_run_only=true.
    """
    if program.config.dry_run_only:
        raise BrowserLaunchRefused(
            f"REFUSING real browser session: program '{program.name}' is dry_run_only "
            f"(NOT READY). Real execution is disabled.")
    if not live:
        raise BrowserLaunchRefused(
            "REFUSING real browser session: live browser not enabled "
            "(pass --live and set BBAGENT_BROWSER_LIVE=1).")
