"""Browser-driven, passive network-observation layer.

This package turns *already-observed* authenticated browser traffic (e.g. a HAR
export from a real, human-driven session) into rows in the existing
:class:`bbagent.surface.store.SurfaceStore`. It is a DISCOVERY source only:

* It never opens a socket, resolves DNS, or issues an HTTP request. All traffic
  was produced by the operator's browser; we only read the recording.
* Every observed exchange is filtered fail-closed through the program's
  :class:`bbagent.scope.engine.ScopeEngine` — out-of-scope traffic is dropped and
  never recorded.
* It records endpoints, parameters, object-reference *candidates*, and auth
  *observations* — never a vulnerability assertion and never authentication
  material (cookies/tokens are read only to label identity and are never stored).

Active testing of anything discovered here still flows exclusively through the
existing PolicyGatedHTTP → AuthorizedHTTPClient path, so ScopeEngine, DataScope,
RunBudget, evidence integrity, human review, and the no-auto-submission rule all
continue to apply unchanged.
"""

from bbagent.browser.controller import (
    BrowserBackend,
    BrowserController,
    BrowserLaunchRefused,
    ExplorationStep,
    ExploreResult,
    ensure_live_allowed,
)
from bbagent.browser.explorer import (
    AutonomousExplorer,
    DeterministicChooser,
    ExplorationActionModel,
    ExplorationLimits,
    ExplorationSummary,
    LLMExplorationChooser,
    seed_origins_from_scope,
)
from bbagent.browser.har import parse_har
from bbagent.browser.identities import (
    ProfileConflict,
    ResearchHeaderUnavailable,
    build_identity_backends,
    identity_profiles,
    research_headers,
)
from bbagent.browser.models import IngestReport, ObservedExchange
from bbagent.browser.observe import NetworkObservationIngestor, ingest_har

__all__ = [
    "ObservedExchange",
    "IngestReport",
    "NetworkObservationIngestor",
    "parse_har",
    "ingest_har",
    "BrowserBackend",
    "BrowserController",
    "BrowserLaunchRefused",
    "ExplorationStep",
    "ExploreResult",
    "ensure_live_allowed",
    "AutonomousExplorer",
    "ExplorationLimits",
    "ExplorationSummary",
    "ExplorationActionModel",
    "DeterministicChooser",
    "LLMExplorationChooser",
    "seed_origins_from_scope",
    "build_identity_backends",
    "identity_profiles",
    "research_headers",
    "ProfileConflict",
    "ResearchHeaderUnavailable",
]
