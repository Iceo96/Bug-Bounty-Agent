"""Diagnosing low live-Temu exploration coverage.

Reproduces, with a local mock backend (NO network, NO Temu), the exact shape of the
live run: a client-rendered SPA shell served from an in-scope host while almost all
of its traffic goes to OUT-OF-SCOPE hosts (CDN/img/api/analytics). This deterministic
model recreates "12 seen, 11 dropped, 1 in-scope, 2 actions, 0 hypotheses" and lets
us verify each part of the diagnosis. Also verifies affordance extraction and the
authenticated-observation classification, without exposing any secret.
"""

from __future__ import annotations

import asyncio

from bbagent.browser.affordances import parse_affordances
from bbagent.browser.controller import BrowserBackend, BrowserController
from bbagent.browser.explorer import AutonomousExplorer, ExplorationLimits
from bbagent.browser.models import ObservedExchange
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore
from bbagent.storage.db import Database
from bbagent_lab.mock_webapp import MOCK_BASE, mock_program

HOME = MOCK_BASE + "/"
REGION = MOCK_BASE + "/region"
# Out-of-scope hosts a real SPA beacons to (CDN/img/api/analytics). 11 of them.
_OUT_HOSTS = [
    "static.cdn-example.net", "img.cdn-example.net", "assets.cdn-example.net",
    "api.other-host.test", "gw.other-host.test", "log.other-host.test",
    "analytics.example.net", "metrics.example.net", "ads.example-3p.net",
    "fonts.example-cdn.net", "rum.example-cdn.net",
]
# A fake secret placed in a DROPPED exchange; must never be stored or surfaced.
_FAKE_COOKIE = "sid=SPA_FAKE_SECRET_do_not_store"

# SPA shell: a root div + an external script, and exactly ONE same-host link.
_SPA_HOME = ("<html><head><script src='https://static.cdn-example.net/app.js'></script>"
             "</head><body><div id='root'></div><a href='/region'>region</a></body></html>")
_SPA_REGION = "<html><head></head><body><div id='root'></div></body></html>"
_RICH = ("<html><body><a href='/a'>a</a><a href='/b'>b</a>"
         "<form action='/search'><input name='q'></form>"
         "<button data-explore='go'>go</button></body></html>")


class SpaLikeBackend(BrowserBackend):
    """Mimics Temu: in-scope SPA document + many out-of-scope sub-resources."""

    def __init__(self) -> None:
        self._buf: list[ObservedExchange] = []

    def _doc(self, url: str, body: str) -> ObservedExchange:
        # Authenticated request: PlaywrightBackend keeps the Cookie header NAME with
        # a redacted (empty) value, so identity can be inferred without the secret.
        return ObservedExchange(
            method="GET", url=url, status=200,
            request_headers={"Cookie": ""}, response_headers={"Content-Type": "text/html"},
            response_body=body, source_page=None, identity_label="researcher")

    async def start(self) -> None:
        self._buf.clear()

    async def close(self) -> None:
        self._buf.clear()

    async def goto(self, url: str) -> None:
        base = url.split("#", 1)[0].rstrip("/")
        if base == MOCK_BASE:
            self._buf.append(self._doc(HOME, _SPA_HOME))
            # 11 out-of-scope sub-resources (dropped fail-closed). One carries a fake
            # secret cookie value to prove dropped traffic is never stored.
            for i, host in enumerate(_OUT_HOSTS):
                self._buf.append(ObservedExchange(
                    method="GET", url=f"https://{host}/r{i}", status=200,
                    request_headers={"Cookie": _FAKE_COOKIE if i == 0 else ""},
                    response_headers={"Content-Type": "application/javascript"},
                    response_body="x", identity_label="researcher"))
        elif base == MOCK_BASE + "/region":
            self._buf.append(self._doc(REGION, _SPA_REGION))

    async def click(self, selector: str) -> None: return None
    async def type_text(self, selector: str, text: str) -> None: return None
    async def scroll(self, selector: str | None = None, amount: int = 3) -> None: return None

    async def drain(self) -> list[ObservedExchange]:
        out = self._buf
        self._buf = []
        return out


def _dump(db: Database) -> str:
    out = []
    for t in ["surface_assets", "surface_endpoints", "surface_params",
              "surface_object_refs", "surface_auth_obs", "surface_js", "surface_apis"]:
        for row in db.connection.execute(f"SELECT * FROM {t}").fetchall():
            out.append(" ".join(str(v) for v in tuple(row)))
    return "\n".join(out)


def _run_spa():
    db = Database(":memory:")
    surface = SurfaceStore(db)
    program = mock_program()
    controller = BrowserController(program, surface, SpaLikeBackend(),
                                   default_identity=AuthIdentity.IDENTITY_A,
                                   identity_map={"researcher": AuthIdentity.IDENTITY_A})
    explorer = AutonomousExplorer(controller, surface,
                                  limits=ExplorationLimits(max_no_progress=6))
    summary = asyncio.run(explorer.run([HOME]))
    return db, surface, program, summary


# --- reproduce the live shape -------------------------------------------------

def test_reproduces_low_coverage_shape():
    db, _, _, s = _run_spa()
    assert s.actions_performed == 2                 # seed + 1 same-host link
    assert s.endpoints_discovered == 2              # only the two in-scope documents
    assert s.out_of_scope_dropped == 11             # every SPA sub-resource dropped
    assert s.exchanges_seen == 13                   # 12 on home + 1 on region
    assert s.stop_reason == "frontier exhausted"    # nothing left to visit
    assert s.object_refs_discovered == 0            # -> planner generates 0 hypotheses
    db.close()


def test_dropped_hosts_are_host_only_no_secrets():
    db, _, _, s = _run_spa()
    assert set(s.dropped_hosts) == set(_OUT_HOSTS)
    for h in s.dropped_hosts:                        # host-only: no path, query, or creds
        assert "/" not in h and "?" not in h and "=" not in h
    # The fake secret from a dropped exchange is never stored anywhere.
    assert "SPA_FAKE_SECRET" not in _dump(db)
    db.close()


def test_authenticated_observation_without_secrets():
    db, surface, program, s = _run_spa()
    # Both in-scope documents were observed as AUTHENTICATED (identity value only).
    assert s.authenticated_endpoints == 2
    assert s.unauthenticated_endpoints == 0
    for ep in surface.list_endpoints(program.name):
        idents = {o.identity for o in surface.auth_observations_for(ep.id)}
        assert AuthIdentity.IDENTITY_A.value in idents
    # No cookie value anywhere in the stored surface.
    assert "SPA_FAKE_SECRET" not in _dump(db)
    db.close()


def test_affordances_empty_on_spa_but_present_on_rich_html():
    # Pinpoints the cause as dynamic/SPA rendering, NOT a parser bug.
    spa = parse_affordances(HOME, _SPA_REGION)
    assert not spa.links and not spa.forms and not spa.click_selectors
    rich = parse_affordances(HOME, _RICH)
    assert len(rich.links) == 2 and len(rich.forms) == 1 and len(rich.click_selectors) == 1


def test_affordances_seen_diagnostic_counts_only_static_links():
    _, _, _, s = _run_spa()
    # Home exposed exactly one static <a>; region exposed none.
    assert s.affordances_seen == 1
