"""Authenticated browser controller.

Drives the controller against a deterministic in-memory mock web application (no
sockets, no real browser) and proves: navigate/click/type/scroll generate captured
traffic that lands in the existing SurfaceStore; scope is fail-closed for both
navigation and observed sub-resources; no auth secret (cookie or typed password)
is ever persisted; and a REAL browser session is refused for dry-run programs
(Temu). NO network access and NO connection to Temu occur here.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from bbagent.browser import (
    BrowserController, BrowserLaunchRefused, ExplorationStep, ensure_live_allowed,
)
from bbagent.browser.playwright_backend import PlaywrightBackend
from bbagent.config.loader import load_program
from bbagent.program.manager import ProgramManager
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore
from bbagent.storage.db import Database
from bbagent import cli
from bbagent_lab.mock_webapp import (
    MOCK_BASE, SECRET_COOKIE, MockBrowserBackend, mock_program,
)

TEMU_YAML = str(Path(__file__).resolve().parents[1] / "programs" / "temu.yaml")
PASSWORD = "hunter2_secret_pw_do_not_persist"


def _full_steps() -> list[ExplorationStep]:
    return [
        ExplorationStep("goto", MOCK_BASE + "/"),
        ExplorationStep("type", "#username", "researcher@example.test"),
        ExplorationStep("type", "#password", PASSWORD, secret=True),
        ExplorationStep("click", "login"),
        ExplorationStep("click", "orders"),
        ExplorationStep("scroll", None, amount=2),
        ExplorationStep("goto", MOCK_BASE + "/dashboard"),
    ]


def _dump_surface(db: Database) -> str:
    tables = ["surface_assets", "surface_endpoints", "surface_params",
              "surface_object_refs", "surface_auth_obs", "surface_js", "surface_apis"]
    out: list[str] = []
    for t in tables:
        for row in db.connection.execute(f"SELECT * FROM {t}").fetchall():
            out.append(" ".join(str(v) for v in tuple(row)))
    return "\n".join(out)


@pytest.fixture
async def explored():
    db = Database(":memory:")
    surface = SurfaceStore(db)
    program = mock_program()
    controller = BrowserController(
        program, surface, MockBrowserBackend(),
        default_identity=AuthIdentity.IDENTITY_A,
        identity_map={"researcher": AuthIdentity.IDENTITY_A},
    )
    result = await controller.explore(_full_steps())
    yield db, surface, program, result
    db.close()


# --- exploration drives capture into the existing graph -----------------------

async def test_actions_generate_captured_traffic(explored):
    _, _, _, result = explored
    assert result.steps_executed == 7
    assert result.exchanges_captured == 7          # 3 (home) +login +orders +scroll +dashboard
    assert result.report.in_scope == 6             # the out-of-scope beacon is excluded
    assert result.report.out_of_scope_dropped == 1


def test_distinct_endpoints_recorded(explored):
    _, surface, program, _ = explored
    keys = {(e.method, e.path) for e in surface.list_endpoints(program.name)}
    assert ("GET", "/") in keys
    assert ("GET", "/static/app.js") in keys
    assert ("POST", "/login") in keys
    assert ("GET", "/api/orders") in keys          # both pages merge on templated path
    assert ("GET", "/dashboard") in keys
    assert all("app.local.test" in e.url for e in surface.list_endpoints(program.name))


def test_object_ref_candidates_captured(explored):
    _, surface, program, _ = explored
    orders = next(e for e in surface.list_endpoints(program.name) if e.path == "/api/orders")
    values = {r.value for r in surface.object_refs_for(orders.id)}
    assert {"9001", "9002", "9003", "u-1", "u-2", "u-3"} <= values
    assert all(r.candidate for r in surface.object_refs_for(orders.id))


def test_page_param_from_scroll(explored):
    _, surface, program, _ = explored
    orders = next(e for e in surface.list_endpoints(program.name) if e.path == "/api/orders")
    assert any(p.name == "page" for p in surface.parameters_for(orders.id))


def test_auth_observations_reflect_login(explored):
    _, surface, program, _ = explored
    home = next(e for e in surface.list_endpoints(program.name) if e.path == "/")
    orders = next(e for e in surface.list_endpoints(program.name) if e.path == "/api/orders")
    assert AuthIdentity.UNAUTHENTICATED.value in {o.identity for o in surface.auth_observations_for(home.id)}
    assert AuthIdentity.IDENTITY_A.value in {o.identity for o in surface.auth_observations_for(orders.id)}


def test_js_asset_recorded(explored):
    _, surface, program, _ = explored
    assert any(j.url.endswith("/static/app.js") for j in surface.list_js_assets(program.name))


# --- fail-closed scope --------------------------------------------------------

async def test_out_of_scope_navigation_refused():
    db = Database(":memory:")
    surface = SurfaceStore(db)
    program = mock_program()
    controller = BrowserController(program, surface, MockBrowserBackend())
    result = await controller.explore([
        ExplorationStep("goto", MOCK_BASE + "/"),
        ExplorationStep("goto", "https://evil.example.com/x"),   # off-scope
    ])
    assert result.navigations_refused == 1
    assert result.steps_executed == 1
    assert all("evil.example.com" not in e.url for e in surface.list_endpoints(program.name))
    db.close()


# --- secrets are never persisted ----------------------------------------------

def test_no_cookie_or_password_persisted(explored):
    db, _, _, _ = explored
    dump = _dump_surface(db)
    assert "MOCK_SECRET" not in dump
    assert SECRET_COOKIE not in dump
    assert PASSWORD not in dump
    assert "Cookie" not in dump


# --- real-session gate: Temu stays disabled -----------------------------------

def test_real_session_refused_for_temu_dry_run():
    temu = ProgramManager(load_program(TEMU_YAML))
    assert temu.config.dry_run_only is True
    with pytest.raises(BrowserLaunchRefused) as exc:
        ensure_live_allowed(temu, live=True)
    assert "dry_run_only" in str(exc.value)


def test_real_session_requires_live_optin():
    prog = mock_program()                       # not dry-run
    with pytest.raises(BrowserLaunchRefused):
        ensure_live_allowed(prog, live=False)
    ensure_live_allowed(prog, live=True)        # allowed only with explicit opt-in


def test_cli_browse_refuses_temu(tmp_path, capsys):
    steps = tmp_path / "steps.json"
    steps.write_text(json.dumps([{"action": "goto", "target": "https://www.temu.com/"}]),
                     encoding="utf-8")
    rc = cli.main(["--db", str(tmp_path / "b.db"), "browse", TEMU_YAML, "--steps", str(steps),
                   "--live"])
    assert rc == 2
    assert "REFUSING real browser session" in capsys.readouterr().err


# --- Playwright backend is optional (lazy import) -----------------------------

async def test_playwright_backend_is_lazy_and_optional():
    if importlib.util.find_spec("playwright") is not None:
        pytest.skip("playwright is installed; lazy-import failure path not exercised")
    backend = PlaywrightBackend()                # construction must not import playwright
    with pytest.raises(RuntimeError, match="Playwright is not installed"):
        await backend.start()


def test_typed_password_never_emitted():
    # A typed value produces no exchange at all (defensive: no secret in traffic).
    backend = MockBrowserBackend()
    import asyncio
    asyncio.run(backend.start())
    asyncio.run(backend.type_text("#password", PASSWORD))
    assert asyncio.run(backend.drain()) == []
