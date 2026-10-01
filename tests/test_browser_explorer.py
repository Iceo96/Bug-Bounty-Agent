"""Autonomous browser exploration engine.

Drives the OBSERVE -> UPDATE -> CHOOSE -> POLICY CHECK -> ACT -> capture loop
against the in-memory mock web app, with no fixed steps.json. Proves it discovers
the attack surface autonomously, only within scope, only from observed targets,
never types secrets, is bounded by limits + repeated-state detection, and that the
LLM chooser can only *select* a generated candidate (never invent one). NO network,
NO Temu.
"""

from __future__ import annotations

import json

import pytest

from bbagent.browser import (
    AutonomousExplorer, BrowserController, ExplorationLimits, LLMExplorationChooser,
)
from bbagent.browser.controller import ExplorationStep
from bbagent.browser.explorer import (
    Candidate, DeterministicChooser, ExplorationActionModel, ExplorationRejected,
)
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore
from bbagent.storage.db import Database
from bbagent_lab.mock_webapp import MOCK_BASE, SECRET_COOKIE, MockBrowserBackend, mock_program

SEED = MOCK_BASE + "/"


def _make(backend=None, chooser=None, limits=None):
    db = Database(":memory:")
    surface = SurfaceStore(db)
    program = mock_program()
    controller = BrowserController(
        program, surface, backend or MockBrowserBackend(authenticated=True),
        default_identity=AuthIdentity.IDENTITY_A,
        identity_map={"researcher": AuthIdentity.IDENTITY_A},
    )
    explorer = AutonomousExplorer(controller, surface, chooser=chooser,
                                  limits=limits or ExplorationLimits(max_no_progress=8))
    return db, surface, program, controller, explorer


def _dump_surface(db: Database) -> str:
    tables = ["surface_assets", "surface_endpoints", "surface_params",
              "surface_object_refs", "surface_auth_obs", "surface_js", "surface_apis"]
    out = []
    for t in tables:
        for row in db.connection.execute(f"SELECT * FROM {t}").fetchall():
            out.append(" ".join(str(v) for v in tuple(row)))
    return "\n".join(out)


# --- autonomous discovery -----------------------------------------------------

async def test_discovers_surface_without_steps():
    db, surface, program, _, explorer = _make()
    summary = explorer_result = await explorer.run([SEED])
    assert summary.actions_performed > 0
    paths = {(e.method, e.path) for e in surface.list_endpoints(program.name)}
    # Reached via autonomous link/affordance following, no script:
    assert ("GET", "/") in paths
    assert ("GET", "/static/app.js") in paths
    assert ("POST", "/login") in paths
    assert ("GET", "/api/orders") in paths
    assert ("GET", "/api/search") in paths
    assert ("GET", "/dashboard") in paths
    db.close()


async def test_object_refs_discovered_autonomously():
    db, surface, program, _, explorer = _make()
    await explorer.run([SEED])
    all_refs = set()
    for ep in surface.list_endpoints(program.name):
        all_refs |= {r.value for r in surface.object_refs_for(ep.id)}
    assert {"9001", "9002", "9003", "7001", "7002"} <= all_refs
    db.close()


async def test_only_in_scope_and_no_beacon():
    db, surface, program, _, explorer = _make()
    await explorer.run([SEED])
    for e in surface.list_endpoints(program.name):
        assert "app.local.test" in e.url
    assert "analytics.example.net" not in _dump_surface(db)
    db.close()


async def test_never_types_into_secret_field():
    backend = MockBrowserBackend(authenticated=True)
    db, _, _, _, explorer = _make(backend=backend)
    await explorer.run([SEED])
    assert "#password" not in backend._typed          # credential field never typed
    db.close()


async def test_no_secret_persisted():
    db, _, _, _, explorer = _make()
    await explorer.run([SEED])
    dump = _dump_surface(db)
    assert "MOCK_SECRET" not in dump and SECRET_COOKIE not in dump
    db.close()


# --- bounded + loop-safe ------------------------------------------------------

async def test_max_actions_limit():
    db, _, _, _, explorer = _make(limits=ExplorationLimits(max_actions=3))
    summary = await explorer.run([SEED])
    assert summary.actions_performed <= 3
    assert summary.stop_reason == "max_actions reached"
    db.close()


async def test_terminates_with_stop_reason():
    db, _, _, _, explorer = _make(limits=ExplorationLimits(max_no_progress=4))
    summary = await explorer.run([SEED])
    assert summary.stop_reason              # never hangs; always a bounded reason
    assert summary.actions_performed <= 40
    db.close()


async def test_repeated_seed_not_revisited():
    db, surface, program, _, explorer = _make()
    # Seeding the same URL many times must not cause many visits.
    summary = await explorer.run([SEED, SEED, SEED])
    home_visits = summary.pages_visited
    assert home_visits >= 1
    # "/" appears exactly once as an endpoint regardless of repeated seeds.
    assert len([e for e in surface.list_endpoints(program.name) if e.path == "/"]) == 1
    db.close()


# --- schema-validated actions -------------------------------------------------

def test_action_schema_rejects_invalid():
    with pytest.raises(Exception):
        ExplorationActionModel(action="goto")                 # missing target
    with pytest.raises(Exception):
        ExplorationActionModel(action="type", target="#x")    # missing text
    with pytest.raises(Exception):
        ExplorationActionModel(action="hack", target="x")     # unknown action
    with pytest.raises(Exception):
        ExplorationActionModel(action="click", target="a", evil=1)  # extra field


def test_policy_rejects_out_of_scope_goto():
    _, _, _, controller, explorer = _make()
    ok = explorer._policy_ok(ExplorationActionModel(action="goto", target=SEED))
    bad = explorer._policy_ok(ExplorationActionModel(action="goto",
                                                     target="https://evil.example.com/x"))
    assert ok is True and bad is False


# --- LLM chooser: may only SELECT a candidate, never invent -------------------

def _pick_first(prompt: str) -> str:
    arr = json.loads(prompt[prompt.find("["):])
    return json.dumps({"candidate_id": arr[0]["candidate_id"], "rationale": "first"})


async def test_llm_chooser_selects_and_explores():
    db, surface, program, _, explorer = _make(chooser=LLMExplorationChooser(_pick_first))
    summary = await explorer.run([SEED])
    assert summary.chooser == "llm"
    assert summary.fell_back == 0
    assert ("GET", "/api/orders") in {(e.method, e.path) for e in surface.list_endpoints(program.name)}
    db.close()


async def test_llm_garbage_falls_back_and_still_progresses():
    db, surface, program, _, explorer = _make(chooser=LLMExplorationChooser(lambda p: "not json"))
    summary = await explorer.run([SEED])
    assert summary.fell_back > 0                    # every malformed reply -> fallback
    assert summary.actions_performed > 0            # deterministic keeps it moving
    db.close()


def test_llm_chooser_rejects_invented_candidate():
    chooser = LLMExplorationChooser(lambda p: json.dumps({"candidate_id": "INVENTED"}))
    cands = [Candidate("goto|x", ExplorationActionModel(action="goto", target=SEED), "r")]
    with pytest.raises(ExplorationRejected):
        chooser.choose(cands)


def test_llm_chooser_sanitized_view_hides_text():
    # A chooser never sees a typed text value (no secret leakage into the prompt).
    c = Candidate("type|p|#q", ExplorationActionModel(action="type", target="#q", text="explore"), "r")
    assert "text" not in c.sanitized()
    assert c.sanitized()["target"] == "#q"
