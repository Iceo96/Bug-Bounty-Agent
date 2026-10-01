"""Local, policy-aware Temu SIMULATION environment.

This NEVER contacts Temu, resolves Temu DNS, or opens a socket. All traffic is
served by an in-process ``httpx.MockTransport``. It lets us exercise the full
autonomous pipeline against Temu-shaped endpoints using Temu's REAL scope,
capability matrix (IDOR/BFLA/SQLi allowed; reflected XSS forbidden), exclusions,
required research header, and data-scoping.

The real Temu policy (``programs/temu.yaml``) is unchanged and remains NOT READY /
``dry_run_only: true``. The simulation program below derives from it and fills only
the runnability gaps (methods, tools, budget, dry_run_only=false, plus ONE
simulation-only second identity for the differential detectors). Findings produced
here live under a clearly-labelled SIMULATION program name so they can never be
mistaken for a real Temu finding.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from bbagent.config.loader import load_program
from bbagent.config.models import ProgramConfig
from bbagent.program.manager import ProgramManager

_TEMU_YAML = str(Path(__file__).resolve().parents[2] / "programs" / "temu.yaml")

# An in-scope Temu host used only for the simulated endpoints (served via mock).
BASE = "https://seller.temu.com"
MANIFEST_URL = f"{BASE}/sim/manifest"

# Synthetic authorized test entities for the simulation (not real Temu data).
OBJECT_ID = "6710000000000000000000ab"      # researcher-owned test object (24-hex)
SQLI_BASELINE_ID = "1"

# Synthetic, non-secret simulation bearer tokens + env vars.
RESEARCHER_TOKEN = "temusim-researcher-token"
OTHER_TOKEN = "temusim-other-token"
ENV_RESEARCHER = "BBAGENT_TEMU_TOKEN"        # same env the real policy references
ENV_OTHER = "BBAGENT_TEMU_SIM_OTHER_TOKEN"
H1_ENV = "BBAGENT_H1_USERNAME"

_TOKENS = {RESEARCHER_TOKEN: ("researcher", "user"), OTHER_TOKEN: ("sim_other", "admin")}

_ADMIN_REPORT = {"report": {"classification": "restricted",
                            "records": [{"seller": "acme", "plan": "gold"}]}}
_ADMIN_SETTINGS = {"settings": {"classification": "restricted", "flags": {"beta": True}}}


def _manifest() -> dict:
    return {"application": "temu-sim", "endpoints": [
        {"url": "/sim/v1/orders/{id}", "method": "GET", "object_scoped": True,
         "example_object_url": f"/sim/v1/orders/{OBJECT_ID}"},
        {"url": "/sim/v1/profiles/{id}", "method": "GET", "object_scoped": True,
         "example_object_url": f"/sim/v1/profiles/{OBJECT_ID}"},
        {"url": "/sim/admin/report", "method": "GET", "example_object_url": "/sim/admin/report"},
        {"url": "/sim/admin/settings", "method": "GET", "example_object_url": "/sim/admin/settings"},
        {"url": "/sim/admin/ping", "method": "GET", "example_object_url": "/sim/admin/ping"},
        {"url": "/sim/catalog", "method": "GET", "example_object_url": f"/sim/catalog?id={SQLI_BASELINE_ID}"},
        {"url": "/sim/catalog-safe", "method": "GET", "example_object_url": f"/sim/catalog-safe?id={SQLI_BASELINE_ID}"},
        {"url": "/sim/catalog-info", "method": "GET", "example_object_url": f"/sim/catalog-info?id={SQLI_BASELINE_ID}"},
        # A reflected-XSS-shaped endpoint that must NEVER be planned/executed (FORBIDDEN).
        {"url": "/sim/search", "method": "GET", "example_object_url": "/sim/search?q=probe"},
    ]}


def _json(status: int, payload: dict) -> httpx.Response:
    return httpx.Response(status, headers={"content-type": "application/json"}, text=json.dumps(payload))


def _identity(request: httpx.Request):
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return _TOKENS.get(auth[7:].strip())
    return None


def _catalog(id_value: str, *, safe: bool, control: bool) -> dict:
    if control:
        n = 1
    elif safe:
        n = 1 if id_value == "1" else 0
    else:
        n = 5 if "OR 1=1" in id_value else (0 if "AND 1=2" in id_value else 1)
    return {"items": [{"name": f"item{i}"} for i in range(n)], "count": n}


def temu_mock_handler(request: httpx.Request) -> httpx.Response:
    from urllib.parse import urlsplit
    path = urlsplit(str(request.url)).path
    ident = _identity(request)
    label = ident[0] if ident else None
    role = ident[1] if ident else None

    if path == "/sim/manifest":
        return _json(200, _manifest())

    if path.startswith("/sim/v1/orders/"):
        if label is None:
            return _json(401, {"error": "unauthenticated"})
        return _json(200, {"order": {"id": path.rsplit("/", 1)[-1], "item": "widget", "total": 999}})
    if path.startswith("/sim/v1/profiles/"):
        if label is None:
            return _json(401, {"error": "unauthenticated"})
        pid = path.rsplit("/", 1)[-1]
        if label != ("researcher" if pid == OBJECT_ID else None):
            return _json(403, {"error": "forbidden"})
        return _json(200, {"profile": {"id": pid, "email": "researcher@example.test"}})

    if path == "/sim/admin/report":
        if label is None:
            return _json(401, {"error": "unauthenticated"})
        return _json(200, _ADMIN_REPORT)
    if path == "/sim/admin/settings":
        if label is None:
            return _json(401, {"error": "unauthenticated"})
        return _json(200 if role == "admin" else 403,
                     _ADMIN_SETTINGS if role == "admin" else {"error": "forbidden"})
    if path == "/sim/admin/ping":
        if label is None:
            return _json(401, {"error": "unauthenticated"})
        return _json(200, {"ok": True})

    if path == "/sim/catalog":
        return _json(200, _catalog(request.url.params.get("id", ""), safe=False, control=False))
    if path == "/sim/catalog-safe":
        return _json(200, _catalog(request.url.params.get("id", ""), safe=True, control=False))
    if path == "/sim/catalog-info":
        return _json(200, _catalog(request.url.params.get("id", ""), safe=False, control=True))

    if path == "/sim/search":
        q = request.url.params.get("q", "")
        return httpx.Response(200, headers={"content-type": "text/html"},
                              text=f"<html><body><p>{q}</p></body></html>")

    return _json(404, {"error": "not_found"})


class TemuMockTransport(httpx.MockTransport):
    """MockTransport that counts how many requests actually reached the handler."""

    def __init__(self):
        self.calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            self.calls += 1
            return temu_mock_handler(request)
        super().__init__(handler)


def temu_mock_transport() -> TemuMockTransport:
    return TemuMockTransport()


def build_temu_sim_program() -> ProgramManager:
    """Temu policy (scope + matrix + exclusions + header) + SIMULATION runnability."""
    data = load_program(_TEMU_YAML).model_dump()
    data.update({
        "name": "temu-SIMULATION-LOCAL-MOCK (not a live target)",
        "dry_run_only": False,                       # SIMULATION: run against the mock
        "allowed_tools": ["http", "recon"],          # SIMULATION gap-fill
        "allow_unauthenticated": True,               # SIMULATION gap-fill
        "request_budget": {"total": 500, "per_target": 500, "per_tool": 500},
        "needs_human_review": [],
        # Keep DataScope ENFORCED, authorizing only the simulation's own test entities.
        "data_scope": {"enforce": True,
                       "authorized_object_ids": [OBJECT_ID, SQLI_BASELINE_ID],
                       "authorized_url_prefixes": []},
        # The SIMULATION uses per-identity bearer tokens so the differential
        # detectors (IDOR/BFLA) can exercise two identities against the mock. The
        # REAL programs/temu.yaml uses Cookie + VerifyAuthToken session headers; that
        # auth flow is covered by test_temu_auth.py, not this pipeline sim.
        "required_header_refs": {"X-HackerOne-Research": H1_ENV},
        "test_accounts": [
            {"label": "researcher", "role": "user", "username": "self-registered",
             "secret_env": ENV_RESEARCHER, "notes": "Researcher-owned Temu test account."},
            {"label": "sim_other", "role": "admin", "secret_env": ENV_OTHER,
             "notes": "SIMULATION-ONLY second identity for differential detectors; "
                      "NOT a real Temu-authorized account."},
        ],
    })
    # allowed_vulnerability_classes (idor/privilege_escalation/sql_injection) and the
    # forbidden reflected-xss come straight from programs/temu.yaml unchanged.
    data["restrictions"]["allowed_methods"] = ["GET"]   # SIMULATION gap-fill
    return ProgramManager(ProgramConfig.model_validate(data))
