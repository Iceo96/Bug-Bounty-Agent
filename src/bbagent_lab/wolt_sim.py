"""Local, policy-aware Wolt SIMULATION environment.

This NEVER contacts Wolt, resolves Wolt DNS, or opens a socket. All traffic is
served by an in-process ``httpx.MockTransport``. It lets us exercise the full
autonomous pipeline and Wolt's policy semantics against Wolt-shaped endpoints,
entirely locally.

The real Wolt policy (``programs/wolt.yaml``) is unchanged and remains NOT READY /
``dry_run_only: true``. The simulation program below reuses Wolt's real scope,
exclusions, forbidden endpoints, required research header (env-ref), forbidden
actions, and the ``consumer_test`` identity — but fills the NEEDS_HUMAN_REVIEW
gaps (methods, tools, vuln classes, budget) with clearly labelled SIMULATION-ONLY
values so the pipeline can run. It also adds ONE simulation-only second identity
(``sim_other``) purely to exercise the differential (IDOR/BFLA) detectors; this is
NOT a claim that Wolt authorizes a second account.
"""

from __future__ import annotations

import html as _html
import json
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from bbagent.config.loader import load_program
from bbagent.config.models import ProgramConfig
from bbagent.program.manager import ProgramManager

_WOLT_YAML = str(Path(__file__).resolve().parents[2] / "programs" / "wolt.yaml")

# In-scope Wolt host used for the simulated endpoints (served only via mock).
BASE = "https://restaurant-api.wolt.com"
MANIFEST_URL = f"{BASE}/sim/manifest"

# Wolt-published test identifiers (public, from the program rules).
CONSUMER_USER_ID = "670fa3e9ead6e49d65cc3614"
VENUE_ID = "670e7897e3c56dcc5b5a0989"

# Synthetic, non-secret simulation bearer tokens + their env vars.
CONSUMER_TOKEN = "woltsim-consumer-token"
OTHER_TOKEN = "woltsim-other-token"
ENV_CONSUMER = "BBAGENT_WOLT_CONSUMER_TOKEN"
ENV_OTHER = "BBAGENT_WOLT_OTHER_TOKEN"
H1_ENV = "BBAGENT_H1_USERNAME"

_TOKENS = {CONSUMER_TOKEN: ("consumer_test", "consumer"), OTHER_TOKEN: ("sim_other", "admin")}

_ADMIN_REPORT = {"report": {"classification": "restricted",
                            "records": [{"venue": VENUE_ID, "plan": "gold"}]}}
_ADMIN_SETTINGS = {"settings": {"classification": "restricted", "flags": {"beta": True}}}


def _manifest() -> dict:
    return {"application": "wolt-sim", "endpoints": [
        {"url": "/sim/v1/orders/{id}", "method": "GET", "object_scoped": True,
         "example_object_url": f"/sim/v1/orders/{CONSUMER_USER_ID}"},
        {"url": "/sim/v1/profiles/{id}", "method": "GET", "object_scoped": True,
         "example_object_url": f"/sim/v1/profiles/{CONSUMER_USER_ID}"},
        {"url": "/sim/admin/report", "method": "GET", "example_object_url": "/sim/admin/report"},
        {"url": "/sim/admin/settings", "method": "GET", "example_object_url": "/sim/admin/settings"},
        {"url": "/sim/admin/ping", "method": "GET", "example_object_url": "/sim/admin/ping"},
        {"url": "/sim/search", "method": "GET", "example_object_url": "/sim/search?q=probe"},
        {"url": "/sim/search-safe", "method": "GET", "example_object_url": "/sim/search-safe?q=probe"},
        {"url": "/sim/echo", "method": "GET", "example_object_url": "/sim/echo?q=probe"},
        {"url": "/sim/catalog", "method": "GET", "example_object_url": "/sim/catalog?id=1"},
        {"url": "/sim/catalog-safe", "method": "GET", "example_object_url": "/sim/catalog-safe?id=1"},
        {"url": "/sim/catalog-info", "method": "GET", "example_object_url": "/sim/catalog-info?id=1"},
    ]}


def _json(status: int, payload: dict) -> httpx.Response:
    return httpx.Response(status, headers={"content-type": "application/json"},
                         text=json.dumps(payload))


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


def wolt_mock_handler(request: httpx.Request) -> httpx.Response:
    path = urlsplit(str(request.url)).path
    q = request.url.params.get("q", "")
    ident = _identity(request)
    label = ident[0] if ident else None
    role = ident[1] if ident else None

    if path == "/sim/manifest":
        return _json(200, _manifest())

    # --- IDOR (object-level) ---
    if path.startswith("/sim/v1/orders/"):
        if label is None:
            return _json(401, {"error": "unauthenticated"})
        oid = path.rsplit("/", 1)[-1]
        return _json(200, {"order": {"id": oid, "item": "burrito", "total": 1290}})  # VULN: any authed
    if path.startswith("/sim/v1/profiles/"):
        if label is None:
            return _json(401, {"error": "unauthenticated"})
        pid = path.rsplit("/", 1)[-1]
        owner = "consumer_test" if pid == CONSUMER_USER_ID else None
        if label != owner:
            return _json(403, {"error": "forbidden"})   # PROTECTED
        return _json(200, {"profile": {"id": pid, "email": "researcher@example.test"}})

    # --- BFLA (function-level) ---
    if path == "/sim/admin/report":
        if label is None:
            return _json(401, {"error": "unauthenticated"})
        return _json(200, _ADMIN_REPORT)                # VULN: no role check
    if path == "/sim/admin/settings":
        if label is None:
            return _json(401, {"error": "unauthenticated"})
        if role != "admin":
            return _json(403, {"error": "forbidden"})   # PROTECTED
        return _json(200, _ADMIN_SETTINGS)
    if path == "/sim/admin/ping":
        if label is None:
            return _json(401, {"error": "unauthenticated"})
        return _json(200, {"ok": True})                 # CONTROL: no privileged data

    # --- Reflected XSS ---
    if path == "/sim/search":
        body = f"<html><body><p>Results for: {q}</p></body></html>"
        return httpx.Response(200, headers={"content-type": "text/html"}, text=body)  # VULN
    if path == "/sim/search-safe":
        body = f"<html><body><p>Results for: {_html.escape(q)}</p></body></html>"
        return httpx.Response(200, headers={"content-type": "text/html"}, text=body)  # SAFE
    if path == "/sim/echo":
        return httpx.Response(200, headers={"content-type": "text/plain"}, text=f"echo: {q}")  # CONTROL

    # --- SQL injection ---
    if path == "/sim/catalog":
        return _json(200, _catalog(request.url.params.get("id", ""), safe=False, control=False))  # VULN
    if path == "/sim/catalog-safe":
        return _json(200, _catalog(request.url.params.get("id", ""), safe=True, control=False))   # SAFE
    if path == "/sim/catalog-info":
        return _json(200, _catalog(request.url.params.get("id", ""), safe=False, control=True))   # CONTROL

    return _json(404, {"error": "not_found"})


class WoltMockTransport(httpx.MockTransport):
    """MockTransport that counts how many requests actually reached the handler."""

    def __init__(self):
        self.calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            self.calls += 1
            return wolt_mock_handler(request)
        super().__init__(handler)


def wolt_mock_transport() -> WoltMockTransport:
    return WoltMockTransport()


def build_wolt_sim_program(*, enforce_data_scope: bool = False) -> ProgramManager:
    """Wolt policy semantics + SIMULATION-ONLY gap-fills so the pipeline can run.

    ``enforce_data_scope=True`` turns on Wolt's mechanical data-scoping (authorized
    consumer/venue ids + venue URL) for policy-scenario tests. The default (False)
    lets the full detector pipeline run with detector probe ids; data-scoping is
    proven independently.
    """
    data = load_program(_WOLT_YAML).model_dump()
    data.update({
        "name": "wolt-SIMULATION (local mock; NOT a live target)",
        "dry_run_only": False,                       # SIMULATION: run against the mock
        "allowed_tools": ["http", "recon"],          # SIMULATION gap-fill
        "allowed_vulnerability_classes": [           # SIMULATION gap-fill
            "idor", "privilege_escalation", "reflected_xss", "sql_injection"],
        "allow_unauthenticated": True,               # SIMULATION gap-fill (XSS/SQLi + discovery)
        "request_budget": {"total": 500, "per_target": 500, "per_tool": 500},
        "needs_human_review": [],
        "data_scope": ({"enforce": True,
                        "authorized_object_ids": [CONSUMER_USER_ID, VENUE_ID],
                        "authorized_url_prefixes": [
                            f"https://wolt.com/en/fin/helsinki/venue/test-{VENUE_ID}-sh0p"]}
                       if enforce_data_scope else {"enforce": False}),
        "test_accounts": [
            {"label": "consumer_test", "role": "consumer",
             "username": f"user_id:{CONSUMER_USER_ID}", "secret_env": ENV_CONSUMER,
             "notes": "Wolt-authorized consumer test account (own data only)."},
            {"label": "sim_other", "role": "admin", "secret_env": ENV_OTHER,
             "notes": "SIMULATION-ONLY second identity for differential detectors; "
                      "NOT a Wolt-authorized account."},
        ],
    })
    data["restrictions"]["allowed_methods"] = ["GET"]  # SIMULATION gap-fill
    return ProgramManager(ProgramConfig.model_validate(data))
