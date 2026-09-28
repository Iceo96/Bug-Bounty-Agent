"""SQLite persistence for the attack-surface graph.

Owns its own tables (created on init) alongside the existing findings/evidence
tables on the same connection. All writes are idempotent upserts keyed on a
natural unique key, maintaining first_seen/last_seen and merging observed sets
(status codes, technologies) so repeated discovery runs converge instead of
duplicating.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

from bbagent.storage.db import Database
from bbagent.surface.models import (
    ApiEndpoint,
    Asset,
    AuthObservation,
    Endpoint,
    JsAsset,
    ObjectRef,
    Parameter,
    Relationship,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS surface_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    scheme TEXT NOT NULL,
    hostname TEXT NOT NULL,
    port INTEGER,
    url TEXT NOT NULL,
    status INTEGER,
    title TEXT,
    content_type TEXT,
    technologies TEXT NOT NULL DEFAULT '[]',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(program, url)
);

CREATE TABLE IF NOT EXISTS surface_endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    path TEXT NOT NULL,
    template_key TEXT NOT NULL,
    query_params TEXT NOT NULL DEFAULT '[]',
    path_params TEXT NOT NULL DEFAULT '[]',
    request_content_type TEXT,
    response_content_type TEXT,
    auth_requirement TEXT NOT NULL DEFAULT 'unknown',
    status_codes TEXT NOT NULL DEFAULT '[]',
    confirmed INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT 'unknown',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(program, template_key)
);

CREATE TABLE IF NOT EXISTS surface_js (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    url TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    content_type TEXT,
    source_page TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(program, url)
);

CREATE TABLE IF NOT EXISTS surface_apis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    api_base TEXT NOT NULL,
    path TEXT NOT NULL,
    method TEXT NOT NULL,
    params TEXT NOT NULL DEFAULT '[]',
    auth_context TEXT NOT NULL DEFAULT 'unknown',
    observed_responses TEXT NOT NULL DEFAULT '[]',
    confirmed INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(program, api_base, path, method)
);

CREATE TABLE IF NOT EXISTS surface_params (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    endpoint_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    location TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'observed',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(endpoint_id, name, location)
);

CREATE TABLE IF NOT EXISTS surface_object_refs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    endpoint_id INTEGER NOT NULL,
    value TEXT NOT NULL,
    kind TEXT NOT NULL,
    location TEXT NOT NULL,
    candidate INTEGER NOT NULL DEFAULT 1,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(endpoint_id, value, kind, location)
);

CREATE TABLE IF NOT EXISTS surface_auth_obs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    endpoint_id INTEGER NOT NULL,
    identity TEXT NOT NULL,
    status_codes TEXT NOT NULL DEFAULT '[]',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(endpoint_id, identity)
);

CREATE TABLE IF NOT EXISTS surface_rels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    src_type TEXT NOT NULL,
    src_id INTEGER NOT NULL,
    dst_type TEXT NOT NULL,
    dst_id INTEGER NOT NULL,
    rel TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(program, src_type, src_id, dst_type, dst_id, rel)
);

CREATE INDEX IF NOT EXISTS ix_surface_ep_program ON surface_endpoints(program);
CREATE INDEX IF NOT EXISTS ix_surface_params_ep ON surface_params(endpoint_id);
CREATE INDEX IF NOT EXISTS ix_surface_objref_ep ON surface_object_refs(endpoint_id);
CREATE INDEX IF NOT EXISTS ix_surface_auth_ep ON surface_auth_obs(endpoint_id);
CREATE INDEX IF NOT EXISTS ix_surface_rels_src ON surface_rels(program, src_type, src_id);
"""


def _merge_ints(existing: str, new: Optional[int]) -> str:
    vals = set(json.loads(existing))
    if new is not None:
        vals.add(new)
    return json.dumps(sorted(vals))


def _merge_strs(existing: str, new: list[str]) -> str:
    vals = set(json.loads(existing))
    vals.update(v for v in new if v)
    return json.dumps(sorted(vals))


class SurfaceStore:
    def __init__(self, db: Database):
        self._db = db
        self._c = db.connection
        self._c.executescript(_SCHEMA)
        self._c.commit()

    # --- assets ---------------------------------------------------------------

    def upsert_asset(
        self,
        program: str,
        *,
        scheme: str,
        hostname: str,
        port: int | None,
        url: str,
        status: int | None = None,
        title: str | None = None,
        content_type: str | None = None,
        technologies: list[str] | None = None,
    ) -> Asset:
        now = time.time()
        row = self._c.execute(
            "SELECT * FROM surface_assets WHERE program=? AND url=?", (program, url)
        ).fetchone()
        techs = technologies or []
        if row is None:
            cur = self._c.execute(
                "INSERT INTO surface_assets(program, scheme, hostname, port, url, status, title,"
                " content_type, technologies, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (program, scheme, hostname, port, url, status, title, content_type,
                 json.dumps(sorted(set(techs))), now, now),
            )
            self._c.commit()
            return self.get_asset(cur.lastrowid)  # type: ignore[arg-type]
        merged_tech = _merge_strs(row["technologies"], techs)
        self._c.execute(
            "UPDATE surface_assets SET status=COALESCE(?, status), title=COALESCE(?, title),"
            " content_type=COALESCE(?, content_type), technologies=?, last_seen=? WHERE id=?",
            (status, title, content_type, merged_tech, now, row["id"]),
        )
        self._c.commit()
        return self.get_asset(row["id"])

    def get_asset(self, asset_id: int) -> Asset:
        r = self._c.execute("SELECT * FROM surface_assets WHERE id=?", (asset_id,)).fetchone()
        return _asset(r)

    def list_assets(self, program: str) -> list[Asset]:
        rows = self._c.execute(
            "SELECT * FROM surface_assets WHERE program=? ORDER BY url", (program,)
        ).fetchall()
        return [_asset(r) for r in rows]

    # --- endpoints ------------------------------------------------------------

    def upsert_endpoint(
        self,
        program: str,
        *,
        method: str,
        url: str,
        path: str,
        template_key: str,
        query_params: list[str] | None = None,
        path_params: list[str] | None = None,
        request_content_type: str | None = None,
        response_content_type: str | None = None,
        status_code: int | None = None,
        confirmed: bool = False,
        source: str = "unknown",
    ) -> Endpoint:
        now = time.time()
        row = self._c.execute(
            "SELECT * FROM surface_endpoints WHERE program=? AND template_key=?",
            (program, template_key),
        ).fetchone()
        qp = query_params or []
        pp = path_params or []
        if row is None:
            cur = self._c.execute(
                "INSERT INTO surface_endpoints(program, method, url, path, template_key, query_params,"
                " path_params, request_content_type, response_content_type, auth_requirement,"
                " status_codes, confirmed, source, first_seen, last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (program, method.upper(), url, path, template_key, json.dumps(sorted(set(qp))),
                 json.dumps(sorted(set(pp))), request_content_type, response_content_type,
                 "unknown", _merge_ints("[]", status_code), 1 if confirmed else 0, source, now, now),
            )
            self._c.commit()
            return self.get_endpoint(cur.lastrowid)  # type: ignore[arg-type]
        self._c.execute(
            "UPDATE surface_endpoints SET query_params=?, path_params=?,"
            " request_content_type=COALESCE(?, request_content_type),"
            " response_content_type=COALESCE(?, response_content_type),"
            " status_codes=?, confirmed=MAX(confirmed, ?), last_seen=? WHERE id=?",
            (
                _merge_strs(row["query_params"], qp),
                _merge_strs(row["path_params"], pp),
                request_content_type, response_content_type,
                _merge_ints(row["status_codes"], status_code),
                1 if confirmed else 0, now, row["id"],
            ),
        )
        self._c.commit()
        return self.get_endpoint(row["id"])

    def set_endpoint_auth_requirement(self, endpoint_id: int, requirement: str) -> None:
        self._c.execute(
            "UPDATE surface_endpoints SET auth_requirement=? WHERE id=?", (requirement, endpoint_id)
        )
        self._c.commit()

    def get_endpoint(self, endpoint_id: int) -> Endpoint:
        r = self._c.execute("SELECT * FROM surface_endpoints WHERE id=?", (endpoint_id,)).fetchone()
        return _endpoint(r)

    def list_endpoints(self, program: str, *, confirmed_only: bool = False) -> list[Endpoint]:
        q = "SELECT * FROM surface_endpoints WHERE program=?"
        if confirmed_only:
            q += " AND confirmed=1"
        q += " ORDER BY template_key"
        return [_endpoint(r) for r in self._c.execute(q, (program,)).fetchall()]

    # --- javascript -----------------------------------------------------------

    def upsert_js_asset(
        self, program: str, *, url: str, sha256: str, size: int,
        content_type: str | None = None, source_page: str | None = None,
    ) -> JsAsset:
        now = time.time()
        row = self._c.execute(
            "SELECT * FROM surface_js WHERE program=? AND url=?", (program, url)
        ).fetchone()
        if row is None:
            cur = self._c.execute(
                "INSERT INTO surface_js(program, url, sha256, size, content_type, source_page,"
                " first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?)",
                (program, url, sha256, size, content_type, source_page, now, now),
            )
            self._c.commit()
            return self.get_js(cur.lastrowid)  # type: ignore[arg-type]
        self._c.execute(
            "UPDATE surface_js SET sha256=?, size=?, content_type=COALESCE(?, content_type),"
            " source_page=COALESCE(?, source_page), last_seen=? WHERE id=?",
            (sha256, size, content_type, source_page, now, row["id"]),
        )
        self._c.commit()
        return self.get_js(row["id"])

    def get_js(self, js_id: int) -> JsAsset:
        r = self._c.execute("SELECT * FROM surface_js WHERE id=?", (js_id,)).fetchone()
        return _js(r)

    def list_js_assets(self, program: str) -> list[JsAsset]:
        return [_js(r) for r in self._c.execute(
            "SELECT * FROM surface_js WHERE program=? ORDER BY url", (program,)).fetchall()]

    # --- api endpoints --------------------------------------------------------

    def upsert_api_endpoint(
        self, program: str, *, api_base: str, path: str, method: str,
        params: list[str] | None = None, auth_context: str = "unknown",
        response_code: int | None = None, confirmed: bool = False,
    ) -> ApiEndpoint:
        now = time.time()
        row = self._c.execute(
            "SELECT * FROM surface_apis WHERE program=? AND api_base=? AND path=? AND method=?",
            (program, api_base, path, method.upper()),
        ).fetchone()
        p = params or []
        if row is None:
            cur = self._c.execute(
                "INSERT INTO surface_apis(program, api_base, path, method, params, auth_context,"
                " observed_responses, confirmed, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (program, api_base, path, method.upper(), json.dumps(sorted(set(p))), auth_context,
                 _merge_ints("[]", response_code), 1 if confirmed else 0, now, now),
            )
            self._c.commit()
            return self.get_api(cur.lastrowid)  # type: ignore[arg-type]
        self._c.execute(
            "UPDATE surface_apis SET params=?, auth_context=?, observed_responses=?,"
            " confirmed=MAX(confirmed, ?), last_seen=? WHERE id=?",
            (_merge_strs(row["params"], p), auth_context,
             _merge_ints(row["observed_responses"], response_code),
             1 if confirmed else 0, now, row["id"]),
        )
        self._c.commit()
        return self.get_api(row["id"])

    def get_api(self, api_id: int) -> ApiEndpoint:
        r = self._c.execute("SELECT * FROM surface_apis WHERE id=?", (api_id,)).fetchone()
        return _api(r)

    def list_api_endpoints(self, program: str) -> list[ApiEndpoint]:
        return [_api(r) for r in self._c.execute(
            "SELECT * FROM surface_apis WHERE program=? ORDER BY api_base, path", (program,)).fetchall()]

    # --- parameters -----------------------------------------------------------

    def upsert_parameter(
        self, program: str, *, endpoint_id: int, name: str, location: str, source: str = "observed",
    ) -> Parameter:
        now = time.time()
        row = self._c.execute(
            "SELECT * FROM surface_params WHERE endpoint_id=? AND name=? AND location=?",
            (endpoint_id, name, location),
        ).fetchone()
        if row is None:
            cur = self._c.execute(
                "INSERT INTO surface_params(program, endpoint_id, name, location, source,"
                " first_seen, last_seen) VALUES(?,?,?,?,?,?,?)",
                (program, endpoint_id, name, location, source, now, now),
            )
            self._c.commit()
            return _param(self._c.execute(
                "SELECT * FROM surface_params WHERE id=?", (cur.lastrowid,)).fetchone())
        self._c.execute("UPDATE surface_params SET last_seen=? WHERE id=?", (now, row["id"]))
        self._c.commit()
        return _param(self._c.execute("SELECT * FROM surface_params WHERE id=?", (row["id"],)).fetchone())

    def parameters_for(self, endpoint_id: int) -> list[Parameter]:
        return [_param(r) for r in self._c.execute(
            "SELECT * FROM surface_params WHERE endpoint_id=? ORDER BY name", (endpoint_id,)).fetchall()]

    # --- object refs ----------------------------------------------------------

    def upsert_object_ref(
        self, program: str, *, endpoint_id: int, value: str, kind: str, location: str,
    ) -> ObjectRef:
        now = time.time()
        row = self._c.execute(
            "SELECT * FROM surface_object_refs WHERE endpoint_id=? AND value=? AND kind=? AND location=?",
            (endpoint_id, value, kind, location),
        ).fetchone()
        if row is None:
            cur = self._c.execute(
                "INSERT INTO surface_object_refs(program, endpoint_id, value, kind, location,"
                " candidate, first_seen, last_seen) VALUES(?,?,?,?,?,1,?,?)",
                (program, endpoint_id, value, kind, location, now, now),
            )
            self._c.commit()
            return _objref(self._c.execute(
                "SELECT * FROM surface_object_refs WHERE id=?", (cur.lastrowid,)).fetchone())
        self._c.execute("UPDATE surface_object_refs SET last_seen=? WHERE id=?", (now, row["id"]))
        self._c.commit()
        return _objref(self._c.execute(
            "SELECT * FROM surface_object_refs WHERE id=?", (row["id"],)).fetchone())

    def object_refs_for(self, endpoint_id: int) -> list[ObjectRef]:
        return [_objref(r) for r in self._c.execute(
            "SELECT * FROM surface_object_refs WHERE endpoint_id=? ORDER BY value", (endpoint_id,)).fetchall()]

    # --- auth observations ----------------------------------------------------

    def record_auth_observation(
        self, program: str, *, endpoint_id: int, identity: str, status_code: int,
    ) -> AuthObservation:
        now = time.time()
        row = self._c.execute(
            "SELECT * FROM surface_auth_obs WHERE endpoint_id=? AND identity=?",
            (endpoint_id, identity),
        ).fetchone()
        if row is None:
            cur = self._c.execute(
                "INSERT INTO surface_auth_obs(program, endpoint_id, identity, status_codes,"
                " first_seen, last_seen) VALUES(?,?,?,?,?,?)",
                (program, endpoint_id, identity, _merge_ints("[]", status_code), now, now),
            )
            self._c.commit()
            return _authobs(self._c.execute(
                "SELECT * FROM surface_auth_obs WHERE id=?", (cur.lastrowid,)).fetchone())
        self._c.execute(
            "UPDATE surface_auth_obs SET status_codes=?, last_seen=? WHERE id=?",
            (_merge_ints(row["status_codes"], status_code), now, row["id"]),
        )
        self._c.commit()
        return _authobs(self._c.execute(
            "SELECT * FROM surface_auth_obs WHERE id=?", (row["id"],)).fetchone())

    def auth_observations_for(self, endpoint_id: int) -> list[AuthObservation]:
        return [_authobs(r) for r in self._c.execute(
            "SELECT * FROM surface_auth_obs WHERE endpoint_id=? ORDER BY identity", (endpoint_id,)).fetchall()]

    # --- relationships --------------------------------------------------------

    def add_relationship(
        self, program: str, *, src_type: str, src_id: int, dst_type: str, dst_id: int, rel: str,
    ) -> Relationship:
        now = time.time()
        row = self._c.execute(
            "SELECT * FROM surface_rels WHERE program=? AND src_type=? AND src_id=? AND dst_type=?"
            " AND dst_id=? AND rel=?",
            (program, src_type, src_id, dst_type, dst_id, rel),
        ).fetchone()
        if row is None:
            cur = self._c.execute(
                "INSERT INTO surface_rels(program, src_type, src_id, dst_type, dst_id, rel,"
                " first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?)",
                (program, src_type, src_id, dst_type, dst_id, rel, now, now),
            )
            self._c.commit()
            return _rel(self._c.execute(
                "SELECT * FROM surface_rels WHERE id=?", (cur.lastrowid,)).fetchone())
        self._c.execute("UPDATE surface_rels SET last_seen=? WHERE id=?", (now, row["id"]))
        self._c.commit()
        return _rel(self._c.execute("SELECT * FROM surface_rels WHERE id=?", (row["id"],)).fetchone())

    def relationships(
        self, program: str, *, src_type: str | None = None, src_id: int | None = None,
    ) -> list[Relationship]:
        q = "SELECT * FROM surface_rels WHERE program=?"
        args: list[Any] = [program]
        if src_type is not None:
            q += " AND src_type=?"
            args.append(src_type)
        if src_id is not None:
            q += " AND src_id=?"
            args.append(src_id)
        return [_rel(r) for r in self._c.execute(q, tuple(args)).fetchall()]

    # --- aggregate view -------------------------------------------------------

    def attack_surface(self, program: str) -> dict:
        """A JSON-serializable snapshot of the whole graph for the planner."""
        endpoints = []
        for ep in self.list_endpoints(program):
            endpoints.append({
                "id": ep.id,
                "method": ep.method,
                "url": ep.url,
                "path": ep.path,
                "template_key": ep.template_key,
                "confirmed": ep.confirmed,
                "source": ep.source,
                "auth_requirement": ep.auth_requirement,
                "status_codes": ep.status_codes,
                "query_params": ep.query_params,
                "path_params": ep.path_params,
                "parameters": [
                    {"name": p.name, "location": p.location, "source": p.source}
                    for p in self.parameters_for(ep.id)
                ],
                "object_refs": [
                    {"value": o.value, "kind": o.kind, "location": o.location, "candidate": o.candidate}
                    for o in self.object_refs_for(ep.id)
                ],
                "auth_contexts": [
                    {"identity": a.identity, "status_codes": a.status_codes}
                    for a in self.auth_observations_for(ep.id)
                ],
            })
        return {
            "program": program,
            "assets": [_asset_dict(a) for a in self.list_assets(program)],
            "javascript": [_js_dict(j) for j in self.list_js_assets(program)],
            "api_endpoints": [_api_dict(a) for a in self.list_api_endpoints(program)],
            "endpoints": endpoints,
            "relationships": [
                {"src_type": r.src_type, "src_id": r.src_id, "dst_type": r.dst_type,
                 "dst_id": r.dst_id, "rel": r.rel}
                for r in self.relationships(program)
            ],
        }


# --- row mappers --------------------------------------------------------------

def _asset(r) -> Asset:
    return Asset(
        id=r["id"], program=r["program"], scheme=r["scheme"], hostname=r["hostname"], port=r["port"],
        url=r["url"], status=r["status"], title=r["title"], content_type=r["content_type"],
        technologies=json.loads(r["technologies"]), first_seen=r["first_seen"], last_seen=r["last_seen"],
    )


def _endpoint(r) -> Endpoint:
    return Endpoint(
        id=r["id"], program=r["program"], method=r["method"], url=r["url"], path=r["path"],
        template_key=r["template_key"], query_params=json.loads(r["query_params"]),
        path_params=json.loads(r["path_params"]), request_content_type=r["request_content_type"],
        response_content_type=r["response_content_type"], auth_requirement=r["auth_requirement"],
        status_codes=json.loads(r["status_codes"]), confirmed=bool(r["confirmed"]), source=r["source"],
        first_seen=r["first_seen"], last_seen=r["last_seen"],
    )


def _js(r) -> JsAsset:
    return JsAsset(
        id=r["id"], program=r["program"], url=r["url"], sha256=r["sha256"], size=r["size"],
        content_type=r["content_type"], source_page=r["source_page"],
        first_seen=r["first_seen"], last_seen=r["last_seen"],
    )


def _api(r) -> ApiEndpoint:
    return ApiEndpoint(
        id=r["id"], program=r["program"], api_base=r["api_base"], path=r["path"], method=r["method"],
        params=json.loads(r["params"]), auth_context=r["auth_context"],
        observed_responses=json.loads(r["observed_responses"]), confirmed=bool(r["confirmed"]),
        first_seen=r["first_seen"], last_seen=r["last_seen"],
    )


def _param(r) -> Parameter:
    return Parameter(
        id=r["id"], program=r["program"], endpoint_id=r["endpoint_id"], name=r["name"],
        location=r["location"], source=r["source"], first_seen=r["first_seen"], last_seen=r["last_seen"],
    )


def _objref(r) -> ObjectRef:
    return ObjectRef(
        id=r["id"], program=r["program"], endpoint_id=r["endpoint_id"], value=r["value"], kind=r["kind"],
        location=r["location"], candidate=bool(r["candidate"]),
        first_seen=r["first_seen"], last_seen=r["last_seen"],
    )


def _authobs(r) -> AuthObservation:
    return AuthObservation(
        id=r["id"], program=r["program"], endpoint_id=r["endpoint_id"], identity=r["identity"],
        status_codes=json.loads(r["status_codes"]), first_seen=r["first_seen"], last_seen=r["last_seen"],
    )


def _rel(r) -> Relationship:
    return Relationship(
        id=r["id"], program=r["program"], src_type=r["src_type"], src_id=r["src_id"],
        dst_type=r["dst_type"], dst_id=r["dst_id"], rel=r["rel"],
        first_seen=r["first_seen"], last_seen=r["last_seen"],
    )


def _asset_dict(a: Asset) -> dict:
    return {"id": a.id, "url": a.url, "hostname": a.hostname, "scheme": a.scheme, "port": a.port,
            "status": a.status, "title": a.title, "content_type": a.content_type,
            "technologies": a.technologies}


def _js_dict(j: JsAsset) -> dict:
    return {"id": j.id, "url": j.url, "sha256": j.sha256, "size": j.size,
            "content_type": j.content_type, "source_page": j.source_page}


def _api_dict(a: ApiEndpoint) -> dict:
    return {"id": a.id, "api_base": a.api_base, "path": a.path, "method": a.method,
            "params": a.params, "auth_context": a.auth_context,
            "observed_responses": a.observed_responses, "confirmed": a.confirmed}
