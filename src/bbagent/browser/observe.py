"""Passive network-observation ingestor.

Turns observed browser traffic into attack-surface graph rows, reusing the exact
same extraction helpers and store the active mapper uses. It makes NO network
requests: it only records what the browser already saw.

Guarantees (fail-closed):
  * Scope is the single source of truth (``ScopeEngine``). Any exchange whose URL
    is not in scope is dropped and never recorded — same rule as the active mapper.
  * Nothing is asserted as a vulnerability. Object identifiers are candidates;
    authentication is recorded as observations, never an authz judgement.
  * No authentication material is persisted. The surface store has no header/body
    columns; request auth headers are read only to *label* identity.
"""

from __future__ import annotations

import hashlib
import json
from typing import Iterable, Mapping
from urllib.parse import urlsplit

from bbagent.browser.models import IngestReport, ObservedExchange
from bbagent.logging_config import get_logger
from bbagent.program.manager import ProgramManager
from bbagent.recon import extract
from bbagent.scope.engine import ScopeEngine
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore
from bbagent.urlutils import endpoint_key, host_port, looks_like_id, query_param_names, templatize_path

log = get_logger(__name__)


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urlsplit(url)
    return p.scheme.lower(), (p.hostname or "").lower(), p.port


def _server_tech(headers: Mapping[str, str]) -> list[str]:
    techs: list[str] = []
    for want in ("server", "x-powered-by"):
        for k, v in headers.items():
            if k.lower() == want and v:
                techs.append(v)
    return techs


class NetworkObservationIngestor:
    """Ingest observed browser exchanges into a :class:`SurfaceStore`."""

    def __init__(
        self,
        program: ProgramManager,
        surface: SurfaceStore,
        *,
        default_identity: AuthIdentity = AuthIdentity.UNKNOWN,
        identity_map: Mapping[str, AuthIdentity] | None = None,
    ):
        self.program = program
        self.surface = surface
        self._name = program.name
        # Fail-closed scope engine — identical source of truth to the active client.
        self._scope = ScopeEngine(program.config.scope)
        self._default_identity = default_identity
        self._identity_map = dict(identity_map or {})

    # --- identity classification (no secret values inspected) -----------------

    def _identity_for(self, ex: ObservedExchange) -> AuthIdentity:
        # A request that carried no auth material is unauthenticated, regardless of
        # which identity was driving the browser.
        if not ex.looks_authenticated():
            return AuthIdentity.UNAUTHENTICATED
        if ex.identity_label and ex.identity_label in self._identity_map:
            return self._identity_map[ex.identity_label]
        return self._default_identity

    # --- recording helpers (mirror the active mapper, minus any requests) -----

    def _record_asset(self, ex: ObservedExchange) -> int:
        scheme, host, port = _origin(ex.url)
        ct = ex.response_content_type
        title = None
        if ct and extract.is_probably_html(ct) and ex.response_body:
            title = extract.html_title(ex.response_body)
        asset = self.surface.upsert_asset(
            self._name, scheme=scheme, hostname=host, port=port, url=ex.url.split("#", 1)[0],
            status=ex.status, title=title, content_type=ct,
            technologies=_server_tech(ex.response_headers),
        )
        return asset.id

    def _record_endpoint(self, ex: ObservedExchange, report: IngestReport) -> int:
        url = ex.url.split("#", 1)[0]
        parts = urlsplit(url)
        path = parts.path or "/"
        key = endpoint_key(ex.method, url)
        path_params = [seg for seg in path.split("/") if seg and looks_like_id(seg)]
        ep = self.surface.upsert_endpoint(
            self._name, method=ex.method, url=url, path=path, template_key=key,
            query_params=query_param_names(url), path_params=path_params,
            request_content_type=ex.request_content_type,
            response_content_type=ex.response_content_type,
            status_code=ex.status, confirmed=True, source="browser",
        )
        report.endpoints += 1
        for name in query_param_names(url):
            self.surface.upsert_parameter(self._name, endpoint_id=ep.id, name=name,
                                          location="query", source="browser")
            report.parameters += 1
        for ref in extract.object_refs_in_path(path):
            self.surface.upsert_object_ref(self._name, endpoint_id=ep.id, value=ref.value,
                                           kind=ref.kind, location=ref.location)
            report.object_refs += 1
        # JSON response object-reference candidates (id-like keys/values).
        if ex.response_body and (ex.response_content_type or "").lower().find("json") != -1:
            try:
                parsed = json.loads(ex.response_body)
            except (json.JSONDecodeError, ValueError):
                parsed = None
            if parsed is not None:
                for ref in extract.object_refs_in_json(parsed):
                    self.surface.upsert_object_ref(self._name, endpoint_id=ep.id, value=ref.value,
                                                   kind=ref.kind, location=ref.location)
                    report.object_refs += 1
        # Mirror API-looking paths into the API table.
        if path.startswith("/api"):
            scheme, host, _ = _origin(url)
            self.surface.upsert_api_endpoint(
                self._name, api_base=f"{scheme}://{host_port(url)}", path=templatize_path(path),
                method=ex.method, params=query_param_names(url),
                auth_context="unknown", response_code=ex.status, confirmed=True,
            )
        return ep.id

    def _record_js(self, ex: ObservedExchange, report: IngestReport) -> None:
        if not ex.response_body:
            return
        if not extract.is_probably_js(ex.url, ex.response_content_type or ""):
            return
        body = ex.response_body
        digest = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
        self.surface.upsert_js_asset(
            self._name, url=ex.url.split("#", 1)[0], sha256=digest,
            size=len(body.encode("utf-8", errors="replace")),
            content_type=ex.response_content_type, source_page=ex.source_page,
        )
        report.js_assets += 1

    # --- entry point ----------------------------------------------------------

    def ingest(self, exchanges: Iterable[ObservedExchange]) -> IngestReport:
        report = IngestReport(program=self._name)
        for ex in exchanges:
            report.exchanges_seen += 1
            if not ex.is_http():
                report.non_http_skipped += 1
                continue
            # FAIL-CLOSED: only in-scope traffic is ever recorded.
            if not self._scope.is_allowed(ex.url):
                report.out_of_scope_dropped += 1
                report.dropped_examples.append((urlsplit(ex.url).hostname or "?"))
                continue

            report.in_scope += 1
            self._record_asset(ex)
            report.assets += 1
            ep_id = self._record_endpoint(ex, report)
            self._record_js(ex, report)

            # Auth observation: a fact about how one identity was treated. Never an
            # authz assertion. auth_requirement is set conservatively, and only from
            # an unauthenticated observation (matching the active mapper's rule).
            if ex.status is not None:
                identity = self._identity_for(ex)
                self.surface.record_auth_observation(
                    self._name, endpoint_id=ep_id, identity=identity.value, status_code=ex.status
                )
                report.auth_observations += 1
                if identity is AuthIdentity.UNAUTHENTICATED:
                    if ex.status in (401, 403):
                        self.surface.set_endpoint_auth_requirement(ep_id, "required")
                    elif ex.status == 200:
                        self.surface.set_endpoint_auth_requirement(ep_id, "none")

        log.info("browser.ingest", program=self._name, seen=report.exchanges_seen,
                 in_scope=report.in_scope, dropped=report.out_of_scope_dropped,
                 endpoints=report.endpoints)
        return report


def ingest_har(
    program: ProgramManager,
    surface: SurfaceStore,
    har: str | bytes | dict,
    *,
    default_identity: AuthIdentity = AuthIdentity.UNKNOWN,
    identity_map: Mapping[str, AuthIdentity] | None = None,
) -> IngestReport:
    """Convenience: parse a HAR and ingest it. No network access occurs."""
    from bbagent.browser.har import parse_har

    ingestor = NetworkObservationIngestor(
        program, surface, default_identity=default_identity, identity_map=identity_map
    )
    return ingestor.ingest(parse_har(har))
