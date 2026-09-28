"""Attack-surface mapper.

Drives authorized discovery and persists a queryable graph. Every request goes
through :class:`AuthorizedHTTPClient`, so scope, rate limits, required headers,
and active-testing controls all apply. The mapper only ever issues GET requests.

Sources supported:
  * the local lab's JSON discovery manifest (``map_manifest``)
  * ordinary HTML crawling (``crawl``) with JavaScript discovery

Nothing here asserts a vulnerability. Object identifiers are recorded as
candidates; authentication is recorded as *observations*, never as an authz
judgement inferred from status codes.
"""

from __future__ import annotations

import collections
import hashlib
import json
from urllib.parse import urljoin, urlsplit

from bbagent.http.client import AuthorizedHTTPClient, HTTPExchange, RequestBlocked
from bbagent.logging_config import get_logger
from bbagent.program.manager import ProgramManager
from bbagent.recon import extract
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore
from bbagent.urlutils import endpoint_key, host_port, looks_like_id, query_param_names, templatize_path

log = get_logger(__name__)


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urlsplit(url)
    return p.scheme.lower(), (p.hostname or "").lower(), p.port


def _server_tech(headers: dict[str, str]) -> list[str]:
    techs = []
    server = headers.get("server") or headers.get("Server")
    if server:
        techs.append(server)
    powered = headers.get("x-powered-by") or headers.get("X-Powered-By")
    if powered:
        techs.append(powered)
    return techs


class AttackSurfaceMapper:
    def __init__(self, program: ProgramManager, http: AuthorizedHTTPClient, surface: SurfaceStore):
        self.program = program
        self.http = http
        self.surface = surface
        self._name = program.name

    # --- safety helper --------------------------------------------------------

    def _in_scope(self, url: str) -> bool:
        """Fail-closed scope check via the client's own engine (no request sent)."""
        return self.http._scope.is_allowed(url)

    # --- assets ---------------------------------------------------------------

    def _record_asset(self, exchange: HTTPExchange) -> int:
        scheme, host, port = _origin(exchange.url)
        ct = exchange.response_headers.get("content-type")
        title = None
        if ct and extract.is_probably_html(ct):
            title = extract.html_title(exchange.response_body)
        asset = self.surface.upsert_asset(
            self._name, scheme=scheme, hostname=host, port=port, url=exchange.url,
            status=exchange.status_code, title=title, content_type=ct,
            technologies=_server_tech(exchange.response_headers),
        )
        return asset.id

    # --- endpoints ------------------------------------------------------------

    def _record_endpoint(
        self, url: str, method: str, *, source: str, confirmed: bool,
        status: int | None = None, req_ct: str | None = None, resp_ct: str | None = None,
    ) -> int:
        parts = urlsplit(url)
        path = parts.path or "/"
        key = endpoint_key(method, url)
        path_params = [seg for seg in path.split("/") if seg and looks_like_id(seg)]
        ep = self.surface.upsert_endpoint(
            self._name, method=method, url=url.split("#", 1)[0], path=path, template_key=key,
            query_params=query_param_names(url), path_params=path_params,
            request_content_type=req_ct, response_content_type=resp_ct,
            status_code=status, confirmed=confirmed, source=source,
        )
        # Query parameters as first-class parameter rows.
        for name in query_param_names(url):
            self.surface.upsert_parameter(self._name, endpoint_id=ep.id, name=name,
                                          location="query", source=source)
        # Object references from the path.
        for ref in extract.object_refs_in_path(path):
            self.surface.upsert_object_ref(self._name, endpoint_id=ep.id, value=ref.value,
                                           kind=ref.kind, location=ref.location)
        # If it looks like an API path, mirror it into the API table.
        if path.startswith("/api"):
            scheme, host, port = _origin(url)
            self.surface.upsert_api_endpoint(
                self._name, api_base=f"{scheme}://{host_port(url)}", path=templatize_path(path),
                method=method, params=query_param_names(url),
                auth_context="unknown", response_code=status, confirmed=confirmed,
            )
        return ep.id

    def _record_json_object_refs(self, endpoint_id: int, body: str) -> None:
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return
        for ref in extract.object_refs_in_json(parsed):
            self.surface.upsert_object_ref(self._name, endpoint_id=endpoint_id, value=ref.value,
                                           kind=ref.kind, location=ref.location)

    # --- identities -----------------------------------------------------------

    def _identity_headers(self, identity: AuthIdentity) -> dict[str, str]:
        accts = self.program.config.test_accounts
        if identity is AuthIdentity.UNAUTHENTICATED:
            return {}
        idx = 0 if identity is AuthIdentity.IDENTITY_A else 1
        if len(accts) <= idx:
            return {}
        label = accts[idx].label
        token = self.program.resolve_account_secret(label)
        if token:
            return {"Authorization": f"Bearer {token}"}
        return {"X-Test-Identity": label}

    async def _probe_auth(self, endpoint_id: int, url: str, method: str = "GET") -> None:
        """Observe how each identity is treated. Records facts, asserts nothing."""
        identities = [AuthIdentity.UNAUTHENTICATED, AuthIdentity.IDENTITY_A, AuthIdentity.IDENTITY_B]
        unauth_status: int | None = None
        for identity in identities:
            headers = self._identity_headers(identity)
            if identity in (AuthIdentity.IDENTITY_A, AuthIdentity.IDENTITY_B) and not headers:
                # No resolvable credential for this identity — skip rather than
                # send an unauthenticated request mislabelled as this identity.
                continue
            try:
                ex = await self.http.request(method, url, headers=headers)
            except RequestBlocked:
                continue
            self.surface.record_auth_observation(
                self._name, endpoint_id=endpoint_id, identity=identity.value, status_code=ex.status_code
            )
            if identity is AuthIdentity.UNAUTHENTICATED:
                unauth_status = ex.status_code
            # Capture object references from any JSON body we legitimately received.
            if ex.status_code == 200:
                self._record_json_object_refs(endpoint_id, ex.response_body)
                self.surface.upsert_endpoint(
                    self._name, method=method, url=url, path=urlsplit(url).path or "/",
                    template_key=endpoint_key(method, url), confirmed=True, source="probe",
                    response_content_type=ex.response_headers.get("content-type"),
                    status_code=ex.status_code,
                )

        # Conservative, clearly-labelled authn requirement from the unauth probe only.
        if unauth_status in (401, 403):
            self.surface.set_endpoint_auth_requirement(endpoint_id, "required")
        elif unauth_status == 200:
            self.surface.set_endpoint_auth_requirement(endpoint_id, "none")
        else:
            self.surface.set_endpoint_auth_requirement(endpoint_id, "unknown")

    # --- manifest -------------------------------------------------------------

    async def map_manifest(self, manifest_url: str) -> None:
        """Discover from the lab's JSON manifest and probe its example objects."""
        if not self._in_scope(manifest_url):
            raise RequestBlocked(f"refusing ambiguous/out-of-scope manifest: {manifest_url}")
        ex = await self.http.get(manifest_url)
        page_id = self._record_asset(ex)
        try:
            manifest = json.loads(ex.response_body)
        except (json.JSONDecodeError, ValueError):
            log.warning("mapper.manifest_not_json", url=manifest_url)
            return

        for entry in manifest.get("endpoints", []):
            example = entry.get("example_object_url")
            method = entry.get("method", "GET")
            if not example:
                continue
            obj_url = urljoin(manifest_url, example)
            if not self._in_scope(obj_url):
                log.info("mapper.skip_out_of_scope", url=obj_url)
                continue
            ep_id = self._record_endpoint(obj_url, method, source="manifest", confirmed=False)
            self.surface.add_relationship(
                self._name, src_type="asset", src_id=page_id, dst_type="endpoint", dst_id=ep_id,
                rel="contains",
            )
            await self._probe_auth(ep_id, obj_url, method)

    # --- crawl ----------------------------------------------------------------

    async def crawl(self, seed_url: str, *, max_pages: int = 25) -> None:
        """BFS crawl of in-scope HTML pages, discovering JS, forms, and endpoints."""
        if not self._in_scope(seed_url):
            raise RequestBlocked(f"refusing ambiguous/out-of-scope seed: {seed_url}")

        queue: collections.deque[str] = collections.deque([seed_url])
        visited: set[str] = set()

        while queue and len(visited) < max_pages:
            url = queue.popleft()
            if url in visited or not self._in_scope(url):
                continue
            visited.add(url)
            try:
                ex = await self.http.get(url)
            except RequestBlocked:
                continue

            page_id = self._record_asset(ex)
            ct = ex.response_headers.get("content-type", "")

            # Record the page itself as an endpoint observed unauthenticated.
            page_ep = self._record_endpoint(
                url, "GET", source="crawl", confirmed=True, status=ex.status_code, resp_ct=ct
            )
            self.surface.record_auth_observation(
                self._name, endpoint_id=page_ep, identity=AuthIdentity.UNAUTHENTICATED.value,
                status_code=ex.status_code,
            )

            if not extract.is_probably_html(ct):
                continue

            parsed = extract.parse_html(ex.response_body)

            # JavaScript.
            for src in extract.absolutize(url, parsed.scripts):
                if self._in_scope(src):
                    await self.analyze_js(src, source_page_id=page_id, source_page_url=url)

            # Forms -> endpoints + parameters.
            for form in parsed.forms:
                if not form.action:
                    continue
                action_url = urljoin(url, form.action)
                if not self._in_scope(action_url):
                    continue
                form_ep = self._record_endpoint(action_url, form.method, source="form", confirmed=False)
                for name in form.params:
                    self.surface.upsert_parameter(
                        self._name, endpoint_id=form_ep, name=name, location="query", source="form"
                    )
                self.surface.add_relationship(
                    self._name, src_type="asset", src_id=page_id, dst_type="endpoint",
                    dst_id=form_ep, rel="contains",
                )

            # Enqueue in-scope HTML links.
            for link in extract.absolutize(url, parsed.links):
                if link not in visited and self._in_scope(link):
                    queue.append(link)

    # --- javascript -----------------------------------------------------------

    async def analyze_js(self, js_url: str, *, source_page_id: int | None = None,
                         source_page_url: str | None = None) -> None:
        if not self._in_scope(js_url):
            return
        try:
            ex = await self.http.get(js_url)
        except RequestBlocked:
            return
        body = ex.response_body
        digest = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
        js = self.surface.upsert_js_asset(
            self._name, url=js_url, sha256=digest, size=len(body.encode("utf-8", errors="replace")),
            content_type=ex.response_headers.get("content-type"), source_page=source_page_url,
        )
        if source_page_id is not None:
            self.surface.add_relationship(
                self._name, src_type="asset", src_id=source_page_id, dst_type="js", dst_id=js.id,
                rel="loads",
            )

        # Candidate URLs/paths -> UNCONFIRMED endpoint/API candidates.
        for cand in extract.extract_js_urls(body):
            cand_url = urljoin(js_url, cand)
            if not self._in_scope(cand_url):
                continue
            ep_id = self._record_endpoint(cand_url, "GET", source="javascript", confirmed=False)
            self.surface.add_relationship(
                self._name, src_type="js", src_id=js.id, dst_type="endpoint", dst_id=ep_id,
                rel="references",
            )
            # Attach any params carried in the candidate URL.
            for name in query_param_names(cand_url):
                self.surface.upsert_parameter(
                    self._name, endpoint_id=ep_id, name=name, location="query", source="javascript"
                )
