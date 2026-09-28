"""Manifest-based endpoint discovery.

Fetches a discovery document (a JSON manifest describing endpoints) via the
authorized HTTP client and records one ``endpoint`` observation per concrete,
testable object URL. The scope engine gates the fetch, so discovery can never
wander off-scope.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin

from bbagent.http.client import AuthorizedHTTPClient
from bbagent.logging_config import get_logger
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.storage.models import Observation

log = get_logger(__name__)


async def discover_from_manifest(
    http: AuthorizedHTTPClient,
    program: ProgramManager,
    db: Database,
    base_url: str,
) -> list[Observation]:
    """GET ``base_url`` (a manifest) and record endpoint observations.

    Returns the observations created. Each object-scoped endpoint with an
    ``example_object_url`` becomes a concrete, in-scope target the detector can
    reason about.
    """
    exchange = await http.get(base_url)  # scope-checked
    observations: list[Observation] = []

    try:
        manifest = json.loads(exchange.response_body)
    except json.JSONDecodeError:
        log.warning("recon.manifest_not_json", url=base_url)
        return observations

    for ep in manifest.get("endpoints", []):
        example = ep.get("example_object_url")
        if not example:
            continue
        object_url = urljoin(base_url, example)
        # Only record targets that are themselves in scope.
        if not http_is_in_scope(http, object_url):
            log.info("recon.skip_out_of_scope", url=object_url)
            continue
        obs = Observation(
            program=program.name,
            kind="endpoint",
            summary=f"{ep.get('method', 'GET')} {object_url}",
            data={
                "url": object_url,
                "method": ep.get("method", "GET"),
                "object_scoped": bool(ep.get("object_scoped")),
                "object_param": ep.get("object_param"),
                "owner": ep.get("owner"),
                "auth_class": ep.get("auth_class"),
                "template": urljoin(base_url, ep.get("url", "")),
            },
            exchange_id=exchange.exchange_id,
        )
        db.add_observation(obs)
        observations.append(obs)

    log.info("recon.discovered", base=base_url, endpoints=len(observations))
    return observations


def http_is_in_scope(http: AuthorizedHTTPClient, url: str) -> bool:
    """Ask the client's scope engine whether ``url`` is in scope (no request sent)."""
    return http._scope.is_allowed(url)  # deliberate: single scope source of truth
