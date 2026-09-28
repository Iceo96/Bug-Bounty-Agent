"""Dataclasses for the attack-surface graph.

These are read models returned by :class:`bbagent.surface.store.SurfaceStore`.
Writes go through the store's upsert methods, which own dedup and
first_seen/last_seen bookkeeping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AuthIdentity(str, Enum):
    """How an endpoint was observed, without asserting an authz decision."""

    UNAUTHENTICATED = "unauthenticated"
    IDENTITY_A = "identity_a"
    IDENTITY_B = "identity_b"
    UNKNOWN = "unknown"


@dataclass
class Asset:
    id: int
    program: str
    scheme: str
    hostname: str
    port: int | None
    url: str
    status: int | None
    title: str | None
    content_type: str | None
    technologies: list[str]
    first_seen: float
    last_seen: float


@dataclass
class Endpoint:
    id: int
    program: str
    method: str
    url: str                    # a representative concrete URL (no fragment)
    path: str
    template_key: str           # METHOD scheme://host[:port]/templated/path
    query_params: list[str]
    path_params: list[str]
    request_content_type: str | None
    response_content_type: str | None
    auth_requirement: str       # observed: "required" | "none" | "unknown"
    status_codes: list[int]
    confirmed: bool             # False for candidates (e.g. extracted from JS)
    source: str                 # "manifest" | "crawl" | "form" | "javascript"
    first_seen: float
    last_seen: float


@dataclass
class JsAsset:
    id: int
    program: str
    url: str
    sha256: str
    size: int
    content_type: str | None
    source_page: str | None
    first_seen: float
    last_seen: float


@dataclass
class ApiEndpoint:
    id: int
    program: str
    api_base: str
    path: str
    method: str
    params: list[str]
    auth_context: str
    observed_responses: list[int]
    confirmed: bool
    first_seen: float
    last_seen: float


@dataclass
class Parameter:
    id: int
    program: str
    endpoint_id: int
    name: str
    location: str               # "query" | "path" | "body"
    source: str                 # "observed" | "javascript" | "form"
    first_seen: float
    last_seen: float


@dataclass
class ObjectRef:
    id: int
    program: str
    endpoint_id: int
    value: str
    kind: str                   # numeric | uuid | hexid | path_id | json_id
    location: str
    candidate: bool             # always True — never asserted as a vulnerability
    first_seen: float
    last_seen: float


@dataclass
class AuthObservation:
    id: int
    program: str
    endpoint_id: int
    identity: str               # AuthIdentity value
    status_codes: list[int]
    first_seen: float
    last_seen: float


@dataclass
class Relationship:
    id: int
    program: str
    src_type: str
    src_id: int
    dst_type: str
    dst_id: int
    rel: str
    first_seen: float
    last_seen: float
