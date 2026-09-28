"""Persistent, queryable attack-surface model."""

from bbagent.surface.models import (
    Asset,
    Endpoint,
    JsAsset,
    ApiEndpoint,
    Parameter,
    ObjectRef,
    AuthObservation,
    Relationship,
    AuthIdentity,
)
from bbagent.surface.store import SurfaceStore

__all__ = [
    "Asset",
    "Endpoint",
    "JsAsset",
    "ApiEndpoint",
    "Parameter",
    "ObjectRef",
    "AuthObservation",
    "Relationship",
    "AuthIdentity",
    "SurfaceStore",
]
