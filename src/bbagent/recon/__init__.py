"""Recon: minimal endpoint discovery.

Only a small manifest-based discovery is implemented so the end-to-end pipeline
(discovery -> hypothesis -> verification -> report) can run. All requests go
through the scope-enforcing HTTP client, so discovery is scope-bounded too.
"""

from bbagent.recon.discovery import discover_from_manifest
from bbagent.recon.mapper import AttackSurfaceMapper

__all__ = ["discover_from_manifest", "AttackSurfaceMapper"]
