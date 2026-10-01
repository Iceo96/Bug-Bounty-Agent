"""Authorization provenance — a READ-ONLY, NON-GRANTING record.

This loads ``programs/<program>.authorization.yaml`` and exposes it for display and
consistency-checking only. It documents WHERE authorization comes from (the program's
published HackerOne policy) and WHO attests to it (the researcher). It must never be
treated as a grant:

* ``grants_authorization`` must be ``false`` — the loader refuses otherwise.
* It never sets ``authorized``, never opens the live gate, and never alters scope,
  policy, DataScope, RunBudget, or any control. It only reads and validates.
* A consistency check fails closed if the captured in-scope assets drift from the
  scope the engine actually enforces (``programs/temu.yaml``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from bbagent.config.loader import load_program
from bbagent.config.models import ScopeKind


class ProvenanceError(Exception):
    """Raised when a provenance record is self-contradictory or inconsistent."""


@dataclass
class AuthorizationProvenance:
    program: str
    authorization_source: str
    grants_authorization: bool                 # always False (enforced on load)
    in_scope_http_assets: list[str] = field(default_factory=list)
    researcher_attestations: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


def load_authorization_provenance(
    path: str | Path, *, program_config_path: str | Path | None = None,
) -> AuthorizationProvenance:
    """Load and validate a provenance record. Performs NO authorization and no I/O
    beyond reading the two local YAML files."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    prov = data.get("provenance", {}) or {}

    # A provenance record may NEVER assert it grants authorization.
    if bool(prov.get("grants_authorization", False)):
        raise ProvenanceError(
            "provenance record must not claim to grant authorization "
            "(grants_authorization must be false); authorization derives from the "
            "published program policy and the researcher's attestation, not this file")

    captured = data.get("captured_from_published_policy", {}) or {}
    assets = [str(a) for a in captured.get("in_scope_http_assets", [])]

    # Consistency: the captured assets must match the scope the engine ENFORCES.
    if program_config_path is not None:
        cfg = load_program(program_config_path)
        enforced = sorted(r.value for r in cfg.scope.in_scope if r.kind is ScopeKind.DOMAIN)
        if sorted(assets) != enforced:
            raise ProvenanceError(
                f"provenance in-scope assets {sorted(assets)} do not match the enforced "
                f"scope in {program_config_path}: {enforced}")

    return AuthorizationProvenance(
        program=str(prov.get("program", "")),
        authorization_source=str(prov.get("authorization_source", "")),
        grants_authorization=False,
        in_scope_http_assets=assets,
        researcher_attestations=[str(a) for a in data.get("researcher_attestations", [])],
        raw=data,
    )
