"""The authorization provenance record is read-only, non-granting, and consistent
with the enforced Temu scope. It must never alter authorization or any gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from bbagent.config.loader import load_program
from bbagent.program.provenance import (
    ProvenanceError, load_authorization_provenance,
)

ROOT = Path(__file__).resolve().parents[1]
TEMU = str(ROOT / "programs" / "temu.yaml")
PROV = str(ROOT / "programs" / "temu.authorization.yaml")


def test_provenance_is_non_granting_and_matches_scope():
    p = load_authorization_provenance(PROV, program_config_path=TEMU)
    assert p.grants_authorization is False
    assert set(p.in_scope_http_assets) == {
        "www.temu.com", "seller.temu.com", "partner.temu.com", "ads.temu.com"}
    assert p.program.startswith("Temu")
    assert "published HackerOne" in p.authorization_source
    assert p.researcher_attestations            # researcher must attest explicitly


def test_provenance_stores_no_raw_identifier_values():
    # Only env-var NAMES are recorded, never the handle/URL values.
    p = load_authorization_provenance(PROV, program_config_path=TEMU)
    assert p.raw["provenance"]["researcher_identity_env"] == "BBAGENT_H1_USERNAME"
    assert "authorization_source_url_env" in p.raw["provenance"]
    # No field literally named like a stored handle/url value.
    assert "researcher_identity" not in p.raw["provenance"]


def test_provenance_rejects_a_grant_claim(tmp_path):
    bad = tmp_path / "bad.authorization.yaml"
    bad.write_text("provenance:\n  grants_authorization: true\n", encoding="utf-8")
    with pytest.raises(ProvenanceError):
        load_authorization_provenance(str(bad))


def test_provenance_detects_scope_drift(tmp_path):
    drift = tmp_path / "drift.authorization.yaml"
    drift.write_text(
        "provenance:\n  grants_authorization: false\n"
        "captured_from_published_policy:\n  in_scope_http_assets: ['www.temu.com']\n",
        encoding="utf-8")
    with pytest.raises(ProvenanceError):
        load_authorization_provenance(str(drift), program_config_path=TEMU)


def test_loading_provenance_has_no_authorization_effect():
    # Loading the record must not change the program's config/gating in any way.
    before = load_program(TEMU)
    load_authorization_provenance(PROV, program_config_path=TEMU)
    after = load_program(TEMU)
    assert before.dry_run_only == after.dry_run_only
    assert [r.value for r in before.scope.in_scope] == [r.value for r in after.scope.in_scope]
    assert before.restrictions.allowed_methods == after.restrictions.allowed_methods
