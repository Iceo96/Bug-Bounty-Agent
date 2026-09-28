"""Evidence store tests: capture, immutability, integrity, tamper detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from bbagent.http.client import HTTPExchange
from bbagent.storage.evidence import EvidenceIntegrityError


def _exchange() -> HTTPExchange:
    return HTTPExchange(
        exchange_id="ex1",
        method="GET",
        url="https://example.com/a",
        request_headers={"x-bug-bounty": "researcher"},
        request_body=None,
        status_code=200,
        response_headers={"content-type": "application/json"},
        response_body='{"ok": true}',
        elapsed_ms=12.3,
    )


def test_store_and_verify(evidence_store):
    req, resp = evidence_store.store_exchange(_exchange())
    assert evidence_store.read_verified(req.id)
    assert evidence_store.read_verified(resp.id)
    assert evidence_store.verify_all() == []


def test_tamper_is_detected(evidence_store):
    req, _resp = evidence_store.store_exchange(_exchange())
    rec = evidence_store._db.get_evidence(req.id)
    # Simulate tampering with the on-disk blob.
    p = Path(rec.blob_path)
    try:
        p.chmod(0o600)
    except OSError:
        pass
    p.write_bytes(b"tampered")
    with pytest.raises(EvidenceIntegrityError):
        evidence_store.read_verified(req.id)
    assert req.id in evidence_store.verify_all()


def test_evidence_row_is_immutable(evidence_store, db):
    req, _ = evidence_store.store_exchange(_exchange())
    with pytest.raises(Exception):
        db.connection.execute("UPDATE evidence SET label='x' WHERE id=?", (req.id,))
    with pytest.raises(Exception):
        db.connection.execute("DELETE FROM evidence WHERE id=?", (req.id,))
