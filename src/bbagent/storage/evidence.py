"""Evidence store: immutable, integrity-checked storage of raw exchanges.

Guarantees:
* Raw request/response bytes are written to content-addressed files.
* A SHA-256 is recorded in the (append-only) ``evidence`` table.
* Files are made read-only after writing.
* Reading verifies the on-disk hash and raises if it has been tampered with.

The LLM/agent never writes evidence directly — it only records observations and
proposes hypotheses. Evidence is captured from real HTTP exchanges here.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Optional

from bbagent.http.client import HTTPExchange
from bbagent.logging_config import get_logger
from bbagent.storage.db import Database
from bbagent.storage.models import EvidenceRecord

log = get_logger(__name__)


class EvidenceIntegrityError(Exception):
    """Raised when stored evidence fails its integrity check."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class EvidenceStore:
    def __init__(self, db: Database, root: str | Path):
        self._db = db
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _write_blob(self, digest: str, data: bytes) -> Path:
        # Content-addressed path: evidence/ab/abcdef...
        sub = self._root / digest[:2]
        sub.mkdir(parents=True, exist_ok=True)
        dest = sub / digest
        if not dest.exists():
            tmp = dest.with_suffix(".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, dest)
            try:
                dest.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            except OSError:
                pass  # best-effort on platforms that don't support it
        return dest

    def store_blob(
        self,
        data: bytes,
        *,
        label: str,
        finding_id: Optional[str] = None,
        hypothesis_id: Optional[str] = None,
        exchange_id: Optional[str] = None,
    ) -> EvidenceRecord:
        """Persist raw bytes and record append-only metadata."""
        digest = _sha256(data)
        path = self._write_blob(digest, data)
        record = EvidenceRecord(
            finding_id=finding_id,
            hypothesis_id=hypothesis_id,
            label=label,
            sha256=digest,
            blob_path=str(path),
            exchange_id=exchange_id,
        )
        self._db.add_evidence(record)
        log.info("evidence.stored", id=record.id, label=label, sha256=digest[:12])
        return record

    def store_exchange(
        self,
        exchange: HTTPExchange,
        *,
        finding_id: Optional[str] = None,
        hypothesis_id: Optional[str] = None,
    ) -> tuple[EvidenceRecord, EvidenceRecord]:
        """Store an HTTP exchange as two blobs: the request and the response."""
        req = {
            "method": exchange.method,
            "url": exchange.url,
            "headers": exchange.request_headers,
            "body": exchange.request_body,
            "started_at": exchange.started_at,
        }
        resp = {
            "status_code": exchange.status_code,
            "headers": exchange.response_headers,
            "body": exchange.response_body,
            "elapsed_ms": exchange.elapsed_ms,
        }
        req_rec = self.store_blob(
            json.dumps(req, indent=2, sort_keys=True).encode("utf-8"),
            label="request", finding_id=finding_id, hypothesis_id=hypothesis_id,
            exchange_id=exchange.exchange_id,
        )
        resp_rec = self.store_blob(
            json.dumps(resp, indent=2, sort_keys=True).encode("utf-8"),
            label="response", finding_id=finding_id, hypothesis_id=hypothesis_id,
            exchange_id=exchange.exchange_id,
        )
        return req_rec, resp_rec

    def read_verified(self, evidence_id: str) -> bytes:
        """Read an evidence blob, verifying its recorded hash. Raises on mismatch."""
        record = self._db.get_evidence(evidence_id)
        if record is None:
            raise EvidenceIntegrityError(f"no evidence record: {evidence_id}")
        path = Path(record.blob_path)
        if not path.is_file():
            raise EvidenceIntegrityError(f"evidence blob missing on disk: {path}")
        data = path.read_bytes()
        actual = _sha256(data)
        if actual != record.sha256:
            raise EvidenceIntegrityError(
                f"evidence tampering detected for {evidence_id}: "
                f"expected {record.sha256[:12]} got {actual[:12]}"
            )
        return data

    def verify_all(self) -> list[str]:
        """Return the ids of any evidence records that fail verification."""
        failed: list[str] = []
        rows = self._db.connection.execute("SELECT id FROM evidence").fetchall()
        for row in rows:
            try:
                self.read_verified(row["id"])
            except EvidenceIntegrityError:
                failed.append(row["id"])
        return failed
