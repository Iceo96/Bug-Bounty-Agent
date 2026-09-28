"""Deterministic evidence validation and report-quality checks.

These gate report generation and approval. They never invent or repair data —
they only confirm that what a verified finding claims is actually backed by
integrity-checked evidence, and that the report has no missing pieces or
placeholder text.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceIntegrityError, EvidenceStore
from bbagent.storage.models import Finding

# Tokens that indicate unfinished / templated text.
_PLACEHOLDERS = ("todo", "tbd", "fixme", "xxx", "placeholder", "lorem ipsum", "<insert", "<fill")


@dataclass
class EvidenceValidation:
    ok: bool
    errors: list[str] = field(default_factory=list)
    request_count: int = 0
    response_count: int = 0
    endpoints: list[str] = field(default_factory=list)


def validate_evidence(finding: Finding, db: Database, evidence: EvidenceStore) -> EvidenceValidation:
    """Verify every referenced evidence blob and that it matches the finding."""
    errors: list[str] = []
    if not finding.evidence_ids:
        return EvidenceValidation(ok=False, errors=["no evidence attached to finding"])

    request_count = 0
    response_count = 0
    request_urls: list[str] = []

    for eid in finding.evidence_ids:
        rec = db.get_evidence(eid)
        if rec is None:
            errors.append(f"missing evidence record: {eid}")
            continue
        try:
            data = evidence.read_verified(eid)  # verifies SHA-256, raises on tamper/missing
        except EvidenceIntegrityError as exc:
            errors.append(f"evidence integrity failure: {exc}")
            continue
        try:
            blob = json.loads(data)
        except (json.JSONDecodeError, ValueError):
            errors.append(f"evidence {eid} is not parseable")
            continue

        if rec.label == "request":
            request_count += 1
            url = blob.get("url")
            if url:
                request_urls.append(url)
        elif rec.label == "response":
            response_count += 1

    if request_count < 1:
        errors.append("no request evidence present")
    if response_count < 1:
        errors.append("no response evidence present")

    # Target/endpoint must match the finding.
    if request_urls:
        if finding.endpoint not in request_urls:
            errors.append("finding endpoint not found among evidence request URLs")
        finding_host = urlsplit(finding.endpoint).hostname
        if not any(urlsplit(u).hostname == finding_host for u in request_urls):
            errors.append("evidence host does not match the finding's affected asset")

    return EvidenceValidation(
        ok=not errors, errors=errors, request_count=request_count,
        response_count=response_count, endpoints=sorted(set(request_urls)),
    )


@dataclass
class ReportQuality:
    complete: bool
    checks: dict[str, bool]
    issues: list[str]


def _has_placeholder(*texts: str) -> bool:
    joined = " ".join(t for t in texts if t).lower()
    return any(tok in joined for tok in _PLACEHOLDERS)


def report_quality(finding: Finding, db: Database, evidence: EvidenceStore) -> ReportQuality:
    """Deterministic completeness checks for a finding's report."""
    ev = validate_evidence(finding, db, evidence)
    checks = {
        "target_exists": bool(finding.affected_asset.strip()),
        "endpoint_exists": bool(finding.endpoint.strip()),
        "vulnerability_class_exists": bool(finding.vuln_type.strip()),
        "reproduction_steps_exist": bool(finding.reproduction.strip()),
        "evidence_exists": bool(finding.evidence_ids),
        "evidence_hashes_validate": ev.ok,
        "expected_behavior_exists": bool(finding.expected_behavior.strip()),
        "actual_behavior_exists": bool(finding.actual_behavior.strip()),
        "no_placeholder_text": not _has_placeholder(
            finding.title, finding.impact, finding.reproduction,
            finding.expected_behavior, finding.actual_behavior, finding.preconditions,
        ),
    }
    issues = [name for name, ok in checks.items() if not ok]
    return ReportQuality(complete=not issues, checks=checks, issues=issues)
