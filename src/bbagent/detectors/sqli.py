"""SQL injection detector/verifier — deterministic boolean/differential strategy.

How it proves SQLi (without errors, timing, or guesswork)
---------------------------------------------------------
It sends three read-only requests and measures a *content-based result count*
(the size of the largest result set in the JSON response), never the status
code, body length, or timing:

    baseline    id = 1              -> B records
    true cond.  id = 1 OR 1=1       -> T records   (should EXPAND if injectable)
    false cond. id = 1 AND 1=2      -> F records   (should SHRINK if injectable)

VERIFIED only when a strict, reproducible differential holds:  T > B > … and
F < B and T > F. That relationship can only occur if the boolean condition was
interpreted as SQL — a parameterized/secure endpoint binds the input as a value,
so T and F never expand/shrink the result set, and a control endpoint that never
touches SQL returns a constant count. SQL errors, generic 500s, length or timing
differences, or a single anomalous response never satisfy the differential.

Payloads are read-only (``OR 1=1`` / ``AND 1=2``) — no DROP/DELETE/UPDATE/INSERT,
no stacked queries, no filesystem/command/network access. Local lab only.

Limitation: this is deterministic *boolean-based* verification suited to the
local lab. It does not claim to detect every SQLi variant (e.g. blind time-based,
second-order, or out-of-band), and it requires a countable (JSON) result set.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from bbagent.detectors.base import (
    Detector,
    DetectionContext,
    VerificationContext,
    VerificationResult,
    Verifier,
    registry,
)
from bbagent.storage.models import Hypothesis
from bbagent.verification.dedup import compute_dedup_key

# Parameters that plausibly reach a SQL query (id-like / filter-like).
_SQL_PARAM = re.compile(
    r"(?i)^(id|.*_id|pid|uid|cat|category|product|product_id|order|order_id|"
    r"sort|filter|user|user_id|offset|page|limit)$"
)


def is_sql_param(name: str) -> bool:
    return bool(_SQL_PARAM.match(name or ""))


def _first_param(url: str) -> str | None:
    params = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    return params[0][0] if params else None


def _strip_query(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


def result_count(body: str) -> int:
    """Content-based result-set size: the largest JSON array length.

    Returns -1 if the body is not JSON (e.g. an error/HTML page), 0 if it is JSON
    but contains no array. Never uses body length or timing.
    """
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return -1

    best = 0
    found_array = False

    def walk(node):
        nonlocal best, found_array
        if isinstance(node, list):
            found_array = True
            best = max(best, len(node))
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            for v in node.values():
                walk(v)

    walk(obj)
    return best if found_array else 0


@registry.register_detector
class SQLInjectionDetector(Detector):
    vuln_type = "sql_injection"
    name = "sql-injection-detector"

    async def detect(self, ctx: DetectionContext) -> list[Hypothesis]:
        hyps: list[Hypothesis] = []
        for obs in ctx.observations:
            if obs.kind != "endpoint":
                continue
            url = obs.data.get("url", "")
            param = _first_param(url)
            if not param or not is_sql_param(param):
                continue
            hyps.append(Hypothesis(
                program=ctx.program.name,
                vuln_type=self.vuln_type,
                title=f"Possible SQL injection at {url}",
                rationale=f"Endpoint parameter '{param}' may reach a SQL query.",
                target_url=url,
                detector=self.name,
                observation_ids=[obs.id],
            ))
        return hyps


@registry.register_verifier
class SQLInjectionVerifier(Verifier):
    vuln_type = "sql_injection"

    async def verify(self, ctx: VerificationContext) -> VerificationResult:
        url = ctx.hypothesis.target_url
        param = _first_param(url)
        if not param:
            return VerificationResult(
                verified=False,
                reason="malformed hypothesis: no input parameter present in target URL",
            )
        base = _strip_query(url)
        base_val = "1"
        true_val = f"{base_val} OR 1=1"
        false_val = f"{base_val} AND 1=2"

        baseline = await ctx.http.get(base, params={param: base_val})
        truthy = await ctx.http.get(base, params={param: true_val})
        falsy = await ctx.http.get(base, params={param: false_val})
        exchanges = [baseline, truthy, falsy]

        b = result_count(baseline.response_body)
        t = result_count(truthy.response_body)
        f = result_count(falsy.response_body)

        if b < 1:
            return VerificationResult(
                verified=False,
                reason=f"no baseline result set to differentiate against (baseline_count={b})",
                exchanges=exchanges,
            )

        differential = (t > b) and (f < b) and (t > f)
        if not differential:
            return VerificationResult(
                verified=False,
                reason=(f"no deterministic SQL differential: baseline={b}, true(OR 1=1)={t}, "
                        f"false(AND 1=2)={f} (need true>baseline>… and false<baseline)"),
                exchanges=exchanges,
            )

        return VerificationResult(
            verified=True,
            reason="boolean conditions injected via the parameter changed the SQL result set",
            exchanges=exchanges,
            expected_behavior=(
                f"the '{param}' parameter must be bound as a value (prepared statement); "
                f"boolean conditions in the input must not change the number of rows returned."
            ),
            actual_behavior=(
                f"result-set size tracked the injected boolean: baseline(id=1)={b} rows, "
                f"'1 OR 1=1'={t} rows (expanded), '1 AND 1=2'={f} rows (collapsed). The input "
                f"was interpreted as SQL, not data."
            ),
            impact=(
                "SQL injection (boolean-based): attacker-controlled input alters query logic, "
                "allowing unauthorized reading/enumeration of database rows."
            ),
            test_identity="unauthenticated",
            reproduction=(
                f"1. GET {base}?{param}=1 — note {b} row(s).\n"
                f"2. GET {base}?{param}=1 OR 1=1 — observe {t} row(s) (expanded).\n"
                f"3. GET {base}?{param}=1 AND 1=2 — observe {f} row(s) (collapsed).\n"
                f"The differential proves the boolean was executed as SQL."
            ),
            dedup_key=compute_dedup_key("sql_injection", base, "GET"),
        )
