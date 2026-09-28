# Universal Bug Bounty Research Agent (`bbagent`)

An agent framework for **authorized** bug bounty research. It loads a program's
scope and rules, maps the attack surface, generates vulnerability hypotheses,
performs only authorized non-destructive tests, verifies candidates with
**reproducible evidence**, and produces Markdown reports for **human review**.

> ⚠️ **Authorized use only.** Configure and run this only against programs you
> are explicitly permitted to test. The tool fails closed: anything not proven
> in-scope is blocked, and it will **never** submit a report on its own.

## Safety invariants

These are enforced structurally, not by convention:

1. **Every outbound request passes the scope engine.** The `AuthorizedHTTPClient`
   is the only sanctioned way to make requests, and it calls `ScopeEngine.enforce`
   before anything leaves the process. Exclusions always beat inclusions, and an
   undetermined scope is denied (`src/bbagent/scope/engine.py`).
2. **A program must declare `authorized: true`** or the loader refuses it
   (`src/bbagent/config/models.py`).
3. **No finding without evidence.** The `VerificationEngine` will only create a
   `Finding` from a `VerificationResult` that is both `verified=True` *and*
   carries real captured HTTP exchanges. A verifier that claims success with no
   exchanges is rejected (`src/bbagent/verification/engine.py`,
   test: `test_verified_without_evidence_is_rejected`).
4. **Evidence is immutable.** Raw request/response pairs are content-addressed,
   hashed (SHA-256), written read-only, and protected by SQLite triggers that
   abort any `UPDATE`/`DELETE`. Reads re-verify the hash and raise on tampering.
5. **The agent cannot submit.** Findings move `VERIFIED → READY_FOR_REVIEW →
   APPROVED_FOR_SUBMISSION`; only a human (non-`agent` actor) may approve, and
   submission is intentionally not implemented (`src/bbagent/review.py`).
6. **Destructive testing is not implemented.** DoS is always forbidden; active
   (state-changing) methods are gated behind `allow_active_testing`.

## Architecture

```
config/       Pydantic program models + YAML/JSON loader (source of truth for scope)
program/      ProgramManager — authoritative accessor for scope, headers, accounts
scope/        ScopeEngine — the fail-closed gate every request passes
http/         AuthorizedHTTPClient (+ token-bucket rate limiter) — only way to send
storage/      SQLite schema, domain models, immutable EvidenceStore
detectors/    Detector/Verifier interfaces + pluggable registry (+ example: idor)
verification/ VerificationEngine (hypothesis→finding lifecycle) + deduplication
review.py     Human approval state machine
report.py     Markdown report generation from verified data + evidence
cli.py        Conservative CLI (validate config, scope-check a URL)
```

### Key design decisions

- **Config is the single source of truth for scope.** Pydantic models validate
  shape at load time (e.g. wildcards must start with `*.`), and nothing else may
  widen scope. Secrets for test accounts are referenced by **environment
  variable name** — never stored in the YAML.
- **Fail-closed scope engine.** Supports exact domains, `*.` wildcards (subdomains
  only, not the apex), URL prefixes, and CIDR ranges. Unparseable targets, bad
  schemes, and unmatched hosts are denied. The engine is pure/side-effect-free so
  it can be tested exhaustively.
- **One choke point for the network.** No component (including the future LLM
  "brain") talks to the network except through `AuthorizedHTTPClient`, which
  layers: dry-run kill switch → scope → method/path restrictions → active-testing
  gate → required-header injection → rate limiting.
- **Hypothesis ≠ finding.** Detectors are cheap and speculative; they only emit
  `Hypothesis` objects and may never create findings or evidence. The
  `VerificationEngine` is the sole promoter, and it demands evidence. This is what
  prevents an LLM from "inventing" a vulnerability.
- **Stdlib `sqlite3`, not an ORM.** Keeps dependencies minimal and lets us use
  SQLite triggers to make the evidence table genuinely append-only. Domain
  objects are dataclasses, so callers never hand-write SQL.
- **Async HTTP (`httpx`) with a per-host token-bucket limiter**, because recon and
  verification are I/O-bound and rate limits are usually per-host. A `MockTransport`
  is injectable for deterministic tests.
- **Pluggable detectors/verifiers** via a small registry keyed on `vuln_type`.
  Adding a detector is: subclass, `@registry.register_detector`, import. The
  shipped `idor` module is a full non-destructive example (compares what two test
  identities can read).

## The LLM "Agent Brain" (design)

The brain is intentionally *not* wired to the network or a shell. When added, it
will only be handed **controlled tools** (`discover_assets`, `crawl`,
`inspect_endpoint`, `send_authorized_request`, `compare_responses`,
`analyze_response`, `save_observation`, `create_hypothesis`). Each network tool
delegates to `AuthorizedHTTPClient`, so scope and rate limits apply regardless of
what the model asks for. The brain can *propose* hypotheses; it cannot mint
findings or evidence.

## Finding lifecycle

```
Hypothesis(proposed) → investigating → verifying
    → verified  → Finding(VERIFIED) → READY_FOR_REVIEW → APPROVED_FOR_SUBMISSION
    → discarded (no evidence / not reproducible / duplicate)
```

## Report contents

`report.generate_report` emits: title, summary, affected asset, endpoint,
vulnerability type, preconditions, steps to reproduce, expected vs actual
behavior, impact, and evidence blocks (each integrity-verified before inclusion).
**No severity** is emitted unless the caller supplies one from a program-specific
methodology.

## Getting started

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate     |  macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env        # fill in secrets; .env is git-ignored

# Validate a program and check scope:
python -m bbagent.cli validate programs/example.yaml
python -m bbagent.cli scope programs/example.yaml http://localhost/x

# Run the tests:
pytest -q
```

The shipped `programs/example.yaml` points **only at local hosts** and is safe to
experiment with. Do not point a config at a target you are not authorized to test.

## Testing

`pytest` covers: scope validation and exclusions, required-header injection,
method/path restrictions, rate limiting, the authorization gate on config load,
evidence capture/immutability/tamper-detection, hypothesis→finding verification,
the no-evidence-no-finding rule, deduplication, and the human-approval state
machine. All exchanges in tests use an injected `httpx.MockTransport` — the suite
makes **no real network calls**.

## Roadmap (not yet implemented)

- Recon engine (asset/HTTP/endpoint/JS/API/param discovery, tech fingerprinting)
- Attack-surface mapper persistence beyond the core tables
- Additional detectors (XSS, SSRF, SQLi, path traversal, upload, auth, biz-logic)
- The controlled-tool LLM brain
- A local deliberately-vulnerable test lab for end-to-end exercises

## Local test lab (planned)

Before any real engagement, stand up a local vulnerable app (e.g. a small Flask
app with intentional IDOR/XSS) and point `programs/example.yaml` at `localhost`.
This lets the full pipeline — recon → hypothesis → verification → evidence →
report — run without touching any external target.
