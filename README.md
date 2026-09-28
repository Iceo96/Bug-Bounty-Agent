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
recon/        Manifest-based endpoint discovery (scope-bounded)
detectors/    Detector/Verifier interfaces + pluggable registry + real IDOR/BOLA detector
verification/ VerificationEngine (hypothesis→finding lifecycle) + deduplication
review.py     Human approval state machine
report.py     Markdown report generation from verified data + evidence
cli.py        Conservative CLI (validate config, scope-check a URL)

bbagent_lab/  Local deliberately-vulnerable app + agent glue (loopback only)
  app.py        Vulnerable WSGI app: /api/notes/{id} (IDOR) + /api/profile/{id} (protected)
  data.py       Deterministic synthetic accounts/objects (non-secret test tokens)
  server.py     Loopback-only WSGI server + BackgroundLab for tests
  agent_config.py  Builds the loopback-scoped ProgramConfig for the lab
  pipeline.py   Wires recon → detect → verify → evidence → findings
  demo.py       Runs the full pipeline and writes example reports
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

## Getting started (Windows / PowerShell)

Exact commands, run from the project root (`C:\...\Bug-Bounty-Agent`):

```powershell
# 1) Create the environment
python -m venv .venv

# 2) Install dependencies (editable, with dev/test extras)
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -e ".[dev]"

# 3) (optional) create your local .env — it is git-ignored; never commit secrets
Copy-Item .env.example .env

# Validate a program and check scope:
.venv\Scripts\python.exe -m bbagent.cli validate programs\lab.yaml
.venv\Scripts\python.exe -m bbagent.cli scope programs\lab.yaml http://127.0.0.1/api/notes/note-a1
```

> macOS/Linux: use `source .venv/bin/activate` then `pip install -e ".[dev]"`.

## The local vulnerable lab

A completely local, deliberately-vulnerable app that exercises the agent from
discovery through verified finding and report. It **binds only to 127.0.0.1** and
makes **no external requests**. Data is harmless and synthetic.

- `GET /api/notes/{id}` — **vulnerable** (IDOR/BOLA): any authenticated user can
  read any note.
- `GET /api/profile/{id}` — **correctly protected**: only the owner may read it.

### Start / stop the lab (Windows)

```powershell
# Start (foreground; press Ctrl+C to stop):
.venv\Scripts\python.exe -m bbagent_lab.server --port 8000
#   or: powershell -ExecutionPolicy Bypass -File scripts\start-lab.ps1 -Port 8000

# Stop a lab you started in another window/background:
powershell -ExecutionPolicy Bypass -File scripts\stop-lab.ps1 -Port 8000
```

Once running, the discovery manifest is at `http://127.0.0.1:8000/`.

### Run the integration tests

```powershell
# Just the lab integration suite:
.venv\Scripts\python.exe -m pytest tests\test_integration_lab.py -q

# The complete suite:
.venv\Scripts\python.exe -m pytest -q
```

The integration tests start the lab in-process on an ephemeral loopback port, so
you do **not** need to start the server manually for them.

### Generate the example report

```powershell
.venv\Scripts\python.exe -m bbagent_lab.demo
```

This starts the lab in-process, runs discovery → verification → report, and
writes one Markdown report per verified finding into `.\reports\` (git-ignored).
It prints the path of each report it writes.

## Testing

`pytest` covers, in unit tests (mocked transport, no sockets):
scope validation and exclusions, required-header injection, method/path
restrictions, rate limiting, the authorization gate on config load, evidence
capture/immutability/tamper-detection, hypothesis→finding verification, the
no-evidence-no-finding rule, deduplication, and the human-approval state machine.

And in **integration tests** against the real lab over a localhost socket:
the vulnerable endpoint is detected, the protected endpoint is not, evidence is
captured and its hashes stay valid, a finding cannot exist without evidence,
scope rules still apply (non-loopback denied), and every touched/recorded target
is loopback (no external requests).

## Roadmap (not yet implemented)

- Broader recon (asset/HTTP/JS/API/param discovery, tech fingerprinting) beyond
  the current manifest-based endpoint discovery
- Attack-surface mapper persistence beyond the core tables
- Additional detectors (XSS, SSRF, SQLi, path traversal, upload, auth, biz-logic)
- The controlled-tool LLM brain
