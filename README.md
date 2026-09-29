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
recon/        Manifest discovery + attack-surface mapper (crawl, JS, extract)
surface/      Persistent, queryable attack-surface graph (SQLite)
detectors/    Detector/Verifier interfaces + registry + IDOR/BOLA + BFLA + reflected-XSS + SQLi
verification/ VerificationEngine (hypothesis→finding lifecycle) + deduplication
planner/      Deterministic planner, capability registry, budgets, run history, LLM boundary
llm/          LLM Reasoner adapter (prioritization only): sanitizer, strict schema, validation
tools/        Tool abstraction: Tool interface, registry, HTTP tool, local recon tool, router,
              and PolicyGatedHTTP (the single policy-gated path for detector verification)
policy/       ProgramPolicyEngine (ALLOW/DENY, fail-closed) incl. mechanical data-scoping
validation.py Evidence validation + deterministic report-quality checks
reviewstore.py Persistent human-review queue (immutable + edited reports, duplicates)
review.py     Approval state machine (human-only approval)
report.py     Markdown report generation (marks incomplete rather than guessing)
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

Function-level authorization scenario (separate admin manifest at
`/admin-scope/manifest`, so the object-level scenario above is untouched):

- `GET /api/admin/report` — **vulnerable** (BFLA): performs no role check, so any
  authenticated user receives the restricted admin report.
- `GET /api/admin/settings` — **correctly protected**: requires the admin role
  (non-admins get 403).
- `GET /api/admin/ping` — **control**: an admin-like path that returns a generic
  `{"ok":true}` with no privileged data — must NOT be flagged.

Identities: `user_a` is an admin, `user_b` is a regular user (both synthetic).

Reflected-XSS scenario (separate manifest at `/xss-scope/manifest`):

- `GET /search?q=` — **vulnerable**: reflects `q` into HTML text context without
  encoding.
- `GET /search-safe?q=` — **secure**: reflects `q` but HTML-encodes it (inert).
- `GET /echo?q=` — **control**: reflects `q` verbatim in a `text/plain` response —
  the string appears but cannot execute, so it must NOT be flagged.

All payloads are harmless, deterministic, loopback-only (no scripts, no callbacks,
no cookies/credentials).

SQL-injection scenario (separate manifest at `/sqli-scope/manifest`), backed by a
per-request in-memory SQLite `products` table `(id, name, category, price)` with 5
deterministic synthetic rows:

- `GET /products?id=` — **vulnerable**: interpolates `id` into the SQL string
  (boolean-injectable).
- `GET /products-safe?id=` — **secure**: parameterized/prepared statement — the
  same boolean input is bound as a value and cannot change query semantics.
- `GET /whoami?id=` — **control**: input never reaches SQL (constant echoed
  record), so there is no differential to exploit.

Probes are read-only (`OR 1=1` / `AND 1=2`) — no DROP/DELETE/UPDATE/INSERT, no
stacked queries, no filesystem/command/network access.

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

## Detectors (access-control)

Two pluggable, non-destructive access-control detectors are registered in the
capability registry; both are read-only (GET) and produce a VERIFIED finding
only from real, reproducible evidence — never from a status code, error message,
response length, timing, or an LLM guess.

**1. IDOR / BOLA (`idor`)** — object-level authorization. Baseline as the owner,
then request the *same object* as a second identity; confirmed only when the
second identity receives the owner's object contents (identical body).

**2. Privilege escalation / BFLA (`privilege_escalation`)** — function-level
authorization. It fires on admin-like endpoints when the program has an admin and
a non-admin test identity. Verification is concrete:

1. **Baseline** — the admin identity must receive `200` with identifiable
   *privileged content* (a value under a sensitive key such as `classification`
   or `records`). No privileged baseline ⇒ DISPROVEN.
2. **Access control** — an unauthenticated request must be denied (non-200), or
   the resource is simply public, not a privilege boundary ⇒ DISPROVEN.
3. **Escalation** — the non-privileged identity must receive `200` **and** its
   body must actually disclose the baseline's privileged marker(s). A matching
   `200` with no privileged data (a generic response) ⇒ DISPROVEN.

All three exchanges (privileged baseline, unauthenticated, non-privileged) are
captured as immutable evidence. Against the lab: `/api/admin/report` → VERIFIED,
`/api/admin/settings` → DISPROVEN (403), `/api/admin/ping` → DISPROVEN (no
privileged content). False positives explicitly rejected: correct 401/403,
own-resource access, generic 200s, public endpoints, missing/incorrect identities,
and (via the engine) insufficient evidence, out-of-scope targets, and budget
exhaustion.

**3. Reflected XSS (`reflected_xss`)** — proposed only when an endpoint has a
user-controlled query parameter. The verifier injects a **unique, harmless marker
payload** (a custom element + attribute — no JavaScript, handlers, or callbacks)
through the AuthorizedHTTPClient and analyzes the response with `html.parser`:

- **Reflection baseline** — a benign value must first be reflected, or the
  parameter is not a sink ⇒ DISPROVEN.
- **Context analysis** — VERIFIED only when the marker becomes **live markup** (a
  new element or an injected attribute materializes in the parsed HTML). This is
  the deterministic, browser-free proof that input crossed from data into HTML
  structure (HTML-text and attribute-breakout contexts).
- Encoded reflection (`&lt;…&gt;`), plain-text / non-HTML responses, generic
  responses, and non-reflected input are all DISPROVEN. Reflection that lands
  only inside a `<script>` block is **INCONCLUSIVE** (not VERIFIED).

**Limitation (by design):** there is no browser/JS engine, so the detector proves
*reflected executable HTML context* (markup creation) — it does **not** claim
JavaScript execution. Script-context-only reflection is reported inconclusive
rather than verified, and would require an actual browser engine to confirm.

**4. SQL injection (`sql_injection`)** — proposed only for plausibly SQL-reaching
parameters (id-like: `id`, `*_id`, `category`, `page`, …). Verification uses a
deterministic **boolean/differential** strategy on a content-based *result count*
(the largest JSON array length in the response) — never status code, body length,
timing, or error messages:

```
baseline    id = 1          -> B rows
true  cond. id = 1 OR 1=1   -> T rows   (must EXPAND if injectable)
false cond. id = 1 AND 1=2  -> F rows   (must SHRINK if injectable)
```

VERIFIED only when the strict relationship `T > B` and `F < B` and `T > F` holds —
which can only happen if the boolean was executed as SQL. A parameterized endpoint
binds the input (T and F never expand/shrink), a control endpoint returns a
constant count, and SQL errors / generic 500s / length or timing differences never
satisfy the differential. The three exchanges (baseline, true, false) are captured
as immutable evidence. Read-only probes only.

**Limitation (by design):** this is deterministic boolean-based verification for
the local lab. It does not claim to detect every SQLi variant (blind time-based,
second-order, out-of-band) and needs a countable (JSON) result set.

All four detectors run through the **same** planner → verification engine →
evidence store → review workflow; none makes raw HTTP requests or bypasses
scope, rate limits, budgets, or the human-approval gate.

## Attack-surface mapper

The mapper turns authorized discovery into a **persistent, queryable graph** in
SQLite that a future planner can reason over. It drives everything through the
existing `AuthorizedHTTPClient`, so scope, rate limits, required headers, and
active-testing controls all apply; it issues **GET only** and refuses ambiguous
or out-of-scope targets.

What it records (all deduplicated, with `first_seen`/`last_seen`):

- **Assets** — scheme, host, port, URL, status, title, content type, technologies
- **Endpoints** — method, normalized URL, path, query/path params, request/response
  content types, observed status codes, and a `confirmed` flag (candidates from JS
  are unconfirmed until a real request is made)
- **JavaScript** — downloaded files with SHA-256, size, and the page that loaded them
- **API endpoints** — tracked separately (base, path, method, params, responses)
- **Parameters** — query/path/body/form, with their source
- **Object references** — numeric / UUID / hex / path / JSON-id **candidates only**
  (never called an IDOR)
- **Authentication contexts** — how each endpoint responded when *unauthenticated*,
  *as identity A*, and *as identity B* (recorded as observations; no authz decision
  is inferred from status codes)
- **Relationships** — `asset → js`, `asset → endpoint`, `js → endpoint`, plus the
  FK links endpoint → parameter / object-ref / auth-observation, so the planner can
  walk host → page → JS → endpoint → parameter → object-ref → auth-context.

### Run the mapper (Windows, against the local lab)

Start the lab in one terminal (`... -m bbagent_lab.server --port 8000`), then in
another (the tokens let the mapper probe identities A and B):

```powershell
$env:BBAGENT_LAB_TOKEN_A = "tok_test_a_11111111"
$env:BBAGENT_LAB_TOKEN_B = "tok_test_b_22222222"

# Discover from the manifest and crawl the HTML site into a DB:
.venv\Scripts\python.exe -m bbagent.cli --db data\lab.db recon programs\lab.yaml `
    --manifest http://127.0.0.1:8000/ --crawl http://127.0.0.1:8000/site

# Query the persisted attack surface:
.venv\Scripts\python.exe -m bbagent.cli --db data\lab.db assets "Local Vulnerable Lab"
.venv\Scripts\python.exe -m bbagent.cli --db data\lab.db endpoints "Local Vulnerable Lab"
.venv\Scripts\python.exe -m bbagent.cli --db data\lab.db attack-surface "Local Vulnerable Lab" --json
```

`--json` on `assets` / `endpoints` / `attack-surface` emits a machine-readable
snapshot for the planner; without it you get a human-readable summary. Read
commands accept a program **name** or a path to its config file. Example
`endpoints` output:

```
GET http://127.0.0.1:8000/api/notes/note-a1
    source=manifest confirmed authn=required status=[200]
    object-refs: note-a1(json_id),note-a1(path_id)
    auth-observations: identity_a=[200]; identity_b=[200]; unauthenticated=[401]
```

## Autonomous testing planner

The planner is the reasoning/orchestration layer over the attack-surface graph.
It is **deterministic and bounded**: it queries the graph, generates and
prioritizes candidate hypotheses, and executes only authorized tests through the
existing verification engine — it never performs HTTP itself and never turns a
heuristic match into a finding.

Loop: `OBSERVE → GENERATE → PRIORITIZE → EXECUTE → RECORD → VERIFY → UPDATE →
REPLAN`, stopping when no useful hypotheses remain, the budget is exhausted, the
program forbids the next test, or the operator stops it.

- **Capability registry** — describes what each detector/verifier can test. Only
  the existing IDOR/access-control capability is registered (no new vuln classes).
- **Prioritization** (deterministic scoring) favors endpoints with object
  references, observed under multiple identities, with differing authorization
  observations, that require auth, that are API endpoints, and that carry
  parameters. A match is only a *candidate* — verification decides.
- **Deduplication** on `target + endpoint + vuln-class + object-refs`; verified
  hypotheses are never regenerated.
- **Budget**: `max_requests`, `max_tests_per_endpoint`, `max_tests_per_host`,
  `max_runtime`, concurrency — enforced, with the stop reason recorded.
- **Run history**: each run persists id, timings, and counts (generated /
  executed / verified / disproven / inconclusive / requests / findings).
- **LLM boundary**: `LLMPlanner` accepts a `Reasoner` that receives *serialized
  candidate data only* and may only reorder/annotate. It never gets the HTTP
  client, the database, shell, or any way to execute. The core planner is
  deterministic so the whole system is testable without an LLM.

### Plan and run (Windows, against the local lab)

Start the lab and populate the graph with `recon` (above), then:

```powershell
$env:BBAGENT_LAB_TOKEN_A = "tok_test_a_11111111"
$env:BBAGENT_LAB_TOKEN_B = "tok_test_b_22222222"

# Preview the prioritized hypothesis queue (no execution):
.venv\Scripts\python.exe -m bbagent.cli --db data\lab.db plan programs\lab.yaml

# Dry run: persist the planned queue, execute nothing:
.venv\Scripts\python.exe -m bbagent.cli --db data\lab.db run programs\lab.yaml --dry-run

# Execute authorized tests and verify (writes evidence + findings):
.venv\Scripts\python.exe -m bbagent.cli --db data\lab.db run programs\lab.yaml
```

`plan` output looks like:

```
[1] HIGH
idor — Authorization boundary
GET http://127.0.0.1:8000/api/notes/note-a1
Reason: object reference (json_id, path_id); multiple authorized test identities
available; observed under multiple identity contexts; differing authorization
observations across identities; authentication required; API endpoint
Auth context: user_a, user_b  Expected signal: user_b receives user_a's object ...

[2] HIGH
idor — Authorization boundary
GET http://127.0.0.1:8000/api/profile/1001
...
```

A full `run` verifies the vulnerable notes endpoint (finding + evidence) and
**disproves** the protected profile endpoint (owner=200, other=403 → not a
finding, because a 200 alone is never treated as evidence):

```
generated=2 executed=2 verified=1 disproven=1 inconclusive=0 requests=4
findings_created=1 stop=no useful hypotheses remain
```

## Optional LLM reasoner (prioritization only)

An LLM can be plugged in to **reorder and explain** the candidate queue. It is a
reasoning component only and is **disabled by default**.

**Hard security boundary** — the LLM has NO access to HTTP, the shell, filesystem
writes, SQLite, credentials, arbitrary URLs, or the `AuthorizedHTTPClient`. It
receives only *sanitized* candidate data that already passed the deterministic
planner's scope and capability checks, and it may only return a ranking. It may
**not** create targets/URLs, execute tests, modify the graph or evidence, create
or approve findings, or submit reports. Its response is validated against a
strict Pydantic schema and the known candidate set:

- malformed response, unknown/invented candidate, or any attempt to change a
  `target` / `endpoint` / `method` → the response is **discarded** and the run
  falls back to deterministic ordering (unless `fallback_to_deterministic: false`,
  which aborts instead).
- credentials/tokens/auth headers and sensitive fields are stripped and scrubbed
  before anything is sent; secrets are never logged.

### Setup and configuration

```powershell
# Install the optional backend:
.venv\Scripts\python.exe -m pip install -e ".[llm]"

# Provide the API key via environment (never in config; .env is git-ignored):
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```

Configure per program (defaults shown; the block is optional and starts disabled):

```yaml
llm:
  enabled: false
  provider: "anthropic"
  model: "claude-sonnet-5-5"
  max_candidates: 20
  timeout_seconds: 30
  fallback_to_deterministic: true
```

### Enabling / disabling

- **Disabled (default):** every `plan`/`run` uses the deterministic planner.
- **Enabled:** pass `--llm` to `plan` or `run`:

```powershell
.venv\Scripts\python.exe -m bbagent.cli --db data\lab.db plan programs\lab.yaml --llm
.venv\Scripts\python.exe -m bbagent.cli --db data\lab.db run  programs\lab.yaml --llm
```

Flow with `--llm`: deterministic candidates → LLM prioritization → strict
validation → execution through the **same** verification pipeline. If the API key
or SDK is missing, the CLI warns and uses the deterministic planner (or aborts if
fallback is disabled). Logs show the candidate count, that the LLM was requested,
whether its response was validated or rejected, whether fallback was used, and
the final execution order — never any secret.

## Human review & reporting

Verified findings do not go anywhere automatically. They pass through a
persistent review queue and require a **human** to approve them; the agent/LLM
can never approve, and **nothing is ever auto-submitted**.

Statuses: `VERIFIED → READY_FOR_REVIEW → APPROVED_FOR_SUBMISSION`, with
`CHANGES_REQUESTED` and `REJECTED` as branches. Only a human actor may reach
`APPROVED_FOR_SUBMISSION`.

Before a finding enters the queue:

- **Evidence is validated** — every referenced blob is re-hashed (SHA-256),
  required request/response exchanges must exist, and the request URLs must match
  the finding's endpoint/asset. Missing or corrupt evidence blocks report
  generation entirely.
- **Quality is checked** deterministically — target, endpoint, vuln class,
  reproduction steps, evidence, valid hashes, expected/actual behavior, and no
  placeholder text. If anything is missing the report is marked **INCOMPLETE**
  (never guessed) and approval is refused.
- **Duplicates are surfaced** — existing findings sharing the dedup key or the
  same vuln-class + endpoint template are shown to the reviewer, never silently
  discarded.

The generated report is stored **immutably**; operator edits are stored
separately with timestamps and the reviewer's action.

### Review CLI

```powershell
# List findings and their review status:
.venv\Scripts\python.exe -m bbagent.cli --db data\lab.db findings

# Enqueue (validate + generate report + surface duplicates) and inspect:
.venv\Scripts\python.exe -m bbagent.cli --db data\lab.db review <finding-id>

# Print the report (current, or --generated for the immutable original):
.venv\Scripts\python.exe -m bbagent.cli --db data\lab.db report <finding-id>

# Approve FOR SUBMISSION — requires typing the finding id to confirm (human only):
.venv\Scripts\python.exe -m bbagent.cli --db data\lab.db approve <finding-id> --reviewer you

# Reject:
.venv\Scripts\python.exe -m bbagent.cli --db data\lab.db reject <finding-id> --reviewer you --note "duplicate"
```

`approve` reaches `APPROVED_FOR_SUBMISSION` and then **stops** — it prints a
reminder that you submit the report to the bug bounty platform manually.
Automatic submission is intentionally not implemented.

## Controlled tool layer & Program Policy Engine

The agent/LLM never executes anything directly. It emits a **structured
`ToolRequest`**; the **Tool Router** validates the tool exists, validates the
arguments against the tool's schema, runs the request through the **Program
Policy Engine**, and only on ALLOW executes it. Denied or malformed requests
never reach a tool. Tools return a **sanitized `ToolResult`** (secret header
values redacted).

```
Program Configuration
        ↓
Program Policy Engine  ── ALLOW / DENY (fail-closed)
        ↓
Agent / Planner
        ↓
   ToolRequest ──►  Tool Router
                      ├─ tool exists?           (else DENY: unknown tool)
                      ├─ arguments match schema? (else DENY: malformed)
                      ├─ Policy gates:
                      │    tool allowed · vuln-class allowed · identity authorized
                      │    scope · exclusions · method · required-header override
                      │    active-testing · request budget (total/per-target/per-tool)
                      ├─ record budget · inject identity token (server-side)
                      └─ Tool.execute  ─►  AuthorizedHTTPClient / local recon
                                              ↓
                                        Sanitized ToolResult ──► Agent / Planner
```

**Tools** (each has a name, description, version, input/output schema,
permissions, and an `execute` method):

- **`http`** — wraps the existing `AuthorizedHTTPClient` (not reimplemented). It
  keeps enforcing scope, exclusions, allowed methods, required headers,
  active-testing, dry-run, rate limits, and request budgets. Required headers are
  force-applied last (cannot be removed/overridden), an identity's bearer token is
  resolved from the environment **inside the layer** and never shown to the LLM,
  and the result redacts `Authorization`/`Cookie`/`Set-Cookie` values.
- **`recon`** — local, deterministic asset discovery from the *authorized scope*
  only. It resolves loopback names without real DNS and performs **no**
  Internet-wide enumeration; every host it returns is still scope-checked.

**Program Policy Engine** — evaluates every request and returns an explicit
`PolicyDecision` (allowed, reason, matched rule, tool, action, target, identity,
vuln class; **no secrets**). It **fails closed**: a missing/ambiguous field (e.g.
no `allowed_tools`, no target) DENIES rather than guessing. Decisions include:

| Situation | Decision |
|---|---|
| in-scope GET with an allowed test identity | ALLOW |
| target out of scope / excluded path | DENY |
| HTTP method not allowed / active method on a passive program | DENY |
| attempt to override a required header | DENY |
| unauthorized identity handle | DENY |
| tool not in `allowed_tools` | DENY |
| vulnerability class not in `allowed_vulnerability_classes` | DENY |
| request budget exhausted (stricter of total/per-target/per-tool) | DENY |
| unauthenticated action when `allow_unauthenticated: false` | DENY |
| unknown tool / malformed arguments (router) | DENY |

Policy config lives in the program (`allowed_tools`, `allowed_vulnerability_classes`,
`forbidden_actions`, `allow_unauthenticated`, `request_budget`, `data_scope`, plus
the existing scope/exclusions/methods/required-headers/test-accounts). Secrets stay
in environment variables referenced by handle — never in YAML, never in decisions.

**Mechanical data-scoping** — when a program sets `data_scope.enforce: true`, the
engine extracts id-like references from every request URL (id-like path segments
and id-like query values) and denies any that are not in `authorized_object_ids`,
unless the URL matches an `authorized_url_prefixes` entry. This is enforced in the
policy layer — not via planner/detector/LLM behavior — so an unauthorized
object/data reference is refused before transport. (Wolt uses this for its
authorized consumer/venue test entities and the authorized venue URL.)

**Policy-gated verification (no bypass path)** — detector verifiers do not touch
the HTTP client directly. Each verification request goes through `PolicyGatedHTTP`,
which runs the *same* `ProgramPolicyEngine` (vulnerability-class, identity, scope,
method, required-headers, forbidden-action, budget, data-scope) before executing,
records the budget, injects the identity credential server-side, and returns the
raw exchange for evidence. A denied verification request raises and never reaches
the transport. When a differential detector (IDOR/BFLA) needs a second authorized
identity the program does not provide, the hypothesis is marked
**INCONCLUSIVE / NEEDS_HUMAN_REVIEW** rather than using an unauthorized identity.

### Real-program policy adapter (dry-run / validation only)

A real program's *explicitly published* rules are represented as a `ProgramConfig`
— never scraped, guessed, or inferred. Two config-only, network-free commands
operate on it:

```powershell
# Validate a program's policy (fail-closed): scope, exclusions, methods, headers,
# identities, tools, vuln classes, forbidden actions, budgets, conflicts,
# ambiguities, and NEEDS_HUMAN_REVIEW markers. Exit code 1 when NOT READY.
.venv\Scripts\python.exe -m bbagent.cli policy-check programs\real-program.example.yaml

# Dry-run: show the policy decision for each hypothetical action WITHOUT sending
# anything (target, method, identity, vuln class, tool, ALLOW/DENY, reason).
.venv\Scripts\python.exe -m bbagent.cli policy-simulate programs\real-program.example.yaml `
    --actions actions.yaml
```

`programs/wolt.yaml` is a real example built **only** from the Wolt program's
supplied published rules: the full in-scope set (incl. `*.wolt.com`), every
explicit exclusion (hosts, `*.pipedrive.com`, Typeform, and specific URLs/paths),
the forbidden-POST endpoints (represented as full-URL exclusions — stricter), the
required `X-HackerOne-Research` header as an **env reference** (`BBAGENT_H1_USERNAME`,
never hardcoded), the single authorized `consumer_test` identity (courier/merchant
absent), and all do-not-test / non-eligible web & mobile categories as
`forbidden_actions`. Everything the rules do **not** explicitly grant — allowed
methods, rate limits/budgets, tool/automation permission, which detector classes
are permitted, unauthenticated testing, `blog.wolt.com` WordPress-only probes, and
venue/account data-scoping — is left empty and listed under `needs_human_review`,
so `policy-check` reports **NOT READY** and `dry_run_only: true` blocks every
request. It is a policy artifact only; nothing is ever sent to Wolt.

A **local Wolt simulation** (`bbagent_lab/wolt_sim.py`) exercises the full
autonomous pipeline against Wolt-shaped endpoints entirely through an in-process
`httpx.MockTransport` — no socket, no DNS, no real Wolt contact. It reuses Wolt's
real scope, exclusions, forbidden endpoints, required research header (env-ref),
forbidden-action categories, and the `consumer_test` identity, and fills the
`NEEDS_HUMAN_REVIEW` gaps with clearly-labelled *simulation-only* values (methods,
tools, vuln classes, budget, and one simulation second identity) so the pipeline
can run. In simulation the agent verifies one finding per class (IDOR, BFLA,
reflected-XSS, SQLi) from Wolt-shaped URLs and routes them to human review, while
policy denials (excluded host/path, forbidden-POST endpoint, missing/overridden
`X-HackerOne-Research`, unauthorized/courier/merchant identity, forbidden class or
action, undefined method/tool) are all refused **before reaching the transport**.
The real `programs/wolt.yaml` stays NOT READY and `dry_run_only: true` throughout.

`programs/real-program.example.yaml` is a **fail-closed template**: since no
published rules were supplied, every program-specific permission is marked
`NEEDS_HUMAN_REVIEW`, `allowed_tools`/`allowed_vulnerability_classes`/`request_budget`
are empty (ambiguous → NOT READY), and `dry_run_only: true` makes the HTTP client
**permanently block every outbound request** for that configuration — independent
of the `BBAGENT_DRY_RUN` env switch. `policy-check` reports NOT READY until a human
fills each field from the program's published rules; `validate_policy` fails closed
on any ambiguity, conflict, or review marker and never invents a permission.

### Local Bug Bounty Program Simulator

`bbagent_lab/simulator.py` builds a fully local, synthetic program
(`local-security-program`): loopback-only scope, an `/excluded/` exclusion, `GET`
only, a required `X-Research-ID` header, two synthetic identities, request
budgets, `allowed_tools: [http, recon]`, and the four allowed vulnerability
classes. The end-to-end test drives it: allowed recon → allowed in-scope HTTP →
denied out-of-scope/excluded/unknown-tool (never executed) → map the surface →
run the four detectors → verify with immutable evidence → human review. The agent
cannot escape scope, use an unauthorized identity, remove required headers, use a
forbidden tool/method, exceed budgets, **approve**, or **submit**.

### Autonomous run

`bbagent.orchestrator.autonomous_run(...)` performs one bounded, policy-governed
run end to end: read the program → policy-gated local recon → policy-gated surface
discovery (each manifest ALLOW-checked before mapping) → plan + prioritize → run
the **four existing detectors** through the verification engine → immutable
evidence → generate reports → enqueue every verified finding for **human** review.
It adds no detectors and no tools, and never approves or submits.

```powershell
$env:BBAGENT_LAB_TOKEN_A = "tok_test_a_11111111"
$env:BBAGENT_LAB_TOKEN_B = "tok_test_b_22222222"
.venv\Scripts\python.exe -m bbagent_lab.server --port 8020    # in one terminal
.venv\Scripts\python.exe -m bbagent.cli --db data\auto.db `
    autorun programs\simulator.yaml --base http://127.0.0.1:8020
```

Against the lab's combined `/full-scope/manifest`, a single run discovers ~11
endpoints, generates ~14 hypotheses, and verifies **exactly one finding per
class** while disproving the secure/control endpoints:

```
# Autonomous run: local-security-program
recon hosts: 127.0.0.1, localhost
manifests allowed: 1  denied: 0
endpoints discovered: 11
hypotheses: 14
verified findings: 4 [idor, privilege_escalation, reflected_xss, sql_injection]
  - idor: .../api/notes/note-a1 -> ready_for_review (find_...)
  - privilege_escalation: .../api/admin/report -> ready_for_review (find_...)
  - reflected_xss: .../search?q=... -> ready_for_review (find_...)
  - sql_injection: .../products?id=1 -> ready_for_review (find_...)
run: executed=14 verified=4 disproven=10 requests=32
All verified findings await HUMAN review. The agent did not approve or submit.
```

## End-to-end lifecycle

```
program config
  → authorized discovery (recon / attack-surface mapper)
  → attack-surface graph (assets, endpoints, params, object-refs, auth-contexts)
  → planner: generate → prioritize (deterministic, optional LLM) → dedup
  → execute authorized test via existing verifier (scope + rate + budget enforced)
  → verification: real request/response evidence, hashed & stored immutably
  → verified finding  (a hypothesis is never a finding without evidence)
  → evidence validation + report-quality checks
  → Markdown report (incomplete-marked if anything is missing)
  → human review queue  (duplicates surfaced; report editable, original immutable)
  → human approval  → APPROVED_FOR_SUBMISSION
  → [operator submits manually — no auto-submission]
```

Every outbound request in that chain passes the scope engine, rate limits,
required headers, and active-testing controls; the LLM (if enabled) only reorders
sanitized candidate data; and only a human can approve.

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

Plus **attack-surface mapper** tests (unit + lab integration): asset/endpoint
discovery, HTML crawling, JavaScript discovery, API-candidate and parameter
extraction, object-reference detection, dedup across runs, authentication-context
tracking, scope enforcement, excluded-target handling, loopback-only behavior,
and the CLI recon → query round-trip.

Plus **planner** tests (unit + lab integration): deterministic prioritization,
hypothesis generation, dedup / verified-regeneration guard, budget enforcement,
state transitions, verification feedback, dry-run (zero requests), the LLM
data-only boundary, scope enforcement on execution, the protected-endpoint
negative case, no external network, and a complete local end-to-end run.

Plus **LLM reasoner** tests (fake completion backend, no real API): valid
reorder, malformed response, invented candidate, modified endpoint/target/method
rejection, faithful-echo acceptance, `max_candidates` truncation, secret
scrubbing + key stripping, prompt-contains-no-secrets, LLM-disabled default, and
deterministic fallback (with and without fallback enabled).

Plus **privilege-escalation (BFLA)** tests (unit + lab integration): vulnerable
case VERIFIED, secure case DISPROVEN, generic-200 not flagged, public endpoint
rejected, missing admin/non-admin identity handled, capability/planner/
verification/review integration, evidence hashes validated, duplicate/regen
guard, out-of-scope blocked, budget enforced, and dry-run makes no requests.

Plus **reflected-XSS** tests (unit + lab integration): vulnerable reflection
VERIFIED, HTML-encoded reflection DISPROVEN, plain-text/non-HTML DISPROVEN,
generic 200 DISPROVEN, payload-not-reflected DISPROVEN, attribute-breakout
VERIFIED, script-context inconclusive (not VERIFIED), malformed hypothesis (no
param), out-of-scope blocked, dry-run makes no requests, budget enforced,
evidence hashes validated, and review-workflow integration.

Plus **data-scoping** tests (Priority 1): authorized entity proceeds; arbitrary
user_id/venue_id and an unauthorized venue URL are denied before transport (zero
transport calls); the authorized venue URL is exempt; the LLM cannot smuggle a
different identifier. Plus **verification-gate** tests (Priorities 2–3): every
verification request is refused before transport when it violates vuln-class,
identity, scope, method, required-header, forbidden-action, or budget; and
IDOR/BFLA go INCONCLUSIVE (never an unauthorized identity) when a second
authorized identity is unavailable, with the real Wolt policy unable to select
the simulation-only `sim_other`.

Plus the **autonomous run** test: a single orchestrated run against the simulator
discovers the full surface and verifies one finding per class across all four
detectors (with valid evidence, all queued for human review), and denies an
out-of-scope discovery manifest.

Plus **policy-adapter** tests: `validate_policy` fails closed on missing/empty
`allowed_tools`/`allowed_vulnerability_classes`/`request_budget`, unknown tools or
vuln classes, in-scope-also-excluded, active-methods-without-active-testing,
auth-required-without-identities, and `NEEDS_HUMAN_REVIEW` markers; the real-program
template validates as NOT READY; dry-run simulation reports per-action decisions
with **no network**; and a `dry_run_only` program blocks real execution even when
policy would ALLOW (counting transport proves zero requests).

Plus **adversarial policy-hardening** tests: every DENY path is driven through the
router with a counting transport proving the HTTP execution layer is **never
called** on a denial (out-of-scope, excluded path/host, unauthorized identity,
required-header override, forbidden method, forbidden vuln class, exhausted
budget, unknown tool, invalid targets/identities, malformed arguments,
active-testing and dry-run blocks); malformed/malicious LLM requests cannot
smuggle fields (`ToolRequest`/`HttpArgs` reject extras); program config (scope,
exclusions, allowed tools/classes, identities, budgets) is immutable across
requests; and the planner refuses to plan a forbidden vulnerability class.

Plus **tool-layer + policy** tests: tool registration/schema, unknown tool,
malformed arguments, `ToolRequest` rejecting unknown fields, and every policy
decision (allow in-scope; deny out-of-scope, excluded path, forbidden method,
required-header override, unauthorized identity, unauthorized tool, forbidden
vuln class, exhausted budget, unauthenticated-when-required, and fail-closed with
no `allowed_tools`); plus router tests proving a denied request never reaches the
HTTP client and results are sanitized, and an end-to-end simulator run.

Plus **SQL-injection** tests (unit + lab integration): vulnerable endpoint
VERIFIED via the true/false differential, secure parameterized endpoint DISPROVEN,
control endpoint DISPROVEN, generic 500 DISPROVEN, differing-length-without-SQL
DISPROVEN, reflected-but-not-interpreted DISPROVEN, malformed hypothesis, the
`result_count` metric, capability gating to id-like params, out-of-scope blocked,
budget enforced, dry-run makes no requests, evidence hashes validated, and
review-workflow integration.

Plus **review workflow** tests: verified finding enters the queue, invalid/
corrupt evidence blocks report generation, missing fields prevent approval, human
approval succeeds, the agent cannot approve, a rejected finding cannot be
submitted, edited reports preserve the immutable original, duplicates are
surfaced, reports contain only verified evidence, incomplete reports are marked
(not guessed), the CHANGES_REQUESTED round-trip keeps the original, and the
review/approve CLI (with interactive confirmation) works end to end.

## Roadmap (not yet implemented)

- Additional detectors (XSS, SSRF, SQLi, path traversal, upload, auth, biz-logic)

The pipeline now runs: **program → authorized discovery → persistent
attack-surface graph → deterministic planner → authorized tests via the existing
verifier → immutable evidence → verified finding → Markdown report**, all bounded
by scope, rate limits, budgets, and human-review gating.
