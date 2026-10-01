"""Command-line entry point.

Commands:
  validate <config>                     Load and validate a program config.
  scope <config> <url>                  Check whether a URL is in scope.
  recon <config> [--manifest URL] [--crawl URL]
                                        Run authorized discovery into the DB.
  assets <program> [--json]             List discovered assets.
  endpoints <program> [--json]          List discovered endpoints (+ params/auth).
  attack-surface <program> [--json]     Print the full attack-surface graph.

Read commands accept either a program NAME or a path to its config file.
The database path comes from --db, else $BBAGENT_DB_PATH, else ./data/bbagent.db.
It NEVER submits anything.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from bbagent.config.loader import ProgramConfigError, load_program
from bbagent.http.client import AuthorizedHTTPClient, RequestBlocked
from bbagent.logging_config import configure_logging
from bbagent.llm.reasoner import ReasonerUnavailable, build_reasoner
from bbagent.orchestrator import autonomous_run
from bbagent.planner import LLMPlanner, PlanRunner, PlannedHypothesis, TestBudget
from bbagent.program.manager import ProgramManager
from bbagent.recon import AttackSurfaceMapper
from bbagent.report import generate_report
from bbagent.review import ApprovalError
from bbagent.reviewstore import ReviewError, ReviewStore
from bbagent.scope.engine import ScopeEngine
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent.storage.models import FindingStatus
from bbagent.surface.store import SurfaceStore
from bbagent.validation import validate_evidence


def _default_db() -> str:
    return os.getenv("BBAGENT_DB_PATH", "./data/bbagent.db")


def _evidence_dir() -> str:
    return os.getenv("BBAGENT_EVIDENCE_DIR", "./data/evidence")


def _print_queue(queue: list[PlannedHypothesis]) -> None:
    if not queue:
        print("(no hypotheses)")
        return
    for i, ph in enumerate(queue, 1):
        print(f"[{i}] {ph.priority.value}")
        print(f"{ph.vulnerability_class} — {_cap_title(ph.vulnerability_class)}")
        print(f"{ph.method} {ph.endpoint}")
        print(f"Reason: {ph.reasoning}")
        print(f"Auth context: {', '.join(ph.required_auth_context) or '-'}  "
              f"Expected signal: {ph.expected_signal or '-'}")
        print()


def _cap_title(vuln_class: str) -> str:
    return {
        "idor": "Authorization boundary",
        "privilege_escalation": "Privilege escalation (BFLA)",
        "reflected_xss": "Reflected XSS",
        "sql_injection": "SQL injection",
    }.get(vuln_class, vuln_class)


def _load_actions(path: str):
    """Load a YAML/JSON file with a top-level 'actions' list for simulation."""
    import json as _json
    from pathlib import Path as _Path

    import yaml as _yaml

    p = _Path(path)
    if not p.is_file():
        print(f"error: actions file not found: {path}", file=sys.stderr)
        return None
    raw = p.read_text(encoding="utf-8")
    try:
        data = _yaml.safe_load(raw) if p.suffix.lower() in (".yaml", ".yml") else _json.loads(raw)
    except Exception as exc:  # noqa: BLE001
        print(f"error: could not parse actions file: {exc}", file=sys.stderr)
        return None
    actions = data.get("actions") if isinstance(data, dict) else data
    if not isinstance(actions, list):
        print("error: actions file must contain an 'actions' list", file=sys.stderr)
        return None
    return actions


def _reviewer_name(explicit: str | None) -> str:
    name = explicit or os.getenv("USERNAME") or os.getenv("USER") or "operator"
    if name == "agent":
        name = "operator"  # the agent may never act as an approver
    return name


def _handle_review(args, db: Database, evidence: EvidenceStore, rs: ReviewStore) -> int:
    if args.cmd == "findings":
        program = args.program
        findings = db.list_findings(program)
        if args.status:
            findings = [f for f in findings if f.status.value == args.status]
        if not findings:
            print("(no findings)")
            return 0
        for f in findings:
            print(f"{f.id}  [{f.status.value}]  {f.vuln_type}  {f.http_method} {f.endpoint}")
        return 0

    fid = args.finding_id

    if args.cmd == "review":
        finding = db.get_finding(fid)
        if finding is None:
            print(f"error: no such finding: {fid}", file=sys.stderr)
            return 1
        try:
            item = rs.get(fid)
        except ReviewError:
            item = rs.submit_for_review(fid)  # validates evidence, generates report
        print(f"# Review: {fid}  [{item.status}]")
        print(f"quality_complete={item.quality_complete}")
        if item.duplicates:
            print(f"possible duplicates: {', '.join(item.duplicates)}")
        else:
            print("possible duplicates: none")
        print("\n----- report -----\n")
        print(item.current_report)
        return 0

    if args.cmd == "report":
        try:
            item = rs.get(fid)
            print(item.generated_report if args.generated else item.current_report)
            return 0
        except ReviewError:
            finding = db.get_finding(fid)
            if finding is None:
                print(f"error: no such finding: {fid}", file=sys.stderr)
                return 1
            ev = validate_evidence(finding, db, evidence)
            if not ev.ok:
                print(f"error: evidence invalid: {'; '.join(ev.errors)}", file=sys.stderr)
                return 1
            print(generate_report(finding, db, evidence))
            return 0

    if args.cmd == "reject":
        item = rs.reject(fid, reviewer=_reviewer_name(args.reviewer), note=args.note)
        print(f"{fid} -> {item.status}")
        return 0

    if args.cmd == "approve":
        reviewer = _reviewer_name(args.reviewer)
        if not args.yes:
            try:
                answer = input(f"Type the finding id '{fid}' to APPROVE FOR SUBMISSION: ")
            except EOFError:
                answer = ""
            if answer.strip() != fid:
                print("approval aborted (confirmation did not match)")
                return 1
        item = rs.approve(fid, reviewer=reviewer)
        print(f"{fid} -> {item.status}  (reviewer: {reviewer})")
        print("NOTE: the agent does not submit. Submit the report manually to the platform.")
        return 0

    return 0


def _build_planner(program, use_llm: bool):
    """Return an LLMPlanner when --llm is requested and usable, else None.

    None means the runner uses its default DeterministicPlanner. If the LLM
    backend cannot be built, we fall back to deterministic (default) or, when the
    program disables fallback, abort.
    """
    if not use_llm:
        return None
    llm_cfg = program.config.llm
    try:
        reasoner = build_reasoner(llm_cfg)
    except ReasonerUnavailable as exc:
        if llm_cfg.fallback_to_deterministic:
            print(f"warning: LLM unavailable ({exc}); using deterministic planner", file=sys.stderr)
            return None
        print(f"error: LLM unavailable ({exc}) and fallback_to_deterministic is false",
              file=sys.stderr)
        raise SystemExit(2)
    return LLMPlanner(reasoner, fallback=llm_cfg.fallback_to_deterministic)


def _program_name(arg: str) -> str:
    """Accept a config path or a bare program name; return the program name."""
    p = Path(arg)
    if p.is_file():
        return load_program(p).name
    return arg


# --- recon --------------------------------------------------------------------

async def _run_recon(program: ProgramManager, db_path: str, manifest: str | None, crawl: str | None,
                     max_pages: int) -> int:
    db = Database(db_path)
    surface = SurfaceStore(db)
    try:
        async with AuthorizedHTTPClient(program.config) as http:
            mapper = AttackSurfaceMapper(program, http, surface)
            if manifest:
                await mapper.map_manifest(manifest)
            if crawl:
                await mapper.crawl(crawl, max_pages=max_pages)
    finally:
        db.close()
    print(f"recon complete for '{program.name}' -> {db_path}")
    print(f"  run: bbagent attack-surface \"{program.name}\" --db {db_path}")
    return 0


# --- output helpers -----------------------------------------------------------

def _print_assets(surface: SurfaceStore, program: str, as_json: bool) -> None:
    assets = surface.list_assets(program)
    if as_json:
        print(json.dumps(surface.attack_surface(program)["assets"], indent=2))
        return
    if not assets:
        print("(no assets)")
        return
    for a in assets:
        techs = ", ".join(a.technologies) or "-"
        print(f"[{a.status}] {a.url}  ({a.content_type or '-'})  tech: {techs}")


def _print_endpoints(surface: SurfaceStore, program: str, as_json: bool) -> None:
    eps = surface.list_endpoints(program)
    if as_json:
        surf = surface.attack_surface(program)
        print(json.dumps(surf["endpoints"], indent=2))
        return
    if not eps:
        print("(no endpoints)")
        return
    for e in eps:
        params = ",".join(p.name for p in surface.parameters_for(e.id)) or "-"
        auth = "; ".join(
            f"{a.identity}={a.status_codes}" for a in surface.auth_observations_for(e.id)
        ) or "-"
        objs = ",".join(f"{o.value}({o.kind})" for o in surface.object_refs_for(e.id)) or "-"
        flag = "confirmed" if e.confirmed else "candidate"
        print(f"{e.method} {e.url}")
        print(f"    source={e.source} {flag} authn={e.auth_requirement} status={e.status_codes}")
        print(f"    params: {params}")
        print(f"    object-refs: {objs}")
        print(f"    auth-observations: {auth}")


# --- main ---------------------------------------------------------------------

def _load_env() -> None:
    """Load the project's git-ignored .env into the process environment.

    Uses python-dotenv if available. Existing environment variables win (no
    override), and values are never printed or persisted anywhere — only made
    available to os.getenv for required-header/identity resolution at runtime.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(override=False)


def _make_browser_backend(profile_dir: str | None, *, headless: bool):
    """Construct the real browser backend, wiring the persistent profile through.

    ``profile_dir`` is the operator's pre-authenticated Chromium profile. It is
    only passed to Playwright; its contents are never read, copied, or persisted
    by the agent.
    """
    from bbagent.browser.playwright_backend import PlaywrightBackend
    return PlaywrightBackend(headless=headless, user_data_dir=profile_dir)


def main(argv: list[str] | None = None) -> int:
    _load_env()
    configure_logging()
    parser = argparse.ArgumentParser(prog="bbagent", description="Authorized bug bounty research agent")
    parser.add_argument("--db", default=None, help="SQLite path (default $BBAGENT_DB_PATH or ./data/bbagent.db)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_val = sub.add_parser("validate", help="Load and validate a program config")
    p_val.add_argument("config")

    p_scope = sub.add_parser("scope", help="Check whether a URL is in scope")
    p_scope.add_argument("config")
    p_scope.add_argument("url")

    p_polcheck = sub.add_parser("policy-check", help="Validate a program policy (fail-closed)")
    p_polcheck.add_argument("config")

    p_pilot = sub.add_parser("pilot", help="Pre-flight gate for a controlled real pilot (LIVE off by default)")
    p_pilot.add_argument("config")
    p_pilot.add_argument("--live", action="store_true", help="Request live mode (still requires readiness + confirmation)")
    p_pilot.add_argument("--yes", action="store_true", help="Skip the interactive confirmation")

    p_polsim = sub.add_parser("policy-simulate",
                              help="Dry-run: show policy decisions for hypothetical actions (no network)")
    p_polsim.add_argument("config")
    p_polsim.add_argument("--actions", required=True, help="YAML/JSON file with an 'actions' list")

    p_recon = sub.add_parser("recon", help="Run authorized discovery into the DB")
    p_recon.add_argument("config")
    p_recon.add_argument("--manifest", help="Discovery manifest URL (in scope)")
    p_recon.add_argument("--crawl", help="Seed URL to crawl (in scope)")
    p_recon.add_argument("--max-pages", type=int, default=25)

    p_observe = sub.add_parser(
        "observe",
        help="Ingest an authenticated browser session's network log (HAR) into the "
             "attack surface. NO requests are sent; scope is enforced fail-closed.")
    p_observe.add_argument("config", help="Program config path")
    p_observe.add_argument("--har", required=True,
                           help="Path to a HAR export from the authenticated browser session")
    p_observe.add_argument("--identity", default="researcher",
                           help="Identity label for authenticated traffic (default: researcher)")
    p_observe.add_argument("--json", action="store_true")

    p_login = sub.add_parser(
        "browser-login",
        help="Open a HEADED browser using a persistent profile directory so you can "
             "log in manually. Reuse that same --profile-dir later with research/"
             "explore/browse. The agent never reads or persists the profile contents.")
    p_login.add_argument("--profile-dir", required=True,
                         help="Directory to store the persistent Chromium profile (created if absent)")
    p_login.add_argument("--url", default="https://www.temu.com/",
                         help="Page to open for login (default: Temu home)")

    p_browse = sub.add_parser(
        "browse",
        help="Launch an authenticated browser session and perform CONTROLLED "
             "exploration, ingesting observed traffic. Real execution is gated: "
             "refused while a program is dry_run_only (e.g. Temu).")
    p_browse.add_argument("config", help="Program config path")
    p_browse.add_argument("--steps", required=True,
                          help="JSON file: a list of {action,target,text,amount} steps")
    p_browse.add_argument("--identity", default="researcher",
                          help="Identity label for authenticated traffic (default: researcher)")
    p_browse.add_argument("--live", action="store_true",
                          help="Opt in to a REAL browser session (also needs BBAGENT_BROWSER_LIVE=1)")
    p_browse.add_argument("--headed", action="store_true", help="Show the browser window")
    p_browse.add_argument("--profile-dir", default=None,
                          help="Persistent Chromium profile dir (pre-authenticated session)")
    p_browse.add_argument("--json", action="store_true")

    p_explore = sub.add_parser(
        "explore",
        help="Autonomously explore an app's attack surface (no fixed steps). Real "
             "execution is gated: refused while a program is dry_run_only (e.g. Temu).")
    p_explore.add_argument("config", help="Program config path")
    p_explore.add_argument("--seed", action="append", default=None,
                           help="In-scope seed URL to start from (repeatable)")
    p_explore.add_argument("--seed-scope", action="store_true",
                           help="Also seed from every configured in-scope web origin "
                                "(exact-host/url-prefix rules; never a wildcard)")
    p_explore.add_argument("--identity", default="researcher")
    p_explore.add_argument("--live", action="store_true",
                           help="Opt in to a REAL browser session (also needs BBAGENT_BROWSER_LIVE=1)")
    p_explore.add_argument("--headed", action="store_true", help="Show the browser window")
    p_explore.add_argument("--profile-dir", default=None,
                           help="Persistent Chromium profile dir (pre-authenticated session)")
    p_explore.add_argument("--llm", action="store_true",
                           help="Use the LLM to choose actions (falls back to deterministic)")
    p_explore.add_argument("--max-actions", type=int, default=40)
    p_explore.add_argument("--max-pages", type=int, default=15)
    p_explore.add_argument("--max-seconds", type=float, default=60.0)
    p_explore.add_argument("--json", action="store_true")

    p_research = sub.add_parser(
        "research",
        help="Run the Security Research Loop (explore<->test). Real execution is "
             "gated: refused while a program is dry_run_only (e.g. Temu).")
    p_research.add_argument("config", help="Program config path")
    p_research.add_argument("--seed", action="append", default=None,
                            help="In-scope seed URL to start exploration from (repeatable)")
    p_research.add_argument("--seed-scope", action="store_true",
                            help="Also seed from every configured in-scope web origin "
                                 "(exact-host/url-prefix rules; never a wildcard)")
    p_research.add_argument("--identity", default="researcher")
    p_research.add_argument("--preflight", action="store_true",
                            help="Run readiness checks only; no navigation, no target traffic")
    p_research.add_argument("--live", action="store_true",
                            help="Opt in to REAL execution (also needs BBAGENT_BROWSER_LIVE=1)")
    p_research.add_argument("--headed", action="store_true")
    p_research.add_argument("--profile-dir", default=None,
                            help="Persistent Chromium profile dir (operator's pre-authenticated "
                                 "session). Only passed to the browser; contents never read/persisted.")
    p_research.add_argument("--max-rounds", type=int, default=3)
    p_research.add_argument("--max-seconds", type=float, default=120.0)
    p_research.add_argument("--json", action="store_true")

    p_assets = sub.add_parser("assets", help="List discovered assets")
    p_assets.add_argument("program")
    p_assets.add_argument("--json", action="store_true")

    p_eps = sub.add_parser("endpoints", help="List discovered endpoints")
    p_eps.add_argument("program")
    p_eps.add_argument("--json", action="store_true")

    p_surf = sub.add_parser("attack-surface", help="Print the attack-surface graph")
    p_surf.add_argument("program")
    p_surf.add_argument("--json", action="store_true")

    p_plan = sub.add_parser("plan", help="Preview the prioritized hypothesis queue (no execution)")
    p_plan.add_argument("config", help="Program config path")
    p_plan.add_argument("--json", action="store_true")
    p_plan.add_argument("--llm", action="store_true", help="Use the LLM reasoner for prioritization")

    p_run = sub.add_parser("run", help="Run the planner: execute authorized tests + verify")
    p_run.add_argument("config", help="Program config path")
    p_run.add_argument("--dry-run", action="store_true", help="Show planned tests; execute nothing")
    p_run.add_argument("--llm", action="store_true", help="Use the LLM reasoner for prioritization")
    p_run.add_argument("--max-requests", type=int, default=200)
    p_run.add_argument("--max-per-endpoint", type=int, default=2)
    p_run.add_argument("--max-runtime", type=float, default=120.0)

    p_auto = sub.add_parser("autorun", help="Autonomous policy-governed run against a local target")
    p_auto.add_argument("config", help="Program config path")
    p_auto.add_argument("--base", required=True, help="Loopback base URL of the local target")
    p_auto.add_argument("--manifest-path", default="/full-scope/manifest",
                        help="Discovery manifest path under --base")
    p_auto.add_argument("--llm", action="store_true", help="Use the LLM reasoner for prioritization")

    p_findings = sub.add_parser("findings", help="List findings and their review status")
    p_findings.add_argument("--program", default=None)
    p_findings.add_argument("--status", default=None)

    p_review = sub.add_parser("review", help="Enqueue (if needed) and show a finding for review")
    p_review.add_argument("finding_id")

    p_report = sub.add_parser("report", help="Print the Markdown report for a finding")
    p_report.add_argument("finding_id")
    p_report.add_argument("--generated", action="store_true", help="Show the immutable generated report")

    p_approve = sub.add_parser("approve", help="Approve a finding FOR SUBMISSION (human only)")
    p_approve.add_argument("finding_id")
    p_approve.add_argument("--reviewer", default=None)
    p_approve.add_argument("--yes", action="store_true", help="Skip the interactive confirmation")

    p_reject = sub.add_parser("reject", help="Reject a finding")
    p_reject.add_argument("finding_id")
    p_reject.add_argument("--reviewer", default=None)
    p_reject.add_argument("--note", default="")

    args = parser.parse_args(argv)
    db_path = args.db or _default_db()

    # Pilot gate (config-only; NEVER sends a request in this command).
    if args.cmd == "pilot":
        from bbagent.pilot import preflight
        try:
            program = ProgramManager.from_file(args.config)
        except ProgramConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        report = preflight(program, live=args.live)
        print(report.render())
        if not args.live:
            print("\nLIVE mode is OFF (default). No requests will be sent.")
            return 0
        if not report.ready:
            print("\nREFUSING to go live: unresolved blockers above. No requests will be sent.",
                  file=sys.stderr)
            return 2
        if program.config.dry_run_only:
            print("\nREFUSING to go live: program is dry_run_only. No requests will be sent.",
                  file=sys.stderr)
            return 2
        # Ready + live requested: require explicit human confirmation. (Even then,
        # this command does not itself execute a run.)
        if not args.yes:
            try:
                answer = input(f"Type the program name '{program.name}' to CONFIRM live pilot: ")
            except EOFError:
                answer = ""
            if answer.strip() != program.name:
                print("live pilot aborted (confirmation did not match). No requests sent.")
                return 1
        print("\nConfirmed. The system is READY for a controlled live pilot; launch it with the "
              "autonomous run once you have reviewed the pre-flight above.")
        return 0

    # Policy adapter commands (config-only; NO network).
    if args.cmd in ("policy-check", "policy-simulate"):
        from bbagent.policy.validation import simulate, validate_policy
        try:
            program = ProgramManager.from_file(args.config)
        except ProgramConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.cmd == "policy-check":
            report = validate_policy(program)
            print(report.render())
            return 0 if report.ready else 1
        # policy-simulate
        actions = _load_actions(args.actions)
        if actions is None:
            return 2
        print(f"# Dry-run simulation: {program.name}  (dry_run_only={program.config.dry_run_only})")
        print("# No network requests are made; decisions are policy-only.\n")
        for d in simulate(program, actions):
            print(d.render())
        return 0

    # Config-only commands.
    if args.cmd in ("validate", "scope"):
        try:
            program = load_program(args.config)
        except ProgramConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.cmd == "validate":
            print(f"OK: '{program.name}' loaded — {len(program.scope.in_scope)} in-scope, "
                  f"{len(program.scope.excluded)} excluded rules.")
            return 0
        decision = ScopeEngine(program.scope).check(args.url)
        status = "IN SCOPE" if decision.allowed else "OUT OF SCOPE"
        print(f"{status}: {args.url}\n  reason: {decision.reason}")
        return 0 if decision.allowed else 1

    if args.cmd == "recon":
        try:
            program = ProgramManager.from_file(args.config)
        except ProgramConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not args.manifest and not args.crawl:
            print("error: recon needs --manifest URL and/or --crawl URL", file=sys.stderr)
            return 2
        try:
            return asyncio.run(_run_recon(program, db_path, args.manifest, args.crawl, args.max_pages))
        except RequestBlocked as exc:
            print(f"blocked: {exc}", file=sys.stderr)
            return 1

    # Passive browser-observation ingest (NO network; scope enforced fail-closed).
    if args.cmd == "observe":
        from bbagent.browser import ingest_har
        from bbagent.surface.models import AuthIdentity
        try:
            program = ProgramManager.from_file(args.config)
        except ProgramConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        har_path = Path(args.har)
        if not har_path.is_file():
            print(f"error: no HAR file at {har_path}", file=sys.stderr)
            return 2
        db = Database(db_path)
        surface = SurfaceStore(db)
        try:
            # Authenticated browser traffic is the single researcher identity.
            identity_map = {args.identity: AuthIdentity.IDENTITY_A}
            report = ingest_har(
                program, surface, har_path.read_text(encoding="utf-8", errors="replace"),
                default_identity=AuthIdentity.IDENTITY_A, identity_map=identity_map,
            )
            if args.json:
                print(json.dumps(report.__dict__, indent=2))
            else:
                print(report.render())
            return 0
        finally:
            db.close()

    # Controlled authenticated browser exploration (real execution is gated off for
    # dry-run programs like Temu). Observation only — no vulnerability testing.
    if args.cmd == "browse":
        from bbagent.browser import (
            BrowserController, BrowserLaunchRefused, ExplorationStep, ensure_live_allowed,
        )
        from bbagent.browser.playwright_backend import PlaywrightBackend
        from bbagent.surface.models import AuthIdentity
        try:
            program = ProgramManager.from_file(args.config)
        except ProgramConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        steps_path = Path(args.steps)
        if not steps_path.is_file():
            print(f"error: no steps file at {steps_path}", file=sys.stderr)
            return 2
        live = bool(args.live) and os.getenv("BBAGENT_BROWSER_LIVE") == "1"
        try:
            ensure_live_allowed(program, live=live)
        except BrowserLaunchRefused as exc:
            print(str(exc), file=sys.stderr)
            return 2
        try:
            raw = json.loads(steps_path.read_text(encoding="utf-8"))
            steps = [ExplorationStep(**s) for s in raw]
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            print(f"error: invalid steps file: {exc}", file=sys.stderr)
            return 2

        db = Database(db_path)
        surface = SurfaceStore(db)
        try:
            backend = _make_browser_backend(args.profile_dir, headless=not args.headed)
            controller = BrowserController(
                program, surface, backend,
                default_identity=AuthIdentity.IDENTITY_A,
                identity_map={args.identity: AuthIdentity.IDENTITY_A},
            )
            result = asyncio.run(controller.explore(steps))
            if args.json:
                print(json.dumps(result.report.__dict__, indent=2))
            else:
                print(result.render())
            return 0
        finally:
            db.close()

    # Autonomous browser exploration (real execution gated off for dry-run programs).
    if args.cmd == "explore":
        from bbagent.browser import (
            AutonomousExplorer, BrowserController, BrowserLaunchRefused,
            ExplorationLimits, LLMExplorationChooser, ensure_live_allowed,
        )
        from bbagent.browser.playwright_backend import PlaywrightBackend
        from bbagent.surface.models import AuthIdentity
        try:
            program = ProgramManager.from_file(args.config)
        except ProgramConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        live = bool(args.live) and os.getenv("BBAGENT_BROWSER_LIVE") == "1"
        try:
            ensure_live_allowed(program, live=live)
        except BrowserLaunchRefused as exc:
            print(str(exc), file=sys.stderr)
            return 2

        seeds = list(args.seed or [])
        if args.seed_scope:
            from bbagent.browser import seed_origins_from_scope
            for o in seed_origins_from_scope(program):
                if o not in seeds:
                    seeds.append(o)
        if not seeds:
            print("error: provide --seed URL(s) and/or --seed-scope", file=sys.stderr)
            return 2

        chooser = None
        if args.llm:
            try:
                from bbagent.config.models import LLMConfig
                from bbagent.llm.reasoner import ReasonerUnavailable, anthropic_complete
                chooser = LLMExplorationChooser(anthropic_complete(LLMConfig()))
            except Exception as exc:  # noqa: BLE001 - fall back to deterministic
                print(f"note: LLM chooser unavailable ({exc}); using deterministic", file=sys.stderr)
                chooser = None

        db = Database(db_path)
        surface = SurfaceStore(db)
        try:
            backend = _make_browser_backend(args.profile_dir, headless=not args.headed)
            controller = BrowserController(
                program, surface, backend,
                default_identity=AuthIdentity.IDENTITY_A,
                identity_map={args.identity: AuthIdentity.IDENTITY_A},
            )
            limits = ExplorationLimits(max_actions=args.max_actions, max_pages=args.max_pages,
                                       max_seconds=args.max_seconds)
            explorer = AutonomousExplorer(controller, surface, chooser=chooser, limits=limits)
            summary = asyncio.run(explorer.run(seeds))
            if args.json:
                print(json.dumps(summary.__dict__, indent=2))
            else:
                print(summary.render())
            return 0
        finally:
            db.close()

    # Manual login helper: opens a headed browser with a persistent profile so the
    # operator can authenticate once. The agent drives nothing and never reads,
    # copies, uploads, logs, or persists the profile contents.
    if args.cmd == "browser-login":
        async def _login() -> int:
            try:
                from playwright.async_api import async_playwright
            except ImportError:
                print("error: Playwright is not installed in this interpreter. Install with: "
                      "python -m pip install \"playwright>=1.40\" && python -m playwright install chromium",
                      file=sys.stderr)
                return 2
            async with async_playwright() as pw:
                ctx = await pw.chromium.launch_persistent_context(args.profile_dir, headless=False)
                page = ctx.pages[0] if ctx.pages else await ctx.new_page()
                await page.goto(args.url)
                print(f"Persistent profile: {args.profile_dir}")
                print("Log in to the site in the opened window, then CLOSE the browser to save "
                      "the session into that profile. Reuse it later with --profile-dir.")
                closed = asyncio.Event()
                ctx.on("close", lambda *_: closed.set())
                await closed.wait()
            return 0
        return asyncio.run(_login())

    # Security Research Loop (real execution gated off for dry-run programs).
    if args.cmd == "research":
        from bbagent.browser import BrowserLaunchRefused, ensure_live_allowed
        from bbagent.browser.playwright_backend import PlaywrightBackend
        from bbagent.research import ResearchLimits, research_preflight, run_security_research
        try:
            program = ProgramManager.from_file(args.config)
        except ProgramConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        limits = ResearchLimits(max_rounds=args.max_rounds, max_seconds=args.max_seconds)

        # Resolve seeds: explicit --seed values plus, if --seed-scope, one origin per
        # configured in-scope web asset (never a wildcard; scope engine unchanged).
        seeds = list(args.seed or [])
        if args.seed_scope:
            from bbagent.browser import seed_origins_from_scope
            for o in seed_origins_from_scope(program):
                if o not in seeds:
                    seeds.append(o)

        # Preflight: readiness checks only. No navigation, no target traffic.
        if args.preflight:
            report = research_preflight(
                program, seed_urls=seeds, limits=limits,
                live=bool(args.live), identity=args.identity)
            print(json.dumps(report.__dict__, indent=2, default=lambda o: o.__dict__)
                  if args.json else report.render())
            return 0 if report.ready else 1
        if not seeds:
            print("error: provide --seed URL(s) and/or --seed-scope", file=sys.stderr)
            return 2

        live = bool(args.live) and os.getenv("BBAGENT_BROWSER_LIVE") == "1"
        try:
            ensure_live_allowed(program, live=live)
        except BrowserLaunchRefused as exc:
            print(str(exc), file=sys.stderr)
            return 2
        db = Database(db_path)
        evidence = EvidenceStore(db, _evidence_dir())

        async def _do_research() -> int:
            backend = _make_browser_backend(args.profile_dir, headless=not args.headed)
            limits = ResearchLimits(max_rounds=args.max_rounds, max_seconds=args.max_seconds)
            report = await run_security_research(
                program, db, evidence, browser_backend=backend, seed_urls=seeds,
                identity=args.identity, limits=limits, live=live)
            print(json.dumps(report.__dict__, indent=2, default=str) if args.json else report.render())
            return 0
        try:
            return asyncio.run(_do_research())
        finally:
            db.close()

    # Autonomous run.
    if args.cmd == "autorun":
        try:
            program = ProgramManager.from_file(args.config)
        except ProgramConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        planner = _build_planner(program, getattr(args, "llm", False))
        manifest = args.base.rstrip("/") + args.manifest_path
        db = Database(db_path)
        evidence = EvidenceStore(db, _evidence_dir())

        async def _do_autorun() -> int:
            report = await autonomous_run(program, db, evidence, manifests=[manifest],
                                          planner=planner)
            print(report.render())
            return 0
        try:
            return asyncio.run(_do_autorun())
        except RequestBlocked as exc:
            print(f"blocked: {exc}", file=sys.stderr)
            return 1
        finally:
            db.close()

    # Planner commands.
    if args.cmd in ("plan", "run"):
        try:
            program = ProgramManager.from_file(args.config)
        except ProgramConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not Path(db_path).exists():
            print(f"error: no database at {db_path}; run 'bbagent recon' first", file=sys.stderr)
            return 2
        db = Database(db_path)
        surface = SurfaceStore(db)
        try:
            use_llm = getattr(args, "llm", False)
            planner = _build_planner(program, use_llm)
            if args.cmd == "plan":
                runner = PlanRunner(program, db, surface, planner=planner)
                queue = runner.generate()
                if args.json:
                    print(json.dumps([h.to_public_dict() for h in queue], indent=2))
                else:
                    src = "LLM-prioritized" if planner is not None else "deterministic"
                    print(f"# Plan for '{program.name}' — {len(queue)} hypothesis(es) [{src}]\n")
                    _print_queue(queue)
                return 0

            # run
            budget = TestBudget(max_requests=args.max_requests,
                                max_tests_per_endpoint=args.max_per_endpoint,
                                max_runtime_seconds=args.max_runtime)
            if args.dry_run:
                runner = PlanRunner(program, db, surface, planner=planner, budget=budget)
                summary = asyncio.run(runner.run(dry_run=True))
                print(f"# Dry-run plan for '{program.name}' (run {summary.run_id})\n")
                _print_queue(getattr(runner, "_dry_queue", []))
                print(f"generated={summary.generated} (no tests executed)")
                return 0

            async def _do_run() -> int:
                async with AuthorizedHTTPClient(program.config) as http:
                    evidence = EvidenceStore(db, _evidence_dir())
                    runner = PlanRunner(program, db, surface, http, evidence,
                                        planner=planner, budget=budget)
                    summary = await runner.run()
                    print(f"# Run {summary.run_id} for '{program.name}'")
                    print(f"generated={summary.generated} executed={summary.executed} "
                          f"verified={summary.verified} disproven={summary.disproven} "
                          f"inconclusive={summary.inconclusive} requests={summary.requests_used}")
                    print(f"findings_created={summary.findings_created} stop={summary.stop_reason}")
                    return 0
            return asyncio.run(_do_run())
        finally:
            db.close()

    # Review / reporting commands.
    if args.cmd in ("findings", "review", "report", "approve", "reject"):
        if not Path(db_path).exists():
            print(f"error: no database at {db_path}", file=sys.stderr)
            return 2
        db = Database(db_path)
        evidence = EvidenceStore(db, _evidence_dir())
        rs = ReviewStore(db, evidence)
        try:
            return _handle_review(args, db, evidence, rs)
        except (ReviewError, ApprovalError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        finally:
            db.close()

    # Read commands (assets/endpoints/attack-surface).
    program_name = _program_name(args.program)
    if not Path(db_path).exists():
        print(f"error: no database at {db_path}; run 'bbagent recon' first", file=sys.stderr)
        return 2
    db = Database(db_path)
    surface = SurfaceStore(db)
    try:
        if args.cmd == "assets":
            _print_assets(surface, program_name, args.json)
        elif args.cmd == "endpoints":
            _print_endpoints(surface, program_name, args.json)
        elif args.cmd == "attack-surface":
            surf = surface.attack_surface(program_name)
            if args.json:
                print(json.dumps(surf, indent=2))
            else:
                print(f"# Attack surface for '{program_name}'")
                print(f"assets={len(surf['assets'])} endpoints={len(surf['endpoints'])} "
                      f"js={len(surf['javascript'])} apis={len(surf['api_endpoints'])} "
                      f"relationships={len(surf['relationships'])}")
                _print_assets(surface, program_name, False)
                print("---")
                _print_endpoints(surface, program_name, False)
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
