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

def main(argv: list[str] | None = None) -> int:
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

    p_polsim = sub.add_parser("policy-simulate",
                              help="Dry-run: show policy decisions for hypothetical actions (no network)")
    p_polsim.add_argument("config")
    p_polsim.add_argument("--actions", required=True, help="YAML/JSON file with an 'actions' list")

    p_recon = sub.add_parser("recon", help="Run authorized discovery into the DB")
    p_recon.add_argument("config")
    p_recon.add_argument("--manifest", help="Discovery manifest URL (in scope)")
    p_recon.add_argument("--crawl", help="Seed URL to crawl (in scope)")
    p_recon.add_argument("--max-pages", type=int, default=25)

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
