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
from bbagent.program.manager import ProgramManager
from bbagent.recon import AttackSurfaceMapper
from bbagent.scope.engine import ScopeEngine
from bbagent.storage.db import Database
from bbagent.surface.store import SurfaceStore


def _default_db() -> str:
    return os.getenv("BBAGENT_DB_PATH", "./data/bbagent.db")


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

    args = parser.parse_args(argv)
    db_path = args.db or _default_db()

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
