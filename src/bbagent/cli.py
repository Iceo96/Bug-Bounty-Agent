"""Minimal command-line entry point.

Deliberately conservative: it can validate a program config, check whether a URL
is in scope, and list/print findings. It NEVER submits reports.
"""

from __future__ import annotations

import argparse
import sys

from bbagent.config.loader import ProgramConfigError, load_program
from bbagent.logging_config import configure_logging
from bbagent.scope.engine import ScopeEngine


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    parser = argparse.ArgumentParser(prog="bbagent", description="Authorized bug bounty research agent")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_val = sub.add_parser("validate", help="Load and validate a program config")
    p_val.add_argument("config")

    p_scope = sub.add_parser("scope", help="Check whether a URL is in scope")
    p_scope.add_argument("config")
    p_scope.add_argument("url")

    args = parser.parse_args(argv)

    try:
        program = load_program(args.config)
    except ProgramConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "validate":
        print(f"OK: '{program.name}' loaded — {len(program.scope.in_scope)} in-scope, "
              f"{len(program.scope.excluded)} excluded rules.")
        return 0

    if args.cmd == "scope":
        decision = ScopeEngine(program.scope).check(args.url)
        status = "IN SCOPE" if decision.allowed else "OUT OF SCOPE"
        print(f"{status}: {args.url}\n  reason: {decision.reason}")
        return 0 if decision.allowed else 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
