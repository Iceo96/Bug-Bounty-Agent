"""Run the full local pipeline and write example Markdown reports.

  python -m bbagent_lab.demo

Starts the vulnerable lab in-process (loopback only), runs discovery ->
verification -> report, and writes one report per verified finding into
``./reports``. Fully local; makes no external requests.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from bbagent.logging_config import configure_logging, get_logger
from bbagent.program.manager import ProgramManager
from bbagent.report import generate_report
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore
from bbagent_lab.agent_config import build_lab_program, export_lab_tokens
from bbagent_lab.pipeline import run_pipeline
from bbagent_lab.server import BackgroundLab

log = get_logger("bbagent_lab.demo")


def main() -> int:
    configure_logging()
    export_lab_tokens()

    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)

    db = Database(":memory:")
    evidence = EvidenceStore(db, data_dir / "lab_evidence")
    program = ProgramManager(build_lab_program())

    with BackgroundLab() as lab:
        print(f"lab running at {lab.base_url}")
        result = asyncio.run(run_pipeline(program, db, evidence, lab.base_url))

    print(
        f"discovered {len(result.observations)} endpoints, "
        f"{len(result.hypotheses)} hypotheses, {len(result.findings)} verified finding(s)"
    )

    written: list[Path] = []
    for finding in result.findings:
        report = generate_report(finding, db, evidence)
        path = out_dir / f"{finding.id}.md"
        path.write_text(report, encoding="utf-8")
        written.append(path)
        print(f"  report: {path}")

    if not written:
        print("no verified findings — no reports written")
    db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
