"""Freeze today's prompts and sandbox-tool answers as golden fixtures.

Run before a change that could move either:

    uv run python scripts/goldens/capture_provider_goldens.py

It imports the live module constants and writes them to tests/fixtures/. It is
committed so a reviewer can re-run it and diff the result against what a branch
carries — the argument that a refactor is behaviour-free rests on these bytes.

What is frozen is what an agent sees when it asks the sandbox tools about a
report, over the whole CAPE corpus. That is the normalisation contract now: the
report is assembled from the answers the tools gave, so an answer that changes
shape changes the report.
"""

from __future__ import annotations

import json
from pathlib import Path

from maljan.agents.dynamic_analyst import _ISR_SYSTEM as DYNAMIC_ISR_SYSTEM
from maljan.agents.static_analyst import _ISR_SYSTEM as STATIC_ISR_SYSTEM
from maljan.providers.sandbox_tools import (
    sandbox_dropped_files,
    sandbox_network,
    sandbox_processes,
    sandbox_signatures,
)

ROOT = Path(__file__).resolve().parents[2]
PROMPTS = ROOT / "tests" / "fixtures" / "prompts"
GOLDEN = ROOT / "tests" / "fixtures" / "golden"
CAPE_GLOBS = ("data/cape_reports/*.json", "data/samples/dynamic/sample_1.json")


def main() -> None:
    PROMPTS.mkdir(parents=True, exist_ok=True)
    (GOLDEN / "sandbox_tools").mkdir(parents=True, exist_ok=True)

    (PROMPTS / "static_isr_system_ghidra.txt").write_text(STATIC_ISR_SYSTEM, encoding="utf-8")
    (PROMPTS / "dynamic_system_cape2.txt").write_text(DYNAMIC_ISR_SYSTEM, encoding="utf-8")

    for pattern in CAPE_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                continue
            out = {
                "sandbox_processes": sandbox_processes(raw),
                "sandbox_network": sandbox_network(raw),
                "sandbox_signatures": sandbox_signatures(raw),
                "sandbox_dropped_files": sandbox_dropped_files(raw),
            }
            dest = GOLDEN / "sandbox_tools" / f"{path.stem}.json"
            dest.write_text(
                json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    print(f"prompts -> {PROMPTS}")
    print(f"goldens -> {GOLDEN}")


if __name__ == "__main__":
    main()
