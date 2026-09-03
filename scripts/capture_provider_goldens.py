"""Freeze today's prompts, allow-lists and extractor outputs as golden fixtures.

Run once, on `dev`, before the provider refactor begins:

    uv run python scripts/capture_provider_goldens.py

It imports the live module constants and writes them to tests/fixtures/. It is
committed so a reviewer can re-run it on `dev` and diff the result against what
this branch carries — the whole argument for the refactor being behaviour-free
rests on these bytes.
"""

from __future__ import annotations

import json
from pathlib import Path

from maljan.agents.dynamic_analyst import _ISR_SYSTEM as DYNAMIC_ISR_SYSTEM
from maljan.agents.ghidra_tool_selector import _CORE_TOOLS
from maljan.agents.static_analyst import _ISR_SYSTEM as STATIC_ISR_SYSTEM
from maljan.agents.static_analyst import StaticAnalyst
from maljan.extractors.dynamic_extractor import build_dynamic_behavior
from maljan.extractors.network_extractor import build_network_iocs

ROOT = Path(__file__).resolve().parents[1]
PROMPTS = ROOT / "tests" / "fixtures" / "prompts"
GOLDEN = ROOT / "tests" / "fixtures" / "golden"
CAPE_GLOBS = ("data/cape_reports/*.json", "data/samples/dynamic/sample_1.json")

# The 13 CAPE MCP tool names the dynamic analyst keeps when
# ``mcp.cape.tools`` is empty (dynamic_analyst.py:121-135).
CAPE_ESSENTIALS = [
    "get_cuckoo_status",
    "search_task",
    "extended_search",
    "submit_file",
    "submit_static",
    "get_task_status",
    "get_task_report",
    "get_task_iocs",
    "get_task_config",
    "list_tasks",
    "view_task",
    "get_latest_tasks",
    "verify_auth",
]


def main() -> None:
    PROMPTS.mkdir(parents=True, exist_ok=True)
    (GOLDEN / "extractors").mkdir(parents=True, exist_ok=True)

    (PROMPTS / "static_isr_system_ghidra.txt").write_text(STATIC_ISR_SYSTEM, encoding="utf-8")
    (PROMPTS / "dynamic_system_cape2.txt").write_text(DYNAMIC_ISR_SYSTEM, encoding="utf-8")

    (GOLDEN / "allowlists.json").write_text(
        json.dumps(
            {
                "ghidra_allowed_tools": sorted(StaticAnalyst._GHIDRA_ALLOWED_TOOLS),
                "ghidra_core_tools": sorted(_CORE_TOOLS),
                "cape_essential_tools": sorted(CAPE_ESSENTIALS),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    for pattern in CAPE_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                continue
            dyn = build_dynamic_behavior(raw)
            net = build_network_iocs(raw)
            out = {
                "dynamic_behavior": dyn.model_dump(mode="json") if dyn is not None else None,
                "network_iocs": net.model_dump(mode="json") if net is not None else None,
            }
            dest = GOLDEN / "extractors" / f"{path.stem}.json"
            dest.write_text(
                json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    print(f"prompts -> {PROMPTS}")
    print(f"goldens -> {GOLDEN}")


if __name__ == "__main__":
    main()
