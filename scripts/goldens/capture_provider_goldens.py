"""Freeze today's prompts and extractor outputs as golden fixtures.

Run once, on `dev`, before the provider refactor begins:

    uv run python scripts/goldens/capture_provider_goldens.py

It imports the live module constants and writes them to tests/fixtures/. It is
committed so a reviewer can re-run it on `dev` and diff the result against what
this branch carries — the whole argument for the refactor being behaviour-free
rests on these bytes.
"""

from __future__ import annotations

import json
from pathlib import Path

from maljan.agents.dynamic_analyst import _ISR_SYSTEM as DYNAMIC_ISR_SYSTEM
from maljan.agents.static_analyst import _ISR_SYSTEM as STATIC_ISR_SYSTEM
from maljan.extractors.dynamic_extractor import build_dynamic_behavior
from maljan.extractors.network_extractor import build_network_iocs

ROOT = Path(__file__).resolve().parents[2]
PROMPTS = ROOT / "tests" / "fixtures" / "prompts"
GOLDEN = ROOT / "tests" / "fixtures" / "golden"
CAPE_GLOBS = ("data/cape_reports/*.json", "data/samples/dynamic/sample_1.json")


def main() -> None:
    PROMPTS.mkdir(parents=True, exist_ok=True)
    (GOLDEN / "extractors").mkdir(parents=True, exist_ok=True)

    (PROMPTS / "static_isr_system_ghidra.txt").write_text(STATIC_ISR_SYSTEM, encoding="utf-8")
    (PROMPTS / "dynamic_system_cape2.txt").write_text(DYNAMIC_ISR_SYSTEM, encoding="utf-8")

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
