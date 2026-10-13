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

import gzip
import json
from pathlib import Path
from typing import Any

from maljan.agents.dynamic_analyst import assemble_dynamic_prompt
from maljan.agents.prompt_fragments import format_fragment
from maljan.agents.static_analyst import assemble_static_prompt
from maljan.core.config import Settings
from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider
from maljan.providers.sandbox_tools import (
    sandbox_api_calls,
    sandbox_dropped_files,
    sandbox_mutexes,
    sandbox_network,
    sandbox_processes,
    sandbox_registry_ops,
    sandbox_services_and_tasks,
    sandbox_signatures,
)
from maljan.providers.static.ghidra import GhidraStaticProvider

ROOT = Path(__file__).resolve().parents[2]
PROMPTS = ROOT / "tests" / "fixtures" / "prompts"
GOLDEN = ROOT / "tests" / "fixtures" / "golden"
# A golden whose text passes this many bytes is stored gzip-compressed beside
# its name (``<stem>.json.gz``); the suite's reader takes either form.
COMPRESS_ABOVE_BYTES = 5 * 1024 * 1024
CAPE_GLOBS = (
    "data/cape_reports/*.json",
    "data/samples/dynamic/sample_1.json",
    "tests/fixtures/sandbox/cape2_synthetic.json",
)


def build_prompts() -> tuple[str, str]:
    """The static prompt on Ghidra and the dynamic prompt on CAPEv2, each with its tools.

    The prompts are built for the tools a request carries; these two are the
    ones sent with the provider's tools attached and no registry server, which
    is what the file names say.
    """
    neutral = format_fragment("unknown", "unknown")
    static = assemble_static_prompt(
        GhidraStaticProvider.from_settings(Settings(_env_file=None)),
        neutral,
        (),
        provider_expected=True,
    )
    dynamic = assemble_dynamic_prompt(
        neutral,
        (),
        provider_fragment=CAPE2SandboxProvider.CAPE_PROMPT_FRAGMENT,
        provider_label="the CAPEv2 tool server",
        provider_expected=True,
    )
    return static, dynamic


def write_golden(directory: Path, stem: str, payload: Any) -> Path:
    """Write one golden as ``<stem>.json``, or ``<stem>.json.gz`` past the size limit.

    The other form is removed, so a golden that crosses the limit either way
    is never left behind in both. The gzip header carries no name or time, so
    the same answer writes the same bytes with the same zlib build; another
    deflate implementation (zlib-ng, for one) can write other bytes for the
    same answer, which the suite does not see, since it compares parsed JSON,
    but git shows as a change.
    """
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    data = text.encode("utf-8")
    plain, packed = directory / f"{stem}.json", directory / f"{stem}.json.gz"
    if len(data) > COMPRESS_ABOVE_BYTES:
        packed.write_bytes(gzip.compress(data, compresslevel=9, mtime=0))
        plain.unlink(missing_ok=True)
        return packed
    plain.write_bytes(data)
    packed.unlink(missing_ok=True)
    return plain


def main() -> None:
    PROMPTS.mkdir(parents=True, exist_ok=True)
    static_prompt, dynamic_prompt = build_prompts()
    (GOLDEN / "sandbox_tools").mkdir(parents=True, exist_ok=True)

    # With the trailing newline the repository's own end-of-file hook would
    # add anyway; without it every run of this script and every commit after
    # it flip the same two bytes back and forth.
    (PROMPTS / "static_isr_system_ghidra.txt").write_text(
        static_prompt.rstrip("\n") + "\n", encoding="utf-8"
    )
    (PROMPTS / "dynamic_system_cape2.txt").write_text(
        dynamic_prompt.rstrip("\n") + "\n", encoding="utf-8"
    )

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
                "sandbox_registry_ops": sandbox_registry_ops(raw),
                "sandbox_api_calls": sandbox_api_calls(raw),
                "sandbox_mutexes": sandbox_mutexes(raw),
                "sandbox_services_and_tasks": sandbox_services_and_tasks(raw),
            }
            write_golden(GOLDEN / "sandbox_tools", path.stem, out)
    print(f"prompts -> {PROMPTS}")
    print(f"goldens -> {GOLDEN}")


if __name__ == "__main__":
    main()
