"""Capture what the report composer sends and writes, to hold a change of its execution to it.

Two uses, both with no model and no network:

* **The golden** (default). The recording stub of
  ``tests/unit/reporting/test_the_composer_writes_its_sections_at_once.py``
  answers every section of its test report; the sorted request bodies (as the
  OpenAI client would send them) and digests of the composed report, its
  Markdown and its HTML are written to
  ``tests/fixtures/composer_requests_before_concurrency.json``. The fixture in
  the repository was captured from cb04d3ad, the last commit that wrote the
  sections one after another; the test of the same name holds the current
  code, writing them at once, to it. Recapture it from that commit's tree::

      git archive cb04d3ad src data | tar -x -C /path/to/base
      PYTHONPATH=/path/to/base/src python scripts/goldens/capture_composer_requests.py

* **Stored runs** (``--replay RUN_DIR ... --out DIR``). Each run's
  ``report.json`` is re-rendered, then its own section values are fed back as
  the answers on the report with those fields cleared; the request bodies,
  report, Markdown, HTML, degradations and tally are written under ``DIR``.
  Run once against a base tree and once against the change (``--concurrent``),
  then ``diff -r`` the two directories.

The maljan package is whichever is first on ``PYTHONPATH``; ``--concurrent``
passes ``concurrent=True``, which a base without it does not take.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

FIXTURE = ROOT / "tests" / "fixtures" / "composer_requests_before_concurrency.json"
FACTS = "DETERMINISTIC FACTS (complete list):\n- file_type: PE32 executable"
RUN_STATE = "Stages run: triage, static. Stages not run: dynamic."
PROSE = (
    "packing_obfuscation",
    "string_resolution",
    "discovery",
    "persistence_detail",
    "evasion_antiforensics",
    "command_and_control",
    "payloads",
)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _compose(llm: Any, report: Any, isr: Any, concurrent: bool, **kwargs: Any) -> Any:
    import maljan.reporting.composer as composer_module
    from maljan.reporting.composer import ReportComposer

    composer = ReportComposer(llm=llm, per_section_timeout=60)
    if concurrent:
        kwargs["concurrent"] = True
    with patch.object(composer_module, "structured_output_supported_for_llm", return_value=False):
        asyncio.run(composer.compose(report, isr, **kwargs))
    return composer


def _written(composer: Any, report: Any) -> dict[str, Any]:
    from maljan.reporting.renderers.html import HtmlRenderer
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    return {
        "report_sha256": _digest(report.model_dump_json()),
        "markdown_sha256": _digest(MarkdownRenderer().render(report)),
        "html_sha256": _digest(HtmlRenderer().render(report)),
        "degradations": list(composer.degradations),
        "tally": composer.validation_tally.to_dict(),
    }


def golden(concurrent: bool) -> dict[str, Any]:
    """The test report's sorted request bodies and what the composer wrote from them."""
    from tests.unit.reporting.test_the_composer_writes_its_sections_at_once import (
        _isr,
        _Recorder,
        _report,
    )

    llm = _Recorder()
    report = _report()
    composer = _compose(llm, report, _isr(), concurrent, facts_block=FACTS, run_state=RUN_STATE)
    return {"requests": sorted(llm.requests), **_written(composer, report)}


def _stored_answers(stored: Any) -> dict[str, Any]:
    """Each section's own value in a stored report, as the answer it was."""
    answers: dict[str, Any] = {"introduction": {"text": stored.intro_background}}
    ta = stored.technical_analysis
    if ta is not None:
        answers["execution_flow"] = {
            "steps": [s.model_dump(mode="json") for s in ta.execution_flow]
        }
        for name in PROSE:
            sub = getattr(ta, name)
            if sub is not None:
                answers[name] = {"body": sub.body, "evidence_refs": list(sub.evidence_refs)}
        answers["configuration"] = {"items": [i.model_dump(mode="json") for i in ta.configuration]}
        answers["host_identifiers"] = {
            "identifiers": [i.model_dump(mode="json") for i in ta.host_identifiers]
        }
        answers["commands"] = {"commands": [i.model_dump(mode="json") for i in ta.commands]}
        answers["cli_flags"] = {"flags": [i.model_dump(mode="json") for i in ta.cli_flags]}
        if ta.encryption_scheme is not None:
            answers["encryption_scheme"] = ta.encryption_scheme.model_dump(mode="json")
        if ta.ransom_note is not None:
            answers["ransom_note"] = ta.ransom_note.model_dump(mode="json")
    answers["communications"] = {
        "channels": [c.model_dump(mode="json") for c in stored.c2_channels]
    }
    return answers


def replay(runs: list[Path], out: Path, concurrent: bool) -> None:
    """Re-render each stored run, and replay its own section values as the answers."""
    from langchain_core.messages import AIMessage
    from tests.unit.reporting.test_the_composer_writes_its_sections_at_once import (
        _Recorder,
        _section_of,
    )

    from maljan.reporting.models import MalwareReport
    from maljan.reporting.renderers.html import HtmlRenderer
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    class _Replay(_Recorder):
        def __init__(self, answers: dict[str, Any]) -> None:
            super().__init__()
            self.answers = answers

        async def ainvoke(self, messages: Any, **kwargs: Any) -> AIMessage:
            await super().ainvoke(messages, **kwargs)
            return AIMessage(content=json.dumps(self.answers.get(_section_of(messages), {})))

    out.mkdir(parents=True, exist_ok=True)
    for run in runs:
        name = run.name
        stored = MalwareReport.model_validate(json.loads((run / "report.json").read_text()))
        (out / f"{name}.rerender.md").write_text(MarkdownRenderer().render(stored))
        (out / f"{name}.rerender.html").write_text(HtmlRenderer().render(stored))
        fresh = stored.model_copy(deep=True)
        fresh.intro_background = ""
        fresh.technical_analysis = None
        fresh.c2_channels = []
        fresh.flagged_statements = []
        llm = _Replay(_stored_answers(stored))
        composer = _compose(
            llm, fresh, None, concurrent, citable_ids=[row.id for row in fresh.evidence_index]
        )
        (out / f"{name}.requests.json").write_text(json.dumps(sorted(llm.requests), indent=0))
        (out / f"{name}.report.json").write_text(fresh.model_dump_json(indent=1))
        (out / f"{name}.md").write_text(MarkdownRenderer().render(fresh))
        (out / f"{name}.html").write_text(HtmlRenderer().render(fresh))
        (out / f"{name}.extra.json").write_text(
            json.dumps(
                {
                    "degradations": composer.degradations,
                    "tally": composer.validation_tally.to_dict(),
                },
                indent=1,
            )
        )
        print(
            f"{name}: {len(llm.requests)} requests, {_digest(''.join(sorted(llm.requests)))[:16]}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--concurrent", action="store_true", help="pass concurrent=True")
    parser.add_argument("--replay", nargs="*", type=Path, default=[], help="stored run directories")
    parser.add_argument("--out", type=Path, help="where --replay writes")
    parser.add_argument("--fixture", type=Path, default=FIXTURE, help="where the golden goes")
    args = parser.parse_args()
    import maljan.reporting.composer as composer_module

    print(f"composer from {composer_module.__file__}", file=sys.stderr)
    if args.replay:
        if args.out is None:
            parser.error("--replay needs --out")
        replay(args.replay, args.out, args.concurrent)
        return 0
    found = golden(args.concurrent)
    args.fixture.write_text(json.dumps(found, indent=1, sort_keys=True) + "\n")
    print(f"{len(found['requests'])} requests written to {args.fixture}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
