"""Declaring that a tool sends the sample out changes how none of its answers is filed.

An answer that is one line of prose saying the call failed is filed as a
failure only for a tool whose source declares no kind for it
(``schemas.evidence.build_entry``): a declared kind is read as before. So the
CAPE MCP block's ``submit_file`` declares that it sends the sample out and no
kind, and its failures ("Error: CAPE API unreachable") are filed as failures,
as on dev, where it declared nothing. Every built-in tool's filing of the
same answers is pinned to what dev filed
(``tests/fixtures/golden/error_filing_on_dev.json``, captured on dev before
the disclosure declarations, each tool given every answer through
``build_entry`` under the default settings' declarations); a tool dev did not
declare is held to dev's filing of its source's undeclared tool.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.core import declared_reading
from maljan.core.config import Settings
from maljan.core.tool_declarations import ToolDeclarations
from maljan.schemas.evidence import build_entry

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "error_filing_on_dev.json"
DEV: dict[str, Any] = json.loads(GOLDEN.read_text(encoding="utf-8"))
UNDECLARED = "zz_not_declared"
# The built-in sources shipped after the golden was captured (the
# identification servers): each tool of theirs declares a kind and files as a
# declared tool of dev's did, and their undeclared tool as dev's undeclared one.
SHIPPED_SINCE = frozenset(
    {"mcp:die", "mcp:ilspy", "mcp:goresym", "mcp:yarax", "mcp:oletools", "mcp:webcrack"}
)


@pytest.fixture
def declared(monkeypatch: pytest.MonkeyPatch) -> ToolDeclarations:
    """The default settings' declarations, read without the environment, for every entry."""
    held = ToolDeclarations.from_settings(Settings(_env_file=None))
    monkeypatch.setattr(declared_reading, "declarations", lambda settings=None: held)
    return held


def _filed(source: Any, tool: str, answer: str) -> list[Any]:
    entry = build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="static",
        tool=tool,
        args={},
        server=source.key or None,
        output=answer,
        source=str(source),
    )
    return [entry.ok, entry.error]


def test_every_built_in_tool_files_every_answer_as_dev_did(declared: ToolDeclarations) -> None:
    changed = []
    for held in declared.sources():
        source = str(held.source)
        for tool in [*sorted(held.tools), UNDECLARED]:
            key = f"{source}::{tool}"
            if source in SHIPPED_SINCE:
                assert tool == UNDECLARED or held.tools[tool].kind, key
                like = UNDECLARED if tool == UNDECLARED else "strings"
                dev = DEV["filed"][f"mcp:analysis::{like}"]
            else:
                dev = DEV["filed"].get(key) or DEV["filed"][f"{source}::{UNDECLARED}"]
            now = [_filed(held.source, tool, answer) for answer in DEV["answers"]]
            if now != dev:
                changed.append(key)
    assert changed == []


@pytest.mark.parametrize(
    "answer", ["Error: CAPE API unreachable", "Failed to submit sample: connection refused"]
)
def test_a_cape_submission_that_failed_is_filed_as_failed(
    declared: ToolDeclarations, answer: str
) -> None:
    from maljan.core.tool_declarations import SourceRef

    assert _filed(SourceRef.parse("provider:cape2"), "submit_file", answer) == [False, answer]


def test_the_cape_submit_tool_still_declares_that_it_sends_the_sample_out(
    declared: ToolDeclarations,
) -> None:
    from maljan.core.declared_reading import facts_record

    stored = facts_record("provider:cape2", "submit_file", declared=declared)

    assert stored is not None
    assert stored["discloses_sample"] is True
    assert stored["kind"] == ""


def test_the_cape_submission_is_an_upload_in_the_runs_disclosure(
    declared: ToolDeclarations,
) -> None:
    from maljan.analysis.disclosure import disclosure_record
    from maljan.core.settings_overrides import public_snapshot

    entry = build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="dynamic",
        tool="submit_file",
        args={"file_path": "/samples/x"},
        server=None,
        output="Error: CAPE API unreachable",
        source="provider:cape2",
    )

    record = disclosure_record(public_snapshot(Settings(_env_file=None), ()), entries=[entry])

    (row,) = record["uploads"]
    assert (row["by"], row["source"], row["calls"], row["failed"]) == (
        "tool",
        "provider:cape2",
        1,
        1,
    )
    assert record["nothing_left"] is False


def test_the_golden_holds_every_kind_of_source() -> None:
    sources = {key.split("::")[0] for key in DEV["filed"]}
    assert {"mcp:virustotal", "provider:cape2", "pack", "sandbox"} <= sources
    assert any(key.startswith("mcp:analysis::") for key in DEV["filed"])
