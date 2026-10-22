"""A ``<server>__`` prefix is taken off only for a call made through that server's handle.

A registry offers a tool two servers both declare as ``<server key>__<tool>``
and records the original name on the tool; the entry its call writes keeps
that name on its facts record (``declared_reading.with_declared_name``). The
read-time readers take the declared name from there and look it up exactly,
so a tool a server natively spells ``<its key>__x``, which nothing renamed, is
read as itself, never as the server's tool ``x``. Such a tool is still used
and recorded at full strength. An entry with no source keeps the name it
always read as.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from langchain_core.tools import StructuredTool

from maljan.agents import base_agent
from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.agents.tool_pinning import DECLARED_NAME_METADATA_KEY, SERVER_METADATA_KEY
from maljan.core.config import Settings
from maljan.core.declared_reading import DECLARED_NAME_KEY, FACTS_VERSION
from maljan.core.reputation import is_lookup_tool
from maljan.core.tool_declarations import ToolDeclarations
from maljan.reporting import tool_kinds
from maljan.schemas.evidence import build_entry


def _declared() -> ToolDeclarations:
    settings = Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    "mine": {
                        "command": "x",
                        "tool_facts": {
                            "x": {"kind": "reputation", "read_only": True},
                        },
                    }
                }
            }
        }
    )
    return ToolDeclarations.from_settings(settings)


@pytest.fixture
def held(monkeypatch: pytest.MonkeyPatch) -> ToolDeclarations:
    declared = _declared()
    monkeypatch.setattr("maljan.core.declared_reading.declarations", lambda *_a, **_k: declared)
    return declared


def _entry(tool: str, declared_name: str | None) -> Any:
    return build_entry(
        entry_id="ev_0001", seq=1, agent="a", tool=tool, args={}, server="mine",
        output="{}", source="mcp:mine", declared_name=declared_name,
    )  # fmt: skip


def test_a_renamed_call_keeps_its_original_name_on_its_record(held: ToolDeclarations) -> None:
    renamed = _entry("mine__x", "x")
    assert renamed.facts is not None
    assert renamed.facts[DECLARED_NAME_KEY] == "x"
    assert renamed.facts["kind"] == "reputation"


def test_a_native_prefixed_call_records_no_other_name(held: ToolDeclarations) -> None:
    native = _entry("mine__x", "mine__x")
    assert native.facts is not None
    assert DECLARED_NAME_KEY not in native.facts
    assert native.facts.get("kind") in ("", None)


class TestTheReportReadsTheDeclaredName:
    def test_a_native_prefixed_tool_is_read_as_itself(self, held: ToolDeclarations) -> None:
        assert tool_kinds.declared_name(_entry("mine__x", "mine__x")) == "mine__x"

    def test_a_native_prefixed_tool_with_no_record_is_read_as_itself(self) -> None:
        row = {"tool": "mine__x", "source": "mcp:mine", "facts": None}
        assert tool_kinds.declared_name(row) == "mine__x"

    def test_a_renamed_tool_is_read_by_its_original_name(self, held: ToolDeclarations) -> None:
        assert tool_kinds.declared_name(_entry("mine__x", "x")) == "x"

    def test_an_entry_with_no_source_keeps_its_own_name(self) -> None:
        assert tool_kinds.declared_name({"tool": "knowledge__capabilities"}) == (
            "knowledge__capabilities"
        )


class TestTheAgentReadsOnlyWhatItsHandleDeclared:
    def test_a_native_prefixed_tool_is_not_the_server_s_read_only_tool(
        self, held: ToolDeclarations
    ) -> None:
        native = _entry("mine__x", "mine__x").model_dump()
        assert base_agent._entry_reads_only(native, "mine", set()) is False

    def test_a_native_prefixed_tool_with_no_record_is_not_read_only(
        self, held: ToolDeclarations
    ) -> None:
        row = {"tool": "mine__x", "source": "mcp:mine"}
        assert base_agent._entry_reads_only(row, "mine", set()) is False

    def test_a_renamed_read_only_tool_still_reads_only(self, held: ToolDeclarations) -> None:
        renamed = _entry("mine__x", "x").model_dump()
        assert base_agent._entry_reads_only(renamed, "mine", set()) is True


def test_a_renamed_call_keeps_its_original_name_when_settings_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unreadable(*_a: Any, **_k: Any) -> ToolDeclarations:
        raise RuntimeError("settings unreadable")

    monkeypatch.setattr("maljan.core.declared_reading.declarations", unreadable)
    renamed = _entry("mine__x", "x")
    assert renamed.facts == {"v": FACTS_VERSION, DECLARED_NAME_KEY: "x"}
    assert tool_kinds.declared_name(renamed) == "x"
    assert _entry("mine__x", "mine__x").facts is None


def _server_tool(declared_name: str | None) -> StructuredTool:
    def answer(q: str) -> str:
        return json.dumps({"ok": q})

    tool = StructuredTool.from_function(answer, name="mine__x", description="answers")
    tool.metadata = {
        SERVER_METADATA_KEY: "mine",
        **({DECLARED_NAME_METADATA_KEY: declared_name} if declared_name else {}),
    }
    return tool


class TestTheRecorderKeepsWhatTheHandleKnew:
    def test_a_renamed_call_through_its_handle_reads_as_the_declared_tool(
        self, held: ToolDeclarations
    ) -> None:
        recorder = EvidenceRecorder("a")
        (wrapped,) = record_tools([_server_tool("x")], recorder)
        wrapped.invoke({"q": "1"})
        (entry,) = recorder.entries
        assert entry.facts is not None and entry.facts[DECLARED_NAME_KEY] == "x"
        assert base_agent._entry_reads_only(entry, "mine", set()) is True

    def test_a_native_prefixed_tool_runs_and_reads_as_itself(self, held: ToolDeclarations) -> None:
        recorder = EvidenceRecorder("a")
        (wrapped,) = record_tools([_server_tool(None)], recorder)
        wrapped.invoke({"q": "2"})
        (entry,) = recorder.entries
        assert entry.ok and '"ok": "2"' in entry.output
        assert entry.facts is not None and DECLARED_NAME_KEY not in entry.facts
        assert base_agent._entry_reads_only(entry, "mine", set()) is False


class TestTheLookupIsFoundByItsDeclaredName:
    def test_a_native_prefixed_name_is_not_the_server_s_lookup(self) -> None:
        assert is_lookup_tool(_declared(), "mine", "mine__x") is False

    def test_the_declared_name_is_the_server_s_lookup(self) -> None:
        assert is_lookup_tool(_declared(), "mine", "x") is True
