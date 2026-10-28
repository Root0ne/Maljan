"""The pack reads its own steps' answers by declared kind, and their measures by implementation.

Two of the triage pack's tables were keyed on a tool's or a step's name
(T-418 PR7):

* whether an answer that says ``reason`` beside its rows established anything
  was looked up by the tool's name (``function_matches``, ``api_capability``).
  It is now looked up by the kind the entry is about to store (the kind its
  declaration in force gives: ``function_matches``, ``api_catalogue``), so a
  tool of that kind under any name is read the same way;
* which of the pack's own steps measures its peak memory in the worker was
  looked up by the step's id. It is now held by the in-process implementation
  the step dispatches to (``_BUILTIN_STEPS``), next to it.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.pipeline import triage_pack


def test_the_shipped_tools_read_as_the_kinds_the_table_names() -> None:
    assert triage_pack._pack_kind("function_matches") == "function_matches"
    assert triage_pack._pack_kind("api_capability") == "api_catalogue"
    assert set(triage_pack._ESTABLISHED) == {"function_matches", "api_catalogue"}


@pytest.mark.parametrize(
    ("kind", "nothing", "something"),
    [
        (
            "function_matches",
            {"matches": [], "reason": "the store is unavailable"},
            {"matches": [{"family": "x"}], "reason": "partial"},
        ),
        (
            "api_catalogue",
            {"capabilities": [{"api": "A", "category": None, "techniques": []}], "reason": "r"},
            {"capabilities": [{"api": "A", "category": "network"}], "reason": "r"},
        ),
    ],
)
def test_a_renamed_tool_of_the_kind_is_read_as_the_shipped_one(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    nothing: dict[str, Any],
    something: dict[str, Any],
) -> None:
    def record(source: str, tool: str, **_: Any) -> dict[str, Any] | None:
        return {"v": 1, "kind": kind} if tool == "acme_lookup" else None

    monkeypatch.setattr("maljan.core.declared_reading.facts_record", record)
    established = triage_pack._ESTABLISHED.get(triage_pack._pack_kind("acme_lookup"))
    assert established is not None
    assert established(nothing) is False
    assert established(something) is True


def test_a_tool_of_no_such_kind_is_never_failed_for_its_reason() -> None:
    assert triage_pack._ESTABLISHED.get(triage_pack._pack_kind("hashes")) is None


def test_a_measured_peak_is_held_by_the_implementation_it_measures() -> None:
    assert all(callable(key) for key in triage_pack._MEASURED_PEAKS)
    assert not any(isinstance(key, str) for key in triage_pack._MEASURED_PEAKS)
    implementations = set(triage_pack._BUILTIN_STEPS.values())
    assert set(triage_pack._MEASURED_PEAKS) <= implementations
