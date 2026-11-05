"""Whether the unread-functions question is put follows the analyst's category (T-559).

The category only adds; the ledger decides whether the question is put:

- an analyst of any category whose entries list code is asked, and sends the
  same turn byte for byte whatever its category, ``other``, none or no
  definition at all included;
- a ``code_reader`` none of whose entries lists code is told why, where
  every other analyst is left alone, as before the category existed.

Every address and name here is made up for the test.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.agents.callees_question import (
    NOT_RUN_CODE_READER_NO_LISTING,
    NOT_RUN_NO_LISTING,
    UNREAD_CALLEES_CODE,
    reads_code,
    states_why,
)
from maljan.agents.composition import ResolvedAgent
from maljan.core.config import AgentDefinition
from maljan.schemas.evidence import LedgerEntry
from tests.unit.agents.test_the_unread_functions_around_what_an_analyst_read_are_asked_once import (  # noqa: E501
    OWN,
    RETRY,
    _acme,
    _Analyst,
    _events,
    _notes,
    tools,  # noqa: F401 — the fixture the validation turn's tests use
)


def _resolved(category: str | None) -> ResolvedAgent:
    extra = {} if category is None else {"category": category}
    return ResolvedAgent(
        key="my_code_reader",
        role="generic",
        prompt="",
        tools=[],
        static_provider_id="none",
        llm=None,
        **extra,
    )


def _lookup() -> LedgerEntry:
    """A declared lookup that lists no code."""
    return LedgerEntry(
        id="ev_0003",
        tool="resolve_host",
        args={"host": "x"},
        output="{}",
        source="mcp:acme",
        facts=_acme("resolve_host", "dns"),
    )


class TestTheSeam:
    def test_a_code_reader_is_read_by_its_entries_and_said_when_none_lists_code(self) -> None:
        reader = AgentDefinition(role="generic", prompt="p", category="code_reader")
        assert reads_code(reader, OWN) == (True, "")
        assert reads_code(reader, []) == (False, NOT_RUN_CODE_READER_NO_LISTING)
        assert states_why(NOT_RUN_CODE_READER_NO_LISTING)

    @pytest.mark.parametrize(
        "definition",
        [
            None,
            _resolved(None),
            *(_resolved(c) for c in ("other", "static", "dynamic", "network", "intel")),
        ],
    )
    def test_every_other_category_is_read_from_the_ledger_as_before(self, definition: Any) -> None:
        assert reads_code(definition, OWN) == (True, "")
        assert reads_code(definition, []) == (False, NOT_RUN_NO_LISTING)
        assert not states_why(NOT_RUN_NO_LISTING)


@pytest.mark.usefixtures("tools")
class TestTheValidationTurn:
    def _turn(self, category: str | None) -> tuple[_Analyst, list[tuple[str, dict[str, Any]]]]:
        analyst = _Analyst([RETRY], list(OWN))
        analyst._resolved = _resolved(category)  # type: ignore[attr-defined]
        return analyst, _events(analyst)

    @pytest.mark.parametrize(
        "category", ["other", "code_reader", "static", "dynamic", "network", "intel"]
    )
    def test_any_category_that_listed_code_is_asked_byte_for_byte_as_before(
        self, category: str
    ) -> None:
        before, _ = self._turn(None)
        analyst, recorded = self._turn(category)
        assert UNREAD_CALLEES_CODE in str(before.seen_turns[-1][-1].content)
        sent = [[(type(m).__name__, m.content) for m in turn] for turn in before.seen_turns]
        assert [
            [(type(m).__name__, m.content) for m in turn] for turn in analyst.seen_turns
        ] == sent
        assert _notes(recorded) == []

    def test_a_code_reader_that_listed_no_code_is_told_why(self) -> None:
        analyst = _Analyst([], [_lookup()])
        analyst._resolved = _resolved("code_reader")  # type: ignore[attr-defined]
        analyst.pack_entries = []
        recorded = _events(
            analyst,
            "CLAIM 1: The host resolves.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\n"
            "TECHNIQUE: NONE\n---\n",
        )
        assert analyst.seen_turns == []
        (said,) = _notes(recorded)
        assert "code reader category" in said["text"]
        assert analyst._budget_records[-1]["callees_question"] == {
            "not_run": NOT_RUN_CODE_READER_NO_LISTING
        }

    def test_without_a_category_one_that_listed_no_code_is_still_not_told(self) -> None:
        analyst = _Analyst([], [_lookup()])
        analyst._resolved = _resolved("other")  # type: ignore[attr-defined]
        analyst.pack_entries = []
        recorded = _events(
            analyst,
            "CLAIM 1: The host resolves.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\n"
            "TECHNIQUE: NONE\n---\n",
        )
        assert _notes(recorded) == []
