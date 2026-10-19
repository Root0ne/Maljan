"""An analyst's input is sized from its window, and a shortened input says so.

``max_token_limit`` cut every analyst's input at 128,000 tokens with a log
line and nothing else, on a model whose window is a million. The limit is
derived from the analyst's window now — the room before the reply, less the
prompt around the input — an operator's number wins, and input that still
does not fit is shortened as a document, the model is told, and the run
records a degradation reason.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest

from maljan.agents.base_agent import INPUT_SHORTENED_NOTICE, BaseAnalyst, shorten_input
from maljan.core.config import Settings
from maljan.core.exceptions import AnalystError
from maljan.core.truncation_ledger import TruncationLedger
from maljan.llm import context_window as cw


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - not exercised
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        return ""


def _analyst(window_tokens: int | None) -> _Analyst:
    agent = _Analyst(llm=None, name="static")  # type: ignore[arg-type]
    agent.truncation_ledger = TruncationLedger()
    budget = (
        None
        if window_tokens is None
        else cw.ContextBudget(cw.WindowFact(window_tokens, cw.DECLARED, "test"), reply_tokens=1000)
    )
    agent._context_budget = lambda: budget  # type: ignore[method-assign]
    agent._system_prompt = lambda *a, **k: "s" * 500  # type: ignore[method-assign]
    return agent


def _cut(agent: _Analyst, text: str, **settings: Any) -> str:
    cfg = Settings(_env_file=None, **settings)
    with patch("maljan.agents.base_agent.get_settings", lambda: cfg):
        return agent._truncate_input(text)


class TestTheRoomIsTheWindow:
    def test_input_that_fits_the_window_is_whole(self) -> None:
        text = "x" * 400_000
        assert _cut(_analyst(1_000_000), text) == text

    def test_with_no_window_learned_the_input_is_whole(self) -> None:
        text = "x" * 2_000_000
        assert _cut(_analyst(None), text) == text

    def test_input_over_the_window_is_shortened_said_and_recorded(self) -> None:
        agent = _analyst(10_000)
        text = "The loader decrypts its payload. " * 3_000

        shown = _cut(agent, text)

        assert shown.startswith("NOTE: this input did not fit the model's window whole")
        assert shown.rstrip().endswith("…")
        assert len(shown) < len(text)
        (reason,) = agent.truncation_ledger.input_shortened
        assert reason.startswith("The static analyst's input was shortened: the first ")

    def test_json_input_is_shortened_as_a_document(self) -> None:
        document = json.dumps({"file": "s.bin", "strings": [f"string {i}" for i in range(5000)]})
        shown, detail = shorten_input(document, 4000)
        body = shown.split("\n\n", 1)[1]
        parsed = json.loads(body)
        assert parsed["file"] == "s.bin" and len(parsed["strings"]) < 5000
        assert "JSON shortened" in detail
        assert INPUT_SHORTENED_NOTICE.split("{")[0] in shown


class TestAnOperatorsLimit:
    def test_wins_over_the_window(self) -> None:
        agent = _analyst(1_000_000)
        text = "word " * 10_000
        shown = _cut(agent, text, max_token_limit=100)
        assert shown.startswith("NOTE:") and len(shown) < 2_000

    def test_the_default_is_derived(self) -> None:
        assert Settings(_env_file=None).max_token_limit is None


def _revised_input(
    agent: _Analyst, data: str, own: str, peers: dict[str, str], feedback: str
) -> str:
    """What ``revise_isr`` is handed as its raw data by ``safe_revise_isr``."""
    seen: list[str] = []

    def revise_isr(original_data: str, *_a: Any, **_k: Any) -> Any:
        seen.append(original_data)
        raise RuntimeError("stop")

    agent.revise_isr = revise_isr  # type: ignore[method-assign]
    cfg = Settings(_env_file=None)
    with patch("maljan.agents.base_agent.get_settings", lambda: cfg), pytest.raises(AnalystError):
        agent.safe_revise_isr(data, own, peers, feedback, 1)
    (shown,) = seen
    return shown


class TestARevisionLeavesRoomForItsReports:
    """A revision's raw data sits beside its own report, its peers' and the feedback.

    The input room is the window less the prompt around one input; a revision
    carries those three sections as well, so its raw data is shortened at the
    room less them, and the shortening is said and recorded as any is.
    """

    def test_data_that_fits_beside_the_reports_is_whole(self) -> None:
        agent = _analyst(1_000_000)
        data = "d" * 10_000
        assert _revised_input(agent, data, "own", {"peer": "theirs"}, "feedback") == data

    def test_data_that_fits_alone_but_not_beside_the_reports_is_shortened(self) -> None:
        agent = _analyst(10_000)
        cfg = Settings(_env_file=None)
        with patch("maljan.agents.base_agent.get_settings", lambda: cfg):
            room = agent._input_room_chars("x")
        assert room is not None and room > 4_000
        data = "The loader decrypts its payload. " * ((room - 100) // 33)
        own, peer, feedback = "o" * 1_000, "p" * 1_500, "f" * 500

        shown = _revised_input(agent, data, own, {"peer": peer}, feedback)

        assert shown.startswith("NOTE: this input did not fit the model's window whole")
        body = shown.split("\n\n", 1)[1]
        assert len(body) <= room - len(own) - len(peer) - len(feedback)
        (reason,) = agent.truncation_ledger.input_shortened
        assert reason.startswith("The static analyst's input was shortened: ")

    def test_with_no_window_learned_the_data_is_whole(self) -> None:
        agent = _analyst(None)
        data = "d" * 2_000_000
        assert _revised_input(agent, data, "o" * 10_000, {}, "f") == data
