"""A tool argument whose value is its own parameter's name is a question, not a call.

The large model's static analyst sent ``strings`` the arguments
``{"pattern": "\\"pattern\\"", "offset": 400, ...}`` twice. The server read the
quoted word as ``pattern``, matched eleven runs, served an empty page past
them, and the second identical call counted toward the repeat cap that ended
the loop. The call is now not run: the model is told which argument named its
own parameter, the value is left as it wrote it, and the question is counted.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool

from maljan.agents.evidence_recorder import (
    SELF_NAMED_ARGUMENT_CODE,
    EvidenceRecorder,
    RepeatGuard,
    record_tools,
    self_named_arguments,
)
from maljan.schemas.evidence import EvidenceCounter


def _strings_tool(ran: list[dict[str, Any]]) -> StructuredTool:
    def strings(pattern: str | None = None, offset: int = 0, limit: int = 100) -> str:
        """List printable runs."""
        ran.append({"pattern": pattern, "offset": offset, "limit": limit})
        return '{"strings": []}'

    return StructuredTool.from_function(func=strings, name="strings")


def _recorded(
    ran: list[dict[str, Any]], asked: list[str], repeats: RepeatGuard
) -> tuple[StructuredTool, EvidenceRecorder]:
    recorder = EvidenceRecorder("static", counter=EvidenceCounter())
    (tool,) = record_tools([_strings_tool(ran)], recorder, repeats, on_question=asked.append)
    return tool, recorder


class TestWhatNamesItsParameter:
    def test_the_benchmark_s_argument(self) -> None:
        assert self_named_arguments({"pattern": '"pattern"', "offset": 400}) == [
            ("pattern", '"pattern"')
        ]

    def test_the_bare_name_and_its_placeholder_forms(self) -> None:
        for value in ("pattern", "PATTERN", "<pattern>", "{pattern}", "${pattern}", "'pattern'"):
            assert self_named_arguments({"pattern": value}), value

    def test_a_value_that_only_contains_the_name_is_a_value(self) -> None:
        for value in ("pattern_match", "re:pattern", "the pattern", "patterns", ""):
            assert self_named_arguments({"pattern": value}) == [], value

    def test_a_list_names_it_only_when_every_item_does(self) -> None:
        assert self_named_arguments({"api_names": ["api_names"]})
        assert self_named_arguments({"api_names": ["api_names", "VirtualAlloc"]}) == []


class TestTheCall:
    def test_it_is_not_run_and_the_model_is_asked(self) -> None:
        ran: list[dict[str, Any]] = []
        asked: list[str] = []
        tool, recorder = _recorded(ran, asked, RepeatGuard())

        answer = tool.invoke({"pattern": '"pattern"', "offset": 400})

        assert ran == []
        assert recorder.entries == [], "no tool ran, so there is no evidence to cite"
        assert answer.startswith("strings was not run: `pattern` is ")
        assert "the name of the parameter itself" in answer
        assert asked == [SELF_NAMED_ARGUMENT_CODE]

    def test_the_value_is_never_rewritten_into_a_call(self) -> None:
        ran: list[dict[str, Any]] = []
        tool, _recorder = _recorded(ran, [], RepeatGuard())

        tool.invoke({"pattern": '"pattern"'})
        tool.invoke({"pattern": "CreateMutexW"})

        assert ran == [{"pattern": "CreateMutexW", "offset": 0, "limit": 100}]

    def test_asking_the_same_thing_again_counts_as_a_repeat(self) -> None:
        repeats = RepeatGuard()
        tool, _recorder = _recorded([], [], repeats)

        tool.invoke({"pattern": '"pattern"', "offset": 400})
        assert repeats.served_repeats == 0
        tool.invoke({"pattern": '"pattern"', "offset": 400})
        assert repeats.served_repeats == 1

    def test_an_ordinary_call_is_untouched(self) -> None:
        ran: list[dict[str, Any]] = []
        asked: list[str] = []
        tool, recorder = _recorded(ran, asked, RepeatGuard())

        answer = tool.invoke({"pattern": "runnung"})

        assert ran == [{"pattern": "runnung", "offset": 0, "limit": 100}]
        assert answer.startswith("[ev_0001]")
        assert asked == []
        assert len(recorder.entries) == 1


def test_the_analyst_counts_the_question_where_the_summary_reads_it() -> None:
    from maljan.agents.base_agent import BaseAnalyst

    class _Analyst(BaseAnalyst):
        def analyze(self, data: str) -> str:  # pragma: no cover - unused
            return ""

        def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
            return ""

    analyst = _Analyst(llm=object(), name="static")  # type: ignore[arg-type]
    analyst._count_question(SELF_NAMED_ARGUMENT_CODE)
    analyst._count_question(SELF_NAMED_ARGUMENT_CODE)

    _rows, _retries, fed_back = analyst.drain_validation_findings()
    assert fed_back == {SELF_NAMED_ARGUMENT_CODE: 2}
