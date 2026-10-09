"""The composer writes its sections at once and applies them in their fixed order.

Every section's request is built before any section answers, from state no
section's answer changes, so the requests are the ones a sequential run sends.
The answers are applied in ``COMPOSED_SECTIONS`` order, with each section's
validation record, degradations and flagged sentences, so the report, its
Markdown and HTML, the tally and the degradation list are byte-identical to a
sequential run given the same answers.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.messages import AIMessage, BaseMessage
from langchain_openai.chat_models.base import _convert_message_to_dict

from maljan.reporting.composer import COMPOSED_SECTIONS, ReportComposer
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
)
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

_LEAD = "The evidence for the "


def _section_of(messages: list[BaseMessage]) -> str:
    text = str(messages[1].content)
    start = text.index(_LEAD) + len(_LEAD)
    return text[start : text.index(" section follows.", start)]


def _report() -> MalwareReport:
    """A report whose every composed section has evidence to be written from."""

    def tool(name: str, output: str) -> dict[str, str]:
        return {"tool_name": name, "symbol": "", "output": output}

    return MalwareReport(
        identity=SampleIdentity(
            hashes=FileHashes(sha256="a" * 64),
            file_type="PE32 executable",
            platform="Windows",
        ),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        network=NetworkIOCs(domains=[NetworkDomain(fqdn="update.example.invalid")]),
        technical_evidence={
            "static": [
                tool("list_strings", "RESTORE_FILES.example.txt --path update.example.invalid"),
                tool("list_segments", ".text .rdata .packed"),
                tool("detect_crypto_constants", "AES sbox at 0x401000"),
                tool("find_anti_analysis_techniques", "IsDebuggerPresent"),
                tool("list_imports", "kernel32.dll FindFirstFileW"),
                tool("extract_iocs_with_context", "update.example.invalid in .rdata"),
            ],
            "reversing": [
                tool("decompile_function", "void dispatch(int c) { switch (c) { case 1: ; } }"),
                tool("emulate_function", "decoded: example-config"),
            ],
        },
    )


def _isr() -> dict[str, Any]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="Encrypts files with AES and drops a ransom note",
                    evidence_ref="detect_crypto_constants",
                    confidence=0.7,
                )
            ],
        )
    }


# One recorded answer per section. Some carry a key their schema does not
# declare, so the run leaves degradations whose order is the sections' order;
# none cites an id, so prose sections leave findings on the record.
_ANSWERS: dict[str, dict[str, Any]] = {
    "introduction": {"text": "A Windows executable that encrypts files."},
    "execution_flow": {
        "steps": [{"order": 1, "action": "Enumerates drives", "voice": "assessed"}],
        "extra_flow": 1,
    },
    "configuration": {"items": [{"key": "Extension", "value": ".locked"}]},
    "host_identifiers": {
        "identifiers": [{"kind": "Note file name", "value": "RESTORE_FILES.example.txt"}]
    },
    "commands": {"commands": [{"id": "1", "name": "dispatch", "description": "Runs case 1"}]},
    "encryption_scheme": {"cipher": "AES", "extra_cipher": "x"},
    "cli_flags": {"flags": [{"flag": "--path", "description": "Limits the walk"}]},
    "ransom_note": {"filename": "RESTORE_FILES.example.txt"},
    "communications": {
        "channels": [
            {"name": "Update", "protocol": "HTTP", "endpoints": ["update.example.invalid"]}
        ]
    },
}


def _answer(section: str) -> dict[str, Any]:
    if section in _ANSWERS:
        return _ANSWERS[section]
    return {"body": f"The {section} evidence shows a packed loader.", "evidence_refs": []}


class _Recorder:
    """A model that records each request as its body would be sent, and answers per section."""

    def __init__(self, *, delay: float = 0.0, failing: frozenset[str] = frozenset()) -> None:
        self.delay = delay
        self.failing = failing
        self.requests: list[str] = []
        self.sections: list[str] = []
        self.spans: dict[str, list[tuple[float, float]]] = {}
        self.in_flight = 0
        self.most_in_flight = 0

    async def ainvoke(self, messages: list[BaseMessage], **kwargs: Any) -> AIMessage:
        section = _section_of(messages)
        self.sections.append(section)
        self.requests.append(
            json.dumps(
                {"messages": [_convert_message_to_dict(m) for m in messages], **kwargs},
                sort_keys=True,
            )
        )
        began = time.monotonic()
        self.in_flight += 1
        self.most_in_flight = max(self.most_in_flight, self.in_flight)
        try:
            await asyncio.sleep(self.delay)
        finally:
            self.in_flight -= 1
            self.spans.setdefault(section, []).append((began, time.monotonic()))
        if section in self.failing:
            raise RuntimeError("the stub refuses this section")
        return AIMessage(content=json.dumps(_answer(section)))


def _compose(
    llm: Any, *, concurrent: bool, timeout: int = 30
) -> tuple[ReportComposer, MalwareReport]:
    report = _report()
    composer = ReportComposer(llm=llm, per_section_timeout=timeout)
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=False):
        asyncio.run(composer.compose(report, _isr(), concurrent=concurrent))
    return composer, report


class TestTheSectionsRunAtOnce:
    def test_every_section_has_evidence_in_the_test_report(self) -> None:
        llm = _Recorder()
        _compose(llm, concurrent=False)
        assert set(llm.sections) == set(COMPOSED_SECTIONS)

    def test_the_requests_are_the_sequential_requests(self) -> None:
        sequential, concurrent = _Recorder(), _Recorder()
        _compose(sequential, concurrent=False)
        _compose(concurrent, concurrent=True)
        assert sorted(concurrent.requests) == sorted(sequential.requests)
        assert len(concurrent.requests) == len(sequential.requests)

    def test_the_report_and_its_renders_are_the_sequential_ones(self) -> None:
        first, report_one = _compose(_Recorder(), concurrent=False)
        second, report_two = _compose(_Recorder(delay=0.01), concurrent=True)
        assert report_two.model_dump_json() == report_one.model_dump_json()
        assert MarkdownRenderer().render(report_two) == MarkdownRenderer().render(report_one)
        assert HtmlRenderer().render(report_two) == HtmlRenderer().render(report_one)
        assert second.degradations == first.degradations
        assert second.validation_tally.to_dict() == first.validation_tally.to_dict()
        assert first.degradations, "the recorded answers leave degradations to order"
        assert report_one.flagged_statements, "and flagged sentences"

    def test_the_order_holds_when_the_sections_finish_in_reverse(self) -> None:
        class _Reversed(_Recorder):
            async def ainvoke(self, messages: list[BaseMessage], **kwargs: Any) -> AIMessage:
                position = COMPOSED_SECTIONS.index(_section_of(messages))
                self.delay = 0.005 * (len(COMPOSED_SECTIONS) - position)
                return await super().ainvoke(messages, **kwargs)

        first, report_one = _compose(_Recorder(), concurrent=False)
        second, report_two = _compose(_Reversed(), concurrent=True)
        assert report_two.model_dump_json() == report_one.model_dump_json()
        assert second.degradations == first.degradations
        assert second.validation_tally.to_dict() == first.validation_tally.to_dict()

    def test_the_wall_time_is_the_slowest_section_not_the_sum(self) -> None:
        delay = 0.2
        llm = _Recorder(delay=delay)
        began = time.monotonic()
        _compose(llm, concurrent=True)
        wall = time.monotonic() - began
        calls = len(llm.requests)
        assert calls >= len(COMPOSED_SECTIONS)
        assert llm.most_in_flight == len(COMPOSED_SECTIONS), "no limit on how many run at once"
        # The slowest section is its answer and its one retry.
        assert wall < delay * calls / 3

    def test_a_failing_section_leaves_the_others_as_they_were(self) -> None:
        _composer, whole = _compose(_Recorder(), concurrent=True)
        failed_composer, partial = _compose(
            _Recorder(failing=frozenset({"commands"})), concurrent=True
        )
        assert partial.technical_analysis is not None and whole.technical_analysis is not None
        assert partial.technical_analysis.commands == []
        assert any("'commands'" in reason for reason in failed_composer.degradations)
        kept = whole.technical_analysis.model_dump()
        kept["commands"] = []
        assert partial.technical_analysis.model_dump() == kept
        assert partial.intro_background == whole.intro_background
        assert partial.c2_channels == whole.c2_channels


class TestTheWaitFollowsThePace:
    def test_a_section_still_running_is_given_the_wait_a_later_pace_sizes(self) -> None:
        """A wait measured before any section answered grows with what was measured since."""

        class _Rates:
            def __init__(self) -> None:
                self.per_call = 0.05

            def call_timeout(self, *_args: Any, **_kwargs: Any) -> float:
                return self.per_call

        rates = _Rates()

        class _Slow(_Recorder):
            async def ainvoke(self, messages: list[BaseMessage], **kwargs: Any) -> AIMessage:
                # A section answering slowly measures a slower pace than the
                # wait every section was given at the start.
                rates.per_call = 5.0
                return await super().ainvoke(messages, **kwargs)

        llm = _Slow(delay=0.2)
        report = _report()
        composer = ReportComposer(llm=llm, per_section_timeout=0, generation_rates=rates)
        composer.per_section_timeout = 0.1  # type: ignore[assignment]
        composer.output_cap = 100
        with patch(
            "maljan.reporting.composer.structured_output_supported_for_llm", return_value=False
        ):
            asyncio.run(composer.compose(report, _isr(), concurrent=True))
        assert not any("did not answer within" in reason for reason in composer.degradations)
        assert report.intro_background


class TestTheCachedHeadIsWrittenFirst:
    def test_on_a_model_that_caches_the_lead_section_answers_before_the_rest_are_sent(
        self,
    ) -> None:
        class _Caching(_Recorder):
            _llm_type = "anthropic-chat"

        llm = _Caching(delay=0.05)
        _compose(llm, concurrent=True)
        lead = llm.sections[0]
        lead_ended = llm.spans[lead][0][1]
        later = [span[0][0] for section, span in llm.spans.items() if section != lead]
        assert later and min(later) >= lead_ended
        assert llm.most_in_flight == len(COMPOSED_SECTIONS) - 1

    def test_the_first_piece_of_the_lead_answer_releases_the_rest(self) -> None:
        from maljan.reporting.composer import _FirstPiece, _on_first_piece

        async def _run() -> bool:
            released = asyncio.Event()
            handler = _FirstPiece()
            with _on_first_piece(released):
                handler.on_llm_new_token("x")
            await asyncio.sleep(0)
            return released.is_set()

        assert asyncio.run(_run())

    def test_a_model_that_does_not_cache_sends_every_section_at_once(self) -> None:
        llm = _Recorder(delay=0.05)
        _compose(llm, concurrent=True)
        assert llm.most_in_flight == len(COMPOSED_SECTIONS)


@pytest.mark.parametrize("concurrent", [False, True])
def test_the_head_note_rides_on_the_section_request(concurrent: bool) -> None:
    """The shared head's length is noted on the request, for the provider that caches it."""
    from maljan.llm.anthropic_history import SHARED_HEAD

    seen: list[BaseMessage] = []

    class _Keeps(_Recorder):
        async def ainvoke(self, messages: list[BaseMessage], **kwargs: Any) -> AIMessage:
            seen.append(messages[1])
            return await super().ainvoke(messages, **kwargs)

    report = _report()
    composer = ReportComposer(llm=_Keeps(), per_section_timeout=30)
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=False):
        asyncio.run(
            composer.compose(
                report, _isr(), facts_block="FACTS", run_state="", concurrent=concurrent
            )
        )
    heads = {str(m.content)[: m.response_metadata[SHARED_HEAD]] for m in seen}
    assert heads == {"FACTS\n\n"}


class _Priced(_Recorder):
    """A priced model that reports usage, so the spend ceiling settles each call."""

    model_name = "priced-model"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.caps: dict[str, list[Any]] = {}

    async def ainvoke(self, messages: list[BaseMessage], **kwargs: Any) -> AIMessage:
        self.caps.setdefault(_section_of(messages), []).append(kwargs.get("max_tokens"))
        answer = await super().ainvoke(messages, **kwargs)
        answer.usage_metadata = {"input_tokens": 100, "output_tokens": 200, "total_tokens": 300}
        return answer


def _compose_under_a_ceiling(concurrent: bool) -> tuple[_Priced, ReportComposer, bool]:
    """Compose under a spend ceiling on a thread of its own; whether it finished in time."""
    import threading

    from maljan.core.spend import SpendMeter
    from maljan.core.token_ledger import TokenLedger

    meter = SpendMeter(
        0.05,
        {"priced-model": {"input_usd_per_mtok": 0.0, "output_usd_per_mtok": 10.0}},
        table={},
    )
    llm = _Priced(delay=0.05)
    composer = ReportComposer(
        llm=llm,  # type: ignore[arg-type]
        section_max_tokens=1000,
        per_section_timeout=30,
        token_ledger=TokenLedger(spend=meter),
        model_label="priced-model",
    )

    def _run() -> None:
        with patch(
            "maljan.reporting.composer.structured_output_supported_for_llm", return_value=False
        ):
            asyncio.run(composer.compose(_report(), _isr(), concurrent=concurrent))

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(20)
    return llm, composer, not worker.is_alive()


class TestUnderASpendCeiling:
    def test_the_sections_finish_and_are_held_as_written_one_after_another(self) -> None:
        sequential, first, finished_one = _compose_under_a_ceiling(False)
        concurrent, second, finished_two = _compose_under_a_ceiling(True)
        assert finished_one and finished_two, "the event loop is never held by an admission"
        assert concurrent.caps == sequential.caps
        assert sorted(concurrent.requests) == sorted(sequential.requests)
        assert second.degradations == first.degradations
