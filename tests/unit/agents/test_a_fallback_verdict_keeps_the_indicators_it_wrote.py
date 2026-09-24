"""A fallback verdict keeps the indicators its answer wrote whole; the one rule decides them.

A reference run's judge was cut at its output cap twice and its verdict fell
back to text extraction. The answer had written its two decoded C2 URLs whole,
right after the assessment, and an earlier run had published both hosts on the
emulation record; the fallback bundle carried no indicator, so nothing put the
hosts to the publish rule and ``/iocs`` and STIX held the hashes alone. The
fallback now keeps each indicator the answer wrote whole, as written, asks it
what every bundle's indicator is asked (an ungrounded one is dropped and
recorded), and the export, the IOC table and ``/iocs`` read the one rule's
answer for it — the same answer an answer that closed would have had.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from langchain_core.messages import AIMessage

from maljan.agents.judge_agent import (
    VERDICT_FALLBACK_CODE,
    JudgeAgent,
    JudgeVerdict,
    stated_indicators_in,
)
from maljan.core.config import get_settings
from maljan.pipeline.outcome import decide_from_bundle, verdict_reading
from maljan.reporting.models import FileHashes, JudgeIndicator, MalwareReport, SampleIdentity
from maljan.reporting.renderers.stix_renderer import (
    emulation_from_ledger,
    exported_indicator_values,
    judge_indicator_rows,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

C2_URL = "https://relay7.example.net/gate/"
INVENTED = "https://nowhere-in-the-run.example.org/x/"


def _indicator(label: str, pattern: str) -> dict[str, Any]:
    return {
        "type": "indicator",
        "id": label,
        "name": label,
        "pattern": pattern,
        "pattern_type": "stix",
        "indicator_types": ["malicious-activity"],
        "x_maljan_confidence": 0.9,
    }


def _cut_answer(verdict: str = "Malware") -> str:
    """Assessment, two whole indicators, then attack-patterns until the cap cuts one."""
    whole = json.dumps(
        {
            "type": "bundle",
            "id": "bundle--1",
            "x_maljan_assessment": {"verdict": verdict, "confidence": 0.9},
            "objects": [
                _indicator("indicator--1", f"[url:value = '{C2_URL}']"),
                _indicator("indicator--2", f"[url:value = '{INVENTED}']"),
                *(
                    {
                        "type": "attack-pattern",
                        "id": f"attack-pattern--{i}",
                        "name": "Obfuscated Files or Information",
                        "description": "x" * 400,
                    }
                    for i in range(60)
                ),
            ],
        },
        indent=2,
    )
    return whole[: len(whole) - 500]


def _answer(text: str) -> AIMessage:
    cap = int(get_settings().llm.judge_max_tokens)
    return AIMessage(
        content=text,
        usage_metadata={"input_tokens": 4000, "output_tokens": cap, "total_tokens": 4000 + cap},
    )


class _Llm:
    def __init__(self, *answers: AIMessage) -> None:
        self.answers = list(answers)

    async def ainvoke(self, _messages: list[Any]) -> AIMessage:
        return self.answers.pop(0)


async def _fallback(verdict: str = "Malware") -> JudgeVerdict:
    judge = JudgeAgent(llm=_Llm(_answer(_cut_answer(verdict)), _answer(_cut_answer(verdict))))  # type: ignore[arg-type]
    return await judge.give_verdict(
        reports={"static": "decoded strings"},
        history=[],
        isr_reports={
            "static": AgentISR(
                agent_id="static",
                domain="static",
                claims=[
                    ClaimEvidence(
                        claim="It posts to a decoded C2 URL.",
                        evidence_ref="[ev_0012]",
                        confidence=0.9,
                    )
                ],
            )
        },
        ledger_ids=["ev_0012"],
        evidence_corpus={C2_URL},
    )


def _report(bundle: Any, verdict: str) -> MalwareReport:
    ledger = [
        LedgerEntry(
            id="ev_0012",
            agent="pipeline",
            tool="floss",
            structured={
                "total": 1,
                "strings": [{"kind": "decoded", "string": C2_URL, "encoding": "UTF-16LE"}],
                "truncated": False,
            },
        ),
        LedgerEntry(
            id="ev_0005",
            agent="pipeline",
            tool="strings",
            structured={"total": 1, "strings": [{"text": "GetProcAddress"}], "truncated": False},
        ),
    ]
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict=verdict,
        overall_confidence=0.9,
        emulated_strings=emulation_from_ledger(ledger),
        judge_indicators=[
            JudgeIndicator(kind=v.kind, value=v.value, algorithm=v.algorithm)
            for v in exported_indicator_values(bundle.model_dump(mode="json"))
        ],
    )


class TestTheIndicatorsAnAnswerWroteWhole:
    def test_each_whole_one_is_read_as_written(self) -> None:
        found = stated_indicators_in(_cut_answer())

        assert [obj["pattern"] for obj in found] == [
            f"[url:value = '{C2_URL}']",
            f"[url:value = '{INVENTED}']",
        ]
        assert found[0]["x_maljan_confidence"] == 0.9

    def test_one_the_cap_cut_is_not_read(self) -> None:
        text = _cut_answer()
        inside = text[: text.index(INVENTED)]

        assert [obj["id"] for obj in stated_indicators_in(inside)] == ["indicator--1"]

    def test_prose_names_no_indicator(self) -> None:
        assert stated_indicators_in(f"The C2 is {C2_URL}, an indicator.") == []

    def test_an_example_the_reasoning_rejected_is_not_read(self) -> None:
        rejected = json.dumps(
            {
                "type": "indicator",
                "pattern": "[domain-name:value = 'update.microsoft.com']",
                "indicator_types": ["benign"],
            }
        )
        text = f"<think>An example I will NOT include: {rejected} …</think> {_cut_answer()}"

        patterns = [obj["pattern"] for obj in stated_indicators_in(text)]

        assert "[domain-name:value = 'update.microsoft.com']" not in patterns
        assert patterns[0] == f"[url:value = '{C2_URL}']"

    def test_an_indicator_nested_in_another_object_is_not_read(self) -> None:
        nested = {
            "type": "relationship",
            "id": "relationship--1",
            "x": _indicator("indicator--9", "[domain-name:value = 'nested.example.org']"),
        }
        text = json.dumps({"type": "bundle", "id": "bundle--1", "objects": [nested]})

        assert stated_indicators_in(text) == []

    def test_an_escaped_indicator_in_a_string_is_not_read(self) -> None:
        inner = json.dumps(_indicator("indicator--9", "[domain-name:value = 'in.example.org']"))
        text = json.dumps(
            {
                "type": "bundle",
                "x_maljan_assessment": {"verdict": "Malware", "rationale": inner},
                "objects": [{"type": "malware", "id": "malware--1", "name": "m"}],
            }
        )

        assert stated_indicators_in(text) == []

    def test_only_the_bundle_s_own_objects_key_is_read(self) -> None:
        text = json.dumps(
            {
                "type": "bundle",
                "x_maljan_assessment": {
                    "verdict": "Malware",
                    "objects": [_indicator("indicator--8", "[url:value = 'https://a.example/']")],
                },
                "objects": [_indicator("indicator--1", f"[url:value = '{C2_URL}']")],
            }
        )

        assert [obj["id"] for obj in stated_indicators_in(text)] == ["indicator--1"]


class TestTheFallbackPath:
    @pytest.mark.asyncio
    async def test_the_grounded_indicator_is_kept_and_the_invented_one_dropped(self) -> None:
        verdict = await _fallback()
        bundle = verdict.bundle

        assert verdict_reading(bundle) == "fallback"
        assert decide_from_bundle(bundle) == "Malware"
        assert VERDICT_FALLBACK_CODE in {v.code for v in verdict.violations}
        patterns = [o.pattern for o in bundle.objects if getattr(o, "type", "") == "indicator"]
        assert patterns == [f"[url:value = '{C2_URL}']"]
        assert "stix.ungrounded_indicator" in {v.code for v in verdict.violations}

    @pytest.mark.asyncio
    async def test_the_one_publish_rule_publishes_the_decoded_host(self) -> None:
        verdict = await _fallback()

        rows = judge_indicator_rows(_report(verdict.bundle, "Malware"))

        assert [(row.value, answer) for row, answer in rows] == [(C2_URL, "yes")]

    @pytest.mark.asyncio
    async def test_under_a_benign_verdict_the_rule_publishes_nothing(self) -> None:
        verdict = await _fallback("Benign")

        rows = judge_indicator_rows(_report(verdict.bundle, "Benign"))

        assert [row.value for row, _answer in rows] == [C2_URL]
        assert all(answer.startswith("no: ") for _row, answer in rows)
