"""What the judge wrote is kept whole where the platform stores it.

The fallback verdict's reasoning was cut to 2,000 characters for the bundle and
the mediator's text to 500 for the mediation summary, each without a mark, so
the stored reasoning ended mid-sentence as if the model had stopped there.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from maljan.agents.judge_agent import JudgeAgent

_LONG = "\n".join(f"Line {n}: the reasoning goes on about the sample." for n in range(200))


def _judge() -> JudgeAgent:
    return JudgeAgent(llm=MagicMock())


class TestTheFallbackVerdictKeepsTheJudgesText:
    def test_a_malware_fallback_keeps_the_reasoning_whole_and_as_written(self) -> None:
        text = f"Verdict: Malware.\n{_LONG}"

        bundle = _judge()._fallback_bundle_from_text(text, {}, {})

        malware = next(
            o for o in bundle.model_dump(mode="json")["objects"] if o["type"] == "malware"
        )
        assert malware["x_maljan_fallback_reasoning"] == text

    def test_a_note_carries_the_reasoning_whole(self) -> None:
        text = f"Verdict: Suspicious.\n{_LONG}"
        judge = _judge()

        bundle = judge._fallback_bundle_from_text(text, {}, {})

        objects = bundle.model_dump(mode="json").get("objects") or []
        notes = [o for o in objects if o["type"] == "note"]
        stored = notes[0]["content"] if notes else bundle.x_maljan_fallback_verdict.reasoning
        assert stored == text


class TestTheMediatorsTextIsKeptWhole:
    def test_the_resolution_summary_is_the_whole_reasoning(self) -> None:
        text = f"{_LONG}\nagreement_confidence: 0.4"

        verdict = _judge()._fallback_mediate(text)

        assert verdict.resolution_summary == text
