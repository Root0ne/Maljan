"""A property the platform does not carry is recorded, and the judge's record holds it.

The domain-object models ignore properties they do not declare, so an
indicator's ``valid_until`` and ``kill_chain_phases``, a relationship's
``description`` and a malware object's ``aliases`` left the judge's bundle with
no row and no log — and the stored judge bundle, a model dump, lost them too,
although every decline sentence points at it as the record of what the judge
wrote. Now each object's undeclared keys are a recorded
``stix.property_not_carried`` row that does not spend the judge's retry, the
stored record is the judge's own JSON as written, and ``sample_refs`` — how a
judge ties a sample file to its malware object — is carried.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import MagicMock

from maljan.agents.judge_agent import JudgeAgent
from maljan.agents.judge_postprocess import PROPERTY_NOT_CARRIED_CODE
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer

ANSWER: dict[str, Any] = {
    "type": "bundle",
    "objects": [
        {
            "type": "malware",
            "id": "malware--1",
            "name": "loader",
            "is_family": False,
            "aliases": ["LDR"],
            "sample_refs": ["file--1"],
        },
        {"type": "file", "id": "file--1", "name": "loader.exe", "hashes": {"MD5": "a" * 32}},
        {
            "type": "indicator",
            "id": "indicator--1",
            "pattern": "[ipv4-addr:value = '82.157.13.47']",
            "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
            "valid_until": "2027-01-01T00:00:00Z",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "c2"}],
        },
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "indicates",
            "source_ref": "indicator--1",
            "target_ref": "malware--1",
            "description": "the address the shell connects to",
        },
    ],
    "x_maljan_assessment": {
        "verdict": "Malware",
        "confidence": 0.9,
        "severity": {"rating": "High", "rationale": "a reverse shell"},
    },
}


def _judge(answer: str) -> Any:
    judge = JudgeAgent.__new__(JudgeAgent)
    judge.logger = MagicMock()
    judge.tools = []
    judge.token_ledger = None
    judge.truncation_ledger = None
    judge._config = None
    judge.evidence_counter = None
    judge._evidence_entries = []
    judge._definition_tool_refs = lambda: []  # type: ignore[method-assign]

    class _Model:
        async def ainvoke(self, messages: Any) -> Any:
            return MagicMock(content=answer)

    judge.llm = _Model()
    return judge


def _verdict() -> Any:
    return asyncio.run(
        _judge(json.dumps(ANSWER)).give_verdict(
            reports={"static": "a reverse shell"},
            history=[],
            evidence_corpus={"82.157.13.47"},
            ledger_ids=["ev_0001"],
        )
    )


class TestTheRow:
    def test_each_object_names_what_is_not_carried(self) -> None:
        rows = [v for v in _verdict().violations if v.code == PROPERTY_NOT_CARRIED_CODE]
        messages = " | ".join(v.message for v in rows)

        assert len(rows) == 3
        for key in ("'aliases'", "'valid_until'", "'kill_chain_phases'", "'description'"):
            assert key in messages, key
        assert "'sample_refs'" not in messages

    def test_it_does_not_spend_the_judges_retry(self) -> None:
        verdict = _verdict()

        assert PROPERTY_NOT_CARRIED_CODE not in verdict.fed_back


class TestTheRecordHoldsWhatTheJudgeWrote:
    def test_the_verdict_carries_the_answer_as_written(self) -> None:
        written = _verdict().written

        assert written == ANSWER

    def test_the_stored_record_is_that_answer(self) -> None:
        from app.worker.analysis_worker import judge_bundle_record

        verdict = _verdict()
        record = judge_bundle_record(
            {
                "stix_output": verdict.bundle.model_dump(),
                "stix_written": verdict.written,
                "stix_labels": verdict.labels,
            }
        )

        assert record is not None
        assert record["bundle"] == ANSWER
        assert record["as_written"] is True


class TestSampleRefs:
    def test_a_malware_objects_sample_is_carried_to_the_export(self) -> None:
        verdict = _verdict()
        report = MalwareReportBuilder(
            file_hash="c" * 64,
            file_name="loader.exe",
            sample_path=None,
            sandbox_report={},
            reports={},
            isr_reports={},
            stix_output=verdict.bundle.model_dump(mode="json"),
            run_summary={},
            discussion_history=[],
            final_decision="Malware",
            overall_confidence=0.9,
            judge_assessment=None,
            malware_category="reverse_shell",
            evidence_ledger=[],
        ).build_deterministic()

        exported = ExtendedSTIXRenderer().render(report, verdict.bundle).model_dump(mode="json")

        (malware,) = [o for o in exported["objects"] if o["type"] == "malware"]
        (file,) = [o for o in exported["objects"] if o["type"] == "file"]
        assert malware["sample_refs"] == [file["id"]]
