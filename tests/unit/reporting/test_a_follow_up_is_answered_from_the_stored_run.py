"""A question asked of a finished run is answered from what the run stored, by the same checks.

The stored report, ledger rows and per-agent findings are read back into what
the question round reads: the ledger entries, the ids the run issued, the
claims in force and the open questions the analysts left (from the report's
own "Open questions" section), and the run state. The round then runs as the
report stage runs it, with its checks, its one retry and its calls recorded
under ``follow-up``; nothing is called but the reporter's model. The model is
the reporter the run's settings snapshot recorded, else the current one.

Every question, entry and answer here is made up for the test.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessage

from maljan.core.spend import TAIL_CALLS
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.follow_up import (
    CURRENT_MODEL,
    FOLLOW_UP_CALL,
    FOLLOW_UP_WHAT,
    MASKED_MODEL,
    MOVED_MODEL,
    RUN_MODEL,
    UNKNOWN_PROVIDER,
    answer_follow_up,
    recorded_reporter,
    reporter_overrides,
    spilled_rows,
    stored_open_questions,
    stored_run,
)
from maljan.reporting.ledger_report import build_sections
from maljan.reporting.models import MalwareReport
from maljan.reporting.question_round import (
    ESTABLISHED_UNGROUNDED_CODE,
    NEGATIVE_ON_OPEN_QUESTION_CODE,
    SYSTEM_PROMPT,
    UNISSUED_ID_CODE,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, OpenQuestion

BENCHMARK = Path("/home/user/Belgeler/kingston/Projects/Maljan/.superpowers/sdd/mandate-2026-09-17")
STORED_RUN = BENCHMARK / "benchmark" / "deepseek" / "run7"

OPEN = OpenQuestion(
    question="Whether the Run key is written after a reboot",
    why_open="needs_sandbox_run",
    detail="no sandbox ran",
    would_answer="a sandbox run",
    evidence_ids=["ev_0001"],
)


def _rows() -> list[dict[str, Any]]:
    """Ledger rows as ``evidence.json`` stores them: ``entry_id`` and every stored column."""
    return [
        {"entry_id": "ev_0002", "seq": 2, "agent": "static", "tool": "strings", "args": {},
         "output": "x", "ok": False, "error": "timed out", "stored_only": "a column"},
        {"entry_id": "ev_0001", "seq": 1, "agent": "static", "tool": "strings", "args": {},
         "output": "beacons to example.test", "ok": True},
    ]  # fmt: skip


def _ledger() -> list[LedgerEntry]:
    return [
        LedgerEntry(
            id=r["entry_id"], **{k: v for k, v in r.items() if k in LedgerEntry.model_fields}
        )
        for r in _rows()
    ]


def _payload() -> dict[str, Any]:
    report = MalwareReportBuilder(
        file_hash="d" * 64,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report=None,
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
    ).build_deterministic()
    isrs = {"static": AgentISR(agent_id="static", domain="static", open_questions=[OPEN])}
    report.sections = build_sections(_ledger(), isrs)
    return report.model_dump(mode="json")


def _findings() -> list[dict[str, Any]]:
    return [
        {
            "agent_name": "static",
            "domain": "static",
            "claims": [
                {
                    "claim": "A Run key is written.",
                    "technique_id": "T1547.001",
                    "evidence_ref": "[ev_0001]",
                    "confidence": 0.7,
                },
                {"not": "a claim"},
            ],
            "dissent_items": [],
            "revision_rounds": 1,
        }
    ]


def _run() -> Any:
    return stored_run(
        _payload(), _rows(), _findings(), {"stages": [{"key": "static", "ran": True}]}
    )


class _Reporter:
    """The narrative agent as the round uses it: one ``ask`` per call, its name recorded."""

    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[str, str]] = []
        self.turns: list[list[Any]] = []

    async def ask(self, turns: list[Any], *, call: str, what: str) -> Any:
        self.calls.append((call, what))
        self.turns.append(list(turns))
        return AIMessage(content=json.dumps(self.answers.pop(0)))


def _reply(outcome: str, **fields: Any) -> dict[str, Any]:
    return {"answers": [{"question": 1, "outcome": outcome, "answer": "From the run.", **fields}]}


class TestTheStoredRun:
    def test_the_ledger_rows_read_back_in_order_with_their_ids(self) -> None:
        run = _run()

        assert [e.id for e in run.ledger] == ["ev_0001", "ev_0002"]
        assert run.citable[:2] == ["ev_0001", "ev_0002"]
        assert run.state["file_hash"] == "d" * 64
        assert run.state["stage_results"] == {"static": {"key": "static", "ran": True}}

    def test_the_open_questions_read_back_from_the_reports_own_section(self) -> None:
        report = MalwareReport.model_validate(_payload())

        (back,) = stored_open_questions(report)["static"]

        assert (back.question, back.why_open, back.detail) == (
            OPEN.question,
            OPEN.why_open,
            OPEN.detail,
        )
        assert back.evidence_ids == ["ev_0001"]
        assert back.would_answer == "a sandbox run"

    def test_the_claims_in_force_are_read_and_a_claim_that_does_not_read_is_said(self) -> None:
        run = _run()

        isr = run.isr_reports["static"]
        assert [c.technique_id for c in isr.claims] == ["T1547.001"]
        assert [q.question for q in isr.open_questions] == [OPEN.question]
        assert run.notes == ["1 stored claim(s) do not read as claims"]

    def test_a_row_that_does_not_read_is_counted(self) -> None:
        run = stored_run(_payload(), [*_rows(), {"entry_id": "ev_9", "ok": "not a flag"}, 3])

        assert run.notes[0] == "2 stored ledger row(s) do not read as ledger entries"

    def test_a_payload_that_is_not_a_report_is_refused(self) -> None:
        with pytest.raises(ValueError, match="does not read as a report"):
            stored_run({"verdict": "nonsense"}, _rows())

    @pytest.mark.skipif(not STORED_RUN.is_dir(), reason="the benchmark's stored run is absent")
    def test_a_real_stored_run_reads_back_whole(self) -> None:
        byjob = json.loads((STORED_RUN / "report-byjob.json").read_text())
        evidence = json.loads((STORED_RUN / "evidence.json").read_text())

        run = stored_run(
            byjob["malware_report"],
            evidence["items"],
            byjob["agent_findings"],
            byjob["run_summary"],
        )

        assert run.notes == []
        assert len(run.ledger) == len(evidence["items"])
        assert run.isr_reports


class TestTheRound:
    @pytest.mark.asyncio
    async def test_the_answer_is_asked_once_under_the_follow_up_name(self) -> None:
        reporter = _Reporter(_reply("established", evidence_ids=["ev_0001"]))

        result = await answer_follow_up(reporter, _run(), "  What does it\n beacon to? ")

        (answer,) = result.answers
        assert answer.outcome == "established"
        assert answer.question == "What does it beacon to?"
        assert reporter.calls == [(FOLLOW_UP_CALL, FOLLOW_UP_WHAT)]
        system, human = reporter.turns[0]
        assert system.content == SYSTEM_PROMPT
        assert "1. " in human.content and "What does it beacon to?" in human.content
        assert "OQ1 static:" in human.content
        assert "sample: " + "d" * 64 in human.content

    @pytest.mark.asyncio
    async def test_an_id_the_run_did_not_issue_and_an_ungrounded_word_are_asked_about(
        self,
    ) -> None:
        reporter = _Reporter(
            _reply("established", evidence_ids=["ev_0002", "ev_0404"]),
            _reply("established", evidence_ids=["ev_0002", "ev_0404"]),
        )

        result = await answer_follow_up(reporter, _run(), "Does it beacon?")

        (answer,) = result.answers
        assert answer.outcome == "not_determinable"
        assert answer.answered == "established"
        assert any("ev_0404" in check and "did not issue" in check for check in answer.checks)
        feedback = str(reporter.turns[1][-1].content)
        assert UNISSUED_ID_CODE in feedback and ESTABLISHED_UNGROUNDED_CODE in feedback

    @pytest.mark.asyncio
    async def test_an_open_question_is_never_a_limited_negative(self) -> None:
        reply = _reply("limited_negative", looked_at=["ev_0001"], open_questions=["OQ1"])
        reporter = _Reporter(reply, reply)

        result = await answer_follow_up(reporter, _run(), "Does it persist after a reboot?")

        (answer,) = result.answers
        assert answer.outcome == "not_determinable"
        assert answer.open_questions == [f"static: {OPEN.question}"]
        assert NEGATIVE_ON_OPEN_QUESTION_CODE in str(reporter.turns[1][-1].content)

    @pytest.mark.asyncio
    async def test_no_reporter_leaves_the_question_not_determinable_with_the_reason(self) -> None:
        result = await answer_follow_up(None, _run(), "Does it beacon?")

        (answer,) = result.answers
        assert answer.outcome == "not_determinable"
        assert answer.checks == ["no report model ran in this run"]

    def test_the_follow_up_call_counts_toward_the_report_tail(self) -> None:
        assert TAIL_CALLS[FOLLOW_UP_CALL] == "report"


class TestTheModel:
    HOST = "http://llm.example.test:8080/v1"
    OLD = "http://old-host.example.test:8080/v1"

    def _current(self, **llm: Any) -> dict[str, Any]:
        return {"llm.provider": "openai", "llm.openai.base_url": self.HOST, **llm}

    def test_a_recorded_entry_gives_its_models_and_never_an_endpoint(self) -> None:
        snapshot = {
            "llm.provider": "openai",
            "llm.agents.reporter.provider": "openai",
            "llm.agents.reporter.model": "gpt-run",
            "llm.agents.reporter.base_url": self.OLD,
            "llm.agents.reporter.effort": None,
            "llm.agents.reporter.fallbacks": [
                {"provider": "openai", "model": "gpt-two", "base_url": self.OLD, "effort": None}
            ],
        }

        recorded, source = recorded_reporter(snapshot)

        assert recorded == {
            "reporter": {
                "provider": "openai",
                "model": "gpt-run",
                "fallbacks": [{"provider": "openai", "model": "gpt-two"}],
            }
        }
        assert source == RUN_MODEL
        assert "base_url" not in json.dumps(recorded)

    def test_a_model_the_run_called_at_another_host_is_not_asked_there(self) -> None:
        snapshot = {
            "llm.agents.reporter.provider": "openai",
            "llm.agents.reporter.model": "gpt-run",
            "llm.agents.reporter.base_url": self.OLD,
        }
        current = self._current()

        merged, source = reporter_overrides(current, snapshot)

        assert merged == current
        assert source == MOVED_MODEL.format(
            provider="openai",
            recorded="http://old-host.example.test:8080",
            current="http://llm.example.test:8080",
        )
        assert "old-host" not in json.dumps(merged)

    def test_a_model_at_the_place_its_provider_is_served_now_is_asked_with_the_current_address(
        self,
    ) -> None:
        snapshot = {
            "llm.provider": "openai",
            "llm.openai.base_url": "http://***@llm.example.test:8080/v1",
            "llm.agents.reporter.provider": "openai",
            "llm.agents.reporter.model": "gpt-run",
            "llm.agents.reporter.base_url": None,
        }

        merged, source = reporter_overrides(self._current(), snapshot)

        assert source == RUN_MODEL
        assert merged["llm.agents"]["reporter"] == {
            "provider": "openai",
            "model": "gpt-run",
            "fallbacks": [],
        }

    def test_an_entrys_own_address_comes_from_the_current_entry(self) -> None:
        own = "http://reporter.example.test:9000/v1"
        snapshot = {
            "llm.agents.reporter.provider": "openai",
            "llm.agents.reporter.model": "gpt-run",
            "llm.agents.reporter.base_url": "http://***@reporter.example.test:9000/v1",
        }
        current = self._current(
            **{"llm.agents": {"reporter": {"provider": "openai", "model": "now", "base_url": own}}}
        )

        merged, source = reporter_overrides(current, snapshot)

        assert source == RUN_MODEL
        assert merged["llm.agents"]["reporter"]["base_url"] == own
        assert merged["llm.agents"]["reporter"]["model"] == "gpt-run"

    def test_the_current_ceilings_are_kept_under_the_runs_model(self) -> None:
        from maljan.core.settings_overrides import settings_from_store

        snapshot = {
            "llm.openai.base_url": self.HOST,
            "llm.agents.reporter.provider": "openai",
            "llm.agents.reporter.model": "gpt-x",
        }
        current = self._current(
            **{
                "llm.agents": {
                    "reporter": {"provider": "openai", "model": "gpt-y", "max_spend_usd": 0.5}
                }
            }
        )

        merged, _ = reporter_overrides(current, snapshot)
        entry = settings_from_store(merged).llm.agents["reporter"]

        assert (entry.model, entry.max_spend_usd) == ("gpt-x", 0.5)

    def test_on_the_judge_role_a_ceiling_only_entry_is_kept_and_a_model_entry_dropped(
        self,
    ) -> None:
        snapshot = {
            "llm.provider": "openai",
            "llm.openai.base_url": self.HOST,
            "llm.openai.judge_model": "judge-run",
        }
        ceiling = {
            "llm.agents": {"reporter": {"max_unpriced_tokens": 1000}, "x": {"max_spend_usd": 1.0}}
        }
        named = {
            "llm.agents": {
                "reporter": {"provider": "openai", "model": "now"},
                "x": {"max_spend_usd": 1.0},
            }
        }

        kept, source = reporter_overrides(self._current(**ceiling), snapshot)
        dropped, _ = reporter_overrides(self._current(**named), snapshot)

        assert source == RUN_MODEL
        assert kept["llm.agents"] == {
            "reporter": {"max_unpriced_tokens": 1000},
            "x": {"max_spend_usd": 1.0},
        }
        assert kept["llm.openai.judge_model"] == "judge-run"
        assert dropped["llm.agents"] == {"x": {"max_spend_usd": 1.0}}

    def test_on_the_judge_role_the_providers_address_is_compared_never_an_entrys(self) -> None:
        evil = "http://elsewhere.example.test:8080/v1"
        entry = {"llm.agents": {"reporter": {"provider": "openai", "model": "n", "base_url": evil}}}
        moved = {
            "llm.provider": "openai",
            "llm.openai.base_url": evil,
            "llm.openai.judge_model": "judge-run",
        }
        same = {**moved, "llm.openai.base_url": self.HOST}

        refused, source = reporter_overrides(self._current(**entry), moved)
        taken, accepted = reporter_overrides(self._current(**entry), same)

        assert refused == self._current(**entry)
        assert source == MOVED_MODEL.format(
            provider="openai",
            recorded="http://elsewhere.example.test:8080",
            current="http://llm.example.test:8080",
        )
        assert accepted == RUN_MODEL
        assert taken["llm.openai.judge_model"] == "judge-run"
        assert "reporter" not in taken["llm.agents"]

    def test_a_provider_no_longer_registered_is_the_current_model_and_said(self) -> None:
        snapshot = {"llm.agents.reporter.provider": "gone", "llm.agents.reporter.model": "m"}

        merged, source = reporter_overrides(self._current(), snapshot)

        assert merged == self._current()
        assert source == UNKNOWN_PROVIDER.format(provider="gone")

    @pytest.mark.parametrize(
        ("snapshot", "source"),
        [
            (None, CURRENT_MODEL),
            ({}, CURRENT_MODEL),
            ({"llm.provider": "openai"}, CURRENT_MODEL),
            ({"llm.agents.reporter.provider": "o***", "llm.agents.reporter.model": "m"},
             MASKED_MODEL),
            ({"llm.provider": "openai", "llm.openai.judge_model": "g***"}, MASKED_MODEL),
            ({"llm.agents.reporter.provider": "openai", "llm.agents.reporter.model": "m",
              "llm.agents.reporter.base_url": "http://***/v1"}, MASKED_MODEL),
        ],
    )  # fmt: skip
    def test_nothing_usable_recorded_is_the_current_model_and_said(
        self, snapshot: Any, source: str
    ) -> None:
        merged, said = reporter_overrides(self._current(), snapshot)

        assert merged == self._current()
        assert said == source

    def test_the_recorded_model_builds_settings(self) -> None:
        from maljan.core.model_assignments import model_label_for
        from maljan.core.settings_overrides import build_settings

        merged, _ = reporter_overrides(
            {}, {"llm.provider": "anthropic", "llm.anthropic.judge_model": "claude-run"}
        )

        assert "claude-run" in model_label_for(build_settings(merged), "reporter", role="judge")


def test_a_row_whose_answer_was_kept_outside_it_is_said_to_be_read_cut() -> None:
    rows = _rows()
    rows[0]["spilled"] = [{"part": "output", "key": "k", "bytes": 9, "sha256": "0" * 64}]
    rows[1]["spilled"] = []

    run = stored_run(_payload(), rows)

    assert spilled_rows(rows) == 1
    assert run.notes == [
        "1 stored ledger row(s) keep part of their answer in object storage; the follow-up "
        "read them as the row holds them, cut"
    ]
