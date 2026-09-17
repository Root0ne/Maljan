"""The pack and the run state reach every prompt that is written for a model.

An analyst's tool loop, an analyst's revision, the mediator, the verdict, the
narrative round and every composer section: each is captured here on the way
to the model and read for the pack heading and the run-state markers. An
agent outside a staged run has neither block and sends exactly what it sent
before, which is what keeps the prompt goldens standing.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from maljan.agents.base_agent import BaseAnalyst, prompt_to_messages
from maljan.agents.judge_agent import JudgeAgent
from maljan.pipeline.nodes import brief_agent
from maljan.pipeline.run_state import RUN_STATE_BEGIN, RUN_STATE_END
from maljan.pipeline.triage_pack import PACK_HEADING, PIPELINE
from maljan.reporting.composer import ReportComposer
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.narrative_agent import NarrativeAgent
from maljan.schemas.evidence import build_entry, format_entry_id

FACTS = f"{PACK_HEADING}\n[ev_0001] identity: pe windows, 1,536 bytes\n[ev_0003] signature: none"
RUN_STATE = "sample: c\nledger: 3 entries (ev_0001–ev_0003), 3 from the triage pack"
REPORT = "CLAIM: it injects\nEVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: T1055\n"


class _LLM:
    """Records every message list it is sent, sync or async."""

    def __init__(self) -> None:
        self.seen: list[list[Any]] = []

    def invoke(self, messages: Any, **_: Any) -> AIMessage:
        self.seen.append(list(messages))
        return AIMessage(content=REPORT)

    async def ainvoke(self, messages: Any, **_: Any) -> AIMessage:
        return self.invoke(messages)


class _Analyst(BaseAnalyst):
    def __init__(self, llm: Any) -> None:
        super().__init__(llm=llm, name="static")

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def _briefed(llm: Any) -> _Analyst:
    agent = _Analyst(llm)
    agent.facts_block = FACTS
    agent.run_state_block = RUN_STATE
    agent.pack_ledger_ids = ["ev_0001", "ev_0002", "ev_0003"]
    return agent


def _system_and_human(messages: list[Any]) -> tuple[str, str]:
    system = next(str(m.content) for m in messages if isinstance(m, SystemMessage))
    human = next(str(m.content) for m in messages if isinstance(m, HumanMessage))
    return system, human


class TestAnAnalystsPrompt:
    def test_the_tool_loop_s_first_turn_carries_both_blocks(self) -> None:
        llm = _LLM()
        agent = _briefed(llm)
        agent.execute_tool_loop([("system", "You are a static analyst."), ("human", "Analyse.")])
        system, human = _system_and_human(llm.seen[0])
        assert system.startswith("You are a static analyst.")
        assert RUN_STATE_BEGIN in system and RUN_STATE_END in system
        assert "ledger: 3 entries" in system
        # The loop's whole budget is what the first turn has left.
        assert "budget remaining:" in system
        assert human.startswith(FACTS + "\n\nAnalyse.")

    def test_a_revision_turn_carries_them_too(self) -> None:
        llm = _LLM()
        agent = _briefed(llm)
        messages = agent.frame_messages(
            prompt_to_messages([("system", "sys"), ("human", "YOUR ORIGINAL REPORT: ...")])
        )
        system, human = _system_and_human(messages)
        assert RUN_STATE_BEGIN in system
        assert human.startswith(PACK_HEADING)

    def test_an_agent_outside_a_staged_run_sends_what_it_always_sent(self) -> None:
        llm = _LLM()
        agent = _Analyst(llm)
        agent.execute_tool_loop([("system", "You are a static analyst."), ("human", "Analyse.")])
        assert [m.content for m in llm.seen[0]] == ["You are a static analyst.", "Analyse."]

    def test_the_node_briefs_the_agent_from_the_state(self) -> None:
        entry = build_entry(
            entry_id=format_entry_id(1),
            seq=1,
            agent=PIPELINE,
            tool="identify_file",
            args={},
            server=PIPELINE,
            output='{"file_type": "pe", "platform": "windows", "size": 10}',
        )
        state: dict[str, Any] = {
            "file_hash": "a" * 64,
            "evidence_ledger": [entry.model_dump(mode="json")],
            "stage_results": {},
        }
        container = MagicMock()
        container.config.reporting.upstream_findings_max_chars = 6000
        agent = _Analyst(_LLM())
        brief_agent(agent, state, container)
        assert agent.facts_block.startswith(PACK_HEADING)
        assert "[ev_0001] identity: pe windows, 10 bytes" in agent.facts_block
        assert agent.pack_ledger_ids == ["ev_0001"]
        assert agent.run_state_block.startswith(f"sample: {'a' * 64}")

    def test_a_run_without_a_pack_briefs_nothing_to_cite(self) -> None:
        container = MagicMock()
        container.config.reporting.upstream_findings_max_chars = 6000
        agent = _briefed(_LLM())
        brief_agent(agent, {"file_hash": "", "evidence_ledger": []}, container)
        assert agent.facts_block == ""
        assert agent.pack_ledger_ids == []
        assert agent.run_state_block == ""


def _judge(seen: list[str]) -> JudgeAgent:
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
            seen.append("\n".join(str(getattr(m, "content", m)) for m in messages))
            return MagicMock(
                content='{"type": "bundle", "objects": [], "x_maljan_assessment": '
                '{"severity": {"rating": "Low", "rationale": "thin"}, "confidence": 0.2}}'
            )

    judge.llm = _Model()
    return judge


class TestTheJudgesPrompts:
    def test_the_mediator_reads_the_pack_and_the_run_state(self) -> None:
        seen: list[str] = []
        asyncio.run(
            _judge(seen).mediate(
                reports={"static": "text"},
                history=[],
                isr_reports={},
                ledger_servers={"virustotal"},
                facts_block=FACTS,
                run_state=RUN_STATE,
            )
        )
        assert seen
        assert PACK_HEADING in seen[0]
        assert RUN_STATE_BEGIN in seen[0]
        assert (
            seen[0].index(RUN_STATE_BEGIN)
            < seen[0].index(PACK_HEADING)
            < seen[0].index("Expert Reports:")
        )

    def test_the_verdict_reads_them_too(self) -> None:
        seen: list[str] = []
        asyncio.run(
            _judge(seen).give_verdict(
                reports={"static": "text"},
                history=[],
                isr_reports={},
                facts_block=FACTS,
                run_state=RUN_STATE,
            )
        )
        assert seen
        assert PACK_HEADING in seen[0]
        assert RUN_STATE_BEGIN in seen[0]

    def test_without_blocks_the_prompts_are_unchanged(self) -> None:
        seen: list[str] = []
        asyncio.run(
            _judge(seen).give_verdict(reports={"static": "text"}, history=[], isr_reports={})
        )
        assert PACK_HEADING not in seen[0]
        assert RUN_STATE_BEGIN not in seen[0]


def _report() -> MalwareReport:
    return MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)))


class TestTheReportRounds:
    def test_the_narrative_prompt_leads_with_the_pack(self) -> None:
        agent = NarrativeAgent.__new__(NarrativeAgent)
        messages = agent._build_prompt(_report(), FACTS)
        assert str(messages[1].content).startswith(FACTS + "\n\nDETERMINISTIC FINDINGS")
        bare = agent._build_prompt(_report())
        assert str(bare[1].content).startswith("DETERMINISTIC FINDINGS")

    def test_every_composer_section_leads_with_the_pack(self) -> None:
        composer = ReportComposer.__new__(ReportComposer)
        composer.per_section_timeout = 5
        composer._facts_block = ""
        seen: list[list[Any]] = []

        async def _invoke(messages: Any, schema: Any, *, section: str) -> Any:
            seen.append(list(messages))
            return None

        composer._invoke = _invoke  # type: ignore[method-assign]
        with patch(
            "maljan.reporting.composer.bundle_for", return_value={"facts": {"verdict": "x"}}
        ):
            composer._facts_block = FACTS
            asyncio.run(
                composer._author("introduction", _report(), None, MagicMock, "Write an intro.")
            )
        assert seen
        human = str(seen[0][1].content)
        assert human.startswith("Write an intro.\n\n" + FACTS)
        assert "SECTION: introduction" in human

    def test_compose_hands_the_pack_to_its_sections(self) -> None:
        composer = ReportComposer.__new__(ReportComposer)
        composer.per_section_timeout = 5
        composer.validation_tally = MagicMock()
        composer._grounding = MagicMock()
        composer._facts_block = ""

        async def _author(*_a: Any, **_k: Any) -> Any:
            return None

        composer._author = _author  # type: ignore[method-assign]
        with patch("maljan.reporting.composer.CapabilityGrounding") as grounding:
            grounding.from_report.return_value = MagicMock()
            asyncio.run(composer.compose(_report(), None, facts_block=FACTS))
        assert composer._facts_block == FACTS
