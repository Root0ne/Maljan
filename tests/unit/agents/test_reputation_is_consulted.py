"""A reputation server that is bound must actually be asked, once.

The live run that produced this: VirusTotal connected for the judge and
offered six of its seven tools, the analysts agreed with each other, and the
judge only opens its tool loop on explicit dissent — so the whole analysis ran
without anyone asking who the sample was. Nineteen ledger entries, every one of
them an analysis-server call, and a family of None on a report whose tool
server could have named it.

Two halves. The analysts that read a file now carry the reference, so the
lookup can happen where the hash is; and the judge opens its loop when it holds
tools and nothing in the run has consulted a reputation source, so the identity
question gets asked once even on a run nobody disagreed about.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from maljan.agents.judge_agent import JudgeAgent
from maljan.core.config import Settings, ToolRef
from maljan.core.virustotal import SERVER_KEY
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, Finding


def _isr(claim: str = "the binary is packed", dissent: bool = False) -> AgentISR:
    return AgentISR(
        agent_id="static",
        domain="static",
        claims=[ClaimEvidence(claim=claim, evidence_ref="ev_0001", confidence=0.6)],
        dissent_items=["dynamic says it persists and no artefact shows it"] if dissent else [],
    )


class TestEveryAnalystThatReadsTheFileCarriesTheReference:
    def test_the_seeded_definitions_name_the_server(self) -> None:
        definitions = Settings(_env_file=None).agents.definitions
        reference = ToolRef(kind="mcp", server=SERVER_KEY)

        for key in ("static", "network", "judge", "triage", "android_static", "reverser"):
            assert reference in definitions[key].tools, key

    def test_the_dynamic_analyst_does_not(self) -> None:
        """Its evidence is a detonation report, and the hash was already asked
        about by the analyst that read the file."""
        definitions = Settings(_env_file=None).agents.definitions

        assert ToolRef(kind="mcp", server=SERVER_KEY) not in definitions["dynamic"].tools

    def test_the_static_prompt_says_how_to_use_what_comes_back(self) -> None:
        from maljan.agents.static_analyst import _ISR_TAIL

        assert "reputation tool" in _ISR_TAIL
        assert "not the verdict" in _ISR_TAIL
        assert "unknown hash is not a clean sample" in _ISR_TAIL


class TestTheJudgeAsksTheIdentityQuestion:
    def _judge(self, refs: list[Any]) -> JudgeAgent:
        judge = JudgeAgent.__new__(JudgeAgent)
        judge.llm = MagicMock()
        judge.logger = MagicMock()
        judge.tools = []
        judge._definition_tool_refs = lambda: refs  # type: ignore[method-assign]
        return judge

    def test_it_opens_the_loop_when_nobody_consulted_a_reputation_source(self) -> None:
        judge = self._judge([ToolRef(kind="mcp", server=SERVER_KEY)])

        assert judge._can_ask_an_identity_question({"static": _isr()}) is True

    def test_an_analyst_that_already_asked_settles_it(self) -> None:
        judge = self._judge([ToolRef(kind="mcp", server=SERVER_KEY)])
        isr = _isr(claim="VirusTotal reports 41 of 70 engines detecting this hash")

        assert judge._can_ask_an_identity_question({"static": isr}) is False

    def test_a_judge_with_no_tools_at_all_stays_on_the_fast_path(self) -> None:
        """The loop costs a full judge timeout, and a judge holding nothing
        cannot answer the question with it."""
        judge = self._judge([])

        assert judge._can_ask_an_identity_question({"static": _isr()}) is False

    def test_a_family_word_counts_as_an_answer_too(self) -> None:
        judge = self._judge([ToolRef(kind="mcp", server=SERVER_KEY)])
        isr = _isr(claim="the sample matches the AsyncRAT malware family")

        assert judge._can_ask_an_identity_question({"static": isr}) is False

    def test_the_finding_titles_are_read_as_well_as_the_claims(self) -> None:
        judge = self._judge([ToolRef(kind="mcp", server=SERVER_KEY)])
        isr = _isr()
        isr.findings = [Finding(title="AbuseIPDB reports the C2 host as abusive")]

        assert judge._can_ask_an_identity_question({"static": isr}) is False


class TestTheMediatorTrigger:
    def _mediator(self, refs: list[Any], answer: str) -> JudgeAgent:
        judge = JudgeAgent.__new__(JudgeAgent)
        judge.logger = MagicMock()
        judge.tools = []
        judge._definition_tool_refs = lambda: refs  # type: ignore[method-assign]
        judge.llm = MagicMock()
        judge.token_ledger = None
        judge.truncation_ledger = None
        judge._config = None
        judge.evidence_counter = None
        judge._evidence_entries = []
        judge._loop_answer = answer
        return judge

    def _run_mediate(self, judge: JudgeAgent, isrs: dict[str, AgentISR]) -> list[str]:
        """Mediate with both paths stubbed, reporting which one ran."""
        import asyncio

        taken: list[str] = []

        async def _loop(messages: Any, *args: Any, **kwargs: Any) -> str:
            taken.append("tools")
            return "Contradictions: none\nagreement_confidence: 0.9"

        async def _no_client() -> None:
            return None

        judge.execute_tool_loop = _loop  # type: ignore[method-assign]
        judge._initialize_mcp_client = _no_client  # type: ignore[method-assign]

        class _LLM:
            async def ainvoke(self, messages: Any) -> Any:
                taken.append("fast")
                return MagicMock(content="Contradictions: none\nagreement_confidence: 0.9")

        judge.llm = _LLM()
        asyncio.run(judge.mediate(reports={"static": "text"}, history=[], isr_reports=isrs))
        return taken

    def test_the_loop_runs_when_no_reputation_source_was_consulted(self) -> None:
        judge = self._mediator([ToolRef(kind="mcp", server=SERVER_KEY)], "")

        assert self._run_mediate(judge, {"static": _isr()}) == ["tools"]

    def test_the_fast_path_is_kept_once_one_was(self) -> None:
        judge = self._mediator([ToolRef(kind="mcp", server=SERVER_KEY)], "")
        isr = _isr(claim="VirusTotal reports this hash as unknown")

        assert self._run_mediate(judge, {"static": isr}) == ["fast"]

    def test_dissent_still_opens_the_loop_on_its_own(self) -> None:
        judge = self._mediator([], "")

        assert self._run_mediate(judge, {"static": _isr(dissent=True)}) == ["tools"]
