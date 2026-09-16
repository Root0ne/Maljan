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
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


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

    def _with_lookup(self) -> JudgeAgent:
        return self._judge([ToolRef(kind="mcp", server=SERVER_KEY)])

    def test_it_opens_the_loop_when_no_reputation_server_was_called(self) -> None:
        judge = self._with_lookup()

        assert judge._can_ask_an_identity_question({"analysis", "knowledge"}) is True

    def test_a_ledger_entry_against_the_reputation_server_closes_it(self) -> None:
        judge = self._with_lookup()

        assert judge._can_ask_an_identity_question({"analysis", SERVER_KEY}) is False

    def test_the_rest_sidecar_counts_as_a_reputation_server_too(self) -> None:
        judge = self._with_lookup()

        assert judge._can_ask_an_identity_question({"threatintel"}) is False

    def test_an_analyst_saying_no_family_was_found_still_opens_the_loop(self) -> None:
        """The sentence an analyst writes when it consulted nothing.

        Reading the prose for words like "malware family" turned the trigger
        off for exactly this case — the one it exists for. Nothing but the
        ledger decides it now.
        """
        judge = self._with_lookup()

        assert judge._can_ask_an_identity_question(set()) is True

    def test_an_empty_ledger_opens_it(self) -> None:
        judge = self._with_lookup()

        assert judge._can_ask_an_identity_question(None) is True

    def test_a_judge_with_no_lookup_tool_stays_on_the_fast_path(self) -> None:
        """The loop costs a full judge timeout, and a judge holding only the
        knowledge sidecar cannot answer an identity question with it."""
        judge = self._judge([ToolRef(kind="mcp", server="knowledge")])

        assert judge._can_ask_an_identity_question(set()) is False

    def test_an_attached_tool_counts_as_holding_the_server(self) -> None:
        """After the client is initialised the refs are spent and the tools
        are what the judge holds."""
        judge = self._judge([])
        judge.tools = [
            type("_T", (), {"name": "get_file_report", "metadata": {"maljan_server": SERVER_KEY}})()
        ]

        assert judge._can_ask_an_identity_question(set()) is True


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

    def _run_mediate(
        self, judge: JudgeAgent, isrs: dict[str, AgentISR], servers: set[str]
    ) -> list[str]:
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
        asyncio.run(
            judge.mediate(
                reports={"static": "text"},
                history=[],
                isr_reports=isrs,
                ledger_servers=servers,
            )
        )
        return taken

    def test_the_loop_runs_when_no_reputation_server_was_called(self) -> None:
        judge = self._mediator([ToolRef(kind="mcp", server=SERVER_KEY)], "")

        assert self._run_mediate(judge, {"static": _isr()}, {"analysis"}) == ["tools"]

    def test_the_fast_path_is_kept_once_one_was_called(self) -> None:
        judge = self._mediator([ToolRef(kind="mcp", server=SERVER_KEY)], "")

        assert self._run_mediate(judge, {"static": _isr()}, {SERVER_KEY}) == ["fast"]

    def test_prose_about_a_family_does_not_close_it(self) -> None:
        judge = self._mediator([ToolRef(kind="mcp", server=SERVER_KEY)], "")
        isr = _isr(claim="no malware family could be determined from static features")

        assert self._run_mediate(judge, {"static": isr}, {"analysis"}) == ["tools"]

    def test_dissent_still_opens_the_loop_on_its_own(self) -> None:
        judge = self._mediator([], "")

        assert self._run_mediate(judge, {"static": _isr(dissent=True)}, {SERVER_KEY}) == ["tools"]


class TestWhatTheDebateStageHandsOver:
    def test_the_reputation_servers_are_named_beside_the_built_ins(self) -> None:
        from maljan.core.config import BUILTIN_SERVER_KEYS, REPUTATION_SERVER_KEYS

        assert set(REPUTATION_SERVER_KEYS) == {SERVER_KEY, "threatintel"}
        assert set(REPUTATION_SERVER_KEYS) <= set(BUILTIN_SERVER_KEYS)

    def test_the_ledger_rows_are_read_for_the_servers_they_name(self) -> None:
        from maljan.pipeline.nodes import _ledger_servers

        state = {
            "evidence_ledger": [
                {"id": "ev_0001", "server": "analysis", "tool": "hashes"},
                {"id": "ev_0002", "server": SERVER_KEY, "tool": "get_file_report"},
                {"id": "ev_0003", "tool": "sandbox_processes"},
            ]
        }

        assert _ledger_servers(state) == {"analysis", SERVER_KEY}

    def test_a_row_that_is_not_a_mapping_costs_no_answer(self) -> None:
        """One malformed row must not decide whether the question is asked."""
        from maljan.pipeline.nodes import _ledger_servers

        row = type("_R", (), {"server": "threatintel"})()

        assert _ledger_servers({"evidence_ledger": [row, "nonsense"]}) == {"threatintel"}

    def test_a_run_with_no_ledger_yet_names_nothing(self) -> None:
        from maljan.pipeline.nodes import _ledger_servers

        assert _ledger_servers({}) == set()

    def test_the_debate_stage_passes_them_to_the_mediator(self) -> None:
        """The trigger is only as good as the call site that feeds it."""
        import inspect

        from maljan.pipeline import nodes

        source = inspect.getsource(nodes)

        assert "ledger_servers=_ledger_servers(state)" in source
