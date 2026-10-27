"""Every mediation runs its tool loop, and the mediator may ask the agents that read the code.

A mediation used to take a single call with no tools whenever no analyst wrote
explicit dissent, and the judge's definition could not name another agent: a
dispute about a function nobody had read stayed open however many rounds the
debate held. Now the loop runs every round with ``read_evidence`` from its
first turn, the judge's definition asks the reverser and the static analyst
and reads the sandbox report, and an ask from the judge's loop runs through
the delegation every other ask runs through: its answer comes back as the
tool's result, the callee's calls land on the judge's ledger, and the judge
still decides.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool

from maljan.agents.composition import ResolvedAgent
from maljan.agents.configurable_analyst import ConfigurableAnalyst
from maljan.agents.delegation import TEAM_SERVER, ask_tool, tool_name
from maljan.agents.judge_agent import JudgeAgent, mediator_system_prompt
from maljan.core.config import Settings, _builtin_definitions
from maljan.schemas.evidence import EvidenceCounter

REVERSER_REPORT = (
    "CLAIM: 0x309c reads the PEB BeingDebugged byte\nEVIDENCE: ev_0001\nCONFIDENCE: 0.8\n"
    "TECHNIQUE: T1622\n"
)
MEDIATION = "CONTRADICTIONS: NONE\nagreement_confidence: 0.9"


class _Scripted(BaseChatModel):
    """Answers each model turn from a script, and remembers what it was sent and bound to."""

    script: list[Any]
    seen: list[list[Any]] = []
    bound: list[list[str]] = []

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any):
        self.seen.append(list(messages))
        answer = self.script.pop(0) if self.script else AIMessage(content="")
        return ChatResult(generations=[ChatGeneration(message=answer)])

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        self.bound.append([str(getattr(tool, "name", "")) for tool in tools])
        return self


def _call(name: str, args: dict[str, Any], call_id: str) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": call_id}])


class _Registry:
    """The tool servers of a job that attaches none."""

    async def aagent_tools(self, *_args: Any, **_kw: Any) -> tuple[list[Any], list[str]]:
        return [], []

    def for_agent(self, *_args: Any, **_kw: Any) -> list[Any]:
        return []

    def handles_for(self, *_args: Any) -> list[Any]:
        return []

    def answer_sizer(self) -> Any:
        return None


class _Container:
    """A job's container, reduced to what the judge's asks need of it."""

    def __init__(self, models: dict[str, Any], tools: dict[str, list[Any]]) -> None:
        self.config = Settings(_env_file=None)
        self.models = models
        self.extra_tools = tools
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.event_sink = lambda kind, payload: self.events.append((kind, payload))
        self._agents: dict[str, Any] = {}
        self._counter = EvidenceCounter()
        self._lock = threading.Lock()
        self._registry = _Registry()

    def get_server_registry(self) -> Any:
        return self._registry

    def get_context_budget(self) -> Any:
        return None

    def get_static_provider(self, _provider_id: str | None = None) -> Any:
        from maljan.providers.registry import get_static_provider

        return get_static_provider(self.config)

    def agent_role(self, key: str) -> str:
        return str(self.config.agents.definitions[key].role)

    def get_agent(self, key: str) -> Any:
        with self._lock:
            if key in self._agents:
                return self._agents[key]
            definition = self.config.agents.definitions[key]
            resolved = ResolvedAgent(
                key=key,
                role=str(definition.role),
                prompt=str(definition.prompt or "You read code."),
                tools=list(self.extra_tools.get(key, [])),
                static_provider_id="none",
                llm=None,
                attck_techniques=definition.attck_techniques,
            )
            agent = ConfigurableAnalyst(key, resolved, self.models.get(key))
            agent.evidence_counter = self._counter
            agent._container = self
            agent._job_id = "job"
            self._agents[key] = agent
            return agent


def _decompile_tool() -> StructuredTool:
    def decompile(address: str) -> dict[str, Any]:
        """Decompile one function."""
        return {"address": address, "listing": "return *(PEB + 2);"}

    return StructuredTool.from_function(func=decompile, name="decompile", description="decompile")


def _mediator(judge_script: list[Any], reverser_script: list[Any]) -> tuple[JudgeAgent, Any]:
    container = _Container(
        models={"reverser": _Scripted(script=reverser_script)},
        tools={"reverser": [_decompile_tool()]},
    )
    judge = JudgeAgent(llm=_Scripted(script=judge_script))  # type: ignore[arg-type]
    judge._container = container
    judge.evidence_counter = container._counter
    judge.pipeline_stage = "debate"
    # What the debate node hands the mediator for its asks (``brief_the_mediator``).
    judge.facts_block = "Facts established before analysis\n[ev_0000] imports"
    judge.run_state_block = "sample: s"
    judge._analysis_file_path = "/samples/s.bin"
    judge.sample_path_choices = {"by_provider": {}, "static": None, "host": "/samples/s.bin"}
    return judge, container


PROMPT = [("system", "You mediate."), ("human", "Expert Reports: the 0x309c gate is disputed.")]


class TestTheJudgeDefinitionAsksTheAgentsThatReadTheCode:
    def test_the_seed_names_the_reverser_the_static_analyst_and_the_sandbox_report(self) -> None:
        tools = _builtin_definitions()["judge"].tools

        assert [ref.agent for ref in tools if ref.kind == "agent"] == ["reverser", "static"]
        assert any(ref.kind == "sandbox" for ref in tools)

    def test_the_mediator_attaches_an_ask_per_named_agent_and_the_sandbox_tools(self) -> None:
        judge, _container = _mediator([], [])

        asyncio.run(judge._initialize_mcp_client())

        names = [tool.name for tool in judge.tools]
        assert tool_name("reverser") in names and tool_name("static") in names
        assert "sandbox_processes" in names
        ask = next(tool for tool in judge.tools if tool.name == tool_name("reverser"))
        assert ask.metadata["maljan_server"] == TEAM_SERVER

    def test_a_profile_with_nothing_to_call_gives_the_judge_no_ask(self) -> None:
        judge, container = _mediator([], [])
        container.config = Settings(_env_file=None, agents={"profile": "measurement"})

        asyncio.run(judge._initialize_mcp_client())

        assert not [tool for tool in judge.tools if tool.name.startswith("ask_")]

    def test_a_stored_judge_row_from_before_reads_as_the_seed(self) -> None:
        for former in (
            [
                {"kind": "mcp", "server": "knowledge"},
                {"kind": "capability", "capability": "reputation"},
            ],
            [{"kind": "mcp", "server": "knowledge"}, {"kind": "mcp", "server": "virustotal"}],
        ):
            settings = Settings(
                _env_file=None,
                agents={"definitions": {"judge": {"role": "judge", "tools": former}}},
            )

            assert settings.agents.definitions["judge"] == _builtin_definitions()["judge"]

    def test_an_edited_judge_tool_list_is_still_refused(self) -> None:
        with pytest.raises(ValueError, match="'judge' is built in; clone it to change it"):
            Settings(
                _env_file=None,
                agents={
                    "definitions": {
                        "judge": {
                            "role": "judge",
                            "tools": [{"kind": "mcp", "server": "knowledge"}],
                        }
                    }
                },
            )


class TestAnAskFromTheMediatorsLoop:
    def test_the_mediator_reads_the_reverser_s_claims_and_still_writes_its_own_answer(
        self,
    ) -> None:
        judge, container = _mediator(
            judge_script=[
                _call(tool_name("reverser"), {"task": "Does 0x309c read BeingDebugged?"}, "a1"),
                AIMessage(content=MEDIATION),
            ],
            reverser_script=[
                _call("decompile", {"address": "0x309c"}, "d1"),
                AIMessage(content=REVERSER_REPORT),
            ],
        )
        asyncio.run(judge._initialize_mcp_client())

        answer = asyncio.run(judge.execute_tool_loop(PROMPT))

        assert answer == MEDIATION
        tool_result = next(
            str(m.content) for m in judge.llm.seen[1] if getattr(m, "type", "") == "tool"
        )
        assert "0x309c reads the PEB BeingDebugged byte" in tool_result

    def test_the_callee_s_calls_and_the_ask_land_on_the_judge_s_ledger(self) -> None:
        judge, container = _mediator(
            judge_script=[
                _call(tool_name("reverser"), {"task": "Does 0x309c read BeingDebugged?"}, "a1"),
                AIMessage(content=MEDIATION),
            ],
            reverser_script=[
                _call("decompile", {"address": "0x309c"}, "d1"),
                AIMessage(content=REVERSER_REPORT),
            ],
        )
        asyncio.run(judge._initialize_mcp_client())
        asyncio.run(judge.execute_tool_loop(PROMPT))

        by_tool = {entry.tool: entry for entry in judge.drain_evidence_entries()}
        assert by_tool["decompile"].agent == "reverser"
        assert by_tool["decompile"].stage == "debate"
        assert by_tool["ask_reverser"].agent == "judge"
        assert by_tool["ask_reverser"].server == TEAM_SERVER
        assert by_tool["ask_reverser"].ok is True
        assert container.get_agent("reverser").drain_evidence_entries() == []

    def test_the_callee_is_briefed_from_the_mediator_and_given_nothing_back(self) -> None:
        judge, container = _mediator(
            judge_script=[
                _call(tool_name("reverser"), {"task": "Read 0x309c."}, "a1"),
                AIMessage(content=MEDIATION),
            ],
            reverser_script=[AIMessage(content=REVERSER_REPORT)],
        )
        asyncio.run(judge._initialize_mcp_client())
        asyncio.run(judge.execute_tool_loop(PROMPT))

        reverser = container.get_agent("reverser")
        first_turn = str(reverser.llm.seen[0][-1].content)
        assert "[ev_0000] imports" in first_turn
        assert "/samples/s.bin" in first_turn
        assert "Task from judge:\nRead 0x309c." in first_turn
        # The ask is over: the callee holds none of the judge's state and the
        # judge's loop budget is gone with its loop.
        assert reverser.call_chain == ()
        assert reverser.facts_block == ""
        assert judge.loop_budget is None

    def test_the_two_transcript_lines_say_the_judge_asked_the_reverser(self) -> None:
        judge, container = _mediator(
            judge_script=[
                _call(tool_name("reverser"), {"task": "Read 0x309c."}, "a1"),
                AIMessage(content=MEDIATION),
            ],
            reverser_script=[AIMessage(content=REVERSER_REPORT)],
        )
        asyncio.run(judge._initialize_mcp_client())
        asyncio.run(judge.execute_tool_loop(PROMPT))

        lines = [
            (data.get("speaker"), data.get("addressed_to"), data.get("kind"))
            for _kind, data in container.events
            if data.get("kind") in ("delegation_ask", "delegation_answer")
        ]
        assert lines == [
            ("judge", "reverser", "delegation_ask"),
            ("reverser", "judge", "delegation_answer"),
        ]

    def test_what_the_callee_s_checks_said_is_drained_once_from_the_judge(self) -> None:
        judge, _container = _mediator(
            judge_script=[
                _call(tool_name("reverser"), {"task": "Read 0x309c."}, "a1"),
                AIMessage(content=MEDIATION),
            ],
            reverser_script=[AIMessage(content=REVERSER_REPORT)],
        )
        asyncio.run(judge._initialize_mcp_client())
        asyncio.run(judge.execute_tool_loop(PROMPT))

        rows, retries, fed_back = judge.drain_validation_findings()
        assert all(str(row["message"]).startswith("reverser: ") for row in rows)
        assert judge.drain_validation_findings() == ([], 0, {})
        assert isinstance(retries, int) and isinstance(fed_back, dict)


class TestTheMediatorsLoopOffersReadEvidenceFromItsFirstTurn:
    def test_the_first_request_is_bound_with_read_evidence(self) -> None:
        judge, _container = _mediator([AIMessage(content=MEDIATION)], [])
        asyncio.run(judge._initialize_mcp_client())

        asyncio.run(judge.execute_tool_loop(PROMPT))

        assert "read_evidence" in judge.llm.bound[0]


class TestTheMediatorsPromptSaysWhatItCarries:
    def test_the_sentence_names_the_team_and_nothing_restricts_the_tools(self) -> None:
        judge, _container = _mediator([], [])
        asyncio.run(judge._initialize_mcp_client())

        text = mediator_system_prompt(
            identity_unanswered=False, lookup_attached=False, sha256="", tools=judge.tools
        )

        assert "your team's other agents" in text
        assert "only to resolve" not in text
        assert "No Threat Intelligence tools are needed" not in text

    def test_the_lookup_sentence_comes_before_the_sentence_about_the_tools(self) -> None:
        from maljan.agents.prompt_fragments import tools_statement

        text = mediator_system_prompt(
            identity_unanswered=True, lookup_attached=True, sha256="ab" * 32, tools=[]
        )

        assert text.endswith(tools_statement([]) + "\n")
        assert text.index("Look the sample's hash up once") < text.index(tools_statement([]))


def test_the_ask_tool_runs_for_the_instance_it_was_built_for() -> None:
    """The judge is two instances under one key; the ask is made for the one that holds it."""
    judge, container = _mediator([], [AIMessage(content=REVERSER_REPORT)])
    tool = ask_tool(container, "judge", "reverser", judge)

    answer = tool.invoke({"task": "Read 0x309c."})

    assert "0x309c reads the PEB BeingDebugged byte" in answer
    assert judge.drain_evidence_entries() == []


class TestTheJudgesAsksCountWhereTheJudgeMediates:
    """Only the mediator runs a tool loop, so the judge's asks count in a team with a debate."""

    def test_a_team_with_a_debate_reaches_the_agents_the_judge_may_ask(self) -> None:
        from maljan.agents.composition import reachable_agents

        settings = Settings(_env_file=None)

        assert reachable_agents(settings, ["judge"]) == ["judge", "reverser", "static"]
        assert reachable_agents(settings, ["judge"], mediated=False) == ["judge"]

    def test_a_team_without_one_does_not(self) -> None:
        from maljan.agents.composition import reachable_agents

        settings = Settings(_env_file=None, agents={"profile": "team_lead"})

        assert reachable_agents(settings, ["judge"]) == ["judge"]

    def test_the_roster_names_the_reverser_as_one_the_judge_may_task(self) -> None:
        from maljan.pipeline.events import roster_payload

        settings = Settings(_env_file=None)
        definitions = settings.agents.definitions
        default = roster_payload(settings.agents.profiles["default"], definitions)
        led = roster_payload(settings.agents.profiles["team_lead"], definitions)

        by_key = {agent["key"]: agent for agent in default["agents"]}
        assert by_key["reverser"]["via"] == ["judge"]
        assert "via" not in by_key["static"]
        assert {agent["key"]: agent for agent in led["agents"]}["reverser"]["via"] == ["lead"]


class TestNoJobIsRefusedOverAnAgentOnlyTheMediatorMayAsk:
    """A failed ask is a failed call on the ledger; it never turns a job away."""

    def test_a_profile_that_withholds_every_server_from_the_judge_reaches_none(self) -> None:
        from maljan.agents.composition import reachable_agents

        settings = Settings(_env_file=None, agents={"profile": "measurement"})

        assert reachable_agents(settings, ["judge"], mediated=True) == ["judge"]

    def test_the_probe_gate_asks_about_no_agent_only_the_mediator_may_ask(self) -> None:
        from maljan.agents.composition import called_assignments

        for profile in ("default", "mobile", "measurement"):
            settings = Settings(_env_file=None, agents={"profile": profile})

            asked = {assignment.agent for assignment in called_assignments(settings)}

            assert "reverser" not in asked, profile

    def test_a_mobile_job_with_an_unreachable_ghidra_is_not_refused(self) -> None:
        from app.services.provider_readiness import unready_static_providers

        settings = Settings(_env_file=None)
        settings.static.ghidra.enabled = True
        settings.static.ghidra.transport = "http"
        settings.static.ghidra.url = "http://127.0.0.1:9"

        refusals = asyncio.run(asyncio.wait_for(unready_static_providers(settings, "mobile"), 60))

        assert refusals == []


def _staged(debate_builtin: bool, verdict_builtin: bool) -> Settings:
    settings = Settings(_env_file=None)
    for stage in settings.agents.profiles["default"].stages:
        if stage.key == "debate":
            stage.builtin_tools = debate_builtin
        if stage.key == "verdict":
            stage.builtin_tools = verdict_builtin
    return settings


class TestTheJudgesAsksFollowTheStageTheyAreMadeFrom:
    def test_a_verdict_stage_that_withholds_built_ins_does_not_refuse_the_mediator(
        self,
    ) -> None:
        from maljan.agents.delegation import refusal

        judge, container = _mediator([], [])
        container.config = _staged(debate_builtin=True, verdict_builtin=False)
        judge.pipeline_stage = "debate"

        assert refusal(container, judge, "reverser") is None

    def test_a_debate_stage_that_withholds_them_does(self) -> None:
        from maljan.agents.delegation import refusal

        judge, container = _mediator([], [])
        container.config = _staged(debate_builtin=False, verdict_builtin=True)
        judge.pipeline_stage = "debate"

        why = refusal(container, judge, "reverser")

        assert why is not None and "the stage it is asking from" in why


class TestALimitEndedLoopIsNotRunAgain:
    def test_an_empty_salvage_names_the_limit_and_the_loop_runs_once(self) -> None:
        from unittest.mock import AsyncMock, patch

        from langchain_core.messages import HumanMessage, SystemMessage

        import maljan.agents.judge_agent as judge_agent

        class _Empty:
            async def ainvoke(self, _messages: Any, **_kw: Any) -> AIMessage:
                return AIMessage(content="")

            def bind_tools(self, *_args: Any, **_kw: Any) -> Any:
                return self

        judge = JudgeAgent(llm=_Empty())  # type: ignore[arg-type]
        runs: list[int] = []

        async def _loop(_prompt: Any) -> str:
            # The loop's own reset, then a salvage after its repeats ended it.
            runs.append(1)
            judge._last_answer, judge._last_answer_cap, judge._last_loop_ending = None, None, ""
            gathered = [SystemMessage(content="You mediate."), HumanMessage(content="Reports")]
            return await judge._reasoning_from_what_was_gathered(
                gathered, 10.0, None, ended_why="3 repeated tool call(s)"
            )

        with (
            patch.object(judge_agent, "_trim_for_synthesis", lambda msgs, _budget: msgs),
            patch.object(judge_agent, "synthesis_budget_chars", return_value=1),
            patch.object(judge, "_initialize_mcp_client", AsyncMock()),
            patch.object(judge, "execute_tool_loop", side_effect=_loop),
        ):
            argument, consensus = asyncio.run(
                judge.mediate(
                    {"static": "a", "dynamic": "b"},
                    [],
                    isr_reports={"static": _claiming("static"), "dynamic": _claiming("dynamic")},
                )
            )

        assert runs == [1]
        assert consensus is None
        assert "3 repeated tool call(s)" in argument.note
        assert "the tool loop was not run again" in argument.note


def _claiming(name: str) -> Any:
    from maljan.schemas.isr_models import AgentISR, ClaimEvidence

    return AgentISR(
        agent_id=name,
        domain=name,
        claims=[ClaimEvidence(claim="claim", evidence_ref="[ev_0001] imports", confidence=0.7)],
    )


def test_a_mediation_settles_a_code_dispute_by_asking_the_reverser() -> None:
    """End to end: ``mediate`` runs its loop, asks, and still writes its own block."""
    from unittest.mock import AsyncMock, patch

    from maljan.pipeline.mediation_models import MediatorVerdict

    judge, container = _mediator(
        judge_script=[
            _call(tool_name("reverser"), {"task": "Does 0x309c read BeingDebugged?"}, "a1"),
            AIMessage(content=MEDIATION),
        ],
        reverser_script=[
            _call("decompile", {"address": "0x309c"}, "d1"),
            AIMessage(content=REVERSER_REPORT),
        ],
    )
    extract = AsyncMock(
        return_value=MediatorVerdict(
            contradictions=[], resolution_summary="settled", confidence=0.9
        )
    )
    with patch.object(judge, "_extract_mediator_verdict", extract):
        argument, consensus = asyncio.run(
            judge.mediate(
                {"static": "0x309c is a gate", "reverser": "0x309c not read"},
                [],
                isr_reports={"static": _claiming("static"), "reverser": _claiming("reverser")},
            )
        )

    assert argument.status == "complete"
    assert consensus is True
    tools = {entry.tool: entry for entry in judge.drain_evidence_entries()}
    assert tools["ask_reverser"].agent == "judge"
    assert tools["decompile"].agent == "reverser"
    assert container.events


class TestTheSettingsRefuseWhatStaysRefused:
    def test_a_reporter_that_asks_another_agent_is_refused(self) -> None:
        from maljan.core.config import AgentDefinition, ToolRef, agent_reference_problems

        definitions = Settings(_env_file=None).agents.definitions
        reporter = AgentDefinition(role="report", tools=[ToolRef(kind="agent", agent="static")])

        assert agent_reference_problems("reporter", reporter, definitions) == [
            "a report definition cannot ask other agents"
        ]

    def test_no_definition_may_ask_the_judge(self) -> None:
        from maljan.core.config import AgentDefinition, ToolRef, agent_reference_problems

        definitions = Settings(_env_file=None).agents.definitions
        asker = AgentDefinition(
            role="generic", prompt="p", tools=[ToolRef(kind="agent", agent="judge")]
        )

        assert agent_reference_problems("asker", asker, definitions) == [
            "'judge' has role 'judge' and cannot be asked"
        ]
