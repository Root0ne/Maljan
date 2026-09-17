"""One agent asks another through ``ask_<key>``, inside the same machinery as any tool.

Driven through the real loop where it matters: a scripted model makes the
caller call ``ask_helper``, the helper's own scripted model calls a tool of its
own and answers with claims, and what is checked is what came out the other
side — the ledger, the budget, the two transcript lines and the answer text
the caller read. The guards are checked on their own, since each is a refusal
before anything runs.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool

from maljan.agents.base_agent import BudgetCeiling, LoopBudget
from maljan.agents.composition import ResolvedAgent
from maljan.agents.configurable_analyst import ConfigurableAnalyst
from maljan.agents.delegation import (
    TEAM_SERVER,
    DelegationRefused,
    ask,
    ask_tool,
    refusal,
    tool_name,
)
from maljan.core.config import Settings
from maljan.schemas.evidence import EvidenceCounter

HELPER_REPORT = (
    "CLAIM: the sample opens a raw socket\nEVIDENCE: ev_0001\nCONFIDENCE: 0.7\nTECHNIQUE: T1095\n"
)
BOSS_REPORT = (
    "CLAIM: the helper saw a raw socket\n"
    "EVIDENCE: ev_0001, ev_0002\n"
    "CONFIDENCE: 0.6\n"
    "TECHNIQUE: T1095\n"
)


class _Scripted(BaseChatModel):
    """Answers each model turn from a script: a tool call, then a report."""

    script: list[Any]
    seen: list[list[Any]] = []

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any):
        self.seen.append(list(messages))
        answer = self.script.pop(0) if self.script else AIMessage(content="")
        return ChatResult(generations=[ChatGeneration(message=answer)])

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


def _call(name: str, args: dict[str, Any], call_id: str) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": call_id}])


def _settings(**over: Any) -> Settings:
    definitions = {
        "boss": {
            "role": "lead",
            "prompt": "You lead.",
            "tools": [{"kind": "agent", "agent": "helper"}],
        },
        "helper": {
            "role": "generic",
            "prompt": "You help.",
            "tools": [{"kind": "agent", "agent": "third"}],
        },
        "third": {"role": "generic", "prompt": "You are third."},
        "sleeper": {"role": "generic", "prompt": "You sleep.", "enabled": False},
    }
    definitions.update(over.pop("definitions", {}))
    return Settings(
        _env_file=None,
        agents={
            "definitions": definitions,
            "profiles": {"led": {"stages": _stages()}},
            "profile": "led",
            **over,
        },
    )


def _stages() -> list[dict[str, Any]]:
    return [
        {"key": "lead", "kind": "analysis", "agents": ["boss"]},
        {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": ["lead"]},
    ]


class _Container:
    """A job's container, reduced to what an ask needs of it.

    Every agent is a ``ConfigurableAnalyst`` over the definition's prompt, the
    tools handed in here and the ``ask_<key>`` tools its definition asks for;
    the instances are cached per key, the counter is shared, and the sink
    records every event.
    """

    def __init__(self, settings: Settings, models: dict[str, Any], tools: dict[str, list[Any]]):
        self.config = settings
        self.models = models
        self.extra_tools = tools
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.event_sink = lambda kind, payload: self.events.append((kind, payload))
        self._agents: dict[str, Any] = {}
        self._counter = EvidenceCounter()
        self._lock = threading.Lock()

    def agent_role(self, key: str) -> str:
        return str(self.config.agents.definitions[key].role)

    def get_agent(self, key: str) -> Any:
        with self._lock:
            if key in self._agents:
                return self._agents[key]
            definition = self.config.agents.definitions[key]
            tools = [
                *self.extra_tools.get(key, []),
                *[
                    ask_tool(self, key, str(ref.agent))
                    for ref in definition.tools
                    if ref.kind == "agent"
                ],
            ]
            resolved = ResolvedAgent(
                key=key,
                role=str(definition.role),
                prompt=str(definition.prompt),
                tools=tools,
                static_provider_id="none",
                llm=None,
            )
            agent = ConfigurableAnalyst(key, resolved, self.models.get(key))
            agent.evidence_counter = self._counter
            agent._container = self
            agent._job_id = "job"
            self._agents[key] = agent
            return agent


def _peek_tool() -> StructuredTool:
    def peek(path: str) -> dict[str, Any]:
        """Look at the sample."""
        return {"socket": "raw", "path": path}

    return StructuredTool.from_function(func=peek, name="peek", description="peek")


def _team(boss_script: list[Any], helper_script: list[Any]) -> _Container:
    return _Container(
        _settings(),
        models={"boss": _Scripted(script=boss_script), "helper": _Scripted(script=helper_script)},
        tools={"helper": [_peek_tool()]},
    )


def _run_boss(container: _Container) -> Any:
    boss = container.get_agent("boss")
    boss.pipeline_stage = "lead"
    boss.facts_block = (
        "Facts established before analysis (ledger ids in brackets; cite them)\n[ev_0000] x"
    )
    boss.run_state_block = "sample: s"
    boss._analysis_file_path = "/samples/s.bin"
    boss.sample_path_choices = {"by_provider": {}, "static": None, "host": "/samples/s.bin"}
    return boss.safe_analyze_isr("Lead this analysis.")


@pytest.fixture
def team() -> _Container:
    return _team(
        boss_script=[
            _call(
                tool_name("helper"),
                {"task": "Does it open a socket?", "context": "See the pack."},
                "ask_1",
            ),
            AIMessage(content=BOSS_REPORT),
        ],
        helper_script=[
            _call("peek", {"path": "/samples/s.bin"}, "peek_1"),
            AIMessage(content=HELPER_REPORT),
        ],
    )


class TestTheToolIsBoundWhereTheDefinitionAsks:
    def test_the_caller_has_the_tool_and_the_callee_does_not_have_one_back(self, team) -> None:
        assert tool_name("helper") in [t.name for t in team.get_agent("boss").tools]
        assert tool_name("boss") not in [t.name for t in team.get_agent("helper").tools]

    def test_the_tool_is_described_from_the_callee_and_takes_a_task(self, team) -> None:
        tool = next(t for t in team.get_agent("boss").tools if t.name == "ask_helper")
        assert "helper" in tool.description and "role generic" in tool.description
        fields = tool.args_schema.model_fields
        assert fields["task"].is_required()
        assert not fields["context"].is_required()
        assert tool.metadata["maljan_server"] == TEAM_SERVER


class TestAnAskThroughTheRealLoop:
    def test_the_caller_reads_the_callee_s_claims_verbatim(self, team) -> None:
        isr = _run_boss(team)
        boss_model = team.models["boss"]
        # The second model turn of the boss saw the tool result: the helper's
        # ISR text, stamped with the ask's own ledger id.
        tool_result = next(
            str(m.content) for m in boss_model.seen[1] if getattr(m, "type", "") == "tool"
        )
        helper_isr = team.get_agent("helper")
        assert tool_result.startswith("[ev_0002]\n")
        assert "[HELPER ANALYST — round 0]" in tool_result
        assert "Claim 1: the sample opens a raw socket (T1095) | Evidence: ev_0001" in tool_result
        assert helper_isr is not None
        assert [c.technique_id for c in isr.claims] == ["T1095"]

    def test_the_ledger_holds_the_callee_s_calls_and_the_ask_under_team(self, team) -> None:
        _run_boss(team)
        entries = team.get_agent("boss").drain_evidence_entries()
        by_id = {e.id: e for e in entries}
        assert by_id["ev_0001"].agent == "helper"
        assert by_id["ev_0001"].tool == "peek"
        assert by_id["ev_0001"].stage == "lead"
        ask_entry = by_id["ev_0002"]
        assert ask_entry.agent == "boss"
        assert ask_entry.server == TEAM_SERVER
        assert ask_entry.tool == "ask_helper"
        assert ask_entry.args == {"task": "Does it open a socket?", "context": "See the pack."}
        assert ask_entry.ok is True
        assert "Claim 1: the sample opens a raw socket" in ask_entry.output
        assert ask_entry.duration_ms >= 0
        # Nothing is left on the callee: one node writes it all.
        assert team.get_agent("helper").drain_evidence_entries() == []

    def test_the_two_transcript_lines_say_who_asked_whom(self, team) -> None:
        _run_boss(team)
        messages = [payload for kind, payload in team.events if kind == "agent_message"]
        asked = next(m for m in messages if m.get("addressed_to") == "helper")
        answered = next(m for m in messages if m.get("addressed_to") == "boss")
        assert asked["speaker"] == "boss" and asked["text"] == "Does it open a socket?"
        assert asked["report"] == "See the pack."
        assert asked["stage"] == "lead" and asked["round"] == 0
        assert answered["speaker"] == "helper" and answered["stage"] == "lead"
        assert answered["status"] == "complete"
        assert answered["claims"][0]["technique_id"] == "T1095"
        assert "Claim 1: the sample opens a raw socket" in answered["report"]
        assert messages.index(asked) < messages.index(answered)

    def test_the_callee_is_framed_like_a_stage_agent(self, team) -> None:
        _run_boss(team)
        first_turn = team.models["helper"].seen[0]
        system = str(first_turn[0].content)
        human = next(str(m.content) for m in first_turn if getattr(m, "type", "") == "human")
        assert system.startswith("You help.")
        assert "sample: s" in system
        assert human.startswith("Facts established before analysis")
        assert "Sample path (use exactly this string" in human
        assert "/samples/s.bin" in human
        assert "Task from boss:\nDoes it open a socket?" in human
        assert "Context from boss:\nSee the pack." in human
        assert "CLAIM:" in human

    def test_the_callee_s_turns_come_off_the_caller_s_budget(self, team) -> None:
        boss = team.get_agent("boss")
        charged: list[int] = []
        original = LoopBudget.charge

        def _charge(self: LoopBudget, steps: int) -> None:
            charged.append(int(steps))
            original(self, steps)

        LoopBudget.charge = _charge  # type: ignore[method-assign]
        try:
            _run_boss(team)
        finally:
            LoopBudget.charge = original  # type: ignore[method-assign]
        # The helper spent one tool round and one plain turn: three steps.
        assert charged == [3]
        assert boss.steps_spent == 3 + 3

    def test_the_callee_never_gets_more_than_the_caller_had_left(self) -> None:
        seen: list[tuple[int, int]] = []
        container = _team(
            boss_script=[
                _call(tool_name("helper"), {"task": "t"}, "ask_1"),
                AIMessage(content=BOSS_REPORT),
            ],
            helper_script=[AIMessage(content=HELPER_REPORT)],
        )
        helper = container.get_agent("helper")
        original = helper._loop_limits

        def _limits() -> tuple[int, int]:
            limits = original()
            seen.append(limits)
            return limits

        helper._loop_limits = _limits  # type: ignore[method-assign]
        _run_boss(container)
        timeout, steps = seen[0]
        # The boss had ten steps and 180 s; the ask happens on its second
        # step, and the callee's clock is what the caller has left, less the
        # margin the caller keeps to read the answer.
        assert steps <= 8
        assert timeout <= 180 - 15


class TestTheGuards:
    def _boss(self, container: _Container, chain: tuple[str, ...] = ()) -> Any:
        boss = container.get_agent("boss")
        boss.call_chain = chain
        return boss

    def test_an_unknown_agent_is_refused_by_name(self) -> None:
        container = _team([], [])
        why = refusal(container, self._boss(container), "nobody")
        assert why is not None and "no agent named 'nobody'" in why

    def test_a_disabled_agent_is_refused_and_the_message_says_so(self) -> None:
        container = _team([], [])
        why = refusal(container, self._boss(container), "sleeper")
        assert why is not None and "'sleeper' is disabled" in why

    def test_a_callee_may_not_ask_anyone_already_waiting_on_it(self) -> None:
        container = _team([], [])
        helper = container.get_agent("helper")
        helper.call_chain = ("boss",)
        why = refusal(container, helper, "boss")
        assert why is not None and "cycle" in why and "boss -> helper -> boss" in why

    def test_an_agent_may_not_ask_itself(self) -> None:
        container = _team([], [])
        why = refusal(container, self._boss(container), "boss")
        assert why is not None and "cycle" in why

    def test_the_depth_limit_counts_the_chain(self) -> None:
        """Two callers above an agent make its own ask the third level."""
        container = _team([], [])
        third = container.get_agent("third")
        third.call_chain = ("boss", "helper")
        container.config.agents.definitions["fourth"] = container.config.agents.definitions["third"]
        why = refusal(container, third, "fourth")
        assert why is not None and "delegation depth of 2" in why
        assert "boss -> helper -> third" in why

    def test_the_second_level_is_within_the_default_depth(self) -> None:
        container = _team([], [])
        helper = container.get_agent("helper")
        helper.call_chain = ("boss",)
        assert refusal(container, helper, "third") is None

    def test_a_deeper_limit_lets_the_same_ask_through(self) -> None:
        container = _Container(
            _settings(delegation_depth=3),
            models={},
            tools={},
        )
        third = container.get_agent("third")
        third.call_chain = ("boss", "helper")
        container.config.agents.definitions["fourth"] = container.config.agents.definitions["third"]
        assert refusal(container, third, "fourth") is None

    def test_a_caller_with_no_budget_left_is_told_to_answer(self) -> None:
        container = _team([], [])
        boss = self._boss(container)
        boss.loop_budget = LoopBudget(max_steps=10, timeout=20.0)
        why = refusal(container, boss, "helper")
        assert why is not None and "not enough budget" in why

    def test_a_refusal_reaches_the_model_as_a_failed_tool_call(self) -> None:
        container = _team([], [])
        with pytest.raises(DelegationRefused, match="no agent named"):
            ask(container, caller_key="boss", callee_key="nobody", task="t")


class TestTheCeiling:
    def test_it_caps_both_dimensions_and_never_below_a_first_turn(self) -> None:
        container = _team([], [])
        helper = container.get_agent("helper")
        helper._budget_ceiling = BudgetCeiling(steps=1, seconds=0.5)
        timeout, steps = helper._loop_limits()
        assert (timeout, steps) == (1, 2)
        helper._budget_ceiling = BudgetCeiling(steps=1000, seconds=100000.0)
        timeout, steps = helper._loop_limits()
        assert timeout <= 180 and steps <= 10


class TestTheLoopBudget:
    def test_delegated_steps_shrink_the_turns_the_caller_is_told(self) -> None:
        from langchain_core.messages import HumanMessage

        budget = LoopBudget(max_steps=10, timeout=100.0)
        assert budget.turns_left([HumanMessage(content="t")]) == 5
        budget.charge(4)
        assert budget.turns_left([HumanMessage(content="t")]) == 3
        assert budget.steps_left() == 6
        assert budget.spent_by_delegates() is False
        budget.charge(6)
        assert budget.spent_by_delegates() is True

    def test_nothing_delegated_never_ends_a_loop_early(self) -> None:
        budget = LoopBudget(max_steps=2, timeout=100.0)
        budget.own_steps = 2
        assert budget.steps_left() == 0
        assert budget.spent_by_delegates() is False


class TestTheNodeBriefsALeadLikeAStaticAgent:
    def test_the_lead_role_is_sample_fed_and_keeps_the_path_choices(self) -> None:
        from maljan.pipeline.nodes import SAMPLE_FED_ROLES, _pin_sample_path

        assert "lead" in SAMPLE_FED_ROLES and "generic" in SAMPLE_FED_ROLES
        container = _team([], [])
        boss = container.get_agent("boss")
        state = {
            "static_sample_paths": {"ghidra": "/mirror/ghidra/s.bin"},
            "static_sample_path": "/mirror/s.bin",
            "sample_path": None,
            "file_hash": "abc",
        }
        _pin_sample_path(boss, state)
        assert boss._analysis_file_path == "/mirror/s.bin"
        assert boss.sample_path_choices["by_provider"] == {"ghidra": "/mirror/ghidra/s.bin"}
        assert boss.sample_path_choices["static"] == "/mirror/s.bin"

    def test_a_callee_opens_its_own_provider_s_mirror(self) -> None:
        from maljan.agents.delegation import _brief_callee

        container = _team([], [])
        boss = container.get_agent("boss")
        helper = container.get_agent("helper")
        boss.sample_path_choices = {
            "by_provider": {"none": "/mirror/none/s.bin", "ghidra": "/mirror/ghidra/s.bin"},
            "static": "/mirror/s.bin",
            "host": "/host/s.bin",
        }
        boss.call_chain = ("top",)
        _brief_callee(boss, helper, stage="lead", round_index=2)
        assert helper._analysis_file_path == "/mirror/none/s.bin"
        assert helper.call_chain == ("top", "boss")
        assert helper.current_round == 2 and helper.pipeline_stage == "lead"
