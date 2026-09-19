"""One agent asks another through ``ask_<key>``, inside the same machinery as any tool.

Driven through the real loop where it matters: a scripted model makes the
caller call ``ask_helper``, the helper's own scripted model calls a tool of its
own and answers with claims, and what is checked is what came out the other
side — the ledger, the budget, the two transcript lines and the answer text
the caller read. The guards are checked on their own, since each is a refusal
before anything runs.
"""

from __future__ import annotations

import contextlib
import threading
from typing import Any
from unittest import mock

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool

from maljan.agents import delegation
from maljan.agents.base_agent import BudgetCeiling, LoopBudget
from maljan.agents.composition import ResolvedAgent
from maljan.agents.configurable_analyst import ConfigurableAnalyst
from maljan.agents.delegation import (
    TEAM_SERVER,
    DelegationRefused,
    _brief_callee,
    ask,
    ask_budget,
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
        # A script entry that is an exception is a model turn that failed, so
        # a callee that cannot answer is driven the same way as one that can.
        if isinstance(answer, BaseException):
            raise answer
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

    def test_the_callee_s_artifacts_travel_with_its_ledger(self) -> None:
        """Only the text crosses back to the model; the structured channel needs carrying."""
        helper_answer = (
            "```maljan-findings\n"
            '{"findings": [{"title": "raw socket", "evidence_ids": ["ev_0001"]}], '
            '"artifacts": [{"kind": "endpoints", "value": "1.2.3.4:443", '
            '"evidence_ids": ["ev_0001"]}]}\n'
            "```\n" + HELPER_REPORT
        )
        container = _team(
            boss_script=[
                _call(tool_name("helper"), {"task": "Where does it call?"}, "ask_1"),
                AIMessage(content=BOSS_REPORT),
            ],
            helper_script=[
                _call("peek", {"path": "/samples/s.bin"}, "peek_1"),
                AIMessage(content=helper_answer),
            ],
        )

        isr = _run_boss(container)

        assert [artifact.value for artifact in isr.artifacts] == ["1.2.3.4:443"]
        assert [artifact.source for artifact in isr.artifacts] == ["helper"]
        assert [finding.title for finding in isr.findings] == ["raw socket"]

    def test_the_ask_leaves_nothing_of_the_caller_s_on_the_callee(self, team) -> None:
        """A callee that runs its own stage later must not still be pinned to the caller's."""
        helper = team.get_agent("helper")
        helper.pipeline_stage = "specialists"
        helper._analysis_file_path = "/its/own/s.bin"
        helper.facts_block = "its own pack"

        _run_boss(team)

        assert helper.pipeline_stage == "specialists"
        assert helper._analysis_file_path == "/its/own/s.bin"
        assert helper.facts_block == "its own pack"
        assert helper.call_chain == ()

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

    def test_the_two_lines_carry_the_kinds_the_console_draws_as_an_arrow(self, team) -> None:
        _run_boss(team)
        messages = [payload for kind, payload in team.events if kind == "agent_message"]
        asked = next(m for m in messages if m.get("addressed_to") == "helper")
        answered = next(m for m in messages if m.get("addressed_to") == "boss")
        assert asked["kind"] == "delegation_ask"
        assert answered["kind"] == "delegation_answer"
        # The label an operator gave, so a reader who cannot open the admin
        # settings still sees a name rather than a registry key.
        assert asked["display_name"] == "boss"
        assert answered["display_name"] == "helper"

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

    def test_the_callee_s_turns_are_noted_and_not_charged(self, team) -> None:
        """The caller's step budget is its own; the specialists' are theirs.

        Sharing one count starved both: the live proof watched the first
        callee die at a recursion limit of five and the lead's third ask
        refused with three steps left.
        """
        boss = team.get_agent("boss")
        noted: list[int] = []
        original = LoopBudget.note_delegated

        def _note(self: LoopBudget, steps: int) -> None:
            noted.append(int(steps))
            original(self, steps)

        LoopBudget.note_delegated = _note  # type: ignore[method-assign]
        try:
            _run_boss(team)
        finally:
            LoopBudget.note_delegated = original  # type: ignore[method-assign]
        # The helper spent one tool round and one plain turn: three steps.
        assert noted == [3]
        # The boss's own conversation is three steps too, and the helper's are
        # not added to them: they come out of the helper's cap and are filed
        # under the helper.
        assert boss.steps_spent == 3

    def test_the_callee_s_steps_come_from_the_delegation_and_not_the_caller(self) -> None:
        seen: list[tuple[int, int]] = []
        container = _team(
            boss_script=[
                _call(tool_name("helper"), {"task": "t"}, "ask_1"),
                AIMessage(content=BOSS_REPORT),
            ],
            helper_script=[AIMessage(content=HELPER_REPORT)],
        )
        steps, seconds = ask_budget(container)
        helper = container.get_agent("helper")
        original = helper._loop_limits

        def _limits() -> tuple[int, int]:
            limits = original()
            seen.append(limits)
            return limits

        helper._loop_limits = _limits  # type: ignore[method-assign]
        _run_boss(container)
        timeout, allowed = seen[0]
        # The boss had ten steps and 180 s. The callee gets the delegation's
        # twelve whatever the caller has left, and a clock that is the per-ask
        # timeout or what the caller has left, whichever is shorter.
        assert allowed == steps == 12
        assert timeout <= 180 - 15 and timeout <= seconds

    def test_a_short_caller_clock_still_cuts_the_ask(self) -> None:
        from maljan.agents.delegation import _what_this_ask_gets

        container = _team([], [])
        budget = LoopBudget(max_steps=10, timeout=60.0)

        ceiling = _what_this_ask_gets(container, budget)

        assert ceiling.steps == 12, "the steps are the delegation's, whole"
        assert 1 <= ceiling.seconds <= 60 - 15 + 1


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

    def test_a_caller_with_no_time_left_is_told_to_answer(self) -> None:
        container = _team([], [])
        boss = self._boss(container)
        boss.loop_budget = LoopBudget(max_steps=10, timeout=20.0)
        why = refusal(container, boss, "helper")
        assert why is not None and "not enough time" in why

    def test_a_caller_with_no_steps_left_may_still_ask(self) -> None:
        """An ask has a step budget of its own, so the caller's say nothing."""
        container = _team([], [])
        boss = self._boss(container)
        boss.loop_budget = LoopBudget(max_steps=10, timeout=3600.0)
        boss.loop_budget.own_steps = 10

        assert boss.loop_budget.steps_left() == 0
        assert refusal(container, boss, "helper") is None

    def test_the_refusal_is_raised_before_the_callee_is_touched(self) -> None:
        container = _team([], [])
        with pytest.raises(DelegationRefused, match="no agent named"):
            ask(container, caller_key="boss", callee_key="nobody", task="t")

    def test_a_refusal_reaches_the_model_as_one_failed_ledger_entry(self) -> None:
        """What the model reads is the recorder's, not an exception the loop survives."""
        from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools

        container = _team([], [])
        recorder = EvidenceRecorder("boss", stage="lead")
        tool = record_tools([ask_tool(container, "boss", "nobody")], recorder)[0]

        answer = tool.invoke({"task": "Have a look."})

        assert len(recorder.entries) == 1
        entry = recorder.entries[0]
        assert entry.ok is False and entry.server == TEAM_SERVER
        assert entry.tool == tool_name("nobody")
        assert "no agent named 'nobody'" in str(entry.error)
        assert entry.id in answer and "no agent named 'nobody'" in answer

    def test_an_ask_cannot_reach_a_server_the_asking_stage_withholds(self) -> None:
        """A stage told to read what it was handed cannot go looking through a colleague."""
        container = _Container(
            _settings(
                definitions={
                    "helper": {
                        "role": "generic",
                        "prompt": "You help.",
                        "tools": [{"kind": "mcp", "server": "knowledge"}],
                    }
                },
                profiles={
                    "led": {
                        "stages": [
                            {
                                "key": "lead",
                                "kind": "analysis",
                                "agents": ["boss"],
                                "builtin_tools": False,
                            },
                            {
                                "key": "verdict",
                                "kind": "verdict",
                                "agents": ["judge"],
                                "depends_on": ["lead"],
                            },
                        ]
                    }
                },
            ),
            models={},
            tools={},
        )

        why = refusal(container, container.get_agent("boss"), "helper")

        assert why is not None and "knowledge" in why and "stage 'lead'" in why

    def test_a_callee_in_the_same_withholding_stage_is_still_askable(self) -> None:
        """Its own stage already took those servers off it, so nothing is widened."""
        container = _Container(
            _settings(
                definitions={
                    "helper": {
                        "role": "generic",
                        "prompt": "You help.",
                        "tools": [{"kind": "mcp", "server": "knowledge"}],
                    }
                },
                profiles={
                    "led": {
                        "stages": [
                            {
                                "key": "lead",
                                "kind": "analysis",
                                "agents": ["boss", "helper"],
                                "builtin_tools": False,
                            },
                            {
                                "key": "verdict",
                                "kind": "verdict",
                                "agents": ["judge"],
                                "depends_on": ["lead"],
                            },
                        ]
                    }
                },
            ),
            models={},
            tools={},
        )

        assert refusal(container, container.get_agent("boss"), "helper") is None

    def test_the_asking_stage_s_policy_holds_for_the_ask_that_ask_makes(self) -> None:
        """A callee that no stage names withholds nothing of its own.

        Without carrying the policy down, it would hold for the first ask and
        lapse for the one that ask makes in turn.
        """
        container = _Container(
            _settings(
                definitions={
                    "third": {
                        "role": "generic",
                        "prompt": "You are third.",
                        "tools": [{"kind": "mcp", "server": "knowledge"}],
                    }
                },
                profiles={
                    "led": {
                        "stages": [
                            {
                                "key": "lead",
                                "kind": "analysis",
                                "agents": ["boss"],
                                "builtin_tools": False,
                            },
                            {
                                "key": "verdict",
                                "kind": "verdict",
                                "agents": ["judge"],
                                "depends_on": ["lead"],
                            },
                        ]
                    }
                },
            ),
            models={},
            tools={},
        )
        boss = container.get_agent("boss")
        boss.pipeline_stage = "lead"
        helper = container.get_agent("helper")
        _brief_callee(boss, helper, stage="lead", round_index=0)

        why = refusal(container, helper, "third")

        assert why is not None and "knowledge" in why

    def test_an_ask_cannot_reach_a_server_the_callee_is_bound_to_by_the_server_map(
        self,
    ) -> None:
        """The other binding mechanism, and the one the built-ins actually use.

        A definition's ``ToolRef(kind="mcp")`` is one way an agent reaches a
        server; ``core.mcp.servers.<key>.agents`` naming the agent is the
        other, and it is how the default map binds ``network``,
        ``threatintel`` and the rest. A guard that read only the first said a
        stage-less specialist brought nothing, so a stage told to read what it
        was handed reached every built-in server through it.
        """
        container = _Container(
            _settings(
                definitions={
                    "helper": {"role": "generic", "prompt": "You help.", "tools": []},
                },
                profiles={
                    "led": {
                        "stages": [
                            {
                                "key": "lead",
                                "kind": "analysis",
                                "agents": ["boss"],
                                "builtin_tools": False,
                            },
                            {
                                "key": "verdict",
                                "kind": "verdict",
                                "agents": ["judge"],
                                "depends_on": ["lead"],
                            },
                        ]
                    }
                },
            ),
            models={},
            tools={},
        )
        container.config.mcp.servers["knowledge"].agents = ["helper"]

        why = refusal(container, container.get_agent("boss"), "helper")

        assert why is not None and "knowledge" in why and "stage 'lead'" in why

    def test_a_server_the_map_binds_to_a_disabled_server_is_not_brought(self) -> None:
        """A server that is off brings nothing, so it is nothing to refuse over."""
        container = _Container(
            _settings(
                definitions={
                    "helper": {"role": "generic", "prompt": "You help.", "tools": []},
                },
                profiles={
                    "led": {
                        "stages": [
                            {
                                "key": "lead",
                                "kind": "analysis",
                                "agents": ["boss"],
                                "builtin_tools": False,
                            },
                            {
                                "key": "verdict",
                                "kind": "verdict",
                                "agents": ["judge"],
                                "depends_on": ["lead"],
                            },
                        ]
                    }
                },
            ),
            models={},
            tools={},
        )
        container.config.mcp.servers["knowledge"].agents = ["helper"]
        container.config.mcp.servers["knowledge"].enabled = False

        assert refusal(container, container.get_agent("boss"), "helper") is None

    def test_a_profile_with_nothing_to_call_binds_no_ask_tool(self) -> None:
        """``exclude_servers: ['*']`` is the tool-free baseline, delegation included."""
        from maljan.agents.composition import _agent_tools

        container = _Container(
            _settings(profiles={"led": {"stages": _stages(), "exclude_servers": ["*"]}}),
            models={},
            tools={},
        )
        definition = container.config.agents.definitions["boss"]

        assert _agent_tools(container, definition, "boss") == []


class TestTheCeiling:
    def test_it_replaces_the_agent_s_own_limits_and_never_goes_below_a_first_turn(self) -> None:
        """A callee answering an ask spends the delegation's budget, not its stage's."""
        container = _team([], [])
        helper = container.get_agent("helper")
        helper._budget_ceiling = BudgetCeiling(steps=1, seconds=0.5)
        assert helper._loop_limits() == (1, 2)
        helper._budget_ceiling = BudgetCeiling(steps=12, seconds=300.0)
        assert helper._loop_limits() == (300, 12)

    def test_the_seeded_lead_has_room_for_several_asks(self) -> None:
        from maljan.core.config import Settings

        seeded = Settings(_env_file=None)
        lead = seeded.agents.definitions["lead"]

        assert lead.max_steps == 40
        assert seeded.agents.delegation_steps == 12
        assert seeded.agents.delegation_timeout_seconds == 300
        fits = lead.timeout_seconds // seeded.agents.delegation_timeout_seconds
        assert fits >= 5, "a lead's stage holds several asks end to end"

    def test_the_lead_carries_its_budget_where_a_clone_of_it_would(self) -> None:
        """The budget travels with the definition, not with the agent's name.

        It used to sit in two maps keyed by agent name, away from the card an
        operator edits, so a clone of the lead arrived with five specialists
        to ask and the deployment's default ten steps to do it in.
        """
        from maljan.core.config import Settings

        seeded = Settings(_env_file=None)

        assert "lead" not in seeded.react_agent_max_steps_overrides
        assert "lead" not in seeded.react_agent_timeout_overrides

    def test_the_lead_prompt_and_the_ask_tool_say_the_same_thing(self, team) -> None:
        """The prompt the lead reads first must not contradict its own tools.

        A prompt that says the specialists' turns are the lead's is the belief
        that makes a lead stop asking and close with no techniques, whatever
        the budget underneath it does.
        """
        from maljan.agents.prompts import LEAD_PROMPT

        described = next(
            t for t in team.get_agent("boss").tools if t.name == tool_name("helper")
        ).description

        assert "budget of its own" in LEAD_PROMPT
        assert "are not yours" in LEAD_PROMPT, "a specialist's steps are its own"
        assert "costs you is time" in LEAD_PROMPT, "the wall clock is what an ask costs"
        assert "shared with the specialists" not in LEAD_PROMPT
        assert "do not come out of your step budget" in described

    def test_the_ask_tool_tells_the_model_what_an_ask_costs(self, team) -> None:
        described = next(
            t for t in team.get_agent("boss").tools if t.name == tool_name("helper")
        ).description

        assert "12 steps" in described and "300 s" in described
        assert "do not come out of your step budget" in described


class TestACalleeAtItsCapWritesUpWhatItHas:
    def test_the_graph_s_own_limit_becomes_a_synthesis_and_not_an_error(self) -> None:
        """The live proof watched a callee die at a recursion limit of five.

        A recursion error is not something a model can read, and the evidence
        the callee gathered before it is the whole of what the ask bought.
        """
        peeks = [_call("peek", {"path": f"/samples/{n}.bin"}, f"peek_{n}") for n in range(8)]
        container = _team(
            boss_script=[
                _call(tool_name("helper"), {"task": "Look at everything."}, "ask_1"),
                AIMessage(content=BOSS_REPORT),
            ],
            helper_script=peeks,
        )
        container.config.agents.delegation_steps = 4

        isr = _run_boss(container)

        # The caller read an answer rather than a tool failure, and the
        # callee's calls are on the record.
        entries = container.get_agent("boss")._evidence_entries
        assert [e.tool for e in entries if e.agent == "helper"], "its calls were kept"
        ask_entry = next(e for e in entries if e.server == TEAM_SERVER)
        assert ask_entry.ok is True, "the ask answered rather than raising"
        assert isr is not None

    def test_a_callee_s_recursion_limit_is_the_delegation_s_steps(self) -> None:
        from maljan.agents.delegation import _what_this_ask_gets

        container = _team([], [])
        container.config.agents.delegation_steps = 7

        assert _what_this_ask_gets(container, None).steps == 7


class TestOneAgentDoesOneThingAtATime:
    """The lock the job holds for each agent, taken by every path that drives it."""

    def _ask_from_a_thread(self, container: _Container, done: list[str]) -> threading.Thread:
        def _go() -> None:
            try:
                ask(container, caller_key="boss", callee_key="helper", task="Have a look.")
                done.append("answered")
            except DelegationRefused as refused:
                done.append(str(refused))

        thread = threading.Thread(target=_go, daemon=True)
        thread.start()
        return thread

    def _held_by_another_thread(self, agent: Any) -> tuple[threading.Event, threading.Thread]:
        """The agent's own-work lock, taken on a thread of its own."""
        return self._held_by_another_thread_on(agent.delegation_lock)

    def _held_by_another_thread_on(self, lock: Any) -> tuple[threading.Event, threading.Thread]:
        """``lock``, taken on a thread of its own and let go on demand."""
        taken, release = threading.Event(), threading.Event()

        def _hold() -> None:
            with lock:
                taken.set()
                release.wait(timeout=10)

        holder = threading.Thread(target=_hold, daemon=True)
        holder.start()
        assert taken.wait(timeout=5)
        return release, holder

    def test_an_ask_waits_while_the_callee_runs_its_own_stage(self) -> None:
        container = _team([], [])
        helper = container.get_agent("helper")
        done: list[str] = []

        release, holder = self._held_by_another_thread(helper)
        thread = self._ask_from_a_thread(container, done)
        thread.join(timeout=0.3)
        assert done == [], "the ask is waiting on the callee's own loop"

        release.set()
        holder.join(timeout=5)
        thread.join(timeout=5)
        assert done == ["answered"], "and is answered the moment the loop lets go"

    def test_the_callee_s_own_stage_waits_while_it_is_answering_an_ask(self) -> None:
        container = _team([], [])
        helper = container.get_agent("helper")
        release, holder = self._held_by_another_thread(helper)
        ran: list[str] = []

        def _stage() -> None:
            helper.analyze_isr = lambda data: ran.append(data) or None  # type: ignore[assignment]
            with contextlib.suppress(Exception):
                helper.safe_analyze_isr("its own stage")

        stage = threading.Thread(target=_stage, daemon=True)
        stage.start()
        stage.join(timeout=0.3)
        assert ran == [], "the stage run is waiting on the ask"
        release.set()
        stage.join(timeout=5)
        assert ran == ["its own stage"]

    def test_a_caller_s_second_ask_waits_for_its_first(self) -> None:
        """Two ``ask_*`` calls in one turn are gathered concurrently by langgraph.

        Two nested loops against one llama-server slot clobber its recurrent
        state and every step then re-processes the whole prompt, which is the
        timeout this project has already diagnosed once.
        """
        container = _team([], [])
        boss = container.get_agent("boss")
        release, holder = self._held_by_another_thread_on(boss.asks_lock)
        done: list[str] = []

        thread = self._ask_from_a_thread(container, done)
        thread.join(timeout=0.3)
        assert done == [], "the second ask is waiting on the first"

        release.set()
        holder.join(timeout=5)
        thread.join(timeout=5)
        assert done == ["answered"]

    def test_the_caller_s_lock_is_not_the_callee_s_so_an_ask_still_nests(self) -> None:
        container = _team([], [])
        boss, helper = container.get_agent("boss"), container.get_agent("helper")

        assert boss.asks_lock is not helper.asks_lock
        assert boss.asks_lock is not boss.delegation_lock

    def test_a_callee_that_never_frees_up_is_refused_in_words_the_model_reads(self) -> None:
        container = _team([], [])
        boss = container.get_agent("boss")
        boss.loop_budget = LoopBudget(max_steps=10, timeout=1000.0)
        helper = container.get_agent("helper")
        release, holder = self._held_by_another_thread(helper)

        try:
            with (
                mock.patch.object(delegation, "_seconds_to_wait_for", return_value=0.05),
                pytest.raises(DelegationRefused, match="busy with its own work"),
            ):
                ask(container, caller_key="boss", callee_key="helper", task="t")
        finally:
            release.set()
            holder.join(timeout=5)

    def test_the_wait_is_what_the_caller_can_spare(self) -> None:
        from maljan.agents.delegation import SECONDS_WAITING_OUTSIDE_A_LOOP, _seconds_to_wait_for

        container = _team([], [])
        boss = container.get_agent("boss")
        assert _seconds_to_wait_for(boss) == SECONDS_WAITING_OUTSIDE_A_LOOP
        boss.loop_budget = LoopBudget(max_steps=10, timeout=100.0)
        assert 80.0 < _seconds_to_wait_for(boss) <= 85.0
        boss.loop_budget = LoopBudget(max_steps=10, timeout=1.0)
        assert _seconds_to_wait_for(boss) == 1.0

    def test_a_chunked_stage_run_may_take_the_lock_it_already_holds(self) -> None:
        """One chunk enters through both wrappers; a plain lock would stop there."""
        container = _team([], [])
        helper = container.get_agent("helper")
        helper.analyze_isr = lambda data: None  # type: ignore[assignment]

        class _Chunk:
            content = "one chunk"

        with contextlib.suppress(Exception):
            helper.safe_analyze_isr_chunked([_Chunk()])


class TestACalleeNeverOutlivesItsCaller:
    def test_the_hard_cap_is_the_ceiling_when_the_ceiling_is_the_shorter(self) -> None:
        from maljan.agents.base_agent import hard_cap

        assert hard_cap(120.0) == 150.0
        assert hard_cap(45.0, BudgetCeiling(steps=4, seconds=45.7)) == 45.7
        assert hard_cap(120.0, BudgetCeiling(steps=4, seconds=1000.0)) == 150.0
        assert hard_cap(1.0, BudgetCeiling(steps=2, seconds=0.0)) == 1.0

    def test_a_caller_whose_loop_ended_is_not_given_the_record(self) -> None:
        """Its node has already drained it; appending now loses the entries or repeats them."""
        from maljan.agents.delegation import _hand_over_the_record
        from maljan.schemas.evidence import build_entry

        container = _team([], [])
        boss = container.get_agent("boss")
        helper = container.get_agent("helper")
        helper._evidence_entries = [
            build_entry(
                entry_id="ev_0001",
                seq=1,
                agent="helper",
                tool="peek",
                args={},
                server=None,
                output="{}",
            )
        ]
        helper.validation_findings = []
        helper.validation_retries = 2

        _hand_over_the_record(boss, helper, still_running=False)

        assert boss._evidence_entries == []
        assert boss.validation_retries == 0
        assert helper._evidence_entries == [], "the callee is drained either way"

    def test_a_callee_that_never_answers_leaves_the_caller_able_to_finish(self) -> None:
        container = _team(
            boss_script=[
                _call(tool_name("helper"), {"task": "Does it open a socket?"}, "ask_1"),
                AIMessage(content=BOSS_REPORT),
            ],
            helper_script=[TimeoutError("the model did not answer in time")],
        )

        isr = _run_boss(container)

        assert [claim.claim for claim in isr.claims] == ["the helper saw a raw socket"]
        failed = [entry for entry in container.get_agent("boss")._evidence_entries if not entry.ok]
        assert [entry.tool for entry in failed] == [tool_name("helper")]
        assert "TimeoutError" in str(failed[0].error), "the caller reads why the ask failed"

    def test_the_ask_hands_over_while_the_caller_is_still_in_its_loop(self, team) -> None:
        _run_boss(team)
        boss = team.get_agent("boss")

        assert [entry.agent for entry in boss._evidence_entries].count("helper") == 1


class TestTheLoopBudget:
    def test_delegated_steps_leave_the_caller_s_turns_where_they_were(self) -> None:
        """What a specialist spends is its own; the lead's line does not move."""
        from langchain_core.messages import HumanMessage

        budget = LoopBudget(max_steps=10, timeout=100.0)
        assert budget.turns_left([HumanMessage(content="t")]) == 5

        budget.note_delegated(4)

        assert budget.turns_left([HumanMessage(content="t")]) == 5
        assert budget.steps_left() == 10
        assert budget.delegated_steps == 4, "noted for the meter"

    def test_the_caller_s_own_turns_are_what_run_it_out(self) -> None:
        budget = LoopBudget(max_steps=2, timeout=100.0)
        budget.own_steps = 2
        assert budget.steps_left() == 0


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


class TestAHandedOverRowStaysWithinTheBound:
    """A chain of delegations prefixed a row once per level and bounded nothing.

    The rows a validator writes are held to eight hundred characters by the
    guard in ``tests/unit/pipeline``; a hand-over adds a name in front of one,
    and five levels of it wrote a row that limit does not describe. What is cut
    is the route, never the finding.
    """

    def test_one_level_reads_as_it_always_did(self) -> None:
        from maljan.agents.delegation import prefixed_within_the_bound

        assert prefixed_within_the_bound("the id cites no evidence", "scout") == (
            "scout: the id cites no evidence"
        )

    def test_a_chain_stays_under_the_limit(self) -> None:
        from maljan.agents.delegation import HANDED_OVER_LIMIT, prefixed_within_the_bound

        message = "the technique id cites no evidence id from this run. " * 12
        assert len(message) < HANDED_OVER_LIMIT
        for level in range(40):
            message = prefixed_within_the_bound(message, f"specialist_{level:02d}")
            assert len(message) <= HANDED_OVER_LIMIT

    def test_the_finding_s_own_sentence_survives_the_cut(self) -> None:
        from maljan.agents.delegation import prefixed_within_the_bound

        sentence = "the technique id cites no evidence id from this run. " * 12
        message = sentence
        for level in range(40):
            message = prefixed_within_the_bound(message, f"specialist_{level:02d}")

        assert message.endswith(sentence)

    def test_the_innermost_names_are_the_ones_kept(self) -> None:
        from maljan.agents.delegation import ELIDED_CHAIN, prefixed_within_the_bound

        sentence = "x" * 770
        message = sentence
        for name in ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot"):
            message = prefixed_within_the_bound(message, name)

        # ``alpha`` prefixed first, so it sits nearest the sentence and is the
        # agent that found the thing; ``foxtrot`` is the outermost caller.
        assert message.startswith(ELIDED_CHAIN)
        assert "alpha: " in message
        assert "foxtrot: " not in message

    def test_a_sentence_over_the_bound_is_never_cut(self) -> None:
        from maljan.agents.delegation import HANDED_OVER_LIMIT, prefixed_within_the_bound

        sentence = "y" * (HANDED_OVER_LIMIT + 50)

        assert prefixed_within_the_bound(sentence, "scout") == sentence

    def test_a_sentence_that_begins_like_a_name_is_not_read_as_one(self) -> None:
        from maljan.agents.delegation import prefixed_within_the_bound

        # A colon inside the finding's own words: the step pattern matches it,
        # which costs the chain room rather than cutting the sentence.
        message = prefixed_within_the_bound("TECHNIQUE: not in the catalogue", "scout")

        assert message.endswith("TECHNIQUE: not in the catalogue")
        assert message.startswith("scout: ")
