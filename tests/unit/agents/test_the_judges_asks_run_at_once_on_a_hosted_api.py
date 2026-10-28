"""The judge's asks run at once on a hosted API and one after the other on a local slot.

Two ``ask_*`` calls in one assistant turn are gathered by langgraph. Against
one llama-server slot two nested loops clobber its recurrent state, so a
caller's asks used to take its own lock and run one after the other whatever
served the asked agents. Where the asked agents' models serve concurrent
requests — a hosted API, as the job's analyst run mode reads it from each
provider's declared concurrency and ``llm.parallel_analysts`` — the judge's
asks now run at once. Each answer is still its own call's result, in the
order of the calls, and the asked agents' ledger entries are merged into the
judge's in ledger order, never in the order the asks finished.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.messages import AIMessage

from maljan.agents import delegation
from maljan.agents.delegation import (
    _hand_over_the_record,
    ask,
    ask_tool,
    asks_run_at_once,
    tool_name,
)
from maljan.core.config import Settings
from maljan.pipeline.analyst_mode import resolve_analyst_mode


def _config(provider: str, **llm: Any) -> Settings:
    definitions = {
        "reader": {"role": "generic", "prompt": "You read the code."},
        "looker": {"role": "generic", "prompt": "You look at the file."},
    }
    return Settings(
        _env_file=None,
        llm={"provider": provider, **llm},
        agents={
            "definitions": definitions,
            "profiles": {
                "team": {
                    "stages": [
                        {"key": "analysis", "kind": "analysis", "agents": ["reader", "looker"]},
                        {
                            "key": "verdict",
                            "kind": "verdict",
                            "agents": ["judge"],
                            "depends_on": ["analysis"],
                        },
                    ]
                }
            },
            "profile": "team",
        },
    )


class _Agent:
    """What an ask reads of an agent on either side of it."""

    def __init__(self, name: str, *, report_buffers: bool = False) -> None:
        self.name = name
        self.asks_lock = threading.Lock()
        self.delegation_lock = threading.Lock()
        self.evidence_lock = threading.Lock()
        self.loop_budget = None
        self.call_chain: tuple[str, ...] = ()
        self._evidence_entries: list[Any] = []
        self.handed: list[Any] = []
        self.validation_retries = 0
        self.validation_fed_back: dict[str, int] = {}
        self.validation_not_run: list[str] = []
        if report_buffers:
            self._artifacts_buffer: list[Any] = []

    def drain_evidence_entries(self) -> list[Any]:
        handed, self.handed = self.handed, []
        return handed

    def drain_validation_findings(self) -> tuple[list[Any], int, int]:
        return [], 0, {}

    def drain_validation_not_run(self) -> list[Any]:
        return []


class _Container:
    """A job's container, reduced to its settings, its agents and its run mode."""

    def __init__(
        self, provider: str, analysts: tuple[str, ...] = ("reader", "looker"), **llm: Any
    ) -> None:
        self.config = _config(provider, **llm)
        self.analysts = list(analysts)
        self.agents = {
            "judge": _Agent("judge"),
            "lead": _Agent("lead", report_buffers=True),
            "reader": _Agent("reader"),
            "looker": _Agent("looker"),
        }

    def get_agent(self, key: str) -> Any:
        return self.agents[key]

    def analyst_keys(self) -> list[str]:
        return list(self.analysts)

    def analyst_mode(self) -> Any:
        return resolve_analyst_mode(self.config, list(self.analysts), probe=False)


@pytest.fixture(autouse=True)
def _every_ask_may_be_made(monkeypatch: pytest.MonkeyPatch) -> Any:
    from maljan.llm import context_window

    context_window.forget_learned_windows()
    monkeypatch.setattr(delegation, "refusal", lambda container, caller, callee_key: None)
    yield
    context_window.forget_learned_windows()


class TestTheDecision:
    def test_a_hosted_provider_lets_the_judge_s_asks_run_at_once(self) -> None:
        container = _Container("anthropic")

        assert asks_run_at_once(container, container.agents["judge"], "reader") is True

    def test_a_runtime_that_serves_one_request_at_a_time_keeps_them_serial(self) -> None:
        container = _Container("ollama")

        assert asks_run_at_once(container, container.agents["judge"], "reader") is False

    def test_the_operator_s_setting_is_used_as_set(self) -> None:
        container = _Container("anthropic")
        container.config.llm.parallel_analysts = "false"

        assert asks_run_at_once(container, container.agents["judge"], "reader") is False

    def test_a_caller_that_merges_its_asks_into_its_own_report_keeps_them_serial(self) -> None:
        container = _Container("anthropic")

        assert asks_run_at_once(container, container.agents["lead"], "reader") is False

    def test_an_asked_specialist_is_read_by_its_own_models(self) -> None:
        hosted = _Container("anthropic", analysts=("looker",))
        local = _Container("ollama", analysts=("looker",))

        assert asks_run_at_once(hosted, hosted.agents["judge"], "reader") is True
        assert asks_run_at_once(local, local.agents["judge"], "reader") is False

    def test_the_operator_s_setting_never_speaks_for_a_specialist_s_own_models(self) -> None:
        """``parallel_analysts`` true runs the stages' analysts at once; a
        specialist on one local slot still keeps its asks serial."""
        on_ollama = _Container("ollama", analysts=("looker",), parallel_analysts="true")
        on_loopback = _Container(
            "openai",
            analysts=("looker",),
            parallel_analysts="true",
            openai={"base_url": "http://127.0.0.1:8080/v1"},
        )
        hosted = _Container("anthropic", analysts=("looker",), parallel_analysts="true")

        assert asks_run_at_once(on_ollama, on_ollama.agents["judge"], "reader") is False
        assert asks_run_at_once(on_loopback, on_loopback.agents["judge"], "reader") is False
        assert asks_run_at_once(hosted, hosted.agents["judge"], "reader") is True

    def test_a_loopback_endpoint_that_reports_no_slots_keeps_them_serial(self) -> None:
        container = _Container("openai", openai={"base_url": "http://127.0.0.1:8080/v1"})

        assert asks_run_at_once(container, container.agents["judge"], "reader") is False

    def test_a_specialist_s_models_are_read_once_per_job(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.pipeline import analyst_mode

        container = _Container("anthropic", analysts=("looker",))
        read = analyst_mode._auto_mode
        calls: list[str] = []

        def _counted(*args: Any, **kwargs: Any) -> Any:
            # The specialist's read, not the job's own run mode.
            if str(kwargs.get("nobody", "")).startswith("reader"):
                calls.append("read")
            return read(*args, **kwargs)

        monkeypatch.setattr(analyst_mode, "_auto_mode", _counted)
        for _ in range(3):
            assert asks_run_at_once(container, container.agents["judge"], "reader") is True

        assert calls == ["read"]

    def test_a_caller_with_no_lock_for_the_hand_over_keeps_them_serial(self) -> None:
        container = _Container("anthropic")
        judge = container.agents["judge"]
        judge.evidence_lock = None

        assert asks_run_at_once(container, judge, "reader") is False

    def test_a_container_with_no_run_mode_keeps_them_serial(self) -> None:
        container = SimpleNamespace(config=_config("anthropic"))

        assert asks_run_at_once(container, _Agent("judge"), "reader") is False


def _two_asks(container: _Container) -> list[str]:
    """The judge asks both analysts from two threads at once."""
    answers: dict[str, str] = {}

    def _go(callee: str) -> None:
        answers[callee] = ask(
            container, caller_key="judge", callee_key=callee, task="Read it.", caller=None
        )

    threads = [threading.Thread(target=_go, args=(key,), daemon=True) for key in container.analysts]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    return [answers.get(key, "") for key in container.analysts]


class TestTheAsksRun:
    def _both_inside(self, monkeypatch: pytest.MonkeyPatch, seconds: float) -> threading.Barrier:
        """An ask that answers only once both asks are running, or says it was alone."""
        started = threading.Barrier(2, timeout=seconds)

        def _answer(container: Any, caller: Any, callee: Any, task: str, context: str, **_: Any):
            try:
                started.wait()
            except threading.BrokenBarrierError:
                return f"{callee.name}: alone"
            return f"{callee.name}: together"

        monkeypatch.setattr(delegation, "_ask", _answer)
        return started

    def test_on_a_hosted_api_both_asks_run_at_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        container = _Container("anthropic")
        self._both_inside(monkeypatch, seconds=5)

        answers = _two_asks(container)

        assert answers == ["reader: together", "looker: together"]

    def test_on_a_local_slot_the_second_waits_for_the_first(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        container = _Container("ollama")
        self._both_inside(monkeypatch, seconds=0.5)

        answers = _two_asks(container)

        assert sorted(answers) == ["looker: alone", "reader: alone"]

    def test_answers_come_back_in_the_order_of_the_calls_whichever_finishes_first(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Through langgraph's own tool node: the first call's ask finishes last."""
        from langgraph.graph import END, START, MessagesState, StateGraph
        from langgraph.prebuilt import ToolNode

        container = _Container("anthropic")
        looker_done = threading.Event()
        finished: list[str] = []

        def _answer(container: Any, caller: Any, callee: Any, task: str, context: str, **_: Any):
            if callee.name == "reader":
                assert looker_done.wait(timeout=5), "the asks ran one after the other"
            finished.append(str(callee.name))
            if callee.name == "looker":
                looker_done.set()
            return f"{callee.name} answered {task}"

        monkeypatch.setattr(delegation, "_ask", _answer)
        judge = container.agents["judge"]
        tools = [ask_tool(container, "judge", key, caller=judge) for key in container.analysts]
        calls = [
            {"name": tool_name(key), "args": {"task": f"t{index}"}, "id": f"call_{index}"}
            for index, key in enumerate(container.analysts)
        ]

        graph = StateGraph(MessagesState)
        graph.add_node("tools", ToolNode(tools))
        graph.add_edge(START, "tools")
        graph.add_edge("tools", END)
        out = asyncio.run(
            graph.compile().ainvoke({"messages": [AIMessage(content="", tool_calls=calls)]})
        )

        assert finished == ["looker", "reader"]
        assert [(m.tool_call_id, m.content) for m in out["messages"][1:]] == [
            ("call_0", "reader answered t0"),
            ("call_1", "looker answered t1"),
        ]


# What the ask tool said on dev, every caller: kept byte for byte wherever
# the asks run one after the other.
DEV_DESCRIPTION = (
    "Ask {key} ({key}, role generic) to work on one focused task with its own tools over "
    "this sample. Its answer comes back as its own claims, each with the ledger ids it "
    "cited, exactly as it gave them. It gets no step limit and no time limit of its own, "
    "and they do not come out of your step budget — your wall clock is what they cost. "
    "Ask one at a time and read each answer before the next."
)


class TestTheAskToolSaysHowItsAsksRun:
    def test_a_serial_caller_reads_the_sentence_it_always_read(self) -> None:
        local = _Container("ollama")
        hosted = _Container("anthropic")

        for container, caller in (
            (local, local.agents["judge"]),
            (hosted, None),
            (hosted, hosted.agents["lead"]),
        ):
            tool = ask_tool(container, "judge", "reader", caller=caller)
            assert tool.description == DEV_DESCRIPTION.format(key="reader")

    def test_a_judge_whose_asks_run_at_once_is_told_so(self) -> None:
        container = _Container("anthropic")

        tool = ask_tool(container, "judge", "reader", caller=container.agents["judge"])

        assert tool.description == DEV_DESCRIPTION.format(key="reader").replace(
            delegation.ONE_AT_A_TIME_SENTENCE, delegation.AT_ONCE_SENTENCE
        )


class _Callee:
    """An asked agent whose ``answer_task`` files ledger entries, as a loop would."""

    def __init__(self, name: str, ids: list[int], started: threading.Barrier) -> None:
        self.name = name
        self.ids = ids
        self.started = started
        self.delegation_lock = threading.Lock()
        self.call_chain: tuple[str, ...] = ()
        self.steps_spent = 0
        self.handed: list[Any] = []
        self.before: Any = None

    def answer_task(self, turn: str) -> tuple[str, Any]:
        from maljan.schemas.isr_models import AgentISR

        self.started.wait()
        if self.before is not None:
            # This ask finishes after the other has handed its record over.
            assert self.before.wait(timeout=5)
        self.handed = [SimpleNamespace(id=f"ev_{number:04d}") for number in self.ids]
        return f"{self.name} answered", AgentISR(
            agent_id=self.name, domain="static", claims=[], dissent_items=[]
        )

    def drain_evidence_entries(self) -> list[Any]:
        handed, self.handed = self.handed, []
        return handed


def _waits_on_the_lock(lock: Any, work: Any) -> list[Any]:
    """Run ``work`` on a thread while this one holds ``lock``; it must wait for the release."""
    done: list[Any] = []
    with lock:
        thread = threading.Thread(target=lambda: done.append(work()), daemon=True)
        thread.start()
        thread.join(timeout=0.2)
        assert thread.is_alive() and done == [], "it did not wait for the evidence lock"
    thread.join(timeout=5)
    assert not thread.is_alive()
    return done


class TestTheEvidenceLockIsTaken:
    """Each place that writes or drains the judge's entries waits for its lock."""

    def _judge(self) -> Any:
        from maljan.agents.judge_agent import JudgeAgent

        judge = JudgeAgent.__new__(JudgeAgent)
        judge.evidence_lock = threading.Lock()
        judge._evidence_entries = [SimpleNamespace(id="ev_0001")]
        return judge

    def test_an_ask_that_ran_at_once_hands_over_under_it(self) -> None:
        container = _Container("anthropic")
        judge = container.agents["judge"]
        container.agents["reader"] = _Callee("reader", [2], threading.Barrier(1))

        done = _waits_on_the_lock(
            judge.evidence_lock,
            lambda: ask(container, caller_key="judge", callee_key="reader", task="Read it."),
        )

        assert done[0].endswith("\nreader answered")
        assert [entry.id for entry in judge._evidence_entries] == ["ev_0002"]

    def test_the_judge_drains_under_it(self) -> None:
        judge = self._judge()

        done = _waits_on_the_lock(judge.evidence_lock, judge.drain_evidence_entries)

        assert [entry.id for entry in done[0]] == ["ev_0001"]
        assert judge._evidence_entries == []

    def test_the_judge_s_loop_keeps_its_entries_under_it(self) -> None:
        judge = self._judge()

        _waits_on_the_lock(
            judge.evidence_lock,
            lambda: judge._keep_the_loop_s_entries([SimpleNamespace(id="ev_0002")]),
        )

        assert [entry.id for entry in judge._evidence_entries] == ["ev_0001", "ev_0002"]


class TestTwoAsksThroughTheRealAsk:
    def test_the_record_is_in_ledger_order_whichever_ask_finishes_first(self) -> None:
        container = _Container("anthropic")
        judge = container.agents["judge"]
        judge._evidence_entries = [SimpleNamespace(id="ev_0001")]
        started = threading.Barrier(2, timeout=5)
        reader = _Callee("reader", [2, 4], started)
        looker = _Callee("looker", [3, 5], started)
        container.agents.update(reader=reader, looker=looker)
        looker_handed = threading.Event()
        reader.before = looker_handed
        answers: dict[str, str] = {}

        def _go(key: str) -> None:
            try:
                answers[key] = ask(container, caller_key="judge", callee_key=key, task="Read it.")
            except Exception as exc:  # noqa: BLE001 — said in the assertion below
                answers[key] = repr(exc)
            if key == "looker":
                looker_handed.set()

        threads = [
            threading.Thread(target=_go, args=(key,), daemon=True) for key in ("reader", "looker")
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert sorted(answers) == ["looker", "reader"]
        assert all(answers[key].endswith(f"\n{key} answered") for key in answers), answers
        assert [entry.id for entry in judge._evidence_entries] == [
            "ev_0001",
            "ev_0002",
            "ev_0003",
            "ev_0004",
            "ev_0005",
        ]


class TestTheRecordIsMergedInLedgerOrder:
    def _entry(self, number: int) -> Any:
        return SimpleNamespace(id=f"ev_{number:04d}")

    def _handed_over(self, order: list[str], *, in_ledger_order: bool) -> list[str]:
        judge = _Agent("judge")
        judge._evidence_entries = [self._entry(1)]
        reader, looker = _Agent("reader"), _Agent("looker")
        reader.handed = [self._entry(2), self._entry(4)]
        looker.handed = [self._entry(3), self._entry(5)]
        for name in order:
            callee = reader if name == "reader" else looker
            _hand_over_the_record(judge, callee, in_ledger_order=in_ledger_order)
        return [entry.id for entry in judge._evidence_entries]

    def test_asks_that_finish_in_either_order_leave_the_same_record(self) -> None:
        first = self._handed_over(["reader", "looker"], in_ledger_order=True)
        second = self._handed_over(["looker", "reader"], in_ledger_order=True)

        assert first == second == ["ev_0001", "ev_0002", "ev_0003", "ev_0004", "ev_0005"]

    def test_a_serial_ask_hands_over_as_it_always_did(self) -> None:
        assert self._handed_over(["looker", "reader"], in_ledger_order=False) == [
            "ev_0001",
            "ev_0003",
            "ev_0005",
            "ev_0002",
            "ev_0004",
        ]
