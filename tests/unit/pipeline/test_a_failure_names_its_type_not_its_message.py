"""What a node may say about an exception on the live feed.

An ``agent_message`` goes to every connected browser, into the Redis stream
and into the ``job_events`` table for the whole retention window. An
exception's *message* is the part that names things a reader of that feed has
no business seeing: an ``OSError`` names the host path of the sample, an
``httpx`` transport error names the request URL, and a base URL configured
with userinfo carries the credential into the text.

So a published failure says what kind of failure it was, and the remedy when
the failure carries one, and never what it said. The verbatim text stays on
the ledger and the log, behind the report's ownership check.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.core.exceptions import AnalystError
from maljan.pipeline import events as ev
from maljan.pipeline.nodes import (
    make_negotiation_node,
    make_revision_node,
    make_stage_agent_node,
)
from tests.stages import ANALYSIS_STAGE, paper_profile
from tests.unit.pipeline._source_names import names_reaching

# One string carrying both of the things a message must not put on the wire.
SECRET = "sk-" + "L" * 32
HOST_PATH = "/home/operator/maljan/data/samples/ab12/evil.exe"
LOUD = f"POST https://user:{SECRET}@llm.internal/v1 failed reading {HOST_PATH}"


class _Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, data))

    def said(self) -> str:
        """Every string in every event, as one blob to search."""
        import json

        return json.dumps(self.events, default=str)


def _container(sink: Any, agents: list[str] | None = None) -> Any:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = sink
    container.agent_registry.list_agents.return_value = agents or ["network"]
    container.analyst_keys.return_value = agents or ["network"]
    container.agent_role.side_effect = lambda n: n
    container.active_profile.return_value = paper_profile(agents or ["network"])
    container.load_data_for_agent.side_effect = lambda n, *, file_hash, **_: container.load_chunked(
        file_hash, n
    )
    return container


def _assert_nothing_leaked(recorder: _Recorder) -> None:
    said = recorder.said()
    assert SECRET not in said, said
    assert "/home/operator" not in said, said
    assert "llm.internal" not in said, said


class TestOnlyTheSafeHelperReachesAPublishSite:
    """The two descriptions of a failure are told apart by name, and checked.

    ``base_agent.describe_exception_for_log`` keeps the exception's message,
    because a log line on the operator's own host is what the message is for.
    ``events.describe_exception`` never does. The two used to share a name, and
    the wrong import fails *open* — a verbose event rather than a broken one,
    which nothing else in the suite would notice. So the names differ and this
    walks the source to say that no publish site calls the log one.
    """

    # What puts text on the wire or into the transcript: the event
    # constructors, the sink itself, and the argument a mediator's round is
    # recorded as.
    PUBLISHERS = frozenset(
        {
            "emit",
            "emit_agent_message",
            "emit_agent_message_delta",
            "emit_budget_tick",
            "emit_judge_question",
            "emit_roster",
            "emit_stage_ended_at_cap",
            "emit_tool_call_finished",
            "emit_tool_call_started",
            "emit_validation_feedback",
            "AgentArgument",
        }
    )
    UNSAFE = "describe_exception_for_log"

    @staticmethod
    def _calls(node: ast.AST) -> set[str]:
        """Every function name called anywhere inside ``node``."""
        names: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func = child.func
                names.add(func.id if isinstance(func, ast.Name) else getattr(func, "attr", ""))
        return names

    @staticmethod
    def _names(node: ast.AST) -> set[str]:
        """Every local this expression reads."""
        return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}

    def _unsafe_names(self, tree: ast.AST) -> set[str]:
        """What the log helper is called in this module, including under an alias.

        The shape the code carried before the two helpers were told apart was
        ``from ... import describe_exception as exception_detail``, so an
        import that renames the unsafe one is exactly the mistake most
        recently made here and the one a walk keyed on a single spelling would
        miss. The resolution is shared with the finding-row guard beside this
        one, which was told the same thing about ``Violation``.
        """
        return names_reaching(tree, self.UNSAFE)

    @staticmethod
    def _assigned(node: ast.AST) -> tuple[list[str], ast.AST | None]:
        """The plain locals an assignment writes, and the expression it writes.

        Tuple and list targets are unpacked, because ``a, b = f(), g()`` taints
        whatever it binds as surely as a single name does, and an annotated or
        augmented assignment binds one name each.

        A tuple taints every name it binds, including the sides that came from
        somewhere safe. Deliberately the wrong way round: a guard that misses a
        publish site fails open and nothing else in the suite would notice,
        while one that over-reaches fails loudly on a line a reader can look
        at. If it ever fires on a mixed tuple, the fix is to split the
        assignment, not to narrow this.
        """
        if isinstance(node, ast.Assign):
            targets = [t for target in node.targets for t in ast.walk(target)]
            return [t.id for t in targets if isinstance(t, ast.Name)], node.value
        if isinstance(node, ast.AnnAssign | ast.AugAssign):
            target = node.target
            return ([target.id] if isinstance(target, ast.Name) else []), node.value
        if isinstance(node, ast.NamedExpr):
            return [node.target.id], node.value
        return [], None

    def _tainted(self, tree: ast.AST, unsafe: set[str]) -> set[str]:
        """Every local that holds, directly or at any remove, what the log said.

        Walked to a fixed point rather than once, so ``a = f"…{unsafe(e)}"``
        followed by ``b = a`` taints ``b`` as well. One pass caught the first
        hop only, which is the shape the tree happens to use today and not a
        property of it.
        """
        tainted: set[str] = set()
        while True:
            grew = False
            for node in ast.walk(tree):
                names, value = self._assigned(node)
                if value is None or not names:
                    continue
                if not (unsafe & self._calls(value) or tainted & self._names(value)):
                    continue
                for name in names:
                    if name not in tainted:
                        tainted.add(name)
                        grew = True
            if not grew:
                return tainted

    def _offenders(self, tree: ast.AST) -> list[int]:
        """The publish sites in ``tree`` whose text describes a failure for the log.

        A node builds its line into a local as often as it writes it inline —
        ``crashed_text = f"…{describe_exception(e)}"`` and then
        ``text=crashed_text`` — so the locals that were built from the unsafe
        helper are collected first and a publisher reading one of them counts
        the same as a publisher calling it.
        """
        unsafe = self._unsafe_names(tree)
        tainted = self._tainted(tree, unsafe)
        found: list[int] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name not in self.PUBLISHERS:
                continue
            for argument in [*node.args, *(kw.value for kw in node.keywords)]:
                if unsafe & self._calls(argument) or tainted & self._names(argument):
                    found.append(node.lineno)
        return found

    def _publishers_in(self, tree: ast.AST) -> int:
        return sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and (
                node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            )
            in self.PUBLISHERS
        )

    def test_no_publish_site_describes_an_exception_for_the_log(self) -> None:
        source_root = Path(ev.__file__).resolve().parents[1]
        offenders: list[str] = []
        publishes = 0

        for path in sorted(source_root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            publishes += self._publishers_in(tree)
            offenders += [f"{path.name}:{line}" for line in self._offenders(tree)]

        assert publishes > 20, "the walk found no publish sites, so it proves nothing"
        assert offenders == [], offenders

    def test_the_walk_sees_a_line_built_into_a_local(self) -> None:
        """The check that the check works: the shape four of the six sites use."""
        written_inline = ast.parse(
            "emit_agent_message(sink, text=f'x {describe_exception_for_log(e)}')"
        )
        built_first = ast.parse(
            "def n():\n"
            "    said = f'x {describe_exception_for_log(e)}'\n"
            "    emit_agent_message(sink, text=said)\n"
        )
        safe = ast.parse(
            "def n():\n"
            "    said = f'x {describe_exception(e)}'\n"
            "    logger.error('%s', describe_exception_for_log(e))\n"
            "    emit_agent_message(sink, text=said)\n"
        )

        assert self._offenders(written_inline) == [1]
        assert self._offenders(built_first) == [3]
        assert self._offenders(safe) == []

    def test_the_walk_follows_an_aliased_import(self) -> None:
        """The shape the code was in before the two helpers were told apart.

        ``from maljan.agents.base_agent import describe_exception as detail``
        is how the unsafe helper last reached a publish site, and a walk that
        only knows one spelling would have let that one through.
        """
        aliased = ast.parse(
            "from maljan.agents.base_agent import describe_exception_for_log as detail\n"
            "def n():\n"
            "    emit_agent_message(sink, text=f'x {detail(e)}')\n"
        )
        unaliased = ast.parse(
            "from maljan.agents.base_agent import describe_exception_for_log\n"
            "def n():\n"
            "    emit_agent_message(sink, text=f'x {describe_exception_for_log(e)}')\n"
        )
        other = ast.parse(
            "from maljan.pipeline.events import describe_exception as detail\n"
            "def n():\n"
            "    emit_agent_message(sink, text=f'x {detail(e)}')\n"
        )

        assert self._offenders(aliased) == [3]
        assert self._offenders(unaliased) == [3]
        assert self._offenders(other) == []

    def test_the_walk_follows_a_line_handed_on_twice(self) -> None:
        two_hops = ast.parse(
            "def n():\n"
            "    said = f'x {describe_exception_for_log(e)}'\n"
            "    passed_on = said\n"
            "    emit_agent_message(sink, text=passed_on)\n"
        )

        assert self._offenders(two_hops) == [4]

    def test_the_walk_follows_the_other_ways_a_name_is_bound(self) -> None:
        """A tuple target, an annotated assignment and an augmented one."""
        unpacked = ast.parse(
            "def n():\n"
            "    said, other = f'x {describe_exception_for_log(e)}', 1\n"
            "    emit_agent_message(sink, text=said)\n"
        )
        annotated = ast.parse(
            "def n():\n"
            "    said: str = f'x {describe_exception_for_log(e)}'\n"
            "    emit_agent_message(sink, text=said)\n"
        )
        appended = ast.parse(
            "def n():\n"
            "    said = 'x'\n"
            "    said += describe_exception_for_log(e)\n"
            "    emit_agent_message(sink, text=said)\n"
        )

        assert self._offenders(unpacked) == [3]
        assert self._offenders(annotated) == [3]
        assert self._offenders(appended) == [4]

    def test_the_two_helpers_do_not_share_a_name(self) -> None:
        from maljan.agents import base_agent

        assert not hasattr(base_agent, "describe_exception")
        assert hasattr(base_agent, self.UNSAFE)

    def test_they_disagree_about_the_message_on_purpose(self) -> None:
        from maljan.agents.base_agent import describe_exception_for_log

        said = describe_exception_for_log(ValueError(LOUD))

        assert SECRET in said, "the log helper is the one that keeps the detail"
        assert SECRET not in ev.describe_exception(ValueError(LOUD))


class TestTheHelper:
    def test_a_message_never_travels(self) -> None:
        assert ev.describe_exception(ValueError(LOUD)) == "ValueError"

    def test_the_class_is_what_is_said(self) -> None:
        assert ev.describe_exception(TimeoutError()) == "TimeoutError"

    def test_a_class_outside_the_builtins_is_qualified(self) -> None:
        """Two ``CancelledError`` classes print the same word; only one is an
        ``Exception``, which is exactly why one of them slipped through."""
        import asyncio as _asyncio
        import concurrent.futures as _futures

        assert ev.describe_exception(_asyncio.CancelledError()) != ev.describe_exception(
            _futures.CancelledError()
        )
        assert "asyncio" in ev.describe_exception(_asyncio.CancelledError())

    def test_a_remediation_the_failure_carries_is_said(self) -> None:
        from maljan.tools.roots import PathOutsideRoots

        said = ev.describe_exception(PathOutsideRoots())

        assert "PathOutsideRoots" in said
        assert PathOutsideRoots.remediation in said

    def test_a_remediation_is_scrubbed_like_anything_else(self) -> None:
        class _Remediated(Exception):
            remediation = f"open {HOST_PATH} and try again"

        said = ev.describe_exception(_Remediated("boom"))

        assert "/home/operator" not in said
        assert "evil.exe" in said

    def test_an_exception_group_names_what_is_inside_it(self) -> None:
        group = ExceptionGroup("several", [ValueError(LOUD), TimeoutError()])

        said = ev.describe_exception(group)

        assert "ValueError" in said and "TimeoutError" in said
        assert SECRET not in said


class TestTheAnalystNode:
    def test_a_failed_analyst_says_the_type_alone(self) -> None:
        recorder = _Recorder()
        container = _container(recorder)
        container.get_agent.side_effect = AnalystError(LOUD)

        make_stage_agent_node(ANALYSIS_STAGE, "network", container)({"file_hash": "a" * 64})

        _assert_nothing_leaked(recorder)
        (message,) = [d for t, d in recorder.events if t == ev.AGENT_MESSAGE]
        assert message["status"] == "failed"
        assert "AnalystError" in message["text"]

    def test_a_crashed_analyst_says_the_type_alone(self) -> None:
        recorder = _Recorder()
        container = _container(recorder)
        container.get_agent.side_effect = RuntimeError(LOUD)

        update = make_stage_agent_node(ANALYSIS_STAGE, "network", container)(
            {"file_hash": "a" * 64}
        )

        _assert_nothing_leaked(recorder)
        assert "RuntimeError" in update["reports"]["network"]
        assert SECRET not in update["reports"]["network"]


class TestTheMediator:
    def test_a_failed_mediation_says_the_type_alone(self) -> None:
        recorder = _Recorder()
        container = _container(recorder)
        judge = MagicMock()
        judge.mediate = AsyncMock(side_effect=RuntimeError(LOUD))
        container.get_judge_agent.return_value = judge

        update = asyncio.run(
            make_negotiation_node(container)(
                {"iteration_count": 1, "reports": {"network": "f"}, "isr_reports": {}}
            )
        )

        _assert_nothing_leaked(recorder)
        finding = update["discussion_history"][0].finding
        assert "RuntimeError" in finding
        assert SECRET not in finding


class TestTheRevision:
    def test_a_failed_revision_says_the_type_alone(self) -> None:
        recorder = _Recorder()
        container = _container(recorder, agents=["network"])
        agent = MagicMock()
        agent.safe_revise_isr.side_effect = OSError(LOUD)
        container.get_agent.return_value = agent

        asyncio.run(
            make_revision_node(container)(
                {"iteration_count": 1, "reports": {"network": "f"}, "isr_reports": {}}
            )
        )

        _assert_nothing_leaked(recorder)
        (message,) = [d for t, d in recorder.events if t == ev.AGENT_MESSAGE]
        assert message["status"] == "failed"
        assert "OSError" in message["text"]


class TestTheJudge:
    def test_a_failed_verdict_says_the_type_alone(self) -> None:
        from maljan.pipeline.nodes import make_judge_node
        from maljan.schemas.evidence import EvidenceCounter
        from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import _Container, _state

        recorder = _Recorder()
        container = _Container(EvidenceCounter())
        container.event_sink = recorder
        container.get_judge_agent(role="judge").give_verdict = AsyncMock(
            side_effect=RuntimeError(LOUD)
        )

        update = asyncio.run(make_judge_node(container)(_state([])))

        _assert_nothing_leaked(recorder)
        assert update["degraded_mode"] is True
        (message,) = [d for t, d in recorder.events if t == ev.AGENT_MESSAGE]
        assert "RuntimeError" in message["text"]


@pytest.mark.parametrize("exc", [ValueError(LOUD), OSError(LOUD), TimeoutError(LOUD)])
def test_no_shape_of_message_survives_the_helper(exc: BaseException) -> None:
    said = ev.describe_exception(exc)

    assert SECRET not in said
    assert "/home/operator" not in said
    assert "llm.internal" not in said
