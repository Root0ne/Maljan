"""Every model call is admitted by the spend ceiling before it is sent.

The mediator's fast path, the judge's reasoning salvage, the structured
mediation extraction and the function summariser went out without being
admitted: nothing held them, nothing reserved them, and one of them could take
the job past its ceiling. The guard below reads the source for every
``invoke``/``ainvoke`` call and pairs it with an admission of its own: the
nearest one before it, in its function or a function around it, that no
earlier call took. One admission does not cover a second call after it, and a
call inside a loop is paired only with an admission in the same loop's body,
since one made before the loop admits its first pass alone. The only calls it
leaves alone are the tool calls listed by name. The tests after it drive the
judge's paths through a meter.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest
from tests.unit.core.test_every_model_call_is_counted import SETTINGS, _judge, _model

from maljan.core.model_assignments import global_model_label
from maljan.core.spend import Price, SpendMeter, _clean
from maljan.core.token_ledger import TokenLedger

SRC = Path(__file__).resolve().parents[3] / "src" / "maljan"
# Where calls are made. The provider layer (``llm/``) is the model client
# itself, and forwards calls already admitted.
SCANNED = ("agents", "reporting", "analysis", "loaders", "memory", "preprocessing", "pipeline")
# The calls that admit a model call: the meter's own, and the wrappers around it.
ADMISSION = frozenset({"_spend_admits", "spend_bound", "_call_limit", "admitted", "admit", "held"})
# The calls of tools, not models, by file and receiver.
TOOL_CALLS = frozenset({("agents/sample_staging.py", "tool"), ("pipeline/nodes.py", "tools[0]")})

Function = ast.FunctionDef | ast.AsyncFunctionDef


def _called_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _own_nodes(function: Function) -> list[ast.AST]:
    """Every node of ``function`` outside the functions nested in it (lambdas are its own)."""
    found: list[ast.AST] = []
    pending: list[ast.AST] = list(ast.iter_child_nodes(function))
    while pending:
        node = pending.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        found.append(node)
        pending.extend(ast.iter_child_nodes(node))
    return found


# A comprehension or a generator expression runs its element once per item,
# as a loop runs its body.
_LOOPS = (
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)


def _position(node: ast.AST) -> tuple[int, int]:
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))


def unadmitted_in(source: str, where: str = "<source>") -> list[str]:
    """The model calls in ``source`` that no admission of their own precedes.

    Each call takes the nearest admission before it that no earlier call took,
    looking in its own function first and then in each function around it,
    innermost first; two calls in the two branches of one ``if`` or conditional
    expression are one call, and may share one. A call inside a loop takes
    only an admission inside the innermost loop around it, in the same function.
    """
    tree = ast.parse(source)
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    found: list[str] = []
    # Each function's admissions in source order, and the calls each one admitted.
    admissions: dict[ast.AST, list[ast.Call]] = {}
    users: dict[ast.Call, list[ast.Call]] = {}

    def own_admissions(function: Function) -> list[ast.Call]:
        if function not in admissions:
            admissions[function] = sorted(
                (
                    seen
                    for seen in _own_nodes(function)
                    if isinstance(seen, ast.Call) and _called_name(seen) in ADMISSION
                ),
                key=_position,
            )
        return admissions[function]

    def innermost_loop(call: ast.Call, function: Function) -> ast.AST | None:
        node = parents.get(call)
        while node is not None and node is not function:
            if isinstance(node, _LOOPS):
                return node
            node = parents.get(node)
        return None

    def inside(node: ast.AST, ancestor: ast.AST) -> bool:
        while node is not None:
            if node is ancestor:
                return True
            node = parents.get(node)  # type: ignore[assignment]
        return False

    def exclusive(one: ast.AST, other: ast.AST) -> bool:
        """Whether the two sit in the two branches of one ``if`` or conditional expression."""
        for branch in (ast.If, ast.IfExp):
            node = parents.get(one)
            while node is not None:
                if isinstance(node, branch) and inside(other, node):
                    first = node.body if isinstance(node.body, list) else [node.body]
                    rest = node.orelse if isinstance(node.orelse, list) else [node.orelse]
                    in_first = any(inside(one, part) for part in first)
                    in_rest = any(inside(one, part) for part in rest)
                    other_first = any(inside(other, part) for part in first)
                    other_rest = any(inside(other, part) for part in rest)
                    return (in_first and other_rest) or (in_rest and other_first)
                node = parents.get(node)
        return False

    def free_for(admission: ast.Call, call: ast.Call) -> bool:
        return all(exclusive(call, earlier) for earlier in users.get(admission, []))

    def take(call: ast.Call, around: list[Function]) -> bool:
        for depth, function in enumerate(reversed(around)):
            loop = innermost_loop(call, function) if depth == 0 else None
            candidates = [
                admission
                for admission in own_admissions(function)
                if _position(admission) < _position(call)
                and (loop is None or inside(admission, loop))
                and free_for(admission, call)
            ]
            if candidates:
                users.setdefault(candidates[-1], []).append(call)
                return True
            if loop is not None:
                return False
        return False

    calls: list[tuple[ast.Call, list[Function]]] = []

    def visit(node: ast.AST, around: list[Function]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                visit(child, [*around, child])
                continue
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr in ("invoke", "ainvoke")
            ):
                calls.append((child, around))
            visit(child, around)

    visit(tree, [])
    for call, around in sorted(calls, key=lambda pair: _position(pair[0])):
        receiver = ast.unparse(call.func.value)  # type: ignore[attr-defined]
        if (where, receiver) in TOOL_CALLS or take(call, around):
            continue
        name = around[-1].name if around else "<module>"
        found.append(f"{where}:{call.lineno} {name}: {receiver}")
    return found


def _unadmitted() -> list[str]:
    found: list[str] = []
    for folder in SCANNED:
        for path in sorted((SRC / folder).rglob("*.py")):
            where = str(path.relative_to(SRC))
            found.extend(unadmitted_in(path.read_text(encoding="utf-8"), where))
    return found


def test_no_model_is_called_outside_an_admitted_function() -> None:
    assert _unadmitted() == []


class TestTheGuard:
    def test_catches_a_bare_call(self) -> None:
        assert unadmitted_in("async def f(llm, m):\n    return await llm.ainvoke(m)\n")

    def test_catches_a_call_beside_an_admitted_one(self) -> None:
        source = (
            "async def give(self, turns):\n"
            "    async def _ask(turns):\n"
            "        self._spend_admits('verdict', turns)\n"
            "        return await self.llm.ainvoke(turns)\n"
            "    first = await _ask(turns)\n"
            "    return await self.llm.ainvoke(turns)\n"
        )
        (found,) = unadmitted_in(source)
        assert ":6 give: self.llm" in found

    def test_catches_a_call_before_its_admission(self) -> None:
        source = (
            "async def f(self, m):\n"
            "    answer = await self.llm.ainvoke(m)\n"
            "    self._spend_admits('x', m)\n"
            "    return answer\n"
        )
        assert unadmitted_in(source)

    def test_catches_a_model_named_like_a_tool(self) -> None:
        source = "async def f(tool_llm, m):\n    return await tool_llm.ainvoke(m)\n"
        assert unadmitted_in(source)

    def test_a_mention_in_a_docstring_admits_nothing(self) -> None:
        source = (
            'async def f(llm, m):\n    """Calls _spend_admits first."""\n'
            "    return await llm.ainvoke(m)\n"
        )
        assert unadmitted_in(source)

    def test_one_admission_does_not_cover_a_second_call_after_it(self) -> None:
        source = (
            "async def f(self, a, b):\n"
            "    self._spend_admits('x', a)\n"
            "    first = await self.llm.ainvoke(a)\n"
            "    return first, await self.llm.ainvoke(b)\n"
        )
        (found,) = unadmitted_in(source)
        assert ":4 f: self.llm" in found

    def test_each_call_with_its_own_admission_passes(self) -> None:
        source = (
            "async def f(self, a, b):\n"
            "    self._spend_admits('x', a)\n"
            "    first = await self.llm.ainvoke(a)\n"
            "    self._spend_admits('y', b)\n"
            "    return first, await self.llm.ainvoke(b)\n"
        )
        assert unadmitted_in(source) == []

    def test_a_call_in_a_loop_needs_its_admission_in_the_loop(self) -> None:
        outside = (
            "async def f(self, turns):\n"
            "    self._spend_admits('x', turns)\n"
            "    for turn in turns:\n"
            "        await self.llm.ainvoke(turn)\n"
        )
        inside = (
            "async def f(self, turns):\n"
            "    for turn in turns:\n"
            "        with admitted(self.ledger, kind='x'):\n"
            "            await self.llm.ainvoke(turn)\n"
        )
        assert unadmitted_in(outside)
        assert unadmitted_in(inside) == []

    def test_a_call_in_a_comprehension_needs_its_admission_in_it(self) -> None:
        outside = (
            "async def f(self, batch):\n"
            "    self._spend_admits('x', batch)\n"
            "    return await gather(*(self.llm.ainvoke(m) for m in batch))\n"
        )
        listed = (
            "async def f(self, batch):\n"
            "    self._spend_admits('x', batch)\n"
            "    return [await self.llm.ainvoke(m) for m in batch]\n"
        )
        assert unadmitted_in(outside)
        assert unadmitted_in(listed)

    def test_two_branches_of_one_choice_share_their_admission(self) -> None:
        source = (
            "async def f(self, m, bound):\n"
            "    self._call_limit(m)\n"
            "    ask = (lambda: self.llm.ainvoke(m, cap=bound)) if bound else (\n"
            "        lambda: self.llm.ainvoke(m))\n"
            "    if bound:\n"
            "        return await ask()\n"
            "    return await ask()\n"
        )
        assert unadmitted_in(source) == []

    def test_a_fallback_after_a_refused_call_needs_its_own(self) -> None:
        source = (
            "async def f(self, m):\n"
            "    self._spend_admits('x', m)\n"
            "    try:\n"
            "        return await self.structured.ainvoke(m)\n"
            "    except ValueError:\n"
            "        pass\n"
            "    return await self.llm.ainvoke(m)\n"
        )
        (found,) = unadmitted_in(source)
        assert ":7 f: self.llm" in found

    def test_passes_an_admitted_call_in_a_closure(self) -> None:
        source = (
            "async def f(self, m):\n"
            "    slot = object()\n"
            "    bound = self._spend_admits('x', m, slot=slot)\n"
            "    async def _ask():\n"
            "        return await self.llm.ainvoke(m)\n"
            "    return await _ask()\n"
        )
        assert unadmitted_in(source) == []


def _priced_judge(ceiling: float, answered: str = "agreement_confidence: 0.95"):
    llm, ledger = _model(answered), TokenLedger()
    meter = SpendMeter(ceiling, table={})
    label = global_model_label(SETTINGS, "expert")
    meter._operator[_clean(label)] = Price(1.0, 1.0, source="test")
    ledger.spend = meter
    judge = _judge(llm, ledger, runs_on="expert")
    kinds: list[str] = []
    admit = meter.admit

    def _admit(**kwargs):
        kinds.append(kwargs["kind"])
        return admit(**kwargs)

    meter.admit = _admit  # type: ignore[method-assign]
    return judge, llm, meter, kinds


class TestTheJudgesCallsAreAdmitted:
    def test_the_mediator_s_fast_path(self) -> None:
        judge, llm, meter, kinds = _priced_judge(100.0)
        asyncio.run(judge.mediate(reports={"static": "text"}, history=[]))
        assert len(llm.asked) == 1 and kinds == ["mediation"]
        assert meter.committed() == meter.spent(), "nothing is left reserved"

    def test_the_structured_extraction(self, monkeypatch: pytest.MonkeyPatch) -> None:
        judge, llm, _meter, kinds = _priced_judge(100.0)
        monkeypatch.setattr(judge, "_supports_structured_output", lambda: True)
        asyncio.run(judge.mediate(reports={"static": "text"}, history=[]))
        assert len(llm.asked) == 2
        assert kinds == ["mediation", "mediation extraction"]

    def test_a_fast_path_the_ceiling_does_not_admit_is_not_sent(self) -> None:
        # The judge's configured cap costs more than the whole ceiling.
        judge, llm, meter, kinds = _priced_judge(0.001)
        asyncio.run(judge.mediate(reports={"static": "text"}, history=[]))
        assert llm.asked == [] and kinds == ["mediation"]
        assert meter.spent() <= 0.001
