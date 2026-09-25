"""Every model call is admitted by the spend ceiling before it is sent.

The mediator's fast path, the judge's reasoning salvage, the structured
mediation extraction and the function summariser went out without being
admitted: nothing held them, nothing reserved them, and one of them could take
the job past its ceiling. The guard below reads the source for every
``invoke``/``ainvoke`` call and fails for one that is not preceded, in its own
function or a function around it, by a call that admits it. The only calls it
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


def unadmitted_in(source: str, where: str = "<source>") -> list[str]:
    """The model calls in ``source`` no admission precedes in their function or one around it."""
    tree = ast.parse(source)
    found: list[str] = []

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
                receiver = ast.unparse(child.func.value)
                if (where, receiver) not in TOOL_CALLS and not any(
                    isinstance(seen, ast.Call)
                    and _called_name(seen) in ADMISSION
                    and seen.lineno < child.lineno
                    for function in around
                    for seen in _own_nodes(function)
                ):
                    name = around[-1].name if around else "<module>"
                    found.append(f"{where}:{child.lineno} {name}: {receiver}")
            visit(child, around)

    visit(tree, [])
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
