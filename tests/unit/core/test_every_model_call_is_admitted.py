"""Every model call is admitted by the spend ceiling before it is sent.

The mediator's fast path, the judge's reasoning salvage, the structured
mediation extraction and the function summariser went out without being
admitted: nothing held them, nothing reserved them, and one of them could take
the job past its ceiling. Every site that calls a chat model now sits in a
function that asks the meter first. The guard below reads the source for
every ``invoke``/``ainvoke`` of a model and fails for one outside such a
function; the tests after it drive the judge's paths through a meter.
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
# Where model calls are made. The provider layer (``llm/``) is the model
# client itself; the pipeline's calls are tool calls.
SCANNED = ("agents", "reporting", "analysis", "loaders", "memory", "preprocessing")
# What a function that admits its calls names.
ADMISSION = ("_spend_admits", "spend_bound", "_call_limit", "admitted(", ".admit(")


def _receiver(node: ast.expr) -> str:
    return ast.unparse(node)


def _outermost_functions(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Module functions and methods, not the closures inside them.

    A closure's admission is in the method around it: the verdict's call is
    made in a nested coroutine the method admits before awaiting.
    """
    found: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    pending: list[ast.AST] = [tree]
    while pending:
        node = pending.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                found.append(child)
            elif not isinstance(child, ast.Lambda):
                pending.append(child)
    return found


def _unadmitted() -> list[str]:
    found: list[str] = []
    for folder in SCANNED:
        for path in sorted((SRC / folder).rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
            for top in _outermost_functions(tree):
                body = ast.get_source_segment(source, top) or ""
                for node in ast.walk(top):
                    if not (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ("invoke", "ainvoke")
                    ):
                        continue
                    receiver = _receiver(node.func.value)
                    if "tool" in receiver.lower():
                        continue
                    if not any(mark in body for mark in ADMISSION):
                        found.append(
                            f"{path.relative_to(SRC)}:{node.lineno} {top.name}: {receiver}"
                        )
    return found


def test_no_model_is_called_outside_an_admitted_function() -> None:
    assert _unadmitted() == []


def test_the_guard_sees_a_call_site() -> None:
    # The guard reads real call sites: the verdict's is one of them.
    sites = []
    for path in (SRC / "agents").rglob("judge_agent.py"):
        sites.extend(line for line in path.read_text().splitlines() if ".ainvoke(" in line)
    assert len(sites) >= 5


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
