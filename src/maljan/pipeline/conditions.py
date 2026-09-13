"""The tiny expression language a stage's ``when`` is written in.

A staged team is only worth the name if a stage can decline to run: the
reversing stage on a PE, the APK stage on an APK, the network stage when the
sample actually talked to something. That decision is operator text, so it has
to be evaluated, and evaluating operator text with ``eval`` would hand every
admin of the console a shell on the worker.

So this is Python's own parser with an allow-list on top. ``ast.parse`` in
``eval`` mode gives the grammar; ``_check`` refuses every node type that is not
in the list below; the evaluator walks the checked tree by hand. No calls, no
comprehensions, no lambdas, no f-strings, no attribute access except one level
into ``stages``, and no names except the fields of ``StageContext``.

The same allow-list serves twice. ``validate_condition`` runs it at save time
against a dummy context, so a typo is a settings error the operator sees while
they are still editing; ``evaluate`` runs it at run time, where a failure is a
skipped stage with the reason written down rather than a crashed pipeline.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ConditionError",
    "StageContext",
    "StageResult",
    "evaluate",
    "validate_condition",
]


class ConditionError(Exception):
    """A ``when`` expression that cannot be parsed, checked or resolved."""


@dataclass(frozen=True)
class StageResult:
    """What one stage left behind, as the next stage's condition sees it.

    Deliberately a handful of scalars rather than the stage's whole output: a
    condition that could reach into an ISR claim would be a query language, and
    a query language over model output is a thing to debug at three in the
    morning. These six answer the questions a topology actually asks — did it
    run, did it find anything, which techniques, who was in it.
    """

    ran: bool
    reason: str = ""
    claim_count: int = 0
    technique_ids: tuple[str, ...] = ()
    finding_count: int = 0
    agents: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ran": self.ran,
            "reason": self.reason,
            "claim_count": self.claim_count,
            "technique_ids": list(self.technique_ids),
            "finding_count": self.finding_count,
            "agents": list(self.agents),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StageResult:
        return cls(
            ran=bool(data.get("ran")),
            reason=str(data.get("reason") or ""),
            claim_count=int(data.get("claim_count") or 0),
            technique_ids=tuple(str(t) for t in (data.get("technique_ids") or ())),
            finding_count=int(data.get("finding_count") or 0),
            agents=tuple(str(a) for a in (data.get("agents") or ())),
        )


@dataclass(frozen=True)
class StageContext:
    """The sample and the run so far, as names a condition may use."""

    file_type: str = ""
    platform: str = ""
    mime: str = ""
    size: int = 0
    extension: str = ""
    sandbox_available: bool = False
    has_pcap: bool = False
    has_sandbox_report: bool = False
    stages: Mapping[str, StageResult] = field(default_factory=dict)


# The context fields a condition may name. Derived from the dataclass so a new
# field is usable the moment it is declared, and an old one cannot linger here
# after it is removed.
CONTEXT_NAMES: frozenset[str] = frozenset(StageContext.__dataclass_fields__)

# The fields of a ``StageResult`` a condition may read off ``stages.<key>``.
STAGE_RESULT_FIELDS: frozenset[str] = frozenset(StageResult.__dataclass_fields__)

_ALLOWED_COMPARISONS = (ast.Eq, ast.NotEq, ast.In, ast.NotIn, ast.Lt, ast.LtE, ast.Gt, ast.GtE)
_ALLOWED_CONSTANTS = (str, int, float, bool, type(None))


def _describe(node: ast.AST) -> str:
    """The node type, in the words an operator writing the expression would use."""
    names = {
        "Call": "a function call",
        "Lambda": "a lambda",
        "ListComp": "a comprehension",
        "SetComp": "a comprehension",
        "DictComp": "a comprehension",
        "GeneratorExp": "a comprehension",
        "JoinedStr": "an f-string",
        "Await": "an await",
        "IfExp": "a conditional expression",
        "BinOp": "arithmetic",
        "NamedExpr": "an assignment",
        "Starred": "unpacking",
        "Dict": "a dict literal",
        "Set": "a set literal",
        "Slice": "a slice",
    }
    return names.get(type(node).__name__, f"{type(node).__name__} syntax")


def _check(node: ast.AST) -> None:
    """Refuse every construct the allow-list does not name. Depth-first."""
    if isinstance(node, ast.Expression):
        _check(node.body)
        return
    if isinstance(node, ast.BoolOp):
        for value in node.values:
            _check(value)
        return
    if isinstance(node, ast.UnaryOp):
        if not isinstance(node.op, ast.Not):
            raise ConditionError(f"{_describe(node)} is not allowed; only 'not' is")
        _check(node.operand)
        return
    if isinstance(node, ast.Compare):
        for op in node.ops:
            if not isinstance(op, _ALLOWED_COMPARISONS):
                raise ConditionError(
                    f"the {type(op).__name__.lower()} operator is not allowed in a condition"
                )
        _check(node.left)
        for comparator in node.comparators:
            _check(comparator)
        return
    if isinstance(node, ast.Name):
        if node.id not in CONTEXT_NAMES:
            known = ", ".join(sorted(CONTEXT_NAMES))
            raise ConditionError(f"unknown name {node.id!r}; the condition may use: {known}")
        return
    if isinstance(node, ast.Constant):
        if not isinstance(node.value, _ALLOWED_CONSTANTS):
            raise ConditionError(f"a {type(node.value).__name__} literal is not allowed")
        return
    if isinstance(node, (ast.Tuple, ast.List)):
        for element in node.elts:
            if not isinstance(element, ast.Constant):
                raise ConditionError("a list or tuple in a condition holds constants only")
            _check(element)
        return
    if isinstance(node, ast.Attribute):
        _check_stage_lookup(node)
        return
    if isinstance(node, ast.Subscript):
        _check_stage_lookup(node)
        return
    raise ConditionError(f"{_describe(node)} is not allowed in a condition")


def _check_stage_lookup(node: ast.Attribute | ast.Subscript) -> None:
    """``stages.<key>.<field>`` and ``stages["<key>"].<field>``, and nothing else.

    Both spellings mean the same lookup, so both are checked here rather than
    once per node type: the shape being enforced is the whole two-step path,
    and splitting it would let ``stages.static`` pass on its own as a value the
    rest of the expression could compare against.
    """
    if not isinstance(node, ast.Attribute) or node.attr not in STAGE_RESULT_FIELDS:
        fields = ", ".join(sorted(STAGE_RESULT_FIELDS))
        raise ConditionError(
            "a stage lookup reads one of its result fields "
            f"(stages.<stage>.<field>, where field is one of: {fields})"
        )
    holder = node.value
    if isinstance(holder, ast.Attribute):
        key_holder: ast.AST = holder.value
    elif isinstance(holder, ast.Subscript):
        if not isinstance(holder.slice, ast.Constant) or not isinstance(holder.slice.value, str):
            raise ConditionError("a stage is looked up by a literal name")
        key_holder = holder.value
    else:
        raise ConditionError("a stage result is read as stages.<stage>.<field>")
    if not isinstance(key_holder, ast.Name) or key_holder.id != "stages":
        raise ConditionError("a stage result is read as stages.<stage>.<field>")


def _stage_key(holder: ast.Attribute | ast.Subscript) -> str:
    if isinstance(holder, ast.Attribute):
        return holder.attr
    assert isinstance(holder.slice, ast.Constant)  # noqa: S101 — guaranteed by _check
    return str(holder.slice.value)


def _resolve(node: ast.AST, ctx: StageContext) -> Any:
    """Evaluate a node the checker has already accepted."""
    if isinstance(node, ast.Expression):
        return _resolve(node.body, ctx)
    if isinstance(node, ast.BoolOp):
        values = node.values
        if isinstance(node.op, ast.And):
            result: Any = True
            for value in values:
                result = _resolve(value, ctx)
                if not result:
                    return result
            return result
        result = False
        for value in values:
            result = _resolve(value, ctx)
            if result:
                return result
        return result
    if isinstance(node, ast.UnaryOp):
        return not _resolve(node.operand, ctx)
    if isinstance(node, ast.Compare):
        left = _resolve(node.left, ctx)
        for op, comparator_node in zip(node.ops, node.comparators, strict=True):
            right = _resolve(comparator_node, ctx)
            if not _compare(op, left, right):
                return False
            left = right
        return True
    if isinstance(node, ast.Name):
        return getattr(ctx, node.id)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Tuple):
        return tuple(_resolve(e, ctx) for e in node.elts)
    if isinstance(node, ast.List):
        return [_resolve(e, ctx) for e in node.elts]
    if isinstance(node, ast.Attribute):
        holder = node.value
        assert isinstance(holder, (ast.Attribute, ast.Subscript))  # noqa: S101 — see _check
        key = _stage_key(holder)
        # A stage nobody ran reads as a stage that did not run, rather than
        # raising: a condition naming an upstream stage that was itself
        # skipped is the normal case, not a configuration error.
        result = ctx.stages.get(key) or StageResult(ran=False, reason="stage did not run")
        return getattr(result, node.attr)
    raise ConditionError(f"{_describe(node)} is not allowed in a condition")


def _compare(op: ast.cmpop, left: Any, right: Any) -> bool:
    """One comparison, with the type errors turned into condition errors.

    ``"x" < 3`` parses and checks cleanly and only fails when the values
    arrive, so the ``TypeError`` is caught here and re-raised in the vocabulary
    the caller reports in — a stage skipped with a reason, not a traceback out
    of a node.
    """
    try:
        if isinstance(op, ast.Eq):
            return bool(left == right)
        if isinstance(op, ast.NotEq):
            return bool(left != right)
        if isinstance(op, ast.In):
            return bool(left in right)
        if isinstance(op, ast.NotIn):
            return bool(left not in right)
        if isinstance(op, ast.Lt):
            return bool(left < right)
        if isinstance(op, ast.LtE):
            return bool(left <= right)
        if isinstance(op, ast.Gt):
            return bool(left > right)
        return bool(left >= right)
    except TypeError as exc:
        raise ConditionError(f"cannot compare those values: {exc}") from exc


def parse_condition(expr: str) -> ast.Expression:
    """Parse and check ``expr``, or raise ``ConditionError``."""
    text = (expr or "").strip()
    if not text:
        raise ConditionError("an empty condition is always true and is not parsed")
    try:
        tree = ast.parse(text, mode="eval")
    except SyntaxError as exc:
        raise ConditionError(f"cannot parse the condition: {exc.msg}") from exc
    _check(tree)
    return tree


def evaluate(expr: str, ctx: StageContext) -> bool:
    """Whether ``expr`` holds for ``ctx``. An empty expression is always true."""
    if not (expr or "").strip():
        return True
    tree = parse_condition(expr)
    return bool(_resolve(tree, ctx))


def validate_condition(expr: str) -> list[str]:
    """Everything wrong with ``expr``, for the settings API. Empty means fine.

    A list rather than a bool because the caller renders it next to the field,
    and a list rather than an exception because an empty condition is valid and
    "valid" should not be an exception path.
    """
    if not (expr or "").strip():
        return []
    try:
        tree = parse_condition(expr)
    except ConditionError as exc:
        return [str(exc)]
    # Parsing proves the grammar; a dry run against a dummy context proves the
    # names resolve and the comparisons are between comparable types, which is
    # the other half of what an operator gets wrong.
    try:
        _resolve(tree, StageContext())
    except ConditionError as exc:
        return [str(exc)]
    except Exception as exc:  # noqa: BLE001 — an unexpected failure is still the operator's
        return [f"the condition could not be evaluated: {exc}"]
    return []
