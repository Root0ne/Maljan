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
into ``stages`` and the fields of ``triage``, no subscript except a stage's key
and ``triage.hits["<key>"]``, and no names except the fields of
``StageContext``.

The same allow-list serves twice. ``validate_condition`` runs it at save time
against a dummy context, so a typo is a settings error the operator sees while
they are still editing; ``evaluate`` runs it at run time, where a failure is a
skipped stage with the reason written down rather than a crashed pipeline.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any

__all__ = [
    "HELD_SCHEDULES",
    "PACK_LEFT_OUT",
    "ConditionError",
    "StageContext",
    "StageResult",
    "TriageFacts",
    "constant_truth",
    "pack_state",
    "pack_state_keys",
    "rule_match_hits",
    "evaluate",
    "stage_references",
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


# The kinds of answer whose rows are rules that matched the sample: a
# capability rule set, a signature rule set and an event rule set, whichever
# tool declares them (``core.tool_declarations``). Vocabulary, never a tool.
RULE_MATCH_KINDS: frozenset[str] = frozenset({"capability_rules", "signature_rules", "event_rules"})
# The legacy fields a stored team's condition reads, and the kind each counts.
SIGNATURE_RULES = "signature_rules"
CAPABILITY_RULES = "capability_rules"


@dataclass(frozen=True)
class TriageFacts:
    """What the triage pack and the run so far established, as the scalars a condition asks about.

    The pack writes tens of ledger entries; a condition wants to know whether
    the sample carries a signature, what a reputation service counted, and
    whether any rule fired. ``reputation_malicious`` is ``None`` when no
    lookup was made or the answer carried no count: an ordered comparison
    (``>``, ``<``) against it is refused at run time rather than reading
    zero, while ``==`` and ``!=`` compare against ``None`` as written — so a
    condition that means "looked up and found malicious" says
    ``reputation_malicious != None and reputation_malicious > 0``.

    ``rule_hits`` is how many rules matched the sample in every answer of a
    rule-matching kind (:data:`RULE_MATCH_KINDS`) recorded so far, the pack's
    and earlier stages' alike, whichever server answered; ``hits`` the same
    count per key: the answer's declared kind (``signature_rules`` …), the
    name its tool declares for corroboration (``source``), and the key of the
    tool server that answered. A key nothing counted reads as zero
    (``triage.hits["<key>"]``). ``yara_hits`` and ``capa_hits`` are kept for
    the stored teams that read them: the pack's own signature-rule and
    capability-rule counts, as they always were.
    """

    has_signature: bool = False
    reputation_malicious: int | None = None
    yara_hits: int = 0
    capa_hits: int = 0
    rule_hits: int = 0
    hits: Mapping[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_signature": self.has_signature,
            "reputation_malicious": self.reputation_malicious,
            "yara_hits": self.yara_hits,
            "capa_hits": self.capa_hits,
            "rule_hits": self.rule_hits,
            "hits": dict(self.hits),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> TriageFacts:
        data = data or {}
        malicious = data.get("reputation_malicious")
        yara = int(data.get("yara_hits") or 0)
        capa = int(data.get("capa_hits") or 0)
        held = data.get("hits")
        if isinstance(held, Mapping):
            hits = {str(k): int(v) for k, v in held.items() if isinstance(v, int)}
        else:
            # Facts written before the per-kind counts: the two the pack kept.
            hits = {k: v for k, v in ((SIGNATURE_RULES, yara), (CAPABILITY_RULES, capa)) if v}
        rule_hits = data.get("rule_hits")
        return cls(
            has_signature=bool(data.get("has_signature")),
            reputation_malicious=int(malicious) if isinstance(malicious, int) else None,
            yara_hits=yara,
            capa_hits=capa,
            rule_hits=int(rule_hits) if isinstance(rule_hits, int) else yara + capa,
            hits=hits,
        )

    def with_hits(self, counted: Mapping[str, int], total: int) -> TriageFacts:
        """These facts with ``hits`` and ``rule_hits`` as counted over a ledger."""
        return replace(self, hits=dict(counted), rule_hits=int(total))


# Where the pack's state holds the record of the pass entries the pack neither
# shows nor counts (``pipeline.nodes._pack_left_out``), and where it holds the
# schedules of steps named as one of its own keys (:func:`pack_state`). The
# second starts with an underscore, which no step id may, so no step's
# schedule can land on it.
PACK_LEFT_OUT = "pack_left_out"
HELD_SCHEDULES = "_held_schedules"


def _own_keys(state: Mapping[str, Any]) -> frozenset[str]:
    """The keys of the pack's state no schedule may take: its facts and counts, its
    left-out record and the place schedules are held apart in."""
    return frozenset(state) | {PACK_LEFT_OUT, HELD_SCHEDULES}


def pack_state(
    facts: TriageFacts,
    *,
    entries: int,
    failed: int,
    duration_ms: int,
    degradation_reasons: list[str],
    schedules: Mapping[str, str],
) -> dict[str, Any]:
    """The triage pack's state channel value: its facts and counts, then each schedule.

    ``pipeline.triage_pack.PackResult.to_state`` writes it. A schedule says
    how a step that may run beside the pack ran and sits under the step's id,
    after every other key. A step named as one of the state's own keys
    (:func:`pack_state_keys`) runs as any other, and its schedule is held apart
    under :data:`HELD_SCHEDULES`, so no schedule replaces a fact, a count or
    the left-out record. Without such a step the value is what it always was.
    """
    state: dict[str, Any] = {
        **facts.to_dict(),
        "entries": entries,
        "failed": failed,
        "duration_ms": duration_ms,
        "degradation_reasons": degradation_reasons,
    }
    own = _own_keys(state)
    state.update((step, said) for step, said in schedules.items() if step not in own)
    held = {step: said for step, said in schedules.items() if step in own}
    if held:
        state[HELD_SCHEDULES] = held
    return state


def pack_state_keys() -> frozenset[str]:
    """The keys the pack's state holds of its own: a step so named has its schedule held apart."""
    return _own_keys(
        pack_state(
            TriageFacts(),
            entries=0,
            failed=0,
            duration_ms=0,
            degradation_reasons=[],
            schedules={},
        )
    )


def rule_match_hits(rows: Any) -> tuple[dict[str, int], int]:
    """``(hits per key, rule_hits)`` over the ok ledger entries of a rule-matching kind.

    Each entry's declared kind and row path (``core.declared_reading``; an
    entry written before facts were stored is read by its shipped facts)
    say whether it is a rule match and where its rows are; each row is one
    rule that matched. A repeat of an earlier entry is not counted twice.
    """
    from maljan.core.declared_reading import facts_of
    from maljan.core.tool_declarations import ToolDeclarations, select

    counted: dict[str, int] = {}
    total = 0
    for row in rows or []:
        get = row.get if isinstance(row, Mapping) else lambda name, r=row: getattr(r, name, None)
        if not get("ok") or get("repeated_of"):
            continue
        facts = facts_of(row)
        if facts is None or facts.kind not in RULE_MATCH_KINDS or not facts.rows:
            continue
        found = len(select(get("structured"), facts.rows))
        if not found:
            continue
        total += found
        source = ToolDeclarations.source_of(row)
        server = source.key if source is not None and source.kind == "mcp" else ""
        for key in dict.fromkeys(k for k in (facts.kind, facts.source, server) if k):
            counted[key] = counted.get(key, 0) + found
    return counted, total


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
    triage: TriageFacts = field(default_factory=TriageFacts)


# The context fields a condition may name. Derived from the dataclass so a new
# field is usable the moment it is declared, and an old one cannot linger here
# after it is removed.
CONTEXT_NAMES: frozenset[str] = frozenset(StageContext.__dataclass_fields__)

# The fields of a ``StageResult`` a condition may read off ``stages.<key>``.
STAGE_RESULT_FIELDS: frozenset[str] = frozenset(StageResult.__dataclass_fields__)

# The fields of ``TriageFacts`` a condition may read off ``triage``.
TRIAGE_FIELDS: frozenset[str] = frozenset(TriageFacts.__dataclass_fields__)

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
        if _is_triage_lookup(node):
            if node.attr not in TRIAGE_FIELDS:
                fields = ", ".join(sorted(TRIAGE_FIELDS))
                raise ConditionError(f"triage has no field {node.attr!r}; it has: {fields}")
            return
        _check_stage_lookup(node)
        return
    if isinstance(node, ast.Subscript):
        if _is_hits_lookup(node):
            if not isinstance(node.slice, ast.Constant) or not isinstance(node.slice.value, str):
                raise ConditionError('triage.hits is read by a literal key: triage.hits["<key>"]')
            return
        _check_stage_lookup(node)
        return
    raise ConditionError(f"{_describe(node)} is not allowed in a condition")


def _is_triage_lookup(node: ast.Attribute) -> bool:
    """``triage.<field>``: one level into the pack's facts, and nothing deeper."""
    return isinstance(node.value, ast.Name) and node.value.id == "triage"


def _is_hits_lookup(node: ast.Subscript) -> bool:
    """``triage.hits[...]``: the one subscript into the pack's facts."""
    holder = node.value
    return isinstance(holder, ast.Attribute) and _is_triage_lookup(holder) and holder.attr == "hits"


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
    if isinstance(node, ast.Subscript) and _is_hits_lookup(node):
        assert isinstance(node.slice, ast.Constant)  # noqa: S101 — guaranteed by _check
        return int(ctx.triage.hits.get(str(node.slice.value), 0))
    if isinstance(node, ast.Attribute):
        if _is_triage_lookup(node):
            return getattr(ctx.triage, node.attr)
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
        _check(tree)
    except SyntaxError as exc:
        raise ConditionError(f"cannot parse the condition: {exc.msg}") from exc
    except (RecursionError, MemoryError) as exc:
        # Python's parser and the checker both descend the tree, and an
        # expression nested thousands deep (``not not not …``) runs out of
        # interpreter stack before either finishes. That is still operator
        # text that cannot be a condition, and it is refused as one rather
        # than escaping as a server error.
        raise ConditionError("the condition is nested too deeply to parse") from exc
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
    # the other half of what an operator gets wrong. The dummy carries a
    # reputation count, because ``None`` compares to nothing and the field is
    # there to be compared to a number.
    try:
        _resolve(tree, StageContext(triage=TriageFacts(reputation_malicious=0)))
    except ConditionError as exc:
        return [str(exc)]
    except Exception as exc:  # noqa: BLE001 — an unexpected failure is still the operator's
        return [f"the condition could not be evaluated: {exc}"]
    return []


def stage_references(expr: str) -> list[str]:
    """Every stage key ``expr`` reads through ``stages.<key>.<field>``, in order.

    Empty for an empty or a refused expression: a condition the checker
    refuses is reported as that, not also as the stages it would have read.
    """
    if not (expr or "").strip():
        return []
    try:
        tree = parse_condition(expr)
    except ConditionError:
        return []
    keys: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and not _is_triage_lookup(node):
            holder = node.value
            if isinstance(holder, (ast.Attribute, ast.Subscript)):
                key = _stage_key(holder)
                if key not in keys:
                    keys.append(key)
    return keys


def constant_truth(expr: str) -> bool | None:
    """What ``expr`` evaluates to when it names nothing, else ``None``.

    A condition that reads no field of the sample or the run has one answer
    for every sample, and that answer is known without guessing. Anything
    that names a field is ``None``: what it will be is the sample's business.
    """
    if not (expr or "").strip():
        return None
    try:
        tree = parse_condition(expr)
    except ConditionError:
        return None
    if any(isinstance(node, ast.Name) for node in ast.walk(tree)):
        return None
    try:
        return bool(_resolve(tree, StageContext()))
    except (ConditionError, RecursionError):
        return None
