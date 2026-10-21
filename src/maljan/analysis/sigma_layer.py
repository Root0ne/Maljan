"""Sigma rule matching over sandbox telemetry, behind ``tools.rules.sigma_match``.

Sigma and YARA are complementary:
  - YARA: looks at the sample's binary content.
  - Sigma: looks at structured telemetry events (process creation, registry
    writes) built from the sandbox report (Sysmon/Windows-Event-Log shaped).

An agent reaches this through the ``analysis`` sidecar and decides what a match
means. It is no longer a pipeline stage that mints claims of its own: a rule
firing is a fact a tool reports, and whether it supports a technique is the
analyst's reading of it.

The tool feeds Sigma structured events built from real sandbox telemetry via
``build_events_from_sandbox`` + ``scan_events`` (strict field matching). The
``scan_report_text``/``scan_log_lines`` prose path is retained only for
tests/back-compat — it must NOT be used on analyst prose, because
``strict=False`` matches rule values against arbitrary text and manufactures
false detections.

Design decisions:
  - Self-contained: rules are parsed via pySigma into an AST and evaluated
    in-process; no out-of-process Sigma backend is required.
  - Graceful degradation: if the rules directory is missing, an empty
    instance is returned and the caller keeps running.
  - Compiled once, indexed: each rule is compiled when the corpus loads,
    identical rules are evaluated as one, and a rule meets only the events
    its platform and the fields it tests let it match (``SigmaLayer.scan``).

Rule set source: data/sigma_rules/**/*.yml, or ``MALJAN_SIGMA_RULES_DIR``.
    Sigma YAML format: https://sigmahq.io/docs/basics/rules.html

Usage:
    layer = SigmaLayer.from_default_rules()
    matches = layer.scan_events(events, log_source="sandbox")
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# pySigma imports
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from maljan.analysis.technique_ids import sigma_technique_ids
from maljan.core.logger import logger
from maljan.providers.call_arguments import pick_argument

# ---------------------------------------------------------------------------
# Default rules directory
# ---------------------------------------------------------------------------

_DEFAULT_RULES_DIR = Path(__file__).resolve().parents[3] / "data" / "sigma_rules"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SigmaMatch:
    """One Sigma rule match result.

    ``technique_id`` is ``None`` when the matched Sigma rule carries no
    ``attack.t####`` tag — previously this surfaced as the literal string
    ``"T0000"``, which polluted the STIX bundle with an invalid MITRE
    AttackPattern SDO.

    ``rule_platforms``: the canonical platform bucket(s) the rule
    declared via ``logsource.product``. Empty when the rule is generic.
    Reported with the match so the agent reading it can weigh a Windows-only
    rule that fired on a Linux sample for itself.

    ``level`` is the rule author's own ``level`` (``informational``, ``low``,
    ``medium``, ``high``, ``critical``), lower-cased, or empty for a rule that
    declares none. It is the only severity a match has: ``confidence`` is the
    rule's maturity status turned into a number and says nothing about how bad
    the behaviour is.
    """

    rule_id: str
    rule_title: str
    technique_id: str | None
    confidence: float
    log_source: str
    matched_fields: dict[str, str] = field(default_factory=dict)
    rule_platforms: tuple[str, ...] = ()
    level: str = ""

    @property
    def evidence_ref(self) -> str:
        """Short evidence reference — used as ISR ClaimEvidence.evidence_ref."""
        fields_str = ", ".join(f"{k}={v}" for k, v in list(self.matched_fields.items())[:3])
        return (
            f"Sigma rule '{self.rule_title}' matched: {fields_str}"
            if fields_str
            else f"Sigma rule '{self.rule_title}' matched"
        )

    @property
    def claim_text(self) -> str:
        """Description used as ISR ClaimEvidence.claim."""
        tech = self.technique_id if self.technique_id else "unmapped"
        return (
            f"Sigma rule detection: {self.rule_title} (technique {tech}, source={self.log_source})"
        )


# ---------------------------------------------------------------------------
# In-Memory AST Evaluator
#
# Each rule is compiled once, when the corpus loads: its condition parsed and
# every value turned into its regular expression. pySigma re-parses a
# condition on every access to ``SigmaCondition.parsed`` and the evaluator
# used to build each regex per (rule, event) pair, so with four thousand rules
# Python's regex cache never held them and a thousand events took minutes.
#
# The compiled rule evaluates exactly as the per-pair evaluator did: the same
# regular expression per value, the same order over conditions, children and
# event fields, the same matched-fields dict, and an error (a value whose
# regex does not compile, a condition pySigma cannot parse) raised at the same
# point of the evaluation it was raised at before.
# ---------------------------------------------------------------------------


def _rule_level(rule: SigmaRule) -> str:
    """The rule author's ``level``, lower-cased, or empty when it declares none."""
    level = getattr(rule, "level", None)
    name = getattr(level, "name", None) if level is not None else None
    return str(name).lower() if name else ""


def _regex_source(val: Any, strict: bool) -> tuple[str, int]:
    """``(expression, flags)`` a Sigma value is matched with (compiled case-insensitive too)."""
    if isinstance(val, SigmaRegularExpression):
        # The rule's own flags travel with its expression; a rule that asked
        # for none gets none (``.`` stops at a line break, as it wrote it).
        names = {getattr(flag, "name", "") for flag in getattr(val, "flags", ()) or ()}
        flags = (re.MULTILINE if "MULTILINE" in names else 0) | (
            re.DOTALL if "DOTALL" in names else 0
        )
        return str(val.regexp), flags
    if isinstance(val, SigmaNumber):
        pat = re.escape(str(val.number))
        return (f"^{pat}$" if strict else pat), 0
    if isinstance(val, SigmaString):
        pattern = ""
        for part in val.s:
            if part == SpecialChars.WILDCARD_MULTI:
                pattern += "(?s:.*)"  # a wildcard reads across a line break
            elif part == SpecialChars.WILDCARD_SINGLE:
                pattern += "(?s:.)"
            else:
                pattern += re.escape(str(part))
        return (f"^{pattern}$" if strict else pattern), 0
    pat = re.escape(str(val))
    return (f"^{pat}$" if strict else pat), 0


def _is_path_anchored(val: Any) -> bool:
    """Whether a value names a path: a literal part of it holds a path separator."""
    if isinstance(val, SigmaString):
        return any(isinstance(part, str) and ("\\" in part or "/" in part) for part in val.s)
    if isinstance(val, SigmaRegularExpression):
        text = str(val.regexp)
        return "\\\\" in text or "/" in text
    return False


@dataclass(frozen=True)
class EventContext:
    """What a reader knows about one event beyond its fields.

    An event given with a context is read as what a sandbox collected: a
    field it does not hold was not collected, so a rule's test of that field
    is neither true nor false but unknown. ``categories`` are the Sigma
    logsource categories the event is (``process_creation``, ...); a rule
    declaring a category meets only the events of that category. ``pathless``
    are the (lower-cased) fields that hold a file name where the source would
    hold a path: a test of a path on one of them is unknown too.

    An event given without a context is read as complete, as Sigma reads a log
    line: a field it does not hold is absent.
    """

    categories: frozenset[str]
    pathless: frozenset[str] = frozenset()


class _Event:
    """One event read once for every rule: its fields in order, by lower-cased name."""

    __slots__ = ("by_field", "context", "items")

    def __init__(
        self, items: tuple[tuple[str, str], ...], context: EventContext | None = None
    ) -> None:
        self.items = items
        self.context = context
        by_field: dict[str, list[tuple[str, str]]] = {}
        for key, value in items:
            by_field.setdefault(key.lower(), []).append((key, value))
        self.by_field = by_field


_Matcher = Callable[[_Event], "dict[str, str] | None"]
# Three-valued: True, False, or None for unknown (Kleene's logic).
_Tri = Callable[[_Event], "bool | None"]


def _raiser(exc: BaseException) -> _Matcher:
    """A matcher that raises ``exc`` wherever the evaluation reaches it, as before."""

    def matcher(_event: _Event) -> dict[str, str] | None:
        raise exc.with_traceback(None)

    return matcher


def _tri_raiser(exc: BaseException) -> _Tri:
    def tri(_event: _Event) -> bool | None:
        raise exc.with_traceback(None)

    return tri


def _never(_event: _Event) -> dict[str, str] | None:
    return None


def _tri_never(_event: _Event) -> bool | None:
    return False


@dataclass
class _Shape:
    """What compiling one condition tree for one mode found.

    ``matcher`` reads an event as complete (two-valued); ``tri`` reads it as
    collected (three-valued, for an event with a context). ``key`` is the
    tree's structure with every value's regex source, the rule's identity for
    deduplication: two rules with equal keys evaluate identically on every
    event. ``needs`` is the set of (lower-cased) fields of which an event must
    hold at least one for ``matcher`` to match, ``None`` when it can match (or
    raise) without any. ``broken`` says a part of the tree raises when the
    evaluation reaches it. ``path_fields`` are the fields a value naming a
    path is tested on; ``tested`` every field the tree tests, as written.
    """

    matcher: _Matcher
    tri: _Tri
    key: Any
    needs: frozenset[str] | None
    broken: bool = False
    path_fields: frozenset[str] = frozenset()
    tested: frozenset[str] = frozenset()


def _compile_null(field: str) -> _Shape:
    """``field: null``, per the Sigma specification: the field is absent, or empty.

    The value used to be matched as the text of the ``SigmaNull`` object, which
    no event holds, so a ``ParentImage: null`` filter never applied and a rule
    excluding parentless processes fired on every one of them. On an event
    read as collected, a field it does not hold makes the test unknown.
    """
    wanted = field.lower()

    def absent_or_empty(event: _Event) -> dict[str, str] | None:
        held = event.by_field.get(wanted)
        if not held:
            return {}
        for _name, value in held:
            if value == "":
                return {field: value}
        return None

    def tri(event: _Event) -> bool | None:
        held = event.by_field.get(wanted)
        if held is None:
            return None
        return any(value == "" for _name, value in held)

    return _Shape(absent_or_empty, tri, ("null", field), None, tested=frozenset({field}))


def _compile_leaf(node: ConditionFieldEqualsValueExpression, strict: bool) -> _Shape:
    field = node.field or None
    if strict and field and isinstance(node.value, SigmaNull):
        return _compile_null(field)
    anchored = bool(field) and _is_path_anchored(node.value)
    path_fields = frozenset({field.lower()}) if field and anchored else frozenset()
    tested = frozenset({field or "keywords"})
    try:
        source, flags = _regex_source(node.value, strict)
        search = re.compile(source, re.IGNORECASE | flags).search
    except Exception as exc:  # noqa: BLE001 — raised where the evaluation reaches it
        return _Shape(
            _raiser(exc), _tri_raiser(exc), ("error", id(node)), None, True, path_fields, tested
        )
    key = ("leaf", field, source, flags)
    if not strict:
        label = field or "raw"

        def loose(event: _Event) -> dict[str, str] | None:
            for _key, value in event.items:
                if search(value):
                    return {label: value}
            return None

        def loose_tri(event: _Event) -> bool | None:
            return loose(event) is not None

        return _Shape(loose, loose_tri, key, None, path_fields=path_fields, tested=tested)
    if field is None:

        def anywhere(event: _Event) -> dict[str, str] | None:
            for name, value in event.items:
                if search(value):
                    return {name: value}
            return None

        def anywhere_tri(event: _Event) -> bool | None:
            # A keyword not found in what was collected may be in what was not.
            return True if anywhere(event) is not None else None

        return _Shape(anywhere, anywhere_tri, key, None, path_fields=path_fields, tested=tested)
    wanted = field.lower()

    def on_field(event: _Event) -> dict[str, str] | None:
        for _name, value in event.by_field.get(wanted, ()):
            if search(value):
                return {field: value}
        return None

    def on_field_tri(event: _Event) -> bool | None:
        held = event.by_field.get(wanted)
        if held is None:
            return None
        if anchored and event.context is not None and wanted in event.context.pathless:
            return None
        return any(search(value) for _name, value in held)

    return _Shape(
        on_field, on_field_tri, key, frozenset({wanted}), path_fields=path_fields, tested=tested
    )


def _tri_and(children: list[_Tri]) -> _Tri:
    def tri(event: _Event) -> bool | None:
        result: bool | None = True
        for child in children:
            res = child(event)
            if res is False:
                return False
            if res is None:
                result = None
        return result

    return tri


def _tri_or(children: list[_Tri]) -> _Tri:
    def tri(event: _Event) -> bool | None:
        result: bool | None = False
        for child in children:
            res = child(event)
            if res is True:
                return True
            if res is None:
                result = None
        return result

    return tri


def _compile_node(node: Any, strict: bool) -> _Shape:
    if isinstance(node, ConditionAND | ConditionOR):
        shapes = [_compile_node(arg, strict) for arg in node.args]
        children = [s.matcher for s in shapes]
        tris = [s.tri for s in shapes]
        broken = any(s.broken for s in shapes)
        paths = frozenset().union(*(s.path_fields for s in shapes))
        tested = frozenset().union(*(s.tested for s in shapes))
        if isinstance(node, ConditionAND):

            def both(event: _Event) -> dict[str, str] | None:
                combined: dict[str, str] = {}
                for child in children:
                    res = child(event)
                    if res is None:
                        return None
                    combined.update(res)
                return combined

            known = [s.needs for s in shapes if s.needs is not None]
            needs = min(known, key=len) if known else None
            key: Any = ("and", tuple(s.key for s in shapes))
            return _Shape(both, _tri_and(tris), key, needs, broken, paths, tested)

        def either(event: _Event) -> dict[str, str] | None:
            for child in children:
                res = child(event)
                if res is not None:
                    return res
            return None

        union: frozenset[str] | None = frozenset()
        for shape in shapes:
            union = None if union is None or shape.needs is None else union | shape.needs
        key = ("or", tuple(s.key for s in shapes))
        return _Shape(either, _tri_or(tris), key, union, broken, paths, tested)

    if isinstance(node, ConditionNOT):
        inner = _compile_node(node.args[0], strict)
        child = inner.matcher
        inner_tri = inner.tri

        def negated(event: _Event) -> dict[str, str] | None:
            return {} if child(event) is None else None

        def negated_tri(event: _Event) -> bool | None:
            res = inner_tri(event)
            return None if res is None else not res

        return _Shape(
            negated,
            negated_tri,
            ("not", inner.key),
            None,
            inner.broken,
            inner.path_fields,
            inner.tested,
        )

    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _compile_leaf(node, strict)

    # Any other node never matches (a keyword list, an unresolved identifier).
    return _Shape(_never, _tri_never, ("never",), frozenset())


class _CompiledRule:
    """A rule's conditions compiled once per mode, on first use of that mode."""

    def __init__(self, rule: SigmaRule) -> None:
        self.rule = rule
        self._shapes: dict[bool, _Shape] = {}

    def shape(self, strict: bool) -> _Shape:
        held = self._shapes.get(strict)
        if held is None:
            held = self._shapes[strict] = self._compile(strict)
        return held

    def _compile(self, strict: bool) -> _Shape:
        try:
            # ``getattr``, not attribute access. A rule whose detection block
            # does not parse gets an ``EmptySigmaDetections``, which has no
            # ``parsed_condition`` at all — 272 of the 4241 rules under
            # ``data/sigma_rules`` are in that state, and reading the
            # attribute raised ``AttributeError`` out of the first one the
            # scan reached.
            parsed = getattr(self.rule.detection, "parsed_condition", None) or []
            if not self.rule.detection or not parsed:
                return _Shape(_never, _tri_never, ("never",), frozenset())
        except Exception as exc:  # noqa: BLE001 — raised where the evaluation reaches it
            return _Shape(_raiser(exc), _tri_raiser(exc), ("error", id(self)), None, True)
        shapes: list[_Shape] = []
        for condition in parsed:
            try:
                tree = condition.parsed
            except Exception as exc:  # noqa: BLE001 — raised where the evaluation reaches it
                shapes.append(
                    _Shape(_raiser(exc), _tri_raiser(exc), ("error", id(condition)), None, True)
                )
                continue
            shapes.append(_compile_node(tree, strict))
        children = [s.matcher for s in shapes]

        # Multiple conditions are rare; any one matching is enough.
        def any_condition(event: _Event) -> dict[str, str] | None:
            for child in children:
                res = child(event)
                if res is not None:
                    return res
            return None

        broken = any(s.broken for s in shapes)
        needs: frozenset[str] | None = frozenset()
        for shape in shapes:
            needs = None if needs is None or shape.needs is None else needs | shape.needs
        key: Any = ("rule", tuple(s.key for s in shapes))
        if broken:
            # A rule that raises somewhere raises at the point the evaluation
            # reaches it, which an index skipping events would move: it meets
            # every event, and shares its result with no other rule.
            needs, key = None, ("broken", id(self))
        paths = frozenset().union(*(s.path_fields for s in shapes))
        tested = frozenset().union(*(s.tested for s in shapes))
        tri = _tri_or([s.tri for s in shapes])
        return _Shape(any_condition, tri, key, needs, broken, paths, tested)


def _prepared(event: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """An event's fields in order, each name and value as the evaluation reads it."""
    return tuple((str(key), str(value)) for key, value in event.items())


class SigmaMemoryEvaluator:
    """Engine that evaluates one pySigma rule in-process against Python dicts."""

    def __init__(self, rule: SigmaRule) -> None:
        self.rule = rule
        self._compiled = _CompiledRule(rule)

    def evaluate(self, event: dict[str, str], strict: bool = True) -> dict[str, str] | None:
        """Try the rule against the given event dict.

        Args:
            event: Event log dict to scan.
            strict: True for exact match (anchored regex), False for search (substring).

        Returns:
            Matched-fields dict on hit, otherwise None.
        """
        return self._compiled.shape(strict).matcher(_Event(_prepared(event)))


@dataclass
class SigmaScan:
    """One evaluation of the corpus over a batch of events.

    ``hits`` holds, in corpus order, each rule that fired as its position in
    the corpus, the rule, and the fields of the first event it fired on.
    ``evaluations`` counts the rule-event evaluations run, both those the
    index left to decide hits and those that found a rule unknown;
    ``rule_errors`` the rules that raised; ``filtered`` the rules the platform
    dropped.

    ``not_evaluable`` maps the position of an event given with a context to
    the rules that did not fire and that ended unknown on it, each with the
    fields that made it so (a field the event was not collected with, as
    written, or ``"<field> path"`` for a path tested on a field holding a file
    name only). ``no_events_of`` counts, per logsource the events never are
    (``category``, or ``service:<name>`` / ``product:<name>`` for a rule
    declaring no category), the rules not evaluated for want of such events.
    """

    hits: list[tuple[int, SigmaRule, dict[str, str]]] = field(default_factory=list)
    evaluations: int = 0
    rule_errors: int = 0
    filtered: int = 0
    not_evaluable: dict[int, list[tuple[int, tuple[str, ...]]]] = field(default_factory=dict)
    no_events_of: dict[str, int] = field(default_factory=dict)


@dataclass
class _Group:
    """Rules whose compiled shapes and logsources are identical: evaluated once.

    ``source`` is the rules' logsource as (category, service, product), lower-cased.
    """

    shape: _Shape
    needs: frozenset[str] | None
    source: tuple[str, str, str]
    members: list[int]


@dataclass
class _Plan:
    """A mode's groups, and the group each corpus position belongs to."""

    groups: list[_Group]
    group_of: list[int]


def _source_label(source: tuple[str, str, str], categories: frozenset[str]) -> str | None:
    """Why a rule of logsource ``source`` meets no event of ``categories``; ``None`` if it does.

    A rule declaring a category meets the events of that category, from an
    operating system (or no product at all); a rule declaring no category but
    a service (``security``, ``sysmon``) or a product that is not an operating
    system (``zeek``, ``azure``) meets none of the events a sandbox report is
    read into; a rule declaring neither meets every event.
    """
    category, service, product = source
    foreign_product = bool(product) and product not in _OS_PRODUCTS
    if category:
        if category not in categories:
            return category
        return f"product:{product}" if foreign_product else None
    if service:
        return f"service:{service}"
    if foreign_product:
        return f"product:{product}"
    return None


def _logsource(rule: SigmaRule) -> tuple[str, str, str]:
    """A rule's logsource as (category, service, product), lower-cased, empty where undeclared."""
    source = rule.logsource
    if source is None:
        return ("", "", "")
    category, service, product = (
        str(getattr(source, name, None) or "").strip().lower()
        for name in ("category", "service", "product")
    )
    return (category, service, product)


def _unknown_fields(shape: _Shape, event: _Event) -> tuple[str, ...]:
    """The fields a rule tests that made it unknown on ``event``.

    Each field it tests that the event was not collected with, as the rule
    writes it, and ``"<field> path"`` for each field it tests a path on that
    holds a file name only.
    """
    pathless = event.context.pathless if event.context is not None else frozenset()
    missing = [
        name for name in shape.tested if name == "keywords" or name.lower() not in event.by_field
    ]
    pathed = [
        f"{name} path"
        for name in shape.tested
        if name.lower() in shape.path_fields and name.lower() in pathless
    ]
    return tuple(sorted(missing) + sorted(pathed))


# ---------------------------------------------------------------------------
# Log source classifier
# ---------------------------------------------------------------------------


def _classify_log_source(log_source: str, product: str) -> str:
    """Normalize log source identifier to canonical string."""
    ls = log_source.lower()
    pr = product.lower()
    if "sysmon" in ls or (pr == "windows" and "process" in ls):
        return "sysmon"
    if "security" in ls or "4688" in ls or "4624" in ls:
        return "windows_security"
    if "zeek" in ls or "bro" in ls:
        return "zeek"
    if "suricata" in ls:
        return "suricata"
    return "generic"


# ---------------------------------------------------------------------------
# Platform compatibility
# ---------------------------------------------------------------------------


# Network-log products: same story — they expect Zeek/Suricata-style
# structured events, not text scans of analyst report blobs.
_NETWORK_LOG_PRODUCTS = frozenset(
    {
        "zeek",
        "suricata",
        "modsecurity",
        "fortios",
        "cisco",
        "paloalto",
        "netflow",
        "rpc_firewall",
    }
)

# Direct one-to-one match with our canonical SampleIdentity.platform values.
_OS_PRODUCTS = frozenset({"windows", "linux", "macos", "android", "ios"})


def _normalise_product(product: str | None) -> str:
    """Lowercase + strip the SigmaRule.logsource.product value."""
    if not product:
        return ""
    return str(product).strip().lower()


def _is_rule_compatible(rule_product: str | None, sample_platform: str | None) -> bool:
    """Return True when the rule should be evaluated against this sample.

    ``sample_platform`` semantics:

    * ``None`` → legacy / no-filter caller (older tests / direct CLI
      usage). Keep every rule so existing behaviour is preserved.
    * ``"unknown"`` → caller explicitly declared "platform inference
      failed" (the bootstrap could not disambiguate). Drop non-generic rules
      rather than report a Windows rule firing on a sample nobody could
      identify. Generic rules still run.
    * any concrete platform string → exact match against the rule's
      ``logsource.product``.

    Resolution order for non-``None`` sample_platform:
      1. rule_product empty → generic; compatible with every sample.
      2. rule_product in network-log set → drop (no network-log layer
         today).
      3. rule_product in OS set → keep only when sample matches.
      4. anything else (an unmapped product — cloud/SaaS rules and the like) →
         drop conservatively.
    """
    product = _normalise_product(rule_product)
    if sample_platform is None:
        return True  # legacy / no-filter caller
    if not product:
        return True  # generic rule, always compatible
    if product in _NETWORK_LOG_PRODUCTS:
        return False
    sp = sample_platform.strip().lower()
    if sp == "" or sp == "unknown":
        return False  # explicit unknown → drop non-generic rules
    if product in _OS_PRODUCTS:
        return product == sp
    return False


def _rule_platforms_tuple(product: str | None) -> tuple[str, ...]:
    """Tuple form of the rule's declared platform — propagated to ISR."""
    p = _normalise_product(product)
    if not p:
        return ()
    return (p,)


# ---------------------------------------------------------------------------
# SigmaLayer
# ---------------------------------------------------------------------------


class SigmaLayer:
    """The compiled Sigma corpus, behind ``tools.rules.sigma_match``.

    Uses pySigma to parse rules into an AST and the in-tree
    ``SigmaMemoryEvaluator`` to evaluate events.
    """

    def __init__(self, collection: SigmaCollection) -> None:
        self._collection = collection
        # Filter out SigmaCorrelationRule; we only evaluate SigmaRule
        self._evaluators: list[tuple[SigmaRule, SigmaMemoryEvaluator]] = [
            (rule, SigmaMemoryEvaluator(rule))
            for rule in collection.rules
            if isinstance(rule, SigmaRule)
        ]
        # Platform filter telemetry.
        self._filtered_count: int = 0
        # Rules that raised while being evaluated. A corpus is third-party data
        # and a rule in it can be malformed in ways pySigma only discovers at
        # evaluation time; before this counter existed one such rule aborted
        # the whole scan and the layer contributed nothing, which reads exactly
        # like a sample that matched no rules.
        self._rule_errors: int = 0
        self._products: list[str] = [
            str(rule.logsource.product) if rule.logsource and rule.logsource.product else ""
            for rule, _evaluator in self._evaluators
        ]
        self._sources: list[tuple[str, str, str]] = [
            _logsource(rule) for rule, _evaluator in self._evaluators
        ]
        # The logsource index: per sample platform, which rules it keeps.
        self._compatible_for: dict[str | None, list[bool]] = {}
        # Per mode, the rules grouped by identical compiled shape and
        # logsource, and the field index over the groups (strict mode only: a
        # loose scan matches a value against every field). Strict is compiled
        # now, at load.
        self._plans: dict[bool, _Plan] = {}
        self._plan(True)

    def _plan(self, strict: bool) -> _Plan:
        held = self._plans.get(strict)
        if held is not None:
            return held
        groups: list[_Group] = []
        group_of: list[int] = []
        by_key: dict[Any, int] = {}
        for position, (_rule, evaluator) in enumerate(self._evaluators):
            shape = evaluator._compiled.shape(strict)
            source = self._sources[position]
            key = (source, shape.key)
            gid = by_key.get(key)
            if gid is None:
                gid = by_key[key] = len(groups)
                groups.append(_Group(shape, shape.needs if strict else None, source, []))
            groups[gid].members.append(position)
            group_of.append(gid)
        plan = self._plans[strict] = _Plan(groups, group_of)
        return plan

    def _compatible(self, sample_platform: str | None) -> list[bool]:
        held = self._compatible_for.get(sample_platform)
        if held is None:
            held = self._compatible_for[sample_platform] = [
                _is_rule_compatible(product, sample_platform) for product in self._products
            ]
        return held

    @property
    def distinct_rule_count(self) -> int:
        """How many distinct compiled rules the corpus holds (identical rules evaluated once)."""
        return len(self._plan(True).groups)

    def scan(
        self,
        events: Iterable[dict[str, Any]],
        *,
        strict: bool = True,
        sample_platform: str | None = None,
        contexts: Iterable[EventContext | None] | None = None,
    ) -> SigmaScan:
        """Every rule that fires on ``events``, each at most once, in corpus order.

        A rule meets only the events that can match it: an event identical to
        an earlier one is evaluated once (it can never be a rule's first
        match), a rule whose platform the sample does not share meets none,
        identical rules are evaluated as one, and in strict mode a rule meets
        only the events that hold one of the fields it needs. For events
        without a context, the hits, their matched fields and the rules that
        raise are those of evaluating every rule against every event in order.

        ``contexts`` (strict mode), one per event, says what each event was
        collected as (:class:`EventContext`): a rule then meets only the events
        of its logsource, a rule fires on such an event only where its
        condition is true in three-valued logic (a test of a field the event
        was not collected with, or of a path on a field holding a file name
        only, is unknown), and each rule that did not fire is listed under
        ``not_evaluable`` for the events it ended unknown on.
        """
        out = SigmaScan()
        plan = self._plan(strict)
        compatible = self._compatible(sample_platform)
        listed = list(events)
        given = list(contexts) if contexts is not None and strict else []
        if given and len(given) != len(listed):
            raise ValueError("scan: one context per event, or none")
        seen: set[tuple[tuple[tuple[str, str], ...], EventContext | None]] = set()
        prepared: list[_Event] = []
        origin: list[int] = []
        for index, event in enumerate(listed):
            items = _prepared(event)
            context = given[index] if given else None
            if (items, context) not in seen:
                seen.add((items, context))
                prepared.append(_Event(items, context))
                origin.append(index)
        holding: dict[str, list[int]] = {}
        for position, read in enumerate(prepared):
            for name in read.by_field:
                holding.setdefault(name, []).append(position)
        every = range(len(prepared))
        fits_for: dict[frozenset[str], list[bool]] = {}

        def fits(gid: int, event: _Event) -> bool:
            if event.context is None:
                return True
            cats = event.context.categories
            row = fits_for.get(cats)
            if row is None:
                row = fits_for[cats] = [_source_label(g.source, cats) is None for g in plan.groups]
            return row[gid]

        # The logsources no event of the stream is: their rules are not run.
        unprovided: dict[int, str] = {}
        if prepared and all(e.context is not None for e in prepared):
            stream: frozenset[str] = frozenset().union(
                *(e.context.categories for e in prepared if e.context is not None)
            )
            for gid, group in enumerate(plan.groups):
                label = _source_label(group.source, stream)
                if label is not None:
                    unprovided[gid] = label

        results: dict[int, dict[str, str] | BaseException | None] = {}
        unknown: dict[int, list[int]] = {}
        for gid, group in enumerate(plan.groups):
            if gid in unprovided or not any(compatible[m] for m in group.members):
                continue
            candidates: Iterable[int]
            if group.needs is None:
                candidates = every
            elif len(group.needs) == 1:
                (only,) = group.needs
                candidates = holding.get(only, ())
            else:
                candidates = sorted(set().union(*(holding.get(f, ()) for f in group.needs)))
            matcher, tri = group.shape.matcher, group.shape.tri
            result: dict[str, str] | BaseException | None = None
            for position in candidates:
                read = prepared[position]
                if not fits(gid, read):
                    continue
                out.evaluations += 1
                try:
                    res = matcher(read)
                    # A two-valued match on a collected event is a hit only
                    # where the condition is true, not merely unknown.
                    if res is not None and read.context is not None and tri(read) is not True:
                        res = None
                except Exception as exc:  # noqa: BLE001 — one bad rule, not the corpus
                    result = exc
                    break
                if res is not None:
                    result = res
                    break  # Each rule fires at most once per event batch.
            results[gid] = result
            if result is None and not group.shape.broken:
                for position in every:
                    read = prepared[position]
                    if read.context is None or not fits(gid, read):
                        continue
                    out.evaluations += 1
                    if tri(read) is None:
                        unknown.setdefault(gid, []).append(position)
        for position, (rule, _evaluator) in enumerate(self._evaluators):
            if not compatible[position]:
                out.filtered += 1
                continue
            gid = plan.group_of[position]
            if gid in unprovided:
                label = unprovided[gid]
                out.no_events_of[label] = out.no_events_of.get(label, 0) + 1
                continue
            result = results.get(gid)
            if isinstance(result, BaseException):
                out.rule_errors += 1
                logger.debug("SigmaLayer: rule %s could not be evaluated (%s).", rule.id, result)
            elif result is not None:
                out.hits.append((position, rule, dict(result)))
            else:
                shape = plan.groups[gid].shape
                for at in unknown.get(gid, ()):
                    out.not_evaluable.setdefault(origin[at], []).append(
                        (position, _unknown_fields(shape, prepared[at]))
                    )
        return out

    def _match(
        self, rule: SigmaRule, matched_fields: dict[str, str], log_source: str
    ) -> SigmaMatch:
        product = str(rule.logsource.product) if rule.logsource and rule.logsource.product else ""
        return SigmaMatch(
            rule_id=str(rule.id) if rule.id else "unknown",
            rule_title=str(rule.title),
            technique_id=self._extract_technique_id(rule),
            confidence=self._get_confidence(rule),
            log_source=_classify_log_source(log_source, product),
            matched_fields=matched_fields,
            rule_platforms=_rule_platforms_tuple(product),
            level=_rule_level(rule),
        )

    @classmethod
    def from_rules_dir(cls, rules_dir: Path) -> SigmaLayer:
        if not rules_dir.exists():
            logger.warning(
                "SigmaLayer: rules directory not found: %s — running without Sigma rules.",
                rules_dir,
            )
            return cls(SigmaCollection(init_rules=[]))

        all_rules = []
        yaml_files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))
        loaded = 0
        for yf in yaml_files:
            try:
                rule_col = SigmaCollection.from_yaml(
                    yf.read_text(encoding="utf-8"), collect_errors=True
                )
                all_rules.extend(rule_col.rules)
                loaded += 1
            except Exception as e:
                logger.debug("SigmaLayer: Failed to parse %s: %s", yf, e)

        collection = SigmaCollection(
            init_rules=all_rules  # type: ignore[arg-type]
        )

        logger.info(
            "SigmaLayer: loaded %d rules from %d YAML files in %s using pySigma.",
            len(collection.rules),
            loaded,
            rules_dir,
        )
        return cls(collection)

    @classmethod
    def from_default_rules(cls) -> SigmaLayer:
        return cls.from_rules_dir(_DEFAULT_RULES_DIR)

    @property
    def rule_count(self) -> int:
        return len(self._collection.rules)

    def techniques_covered(self) -> set[str]:
        covered: set[str] = set()
        for rule in self._collection.rules:
            covered.update(sigma_technique_ids({"tags": [str(tag) for tag in rule.tags]}))
        return covered

    def _extract_technique_id(self, rule: SigmaRule) -> str | None:
        """Return the MITRE ATT&CK technique ID for a Sigma rule, or None.

        ``None`` and not the ``"T0000"`` sentinel this once returned: a
        placeholder id reads as a technique everywhere it goes, and the one
        thing an untagged rule is certain about is that it names no technique.
        Every consumer accepts ``Optional[str]`` and treats it as untagged.

        Read by ``sigma_technique_ids``: a tactic tag (``attack.ta0005``) and a
        group or software tag start with ``attack.`` too, and none of them is
        a technique.
        """
        found = sigma_technique_ids({"tags": [str(tag) for tag in rule.tags]})
        return found[0] if found else None

    def _get_confidence(self, rule: SigmaRule) -> float:
        status = str(rule.status.name).lower() if rule.status else "experimental"
        return {
            "stable": 0.88,
            "test": 0.80,
            "experimental": 0.75,
            "deprecated": 0.60,
        }.get(status, 0.75)

    def scan_events(
        self,
        events: list[dict[str, str]],
        log_source: str = "generic",
        sample_platform: str | None = None,
    ) -> list[SigmaMatch]:
        """Scan structured (JSON/dict) logs. Platform-aware."""
        if not self._collection.rules or not events:
            return []
        scan = self.scan(events, strict=True, sample_platform=sample_platform)
        self._filtered_count += scan.filtered
        self._rule_errors += scan.rule_errors
        self._warn_on_rule_errors("scan_events")
        return [self._match(rule, fields, log_source) for _pos, rule, fields in scan.hits]

    def scan_log_lines(
        self,
        log_lines: list[str],
        log_source: str = "generic",
        sample_platform: str | None = None,
    ) -> list[SigmaMatch]:
        """Scan unstructured raw text lines. (Backward compatibility path.)"""
        if not self._collection.rules or not log_lines:
            return []
        events = [{"_raw": line} for line in log_lines]
        scan = self.scan(events, strict=False, sample_platform=sample_platform)
        self._filtered_count += scan.filtered
        self._rule_errors += scan.rule_errors
        self._warn_on_rule_errors("scan_log_lines")
        return [self._match(rule, fields, log_source) for _pos, rule, fields in scan.hits]

    def scan_report_text(
        self,
        report_text: str,
        sample_platform: str | None = None,
    ) -> list[SigmaMatch]:
        if not report_text or not self._collection.rules:
            return []
        lines = report_text.split("\n")
        return self.scan_log_lines(lines, log_source="generic", sample_platform=sample_platform)

    def _warn_on_rule_errors(self, what: str) -> None:
        """One warning per scan, not one per rule.

        272 unparsable rules would otherwise be 272 log lines per scan, which
        is how a real signal gets filtered out by whoever reads the logs.
        """
        if self._rule_errors:
            logger.warning(
                "SigmaLayer: %d of %d rules could not be evaluated during %s; "
                "the scan used the rest of the corpus.",
                self._rule_errors,
                self.rule_count,
                what,
            )

    @property
    def last_rule_errors(self) -> int:
        """How many rules raised during the most-recent scan suite.

        Non-zero means the corpus contains rules this evaluator cannot read;
        the scan still contributes what the rest of the corpus matched.
        """
        return self._rule_errors

    @property
    def last_filtered_count(self) -> int:
        """How many rules the most-recent scan suite dropped for platform.

        Caller pattern is ``reset_filter_stats() -> scan_*() -> last_filtered_count``;
        the counter accumulates across scan_events / scan_log_lines / scan_report_text
        within one logical scan suite so the judge node can log a single
        aggregate number per pipeline run.
        """
        return self._filtered_count

    def reset_filter_stats(self) -> None:
        """Zero the rule-drop and rule-error counters before a fresh scan suite."""
        self._filtered_count = 0
        self._rule_errors = 0


# ---------------------------------------------------------------------------
# Telemetry -> Sysmon-shaped events (2026-07 deep re-architecture)
# ---------------------------------------------------------------------------


def _sandbox_arg_value(
    args: Any, names: tuple[str, ...], *, empty_held: bool = False
) -> str | None:
    """The value of the first of ``names``, in that order, a sandbox call's ``arguments`` carry.

    Handles both the direct-key form (``{"FullName": "..."}``) and the
    name/value-pair form (``{"name": "FullName", "value": "..."}``); the order
    of ``names`` decides, never the order the call lists its arguments in.
    With ``empty_held`` an empty value is a value (``""``), not none.
    """
    if not isinstance(args, list):
        return None
    if empty_held:
        value = pick_argument(args, names, accept=lambda v: v is not None)
    else:
        value = pick_argument(args, names, accept=lambda v: v not in (None, ""))
    return None if value is None else str(value)


# The note the tool's answer carries for the rules an event left unknown.
NOT_EVALUABLE = (
    "not evaluable: these rules test a field the sandbox did not collect for the event, "
    "or a path on an image the report names only by its file name (image path unknown); "
    "they neither fired nor were found false there, and their silence is not a negative"
)


@dataclass(frozen=True)
class SandboxEvents:
    """The Sysmon-shaped events of a sandbox report, what each is, and where an image has no path.

    ``kinds`` names each event's kind (``schemas.sandbox_document.SIGMA_EVENT_KINDS``).
    ``image_path_unknown`` maps the position of each event whose ``Image`` or
    ``ParentImage`` holds a file name only, because the report holds no path
    for that process, to those fields.
    """

    events: list[dict[str, str]]
    image_path_unknown: dict[int, tuple[str, ...]] = field(default_factory=dict)
    kinds: list[str] = field(default_factory=list)

    def contexts(self) -> list[EventContext]:
        """Each event's :class:`EventContext`: its logsource categories and pathless fields."""
        from maljan.schemas.sandbox_document import SIGMA_EVENT_KINDS

        return [
            EventContext(
                frozenset(SIGMA_EVENT_KINDS[kind][0]),
                frozenset(f.lower() for f in self.image_path_unknown.get(index, ())),
            )
            for index, kind in enumerate(self.kinds)
        ]


def _held(row: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    """The first of ``keys`` the row fills, else ``""`` where it holds one empty, else ``None``."""
    empty = False
    for key in keys:
        value = row.get(key)
        if value is None or isinstance(value, dict | list):
            continue
        text = str(value).strip()
        if text:
            return text
        empty = True
    return "" if empty else None


def _stated_pid(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _is_path(text: str) -> bool:
    return "\\" in text or "/" in text


def _process_image(proc: dict[str, Any]) -> tuple[str | None, bool]:
    """A process row's image (``None`` where the row holds none), and whether it is a full path.

    The path is the row's declared image-path field, or its name where the
    name is itself a path; otherwise the image is the name, never a path made
    up for it.
    """
    from maljan.schemas.sandbox_document import PROCESS_IMAGE_PATH_KEYS, PROCESS_NAME_KEYS

    name = _held(proc, PROCESS_NAME_KEYS)
    path = _held(proc, PROCESS_IMAGE_PATH_KEYS)
    if path and _is_path(path):
        return path, True
    if name and _is_path(name):
        return name, True
    if name:
        return name, False
    if path:
        return path, False
    return ("" if name == "" or path == "" else None), True


def _command_line(proc: dict[str, Any]) -> str | None:
    """The command line a process row holds, read through its declared places, or ``None``."""
    from maljan.schemas.sandbox_document import PROCESS_COMMAND_LINE_PATHS

    empty = False
    for path in PROCESS_COMMAND_LINE_PATHS:
        node: Any = proc
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        if node is None or isinstance(node, dict | list):
            continue
        text = str(node).strip()
        if text:
            return text
        empty = True
    return "" if empty else None


def _registry_kind(api: str) -> str | None:
    """The Sigma event kind of a registry call, by what it does to the key; ``None`` for a read."""
    if "Delete" in api:
        return "registry_delete"
    if "Set" in api:
        return "registry_set"
    if "Create" in api:
        return "registry_add"
    return None


def build_events_from_sandbox(sandbox_report: dict[str, Any] | None) -> list[dict[str, str]]:
    """The Sysmon-shaped events of :func:`read_sandbox_events`, without its notes."""
    return read_sandbox_events(sandbox_report).events


def read_sandbox_events(sandbox_report: dict[str, Any] | None) -> SandboxEvents:
    """Translate real sandbox telemetry into Sysmon-shaped events for strict
    Sigma evaluation.

    Sigma previously scanned concatenated analyst prose with
    ``strict=False``, which matched a rule's *values* against any text — e.g.
    the Ghidra tool name ``list_imports`` appearing in an analyst report
    satisfied a ``CommandLine|contains: list_imports`` rule and surfaced as a
    fake "CommandLine" detection. We now build structured events from actual
    process/registry telemetry and evaluate with ``strict=True`` so a rule only
    fires against the field it targets. No telemetry -> no events -> no matches
    (the correct outcome for static-only runs).

    Each event carries only the fields its kind collects
    (``schemas.sandbox_document.SIGMA_EVENT_KINDS``) that the report holds for
    it, an empty one as ``""``; a field it does not carry was not collected.
    A process row is read through the document's declared process fields
    (``PROCESS_*_KEYS``): ``Image`` where the row names an image, ``CommandLine``
    where it holds one, ``ParentImage`` where its parent id is a process the
    report lists. ``Image`` and ``ParentImage`` are the image's full path where
    the report holds one and the file name otherwise, and an event with a file
    name only is listed in ``image_path_unknown``. A registry event is read
    from each process's own calls and from the flat call list (a call both
    hold is read once); it carries ``TargetObject``, ``Details`` where the
    call has a value argument, and ``Image`` from the process that made it
    (listed in ``image_path_unknown`` where that image has no path).

    Fail-safe: any malformed input yields no events.
    """
    if not isinstance(sandbox_report, dict):
        return SandboxEvents([])
    from maljan.schemas.sandbox_document import (
        PROCESS_ID_KEYS,
        PROCESS_PARENT_KEYS,
        SIGMA_EVENT_KINDS,
        place,
    )

    events: list[dict[str, str]] = []
    kinds: list[str] = []
    unknown: dict[int, tuple[str, ...]] = {}

    def add(kind: str, event: dict[str, str | None]) -> None:
        declared = SIGMA_EVENT_KINDS[kind][1]
        held = {name: event[name] for name in declared if event.get(name) is not None}
        events.append({name: str(value) for name, value in held.items()})
        kinds.append(kind)

    # The neutral report's document (``schemas.sandbox_document``), its parts
    # read by name.
    procs = place(sandbox_report, "processes")
    image_of: dict[int, tuple[str | None, bool]] = {}
    if isinstance(procs, list):
        for proc in procs:
            if not isinstance(proc, dict):
                continue
            pid = _stated_pid(_held(proc, PROCESS_ID_KEYS))
            if pid:
                image_of[pid] = _process_image(proc)
        for proc in procs:
            if not isinstance(proc, dict):
                continue
            image, known = _process_image(proc)
            cmd = _command_line(proc)
            if image is None and cmd is None:
                continue
            ppid = _stated_pid(_held(proc, PROCESS_PARENT_KEYS))
            parent, parent_known = image_of.get(ppid, (None, True)) if ppid else (None, True)
            pathless = tuple(
                label
                for label, value, is_path in (
                    ("Image", image, known),
                    ("ParentImage", parent, parent_known),
                )
                if value and not is_path
            )
            if pathless:
                unknown[len(events)] = pathless
            add(
                "process_creation",
                {
                    "Image": image,
                    # The command line the report holds, or none: a name
                    # standing in for it made rules fire on a guess.
                    "CommandLine": cmd,
                    "ParentImage": parent,
                },
            )

    # The registry calls: each process's own, then the flat list's, a call
    # both hold read once. A call's process gives the event its ``Image``.
    def registry_event(call: dict[str, Any], image: tuple[str | None, bool] | None) -> None:
        api = str(call.get("api") or "").strip()
        kind = _registry_kind(api) if api.startswith("Reg") else None
        if kind is None:
            return
        args = call.get("arguments") or []
        key = _sandbox_arg_value(args, ("FullName", "Key", "lpSubKey", "key"))
        if not key:
            return
        details = _sandbox_arg_value(args, ("Buffer", "Value", "lpData", "data"), empty_held=True)
        owner, owner_known = image if image is not None else (None, True)
        if owner and not owner_known:
            unknown[len(events)] = ("Image",)
        add(kind, {"TargetObject": key, "Details": details, "Image": owner})

    def is_registry_write(call: Any) -> bool:
        if not isinstance(call, dict):
            return False
        api = str(call.get("api") or "").strip()
        return api.startswith("Reg") and _registry_kind(api) is not None

    def written(call: dict[str, Any]) -> str:
        """A call as written, to know it again in the other list."""
        try:
            return json.dumps(call, sort_keys=True, default=str)
        except (TypeError, ValueError):
            return repr(sorted(call.items(), key=lambda item: str(item[0])))

    # Each call read under a process, by object and by how many times its text
    # was read: a flat call is that call's copy while copies remain, and a
    # call of its own otherwise, so identical calls are never merged.
    read_ids: dict[int, str] = {}
    unmatched: Counter[str] = Counter()
    if isinstance(procs, list):
        for proc in procs:
            if not isinstance(proc, dict) or not isinstance(proc.get("calls"), list):
                continue
            maker = _process_image(proc)
            for call in proc["calls"]:
                if not is_registry_write(call) or id(call) in read_ids:
                    continue
                text = written(call)
                read_ids[id(call)] = text
                unmatched[text] += 1
                registry_event(call, maker)

    calls = place(sandbox_report, "calls")
    if isinstance(calls, list):
        for call in calls:
            if not is_registry_write(call):
                continue
            held = read_ids.get(id(call))
            text = held if held is not None else written(call)
            if unmatched[text] > 0:
                unmatched[text] -= 1
                continue  # the copy of a call already read under its process
            if held is not None:
                continue  # the very object, already read under its process
            pid = _stated_pid(_held(call, PROCESS_ID_KEYS))
            registry_event(call, image_of.get(pid) if pid else None)

    return SandboxEvents(events, unknown, kinds)
