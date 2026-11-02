"""The rule matches a ledger entry's answer holds, by declaration or by its shape.

A tool whose declaration names the ``signature_rules`` kind is read where it
says: its rows (``ToolFacts.rows``, else the ``matches`` field the tools of
the kind share) and each row's rule (``values.rule``, else the row's own
``rule`` or ``name``). A tool that declares no kind (an operator's server
with no declaration yet, an entry written before facts were stored) is read
by the shape of its answer alone, never by its name or its server's:

- a list under a key whose name says it holds matches or hits (``matches``,
  ``matched_rules``, ``rule_hits``), every row of which names its rule in a
  field so named (``rule``, ``rule_name``);
- a list or a map under a key whose name says both rules and matches
  (``matched_rules``), every member of which is one rule: a rule name
  holding its matched strings (``{"win_mutex": [{"offset": ...}]}``), or a
  rule name alone.

A list of rules with no word of matching over it (a tool listing the rules
it holds) is no match; a list one row of which names no rule is not read at
all. An empty match list is read as "no rule matched" only where its key
names rules or the answer beside it counts the rules it ran
(``rule_count``), so an empty list of anything else is never read as a rule
scan. A tool that declares another kind is read as that kind, never here.

What the shape reading finds is "rule matches" and nothing more: a byte
signature's, an event rule's, an indicator list's or a technique catalogue's
rows read alike, each named by its entry's tool and server, never sorted
into a kind. Every rule name is cleaned before anything states it
(:func:`clean_rule_name`): it comes from the tool's answer, which a sample's
contents can shape.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

# The declared kind read here: a rule-match list.
SIGNATURE_RULES = "signature_rules"
# The field the tools of the kind share for their rows, where a declaration names none.
_SHARED_ROWS = "matches"

# The words of a key's name: "matchedRules" and "matched_rules" are both
# "matched rules".
_KEY_WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
# A key naming what it holds as matches or hits, and one naming rules.
_MATCH_WORDS = frozenset({"match", "matches", "matched", "hit", "hits"})
_RULE_WORDS = frozenset({"rule", "rules"})
# The words that only say a field counts ("rule_count", "total_rules").
_COUNT_WORDS = frozenset({"count", "counts", "total", "totals", "num", "number", "n"})
# A rule name standing as a key or a plain list item: a rule identifier, its
# namespace before it where written ("ns:rule").
_RULE_IDENTIFIER = re.compile(r"[A-Za-z_][\w.:\-]{0,127}")
# The longest rule name read from a row's field.
_RULE_NAME_CHARS = 200
# What a stated rule name may hold: a cleaned name keeps word characters,
# dots, colons, hyphens and single spaces, at most this long; anything else
# (a semicolon, a quote, a line break) becomes "_".
_RULE_NAME_KEPT = 64
_NOT_IN_A_NAME = re.compile(r"[^\w.:\- ]")
# The words that open the debate's fact of rule-match answers
# (``pipeline.debate_facts``): a fact opening with them is that fact, never a
# count fact, whatever lines it quotes.
RULE_FACT_HEAD = "Every rule-match answer of the ledger, for the listed lines"
# Deliberately not read, so no other list is taken for a match (false
# negatives, by design): a rule name with spaces or other characters standing
# as a key or a bare list item ({"matched_rules": ["a b"]}); a map of rule
# names to counts ({"matched_rules": {"r1": 1}}); a list of rules each
# marked matched or not ({"rules": [{"name": "a", "matched": true}]}).
# How deep the answer is read for a match list, and how many of its nodes:
# a reading linear in the answer and bounded whatever its size.
_DEPTH = 6
_NODES = 20_000


@dataclass(frozen=True)
class RuleMatches:
    """One ledger entry's rule matches: one cleaned rule name per matched row.

    ``rule_count`` is how many rules the answer says it ran, where it says;
    ``declared`` whether the tool's declaration said where the rows are,
    rather than the answer's shape; ``source`` the name the declaration gives
    the tool (its display name or corroboration source), ``""`` for none.
    """

    entry_id: str
    tool: str
    server: str
    rules: tuple[str, ...]
    rule_count: int | None
    declared: bool
    source: str = ""


def clean_rule_name(name: Any) -> str:
    """A rule name as it may be stated: whitespace collapsed, other characters "_", capped.

    ``"?"`` for a name that holds nothing.
    """
    text = " ".join(str(name if name is not None else "").split())
    return _NOT_IN_A_NAME.sub("_", text)[:_RULE_NAME_KEPT].strip() or "?"


def is_rule_fact(fact: Any) -> bool:
    """Whether a debate fact is the one stating rule-match answers (:data:`RULE_FACT_HEAD`)."""
    return str(fact).startswith(RULE_FACT_HEAD)


def _words(key: Any) -> list[str]:
    return [word.lower() for word in _KEY_WORD.findall(str(key))]


def _counts_rules(key: Any, value: Any) -> bool:
    """Whether ``key`` and its ``value`` count rules: an integer under "rule_count", "rules"."""
    if not isinstance(value, int) or isinstance(value, bool):
        return False
    words = [w for w in _words(key) if w not in _COUNT_WORDS]
    return bool(words) and words[-1] in _RULE_WORDS


def _rule_count(node: Mapping[str, Any]) -> int | None:
    """The number of rules a mapping says were run, from its first field counting rules."""
    for key, value in node.items():
        if _counts_rules(key, value):
            return int(value)
    return None


def _row_rule(row: Mapping[str, Any]) -> str | None:
    """The rule a row names in a field so named (``rule``, ``rule_name``), or ``None``."""
    for key, value in row.items():
        if _words(key) in (["rule"], ["rule", "name"], ["rulename"]) and isinstance(value, str):
            name = value.strip()
            if name and len(name) <= _RULE_NAME_CHARS:
                return name
    return None


def _rule_identifier(value: Any) -> bool:
    return isinstance(value, str) and _RULE_IDENTIFIER.fullmatch(value) is not None


def _named_rule_rows(value: Any) -> list[str] | None:
    """The rules a list of rows names, each in its own rule field, or ``None``."""
    if not isinstance(value, list) or not all(isinstance(row, Mapping) for row in value):
        return None
    names = [_row_rule(row) for row in value]
    return None if any(name is None for name in names) else [str(name) for name in names]


def _keyed_rule_members(value: Any) -> list[str] | None:
    """The rules a list or a map of rules holds, each one member, or ``None``.

    A member is a rule name holding what it matched (a list or a map under
    the name), a one-name map of that, or a rule name alone.
    """
    if isinstance(value, Mapping):
        if all(_rule_identifier(k) and isinstance(v, (list, Mapping)) for k, v in value.items()):
            return [str(k) for k in value]
        return None
    if not isinstance(value, list):
        return None
    names: list[str] = []
    for member in value:
        if _rule_identifier(member):
            names.append(str(member))
        elif (
            isinstance(member, Mapping)
            and len(member) == 1
            and all(
                _rule_identifier(k) and isinstance(v, (list, Mapping)) for k, v in member.items()
            )
        ):
            names.append(str(next(iter(member))))
        else:
            return None
    return names


def _match_list(key: Any, value: Any, beside: Mapping[str, Any]) -> list[str] | None:
    """The rules ``value`` under ``key`` holds as matches, or ``None`` when it holds none."""
    words = set(_words(key))
    if not words & _MATCH_WORDS or not isinstance(value, (list, Mapping)):
        return None
    names_rules = bool(words & _RULE_WORDS)
    if not value:
        # An empty list is a rule scan's "nothing matched" only where it says
        # it is one: its key names rules, or the answer counts the rules run.
        return [] if names_rules or _rule_count(beside) is not None else None
    named = _named_rule_rows(value)
    if named is not None:
        return named
    return _keyed_rule_members(value) if names_rules else None


def shaped_rule_matches(answer: Any) -> tuple[list[str], int | None] | None:
    """``(rule per matched row, rules run)`` an answer's shape holds, or ``None`` for none.

    Every match list the answer holds (:func:`_match_list`) is read, at any
    depth up to a bound, in document order; ``rules run`` is the first count
    of rules beside one of them.
    """
    found = False
    rules: list[str] = []
    ran: int | None = None
    budget = [_NODES]

    def visit(node: Any, depth: int) -> None:
        nonlocal found, ran
        if depth > _DEPTH or budget[0] <= 0:
            return
        budget[0] -= 1
        if isinstance(node, list):
            for item in node:
                if isinstance(item, (Mapping, list)):
                    visit(item, depth + 1)
            return
        if not isinstance(node, Mapping):
            return
        for key, value in node.items():
            held = _match_list(key, value, node)
            if held is not None:
                found = True
                rules.extend(held)
                if ran is None:
                    ran = _rule_count(node)
            elif isinstance(value, (Mapping, list)):
                visit(value, depth + 1)

    visit(answer, 0)
    return (rules, ran) if found else None


def _field(entry: Any, name: str) -> Any:
    return entry.get(name) if isinstance(entry, Mapping) else getattr(entry, name, None)


def _answer(entry: Any) -> Any:
    """The entry's answer as an object: its structure, else its output read as JSON."""
    structured = _field(entry, "structured")
    if isinstance(structured, (Mapping, list)):
        return structured
    text = str(_field(entry, "output") or "").strip()
    if not text.startswith(("{", "[")):
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _declared_rules(answer: Any, facts: Any) -> list[str] | None:
    """The rules a declared rule tool's rows name, or ``None`` where it holds no rows."""
    from maljan.core.tool_declarations import first, select

    if facts.rows:
        rows = select(answer, facts.rows)
    elif isinstance(answer, Mapping) and isinstance(answer.get(_SHARED_ROWS), list):
        rows = list(answer[_SHARED_ROWS])
    else:
        return None
    path = (getattr(facts, "values", None) or {}).get("rule", "")
    names: list[str] = []
    for row in rows:
        named = first(row, path) if path else None
        if named is None and isinstance(row, Mapping):
            named = row.get("rule") or row.get("name")
        # An unnamed row is cleaned to "?".
        names.append(str(named) if isinstance(named, (str, int)) else "")
    return names


def rule_matches_of(entry: Any) -> RuleMatches | None:
    """The rule matches one ok ledger entry's answer holds, or ``None``.

    By the declaration the entry stored (``core.declared_reading``) where it
    names the kind; by the answer's shape where it names no kind; never for
    a tool declared as another kind, a failed call or a repeat of an earlier
    entry.
    """
    from maljan.core.declared_reading import facts_of, kind_free_facts

    if not _field(entry, "ok") or _field(entry, "repeated_of"):
        return None
    answer = _answer(entry)
    if answer is None:
        return None
    facts = facts_of(entry)
    kind = str(getattr(facts, "kind", "") or "") if facts is not None else ""
    if kind == SIGNATURE_RULES:
        rules = _declared_rules(answer, facts)
        ran = _rule_count(answer) if isinstance(answer, Mapping) else None
        declared = True
    elif kind:
        return None
    else:
        shaped = shaped_rule_matches(answer)
        rules, ran = shaped if shaped is not None else (None, None)
        declared = False
    if rules is None:
        return None
    source = ""
    if declared and facts is not None:
        # The display name is read without a kind (``kind_free_facts``).
        named = kind_free_facts(entry).display_name
        held = named or getattr(facts, "source", "") or ""
        source = clean_rule_name(held) if held else ""
    return RuleMatches(
        entry_id=str(_field(entry, "id") or _field(entry, "entry_id") or ""),
        tool=clean_rule_name(_field(entry, "tool")) if _field(entry, "tool") else "",
        server=clean_rule_name(_field(entry, "server")) if _field(entry, "server") else "",
        rules=tuple(clean_rule_name(rule) for rule in rules),
        rule_count=ran,
        declared=declared,
        source=source,
    )
