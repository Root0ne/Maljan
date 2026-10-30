"""Which decoded text the code passes, whole, to an API argument of a known role.

A string the sample keeps encoded has no standing as an indicator by its shape:
a decoded ``curl/7.88.1`` the code never hands to anything reads as a user
agent as well as one an HTTP session sends. What gives a decoded text a role is
the call it is passed to. This module reads that, without running anything,
from what the run's tools already stated, and binds a text only where every
link is stated:

* **The text and its blob.** A static decoder's result (kind
  ``decoded_strings``) states the text, its encoding and each place in the code
  that loads the address of its encoded bytes (``references``).
* **The program's own routine.** That address is passed to a call
  (``passed_to``) to a function of the file, not to an import: an API given the
  encoded bytes reads the encoded bytes.
* **The frame slot it was given.** The decoder followed a frame slot that call
  was given as another argument to the next call that receives it
  (``output_passed_to`` with a frame slot; a return value is not the slot's
  contents and binds nothing). The routine wrote the text there, and the
  decoder states that nothing on the way could change it
  (``contents_unchanged``, on the hop and on ``inside``), so the next call
  receives the text; a hop without that statement binds nothing.
* **The API.** That next call is the API, or calls a function of the file whose
  first call receiving the argument is the API (``inside``, one function
  deep). The API is the import the file's table names at the call, or the
  slot a function index entry (kind ``function_index``) names; a slot two
  names fill, or two entries name differently, names nothing.
* **The argument's role.** The argument-role table
  (``data/api_argument_roles_v1.json``) says which argument of which API takes
  a whole value of a role (a mutex's name, a file's path, a user agent), and
  the text encoding the API reads; a text in another encoding is not the
  value the API reads and binds nothing.

The text and the call are about one file: a decoder entry and a function index
entry are read together only when the file argument their tools declare
(``carved``, else the sample) is the same. Every binding keeps the chain that
made it, which every surface that publishes the value states. A text no chain
binds stays a candidate. Linear in the ledger: each entry is read once, each
reference once, and every lookup is a dict.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from maljan.core.paths import resolve_data
from maljan.core.tool_declarations import select
from maljan.reporting import tool_kinds
from maljan.reporting.models import BoundValue

DEFAULT_ARGUMENT_ROLES = "data/api_argument_roles_v1.json"

# The source an IOC row of a bound value is recorded under.
BOUND_SOURCE = "call_argument"

# The consumer whose declared kinds are read here
# (``core.builtin_declarations.CONSUMER_KINDS``), and the two of them: a
# static decoder's results and the function index's slot names.
_CONSUMER = "call_bindings"
_DECODED = "decoded_strings"
_INDEX = "function_index"
# A decoder's rows and each row's text where its declaration names neither.
_ROWS = "/results/*"
_TEXT = "/text"
# How the decoder states a hop that followed a frame slot (``call_sites``):
# the slot's contents, which the routine wrote the text into. Any other hop
# (its return value) is not the text.
_FRAME_SLOT = "the frame slot ["
# The decoder's own check that the slot reaches the call as the routine left
# it (``call_sites``: no store into it, no call that could write it, on the
# way); a hop stated without it, as one stored before it existed, binds nothing.
_UNCHANGED = "contents_unchanged"
# The declared argument role a tool reads a produced file under, as a kind is
# declaration vocabulary (``analysis.coverage.LAYER_ROLE``).
_CARVED_ROLE = "carved"
_CARVED_ARGUMENT = "carved_path"


@dataclass(frozen=True)
class ArgumentRole:
    """What one argument of one API takes: a role, its indicator kind, the parameter's name."""

    role: str
    kind: str
    words: str
    parameter: str
    text: str
    # A condition on another argument of the same call: its position, its
    # parameter's name and the constant values it must hold at the call.
    when: tuple[int, str, frozenset[int]] | None = None


@lru_cache(maxsize=4)
def argument_roles(path: str = DEFAULT_ARGUMENT_ROLES) -> dict[str, dict[int, ArgumentRole]]:
    """``{api: {argument position: role}}`` from the argument-role table."""
    document = json.loads(resolve_data(path).read_text(encoding="utf-8"))
    roles = document.get("roles") or {}
    table: dict[str, dict[int, ArgumentRole]] = {}
    for api, spec in (document.get("apis") or {}).items():
        text = str(spec.get("text") or "")
        for position, argument in (spec.get("arguments") or {}).items():
            role = str(argument.get("role") or "")
            said = roles.get(role) or {}
            if not said.get("kind"):
                continue
            when = argument.get("when")
            table.setdefault(str(api), {})[int(position)] = ArgumentRole(
                role=role,
                kind=str(said["kind"]),
                words=str(said.get("words") or ""),
                parameter=str(argument.get("name") or ""),
                text=text,
                when=(
                    int(when["argument"]),
                    str(when.get("name") or ""),
                    frozenset(int(v) for v in when.get("values") or ()),
                )
                if isinstance(when, Mapping)
                else None,
            )
    return table


@lru_cache(maxsize=4)
def browser_user_agent_prefixes(path: str = DEFAULT_ARGUMENT_ROLES) -> tuple[str, ...]:
    """The prefixes the common browsers' user agents begin with, from the argument-role table."""
    document = json.loads(resolve_data(path).read_text(encoding="utf-8"))
    listed = (document.get("browser_user_agents") or {}).get("prefixes") or ()
    return tuple(str(prefix) for prefix in listed if prefix)


@dataclass(frozen=True)
class BrowserTokens:
    """The tokens the common browsers send in their user agents, casefolded."""

    products: frozenset[str]
    # A product a browser sends only beside one of the products named for it.
    products_beside: Mapping[str, frozenset[str]]
    words: frozenset[str]
    # A comment word a browser sends only right after one of the words named for it.
    words_after: Mapping[str, frozenset[str]]
    # The bare language codes an older browser placed in its comment.
    languages: frozenset[str]
    # A comment word after which the comment's entries name the device.
    device_follows: frozenset[str]
    # The well-known crawlers' own names, each with the domains its info URL is at.
    crawlers: Mapping[str, tuple[str, ...]]


@lru_cache(maxsize=4)
def browser_user_agent_tokens(path: str = DEFAULT_ARGUMENT_ROLES) -> BrowserTokens:
    """The product names and comment words of the browsers' user agents, from the table."""
    document = json.loads(resolve_data(path).read_text(encoding="utf-8"))
    listed = (document.get("browser_user_agents") or {}).get("tokens") or {}

    def _set(words: Any) -> frozenset[str]:
        return frozenset(str(word).casefold() for word in words or () if word)

    def _bound(key: str) -> dict[str, frozenset[str]]:
        return {str(name).casefold(): _set(by) for name, by in (listed.get(key) or {}).items()}

    return BrowserTokens(
        products=_set(listed.get("products")),
        products_beside=_bound("products_beside"),
        words=_set(listed.get("comment_words")),
        words_after=_bound("comment_words_after"),
        languages=_set(listed.get("languages")),
        device_follows=_set(listed.get("device_follows")),
        crawlers={
            str(name).casefold(): tuple(sorted(_set(domains)))
            for name, domains in (listed.get("crawlers") or {}).items()
        },
    )


# The characters a product token takes besides letters and digits (RFC 9110, tchar).
_TCHAR = frozenset("!#$%&'*+-.^_`|~")
_DIGITS = "0123456789"
_VERSION_CHARS = frozenset(_DIGITS + "._")
# What a version after a word's ``/`` or ``:`` holds past its leading digit.
_VERSION_TAIL_CHARS = frozenset(_DIGITS + "._-")
_UPPER = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def _is_product(text: str) -> bool:
    name, _, version = text.partition("/")
    return all(
        part and all(c.isascii() and (c.isalnum() or c in _TCHAR) for c in part)
        for part in ((name, version) if "/" in text else (name,))
    )


def _all_digits(text: str) -> bool:
    return bool(text) and all(c in _DIGITS for c in text)


def _is_version_word(word: str) -> bool:
    """``5.1``, ``10_15_7`` or a build such as ``15E148``: a version, not a word."""
    if word[:1].isdigit() and all(c in _VERSION_CHARS for c in word):
        return True
    # A build: digits, one capital letter, digits.
    rest = word.lstrip(_DIGITS)
    return len(rest) < len(word) and rest[:1] in _UPPER and _all_digits(rest[1:])


def _is_version_tail(tail: str) -> bool:
    """What a word's ``/`` or ``:`` is followed by when it is that word's version."""
    return tail[:1].isdigit() and all(c in _VERSION_TAIL_CHARS for c in tail)


def _is_locale(word: str, languages: frozenset[str]) -> bool:
    """``en-US``, or a bare language code the table lists: the locale an older browser sent."""
    primary, dash, region = word.partition("-")
    if not dash:
        return word in languages
    return (
        len(primary) == 2
        and primary.isascii()
        and primary.isalpha()
        and primary.islower()
        and len(region) == 2
        and region.isascii()
        and region.isalpha()
    )


def _comment_word_is_known(word: str, previous: str, tokens: BrowserTokens) -> bool:
    if word[0].isdigit():
        return _is_version_word(word)
    if _is_locale(word, tokens.languages):
        return True
    folded = word.casefold()
    if folded in tokens.words:
        return True
    if folded in tokens.words_after:
        # Xbox One: the word is a browser's only right after its own.
        return previous.casefold() in tokens.words_after[folded]
    for separator in ("/", ":"):
        if separator in folded:
            # A word's own version after it: rv:121.0, Trident/7.0; never rv:evil.
            head, _, tail = folded.partition(separator)
            return head in tokens.words and _is_version_tail(tail)
    # A version run onto the word: InfoPath.2, SLCC2, GTB7.5.
    return folded.rstrip("0123456789._") in tokens.words


def _crawler(entry: str, tokens: BrowserTokens) -> str:
    """The listed crawler a whole product or comment entry is, ``""`` for none.

    ``name``, ``name/<version>`` or ``name <version>``: the crawler's own token,
    with no more than its version beside it.
    """
    text = " ".join(entry.split()).casefold()
    if text in tokens.crawlers:
        return text
    name, slash, tail = text.partition("/")
    if slash:
        return name if name in tokens.crawlers and _is_version_tail(tail) else ""
    name, _, version = text.rpartition(" ")
    return name if name in tokens.crawlers and _is_version_word(version) else ""


def _is_crawler_info_url(entry: str, crawler: str, tokens: BrowserTokens) -> bool:
    """``+http://host/page`` at the crawler's own domain, as its own token names it."""
    words = entry.split()
    if len(words) != 1:
        return False
    scheme, separator, rest = words[0].removeprefix("+").partition("://")
    if not separator or scheme.casefold() not in ("http", "https"):
        return False
    host = rest
    for end in "/?#:":
        host = host.split(end, 1)[0]
    host = host.casefold()
    return any(host == domain or host.endswith("." + domain) for domain in tokens.crawlers[crawler])


def _user_agent_parts(text: str) -> list[tuple[str, str]] | None:
    """The header's products and comments in order, or None where it is not its grammar.

    One pass over the text: a comment runs to the first ``)`` after its ``(``, and
    a nested or unclosed comment, a backslash in one, or a product holding a
    character no token takes reads as no header at all.
    """
    parts: list[tuple[str, str]] = []
    i, end = 0, len(text)
    while i < end:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "(":
            close = text.find(")", i + 1)
            if close < 0:
                return None
            body = text[i + 1 : close]
            if "(" in body or "\\" in body:
                return None
            parts.append(("comment", body))
            i = close + 1
        else:
            j = i
            while j < end and not text[j].isspace() and text[j] != "(":
                j += 1
            product = text[i:j]
            if not _is_product(product):
                return None
            parts.append(("product", product))
            i = j
    return parts


def _product_is_known(name: str, names: frozenset[str], tokens: BrowserTokens) -> bool:
    """A browser's product, or one it sends beside its own (QQBrowser's ``Core``)."""
    if name in tokens.products:
        return True
    beside = tokens.products_beside.get(name)
    return beside is not None and not beside.isdisjoint(names)


def distinctive_user_agent_token(value: Any) -> str:
    """The first token a browser-shaped user agent carries that the browsers do not send.

    ``""`` for one that does not begin as the browsers' do, for one whose every
    product and comment token the browsers send, and for one that cannot be read
    as the header's grammar: each stays a browser's, unpublished. A well-known
    crawler's own token, and its info URL at its own domain right after it, is not
    distinctive: an indicator on it would match that crawler's traffic.
    """
    text = str(value or "")
    if not text.startswith(browser_user_agent_prefixes()):
        return ""
    parts = _user_agent_parts(text)
    if not parts:
        return ""
    tokens = browser_user_agent_tokens()
    names = frozenset(part.split("/", 1)[0].casefold() for kind, part in parts if kind == "product")
    crawler = ""  # the crawler whose token came last, whose info URL may follow
    for kind, part in parts:
        if kind == "product":
            crawler = _crawler(part, tokens)
            name = part.split("/", 1)[0].casefold()
            if not crawler and not _product_is_known(name, names, tokens):
                return part
            continue
        for entry in (entry for entry in part.replace(",", ";").split(";") if entry.strip()):
            if crawler and _is_crawler_info_url(entry, crawler, tokens):
                crawler = ""
                continue
            crawler = ""
            words = entry.split()
            if words[0].casefold() in tokens.device_follows:
                break  # the rest of the comment names the device
            if all(
                _comment_word_is_known(word, words[i - 1] if i else "", tokens)
                for i, word in enumerate(words)
            ):
                continue
            crawler = _crawler(entry, tokens)
            if not crawler:
                return entry.strip()
        crawler = ""
    return ""


def reads_as_a_browser_user_agent(value: Any) -> bool:
    """Whether a user agent reads as the common browsers' own: no pattern is written for it.

    It begins as theirs do and carries no token they do not send
    (:func:`distinctive_user_agent_token`).
    """
    text = str(value or "")
    return text.startswith(browser_user_agent_prefixes()) and not distinctive_user_agent_token(text)


# Why a bound user agent that reads as a browser's is not published.
BROWSER_LIKE = (
    "but it begins as the common browsers' user agents do, and an indicator for it would "
    "match their ordinary traffic"
)


def carries_its_own_token(token: str) -> str:
    """Why a bound user agent that begins as a browser's is published all the same."""
    return (
        f"it begins as the common browsers' user agents do, but carries '{token}', "
        "a token their own user agents do not send"
    )


def _field(obj: Any, name: str) -> Any:
    return obj.get(name) if isinstance(obj, Mapping) else getattr(obj, name, None)


def _entry_id(entry: Any) -> str:
    return str(_field(entry, "id") or _field(entry, "entry_id") or "")


def _file_of(entry: Any, facts: Any) -> str:
    """The produced file an entry's call read, ``""`` for the sample itself."""
    arguments = getattr(facts, "arguments", None) or {}
    name = str(arguments.get(_CARVED_ROLE) or _CARVED_ARGUMENT)
    args = _field(entry, "args")
    return str(args.get(name) or "") if isinstance(args, Mapping) else ""


def _number(text: Any) -> int | None:
    try:
        return int(str(text), 16)
    except (TypeError, ValueError):
        return None


def _slot_names(ledger: Iterable[Any]) -> dict[tuple[str, int], tuple[str, str] | None]:
    """``{(file, slot RVA): (name, entry)}`` index entries name; ``None`` where they disagree."""
    names: dict[tuple[str, int], tuple[str, str] | None] = {}
    for entry in ledger:
        if not tool_kinds.is_of(entry, _CONSUMER) or tool_kinds.kind_of(entry) != _INDEX:
            continue
        structured = _field(entry, "structured")
        if not isinstance(structured, Mapping):
            continue
        base = _number(structured.get("image_base"))
        resolved = structured.get("resolved_slots")
        if base is None or not isinstance(resolved, Mapping):
            continue
        where = _file_of(entry, tool_kinds.facts_of(entry))
        entry_id = _entry_id(entry)
        ambiguous = structured.get("ambiguous_slots")
        for address in ambiguous if isinstance(ambiguous, Mapping) else ():
            at = _number(address)
            if at is not None:
                names[(where, at - base)] = None
        for address, name in resolved.items():
            at = _number(address)
            if at is None or not name:
                continue
            key = (where, at - base)
            held = names.get(key, ...)
            if held is ...:
                names[key] = (str(name), entry_id)
            elif held is not None and held[0] != str(name):
                names[key] = None
    return names


def _api_of(
    callee: Any, where: str, slots: Mapping[tuple[str, int], tuple[str, str] | None]
) -> tuple[str, str, str, str] | None:
    """``(api, imported as, slot, naming entry)`` for a stated callee, or ``None``."""
    if not isinstance(callee, Mapping):
        return None
    imported = str(callee.get("import") or "")
    if imported:
        # ``KERNEL32.dll!CreateMutexW``; an import by ordinal names no function.
        name = imported.rsplit("!", 1)[-1] if "!" in imported else ""
        return (name, imported, "", "") if name else None
    slot = _number(callee.get("slot"))
    if slot is None:
        return None
    named = slots.get((where, slot))
    if named is None:
        return None
    return named[0], "", hex(slot), named[1]


def _bindings_of_reference(
    text: str,
    encoding: str,
    reference: Mapping[str, Any],
    where: str,
    slots: Mapping[tuple[str, int], tuple[str, str] | None],
    roles: Mapping[str, Mapping[int, ArgumentRole]],
) -> Iterable[tuple[ArgumentRole, dict[str, Any]]]:
    """The role and the chain for each API argument one reference's text reaches whole."""
    first = reference.get("passed_to")
    if not isinstance(first, Mapping):
        return
    callee = first.get("callee")
    if not isinstance(callee, Mapping) or callee.get("import") or not callee.get("function"):
        return
    then = first.get("output_passed_to")
    if not isinstance(then, Mapping):
        return
    if not str(then.get("followed") or "").startswith(_FRAME_SLOT):
        return
    if then.get(_UNCHANGED) is not True:
        return
    inside = then.get("inside")
    for call, through in ((then, None), (inside, then)):
        if not isinstance(call, Mapping) or call.get(_UNCHANGED) is not True:
            continue
        api = _api_of(call.get("callee"), where, slots)
        if api is None:
            continue
        try:
            position = int(call.get("argument") or 0)
        except (TypeError, ValueError):
            continue
        role = (roles.get(api[0]) or {}).get(position)
        if role is None or role.text != encoding or not _holds(role, call):
            continue
        yield (
            role,
            {
                "value": text,
                "api": api[0],
                "imported_as": api[1],
                "slot": api[2],
                "named_by": api[3],
                "argument": position,
                "site": str(reference.get("at") or ""),
                "function": str(reference.get("function") or ""),
                "decoder_call": str(first.get("call_at") or ""),
                "call_at": str(call.get("call_at") or ""),
                "inside": str(call.get("function") or "") if through is not None else "",
                "reaches": str(through.get("call_at") or "") if through is not None else "",
                "reaches_argument": int(through.get("argument") or 0) if through is not None else 0,
                "fall_through": bool(then.get("fall_through"))
                or bool(through is not None and call.get("fall_through")),
            },
        )


def _holds(role: ArgumentRole, call: Mapping[str, Any]) -> bool:
    """Whether the call meets the role's condition: the constant its argument holds there."""
    if role.when is None:
        return True
    position, _name, values = role.when
    stated = call.get("constants")
    held = _number(stated.get(str(position))) if isinstance(stated, Mapping) else None
    return held is not None and held in values


def bound_values_from_ledger(
    ledger: Iterable[Any] | None, roles: Mapping[str, Mapping[int, ArgumentRole]] | None = None
) -> list[BoundValue]:
    """Every decoded text the code passes whole to an API argument of a known role, once each.

    One binding per value and kind, the first in ledger order: the entry that
    stated it first, its first reference that binds.
    """
    entries = list(ledger or ())
    table = argument_roles() if roles is None else roles
    slots = _slot_names(entries)
    out: list[BoundValue] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        if not tool_kinds.is_of(entry, _CONSUMER):
            continue
        facts = tool_kinds.facts_of(entry)
        if facts is None or facts.kind != _DECODED:
            continue
        structured = _field(entry, "structured")
        if not isinstance(structured, Mapping):
            continue
        # The rows and each row's text where the declaration points them.
        rows = select(structured, facts.rows or _ROWS)
        text_path = facts.values.get("text") or _TEXT
        where = _file_of(entry, facts)
        entry_id = _entry_id(entry)
        named = tool_kinds.stated_name(entry, facts)
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            found = select(row, text_path)
            text = str(found[0] or "") if found else ""
            encoding = str(row.get("encoding") or "")
            if not text.strip():
                continue
            for reference in row.get("references") or []:
                if not isinstance(reference, Mapping):
                    continue
                for role, chain in _bindings_of_reference(
                    text, encoding, reference, where, slots, table
                ):
                    key = (role.kind, text)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(
                        BoundValue(
                            kind=role.kind,
                            role=role.role,
                            role_words=role.words,
                            parameter=role.parameter,
                            entry=entry_id,
                            tool=named,
                            offset=str(row.get("offset") or ""),
                            **chain,
                        )
                    )
    return out


def _record(report: Any) -> list[BoundValue]:
    stored = _field(report, "bound_values") or []
    return [
        row if isinstance(row, BoundValue) else BoundValue.model_validate(row) for row in stored
    ]


def bound_value(report: Any, kind: str, value: str) -> BoundValue | None:
    """The report's binding of ``value`` as ``kind``, or ``None``: the value is matched whole."""
    text = str(value or "")
    for row in _record(report):
        if row.kind == kind and row.value == text:
            return row
    return None


def binding_context(bound: BoundValue) -> str:
    """The row's context: the argument and the call, in a few words."""
    parameter = f" ({bound.parameter})" if bound.parameter else ""
    return f"argument {bound.argument}{parameter} of {bound.api} at {bound.call_at}"


def binding_words(bound: BoundValue) -> str:
    """The chain that binds a value, as every surface that publishes it states it."""
    via = (
        f"the import {bound.imported_as}"
        if bound.imported_as
        else f"the slot {bound.slot} that {bound.named_by} names"
    )
    reaches = (
        f"argument {bound.reaches_argument} of the call at {bound.reaches} to the function at "
        f"{bound.inside}, and inside that function argument {bound.argument} of the call at "
        f"{bound.call_at}"
        if bound.inside
        else f"argument {bound.argument} of the call at {bound.call_at}"
    )
    path = ", on the path where every conditional jump falls through" if bound.fall_through else ""
    said = (
        f"the code passes it to {bound.api} as argument {bound.argument}"
        + (f" ({bound.parameter}, {bound.role_words})" if bound.parameter else "")
        + f": {bound.tool or 'the decoder'} decoded it in {bound.entry}"
        + (f" (blob at file offset {bound.offset})" if bound.offset else "")
        + f", loaded at {bound.site}"
        + (f" in the function at {bound.function}" if bound.function else "")
        + f" and given to the routine called at {bound.decoder_call}; the frame slot that "
        f"routine was given is {reaches}, through {via}{path}"
    )
    return said
