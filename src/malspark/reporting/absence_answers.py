"""What an agreement answer on an absence is read for: the absence a rewrite keeps, the
words a kept sentence is quoted on, and the failure counts a sentence states (T-568).

haiku12's limitations kept sentences the body said otherwise of, and its
rewrites kept the absence they were asked to correct: "the mutex name is not
passed in that call" stood beside "the code passes runnung as argument 3". The
agreement round now answers every sentence of the closing sections, and these
readers check the answer, never choose the sentence:

- :func:`negated_clauses` cuts a sentence into its clauses and keeps those that
  deny something; :func:`kept_absence` says which of them a rewrite states
  again, the same words on the same addresses, measured clause by clause;
- :func:`quote_stands` says whether a kept sentence's quote stands in a source
  the answer names, and :func:`carries_negation` whether it states an absence;
- :func:`failure_counts` reads the number a sentence gives failed calls, and
  :func:`count_disagrees` holds it to the ledger's count.

Each reader is one pass over its text.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from functools import lru_cache

# A word that denies something: what makes a clause an absence.
_NEGATION = re.compile(
    r"\b(?:no|not|never|none|nothing|nor|neither|without|cannot|unknown|unread|unestablished|"
    r"unnamed|unresolved|unidentified|unconfirmed|unrecovered|undetermined|unattributed|"
    r"unobserved|unshown)\b"
    r"|n't\b",
    re.IGNORECASE,
)
# Where a clause ends inside a sentence: a mark, a citation's bracket, or a word
# that joins two clauses.
_CLAUSE_SPLIT = re.compile(
    r"[;:,()\[\]—–]|\s(?:but|while|whereas|although|though|so|because|since)\s",
    re.IGNORECASE,
)
_WORD = re.compile(r"[a-z0-9][\w'-]*", re.IGNORECASE)
_ENTRY_ID = re.compile(r"^ev_\w+$", re.IGNORECASE)
_HEX = re.compile(r"^(?:0x)?[0-9a-f]+h?$", re.IGNORECASE)
# Words that say nothing of what a clause is about.
_STOPWORDS = frozenset(
    (
        "the and for that this with from was were are has have had been its which whether "
        "into onto any all also only then than there their they them these those such each "
        "our out per via would could can may might does did being what who how where when "
        "yet still here both either one some most more less same other not none nor neither "
        "never nothing without cannot but because"
    ).split()
)
# A word whose prefix denies it ("unnamed"): read as the word it denies ("named").
_DENIED_WORDS = frozenset(
    (
        "unknown unread unestablished unnamed unresolved unidentified unconfirmed "
        "unrecovered undetermined unattributed unobserved unshown"
    ).split()
)
# Two words are one where the shorter, at least this long, begins the longer
# ("name" and "named", "establish" and "established"); a longer word's prefixes
# are read up to :data:`_PREFIX_REACH` characters, so a long word costs no more.
_STEM_FLOOR = 4
_PREFIX_REACH = 24
# A clause's subject, the words before its negation, is the absence's own where it
# holds at least this many words.
_SUBJECT_WORDS = 2
# A word shorter than this names nothing on its own (pitfall: trivial values).
_WORD_FLOOR = 3
# The share of an absence's own words a rewrite's clause must state again, with a
# negation and on the same addresses, to state that absence again.
KEPT_SHARE = 0.8
# A clause needs at least this many words of its own to be compared at all.
_LEAST_WORDS = 2
# A quote shorter than this, once its spacing is read, quotes nothing.
QUOTE_FLOOR = 12


def carries_negation(text: str) -> bool:
    """Whether the text denies something (:data:`_NEGATION`)."""
    return _NEGATION.search(text) is not None


def clauses_of(sentence: str) -> list[str]:
    """The clauses of a sentence, in the order they stand, empty ones left out."""
    return [part.strip() for part in _CLAUSE_SPLIT.split(sentence) if part and part.strip()]


def negated_clauses(sentence: str) -> list[str]:
    """The clauses of a sentence that deny something, in the order they stand."""
    return [clause for clause in clauses_of(sentence) if carries_negation(clause)]


def _possessive_off(word: str) -> str:
    """A word without its possessive ending ("sandbox's": "sandbox")."""
    return word[:-2] if word.endswith("'s") else word


def content_words(text: str) -> frozenset[str]:
    """The words a clause is about: lowered, at least three characters, no stop word, no
    negation, no entry id and no bare number; a word its prefix denies as the word it
    denies ("unnamed": "named")."""
    out: set[str] = set()
    for match in _WORD.finditer(text):
        word = _possessive_off(match.group(0).lower().strip("'-"))
        if word in _DENIED_WORDS:
            word = word[2:]
        if len(word) < _WORD_FLOOR or word in _STOPWORDS or _ENTRY_ID.match(word):
            continue
        if word.isdigit():
            continue
        out.add(word)
    return frozenset(out)


class _Said:
    """A rewrite clause's words, read so a word of an absence is found in it whole or by
    a shared beginning (:data:`_STEM_FLOOR`), in time linear in the words."""

    def __init__(self, words: frozenset[str]) -> None:
        self.words = words
        self.prefixes = {
            word[:end]
            for word in words
            for end in range(_STEM_FLOOR, min(len(word), _PREFIX_REACH) + 1)
        }

    def holds(self, word: str) -> bool:
        if word in self.words or (len(word) >= _STEM_FLOOR and word in self.prefixes):
            return True
        if word.endswith("s") and word[:-1] in self.words:
            return True  # "apis" in "API"
        if "-" in word:
            # "file-mode" is not "file": a hyphenated word is held whole or not at all.
            return False
        return any(
            word[:end] in self.words for end in range(_STEM_FLOOR, min(len(word), _PREFIX_REACH))
        )

    def count(self, words: Iterable[str]) -> int:
        """How many of ``words`` the text holds."""
        return sum(1 for word in words if self.holds(word))


def _subject(clause: str) -> frozenset[str]:
    """The words of a clause before its first negation: what it denies something of."""
    found = _NEGATION.search(clause)
    return content_words(clause[: found.start()]) if found else frozenset()


def _denied(clause: str) -> str:
    """The first word of a clause after its first negation: what it denies ("passed" of
    "the mutex name is not passed in that call"), or ``""``."""
    found = _NEGATION.search(clause)
    if not found:
        return ""
    for word in _ordered_words(clause[found.end() :]):
        return word
    return ""


def _ordered_words(text: str) -> Iterator[str]:
    """:func:`content_words`'s words in the order they stand."""
    for match in _WORD.finditer(text):
        word = _possessive_off(match.group(0).lower().strip("'-"))
        if word in _DENIED_WORDS:
            word = word[2:]
        if len(word) < _WORD_FLOOR or word in _STOPWORDS or _ENTRY_ID.match(word):
            continue
        if not word.isdigit():
            yield word


def _prefix_denied(clause: str) -> frozenset[str]:
    """The words a clause denies by a prefix ("named" of "unnamed")."""
    return frozenset(
        word.lower()[2:]
        for word in (m.group(0) for m in _WORD.finditer(clause))
        if word.lower() in _DENIED_WORDS
    )


def shares_words(text: str, words: frozenset[str], least: int) -> bool:
    """Whether ``text`` holds at least ``least`` of ``words``, whole or by a shared
    beginning (:class:`_Said`)."""
    return said_of(text).count(words) >= least


@lru_cache(maxsize=1024)
def said_of(text: str) -> _Said:
    """The words of ``text`` as :class:`_Said` reads them, read once per text."""
    return _Said(content_words(text))


def absence_subject(sentence: str) -> frozenset[str]:
    """The words of a sentence before its first negation: what it denies something of
    ("request", "body" of "The C2 request body is also not established")."""
    return _subject(sentence)


# Where the clause a negation stands in begins, read back from the negation: a mark,
# or a word joining two clauses.
# Where an item of what a sentence denies begins: a mark, or a word joining two
# clauses or list items (kept, as it tells a coordinated item from a new clause).
_ITEM_BREAK = re.compile(r"[,;:]|\b(?:and|but|so|because)\b", re.IGNORECASE)
# The words that open an item of a coordinated list ("whether its gates pass, whether
# its beacon reaches the hosts, and how it persists were not established").
_LIST_OPENERS = frozenset("whether how what which who when where why if".split())
# The words that open a frame ("In the sandbox run", "For the sandbox run", "as for
# the sandbox run"): it sets the scene of the denial and is never what is denied.
_FRAME_OPENERS = frozenset(
    "in for during on as from within after before at by under over including excluding "
    "such like".split()
)
_JOINS = frozenset({"and"})
# The negations that deny what follows them ("no packer signature"), not what stands
# before ("the body was not read").
_DENIES_WHAT_FOLLOWS = frozenset({"no", "none", "nothing", "neither", "nor", "without"})
# The words after which an item's own words end and a modifier begins.
PREPOSITIONS = frozenset(
    (
        "in for during on as from within after before at by under over beyond of to with "
        "through via about into onto than like across behind between among toward towards "
        "outside inside including excluding except"
    ).split()
)


@dataclass(frozen=True)
class _Item:
    """One item of what a sentence denies something of: its words, its first word, and
    whether "and" joins it to the item before."""

    words: frozenset[str]
    opener: str
    joined: bool
    # The last word of its own before a preposition: what the item is ("protocol" of
    # "The C2 protocol beyond the request keys", "results" of "the sandbox run
    # results").
    head: str = ""
    # Its words before its first preposition ("certificate", "handling" of "The
    # certificate handling of the HTTPS channel"); for a phrase opening on one, its
    # last word ("ransomware" of "in the evidence shows ransomware").
    group: frozenset[str] = frozenset()


def _items_before_negation(sentence: str) -> list[_Item]:
    """The items of a sentence's words before its first negation, in order, each marked
    where "and" joins it to the item before; an item of no word at all is left out."""
    found = _NEGATION.search(sentence)
    if not found:
        return []
    before = sentence[: found.start()]
    items: list[_Item] = []
    begin, joined = 0, False
    for match in [*_ITEM_BREAK.finditer(before), None]:
        end = match.start() if match is not None else len(before)
        part = before[begin:end]
        first = next((w.lower() for w in _WORD.findall(part)), "")
        if first:
            own = _without_references(part)
            items.append(_Item(content_words(own), first, joined, _head(own), _group(own)))
            joined = False
        if match is not None:
            begin = match.end()
            joined = joined or match.group(0).lower() in _JOINS
    return items


# The verbs that make a denial one of observation ("observed no network exchange", "was
# not recorded"): only an observation says otherwise of it.
_OBSERVING = frozenset("observed recorded seen captured watched logged shown".split())
# How many words on either side of a negation are read for such a verb.
_OBSERVING_REACH = 3


def denies_an_observation(sentence: str) -> bool:
    """Whether a sentence's first negation denies an observation: an observing verb stands
    within :data:`_OBSERVING_REACH` words of it ("observed no network exchange", "was not
    observed")."""
    found = _NEGATION.search(sentence)
    if not found:
        return False
    before = [w.lower() for w in _WORD.findall(sentence[: found.start()])][-_OBSERVING_REACH:]
    after = [w.lower() for w in _WORD.findall(sentence[found.end() : found.end() + 80])][
        :_OBSERVING_REACH
    ]
    return any(word in _OBSERVING for word in (*before, *after))


# A noun a demonstrative points back with ("that set", "these routines"): it names what
# the sentence said before, nothing a source could say otherwise of on its own.
_REFERENCE = re.compile(r"\b(?:that|this|these|those)\s+[\w'-]+", re.IGNORECASE)


def _without_references(part: str) -> str:
    """An item's text without the nouns a demonstrative points back with."""
    return _REFERENCE.sub(" ", part)


def frame_words(sentence: str) -> frozenset[str]:
    """The words of the frame a sentence opens with ("analysed", "sample" of "In the
    analysed sample, …"), or none: the scene a report sets, not what it says."""
    first = next((w.lower() for w in _WORD.findall(sentence[:40])), "")
    if first not in _FRAME_OPENERS:
        return frozenset()
    cut = _ITEM_BREAK.search(sentence)
    return content_words(sentence[: cut.start()] if cut else sentence) - _addresses(sentence)


def _before_preposition(part: str) -> str:
    """An item's words up to its first preposition past its first word ("YARA hits" of
    "YARA hits among 31 rules")."""
    words = part.split()
    for at, word in enumerate(words):
        if at > 0 and word.lower().strip(",.;:()") in PREPOSITIONS:
            return " ".join(words[:at])
    return part


def _group(part: str) -> frozenset[str]:
    """An item's own words before its first preposition (past its first word); for one
    opening on a preposition, its last word of its own."""
    words = [m.group(0) for m in _WORD.finditer(part)]
    if words and words[0].lower() in PREPOSITIONS:
        head = _head(part)
        return frozenset({head}) if head else frozenset()
    cut = next(
        (at for at, word in enumerate(words) if at > 0 and word.lower() in PREPOSITIONS),
        len(words),
    )
    return content_words(" ".join(words[:cut]))


def _head(part: str) -> str:
    """The last word of its own an item writes before its first preposition (past its first
    word), else its last word of its own."""
    words = [m.group(0) for m in _WORD.finditer(part)]
    cut = next(
        (at for at, word in enumerate(words) if at > 0 and word.lower() in PREPOSITIONS),
        len(words),
    )
    for chosen in (words[:cut], words):
        own = list(_ordered_words(" ".join(chosen)))
        if own:
            return own[-1]
    return ""


def _denied_items(sentence: str) -> list[_Item]:
    """The items of what a sentence denies something of, never the scene it sets.

    The item right before its first negation. Where that item is a bare verb ("..., and
    the server responses, were not recovered"), the item before it with every item
    "and" chains to it ("The C2 protocol beyond the request keys ...", "the server
    responses"). Where the item opens a coordinated list ("..., and how it persists were
    not established"), every item of that list ("whether its gates pass", "whether its
    beacon reaches the configured hosts"). An item opening with a preposition ("In the
    sandbox run", "as for the sandbox run") is a frame, never what is denied. Where the
    negation denies what follows it ("no packer signature", "no contact with the C2
    hosts", "neither configured host"), that phrase, up to the next clause break. One
    pass over the words around the negation.
    """
    found = _NEGATION.search(sentence)
    if found and found.group(0).lower() in _DENIES_WHAT_FOLLOWS:
        rest = sentence[found.end() :]
        cut = _ITEM_BREAK.search(rest)
        part = _without_references(_before_preposition(rest[: cut.start()] if cut else rest))
        words = content_words(part)
        return [_Item(words, "", False, _head(part), _group(part))] if words else []
    items = [item for item in _items_before_negation(sentence) if item.opener not in _FRAME_OPENERS]
    chained = False
    while items and not items[-1].words:
        if items.pop().joined:
            # "it rests on decoded strings and was not observed": the bare verb "and"
            # joins shares the clause's own subject ("it"), which no word names.
            return []
        chained = True
    if not items:
        return []
    last = items[-1]
    out = [last]
    if last.opener in _LIST_OPENERS:
        out.extend(item for item in items[:-1] if item.opener in _LIST_OPENERS)
    elif chained:
        # The bare verb's subject is a coordinated list: every item "and" chains to it.
        for at in range(len(items) - 1, 0, -1):
            if not items[at].joined:
                break
            out.append(items[at - 1])
    return out


def denied_subject(sentence: str) -> frozenset[str]:
    """The words of what a sentence denies something of (:func:`_denied_items`)."""
    return frozenset(word for item in _denied_items(sentence) for word in item.words)


def denied_items(sentence: str) -> list[tuple[frozenset[str], frozenset[str]]]:
    """Each item a sentence denies something of: its words, and its own words
    (:func:`_denied_items`, :func:`_group`)."""
    return [(item.words, item.group) for item in _denied_items(sentence)]


# A denial of reading or listing code: "was not read", "body unread", "not decompiled",
# "no entry lists its code".
_READING_DENIAL = re.compile(
    r"\bunread\b"
    r"|\bread\s+(?:only\s+)?(?:in\s+part|partly|partially)\b"
    r"|\b(?:partly|partially)\s+read\b"
    r"|\b(?:not|never|no)\b[^.;:]{0,40}?\b(?:read|decompiled|disassembled|listed|lists|"
    r"examined|opened)\b",
    re.IGNORECASE,
)


def denies_reading(text: str) -> bool:
    """Whether the text denies that code was read or listed (:data:`_READING_DENIAL`)."""
    return _READING_DENIAL.search(text) is not None


def reading_denied_in(text: str) -> str:
    """The clause of the text denying that code was read or listed, or ``""``: its words
    from the clause break before the denial to the one after it."""
    found = _READING_DENIAL.search(text)
    if not found:
        return ""
    begin = 0
    for match in _ITEM_BREAK.finditer(text[: found.start()]):
        if match.group(0) in ",;:":
            begin = match.end()
    after = re.search(r"[,;:]", text[found.end() :])
    return text[begin : found.end() + (after.start() if after else len(text))]


def denied_groups(sentence: str) -> frozenset[str]:
    """The own words of each item a sentence denies something of (:func:`_group`)."""
    return frozenset(word for item in _denied_items(sentence) for word in item.group)


def denied_heads(sentence: str) -> frozenset[str]:
    """What each item a sentence denies something of is (:func:`_head`)."""
    return frozenset(item.head for item in _denied_items(sentence) if item.head)


def _addresses(text: str) -> frozenset[str]:
    """The hex words a clause writes, lowered: what a clause's absence is said of."""
    return frozenset(
        word.lower()
        for word in (m.group(0) for m in _WORD.finditer(text))
        if word.lower().startswith("0x") and _HEX.match(word)
    )


def kept_absence(absences: Iterable[str], rewrite: str) -> str | None:
    """The first of ``absences`` (clauses a source contradicts) the rewrite states again.

    A rewrite's clause states an absence again where it denies something, writes
    the same addresses (none for none), and holds at least :data:`KEPT_SHARE` of
    the absence's own words (at least two of them), or every word of the subject
    the absence denies something of (two or more) together with the word it denies,
    the first after its negation ("the mutex name is not passed" of "the mutex name
    is not passed in that call" holds "passed"; "what the mutex name guards is not
    known" denies something else of the same subject and is another absence), or
    with a word of that subject the rewrite denies by its prefix ("The mutex is
    unnamed" of "The mutex name is not established"). A word is held
    whole or by a shared beginning ("name", "named"). Measured for each pair of
    clauses on its own, never pooled. A clause that splits the absence ("0x10 was
    not read" from "0x10 and 0x20 were not read") names other addresses and is
    another statement. The rewrite's clauses are read once each, indexed by the
    addresses they write and the beginnings of their words; an absence is compared
    only with the clauses on its addresses sharing a word with it, at most
    :data:`_COMPARED_CLAUSES` of those, so the read is linear in both texts and any
    number of unrelated denials cannot hide the one that restates it.
    """
    by_address: dict[frozenset[str], _Clauses] = {}
    for clause in negated_clauses(rewrite):
        by_address.setdefault(_addresses(clause), _Clauses()).add(clause)
    if not by_address:
        return None
    seen: set[tuple[frozenset[str], frozenset[str]]] = set()
    for absence in absences:
        words, named = content_words(absence), _addresses(absence)
        if len(words) < _LEAST_WORDS or (words, named) in seen:
            continue
        seen.add((words, named))
        subject, denied = _subject(absence), _denied(absence)
        need = KEPT_SHARE * len(words)
        group = by_address.get(named)
        for said, by_prefix in group.sharing(words) if group is not None else ():
            if said.count(words) >= need:
                return absence
            if len(subject) < _SUBJECT_WORDS or said.count(subject) < len(subject):
                continue
            # The same subject, and the same thing denied of it: the word the absence
            # denies, or a word of the subject the rewrite denies by its prefix ("The
            # mutex is unnamed" of "The mutex name is not established").
            if (denied and said.holds(denied)) or any(by_prefix.holds(w) for w in subject):
                return absence
    return None


# How many of a rewrite's denying clauses sharing a word with an absence, on its
# address set, the absence is compared with at most.
_COMPARED_CLAUSES = 64


def _stem(word: str) -> str:
    """The beginning two words held as one share (:data:`_STEM_FLOOR` characters)."""
    return word[:_STEM_FLOOR]


class _Clauses:
    """A rewrite's denying clauses on one address set, each read once, indexed by the
    beginnings of their words, so an absence is compared only with the clauses that share
    a word with it: a clause sharing none states no absence of it, however many such
    clauses the rewrite writes."""

    def __init__(self) -> None:
        self.said: list[tuple[_Said, _Said]] = []
        self.seen: set[frozenset[str]] = set()
        self.index: dict[str, list[int]] = {}

    def add(self, clause: str) -> None:
        words = content_words(clause)
        if words in self.seen:
            return
        self.seen.add(words)
        self.said.append((_Said(words), _Said(_prefix_denied(clause))))
        place = len(self.said) - 1
        for stem in {_stem(word) for word in words}:
            self.index.setdefault(stem, []).append(place)

    def sharing(self, words: Iterable[str]) -> list[tuple[_Said, _Said]]:
        """The clauses sharing a word's beginning with ``words``, in the order they stand,
        at most :data:`_COMPARED_CLAUSES` of them; each posting is read until then."""
        found: set[int] = set()
        for stem in sorted({_stem(word) for word in words}):
            for place in self.index.get(stem, ()):
                found.add(place)
                if len(found) >= _COMPARED_CLAUSES:
                    break
            if len(found) >= _COMPARED_CLAUSES:
                break
        return [self.said[place] for place in sorted(found)]


def _spaced(text: str) -> str:
    """Text lowered, its spacing read as one space, its curly quotes as straight ones."""
    plain = text.replace("‘", "'").replace("’", "'")
    plain = plain.replace("“", '"').replace("”", '"')
    return " ".join(plain.lower().split())


def quote_stands(quote: str, texts: Sequence[str]) -> bool:
    """Whether the quote, read without its outer quotes or an ellipsis at either end,
    stands whole in one of ``texts``, and is at least :data:`QUOTE_FLOOR` characters."""
    said = _spaced(quote).strip().strip("\"'").strip()
    for mark in ("…", "..."):
        said = said.removeprefix(mark).removesuffix(mark).strip()
    if len(said) < QUOTE_FLOOR:
        return False
    return any(said in _spaced(text) for text in texts)


# The number words a failure count is read in.
_NUMBERS = {
    word: value
    for value, word in enumerate(
        (
            "zero one two three four five six seven eight nine ten eleven twelve thirteen "
            "fourteen fifteen sixteen seventeen eighteen nineteen twenty"
        ).split()
    )
}
# A word that says a call failed.
_FAILED_WORDS = frozenset({"failed", "fail", "fails", "errored"})
# How many words may stand between a count and the word saying the calls failed.
_COUNT_REACH = 6
# A sentence names calls where it writes one of these.
_NAMES_CALLS = re.compile(
    r"\bcalls?\b|\btools?\b|\bdecompil\w*|\bdisassembl\w*|\bemulat\w*", re.IGNORECASE
)
# A redo denied: "were not redone", "never retried", "not answered later".
_DENIES_REDO = re.compile(
    r"\b(?:not|never)\s+(?:been\s+)?(?:redone|retried|re-?run|re-?issued|answered)\b",
    re.IGNORECASE,
)
_TOKEN = re.compile(r"[A-Za-z0-9]+|[;:,()—–.]")
_BREAKS = frozenset(";:,()—–.")


def _number(word: str) -> int | None:
    lowered = word.lower()
    if lowered.isdigit() and len(lowered) <= 6:
        return int(lowered)
    return _NUMBERS.get(lowered)


# What a number counts where it counts calls: the word after it, or after "of [the]
# N" ("4 of 158 tool calls"), one of these or a word before one ("two decompile
# calls"). "20 candidate API names" or "3 of the 150 functions" count no call.
_COUNTED_NOUNS = frozenset({"call", "calls", "tool", "tools", "failure", "failures"})
# How many words after a count (or its whole) may name what it counts.
_NOUN_REACH = 2


def _counted(tokens: Sequence[str], at: int) -> tuple[int, bool]:
    """Where the words after the number at ``at`` end that a count's whole is read in, and
    whether the words after it name calls (:data:`_COUNTED_NOUNS`)."""
    after = at + 1
    if after < len(tokens) and tokens[after].lower() == "of":
        step = after + 1
        if step < len(tokens) and tokens[step].lower() == "the":
            step += 1
        if step < len(tokens) and _number(tokens[step]) is not None:
            after = step + 1
    nouns = [t.lower() for t in tokens[after : after + _NOUN_REACH]]
    return after, any(noun in _COUNTED_NOUNS for noun in nouns)


def failure_counts(sentence: str) -> list[int]:
    """Each number the sentence gives failed calls: a number counting calls
    (:func:`_counted`) at most :data:`_COUNT_REACH` words before a word saying they
    failed, in its clause ("4 of 158 tool calls failed": 4). None where the sentence
    names no call. One pass over the words."""
    if not _NAMES_CALLS.search(sentence):
        return []
    tokens = [m.group(0) for m in _TOKEN.finditer(sentence)]
    out: list[int] = []
    last: tuple[int, int] | None = None  # (place, number) of the count in the clause
    skip_to = -1
    # Calls counted before ("Of 158 tool calls, 12 hit cached answers and 4 failed"):
    # a bare number right before a word saying they failed counts them.
    calls_named = False
    for at, token in enumerate(tokens):
        if token in _BREAKS:
            last = None
            continue
        if at < skip_to:
            continue
        value = _number(token)
        if value is not None:
            skip_to, counts_calls = _counted(tokens, at)
            before = [t.lower() for t in tokens[max(0, at - 2) : at]]
            if counts_calls and (before[-1:] == ["of"] or before == ["of", "the"]):
                calls_named = True
                last = None
                continue
            bare = calls_named and at + 1 < len(tokens) and tokens[at + 1].lower() in _FAILED_WORDS
            last = (at, value) if counts_calls or bare else None
            continue
        if token.lower() in _FAILED_WORDS and last is not None:
            if at - last[0] <= _COUNT_REACH:
                out.append(last[1])
            last = None
    return out


@dataclass(frozen=True)
class FailureCounts:
    """The ledger's count of failed calls: all of them, the redone ones, and the same by
    each kind word and tool name a sentence may count them under."""

    failed: int = 0
    redone: int = 0
    # Each kind stem or tool name, with its failed and redone counts.
    by_name: dict[str, tuple[int, int]] = field(default_factory=dict)

    def agreeing(self, denies_redo: bool) -> frozenset[int]:
        """The counts a sentence may give: the ones left after the redos where it
        denies a redo, else any of the whole, the redone and the left."""
        pairs = [(self.failed, self.redone), *self.by_name.values()]
        if denies_redo:
            return frozenset(f - r for f, r in pairs)
        return frozenset(n for f, r in pairs for n in (f, r, f - r))


def count_disagrees(sentence: str, counts: FailureCounts | None) -> bool:
    """Whether the sentence gives failed calls a number the ledger's count does not."""
    if counts is None:
        return False
    found = failure_counts(sentence)
    if not found:
        return False
    agreeing = counts.agreeing(_DENIES_REDO.search(sentence) is not None)
    return any(n not in agreeing for n in found)
