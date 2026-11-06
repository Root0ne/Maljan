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
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

# A word that denies something: what makes a clause an absence.
_NEGATION = re.compile(
    r"\b(?:no|not|never|none|nor|neither|without|cannot|unknown|unread|unestablished|"
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
        "never without cannot"
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


def content_words(text: str) -> frozenset[str]:
    """The words a clause is about: lowered, at least three characters, no stop word, no
    negation, no entry id and no bare number; a word its prefix denies as the word it
    denies ("unnamed": "named")."""
    out: set[str] = set()
    for match in _WORD.finditer(text):
        word = match.group(0).lower().strip("'-")
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
        return any(
            word[:end] in self.words for end in range(_STEM_FLOOR, min(len(word), _PREFIX_REACH))
        )


def _subject(clause: str) -> frozenset[str]:
    """The words of a clause before its first negation: what it denies something of."""
    found = _NEGATION.search(clause)
    return content_words(clause[: found.start()]) if found else frozenset()


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
    the absence denies something of where that subject has two or more ("The
    mutex is unnamed" of "The mutex name is not established"); a word is held
    whole or by a shared beginning ("name", "named"). Measured for each pair of
    clauses on its own, never pooled. A clause that splits the absence ("0x10 was
    not read" from "0x10 and 0x20 were not read") names other addresses and is
    another statement. Identical clauses are read once, so a text repeating one
    clause costs one comparison.
    """
    kept: dict[tuple[frozenset[str], frozenset[str]], _Said] = {}
    for clause in negated_clauses(rewrite):
        key = (content_words(clause), _addresses(clause))
        if key not in kept:
            kept[key] = _Said(key[0])
    if not kept:
        return None
    seen: set[tuple[frozenset[str], frozenset[str]]] = set()
    for absence in absences:
        words, named = content_words(absence), _addresses(absence)
        if len(words) < _LEAST_WORDS or (words, named) in seen:
            continue
        seen.add((words, named))
        subject = _subject(absence)
        need = KEPT_SHARE * len(words)
        for (_said, where), said in kept.items():
            if where != named:
                continue
            if sum(1 for word in words if said.holds(word)) >= need:
                return absence
            if len(subject) >= _SUBJECT_WORDS and all(said.holds(word) for word in subject):
                return absence
    return None


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


def failure_counts(sentence: str) -> list[int]:
    """Each number the sentence gives failed calls: the nearest number at most
    :data:`_COUNT_REACH` words before a word saying calls failed, in its clause ("4 of
    158 tool calls failed": 4). None where the sentence names no call."""
    if not _NAMES_CALLS.search(sentence):
        return []
    out: list[int] = []
    last: tuple[int, int] | None = None  # (place, number) of the last number in the clause
    place = 0
    for match in _TOKEN.finditer(sentence):
        token = match.group(0)
        if token in _BREAKS:
            last = None
            continue
        place += 1
        value = _number(token)
        if value is not None:
            # "4 of 158": the count is the first number, the whole the second.
            if not (last is not None and place - last[0] == 2):
                last = (place, value)
            continue
        if token.lower() in _FAILED_WORDS and last is not None:
            if place - last[0] <= _COUNT_REACH:
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
