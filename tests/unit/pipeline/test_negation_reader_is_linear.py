"""The readings of absence cost the length of the text, and answer as they always did.

The readings were written against a copy of the text before each mention, so a
long run's evidence with many negated mentions took the square of its length
(224 KB: 81 s). ``_NegationReader`` reads the text once. The old readings are
kept here, verbatim, as the reference: every case below is asked of both, and
the work the new one does is counted, never timed.
"""

from __future__ import annotations

import random
import re
import sys
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from maljan.pipeline import validation

# --- The reference: the readings as they were, verbatim -----------------------

_ASSERTION_BETWEEN_RE = re.compile(
    r",|\b(?:and|instead|only|but|yet|so|then|rather|while)\b", re.IGNORECASE
)
_DASH_RE = re.compile(r"—|(?<=\s)–(?=\s)")
_OWN_VERB_RE = re.compile(
    r"\b(?:is|are|was|were|be|been|being|has|have|had|does|do|did|can|could|will|would"
    r"|may|might|must|should|shall|exists?|existed|appears?|appeared|occurs?|occurred)\b",
    re.IGNORECASE,
)
_SET_ASIDE_CUE_RE = re.compile(r"\b(?:instead\s+of|rather\s+than)\b[^.;:!?\n]*$", re.IGNORECASE)
_CUE_THAT_ASSERTS_RE = re.compile(
    r"^\W*(?:longer|merely|only|just|simply|stops?|ceases?|fails?\s+to\s+stop|end)\b",
    re.IGNORECASE,
)
_NEED_VERB_RE = re.compile(r"^\s+(?:require|need|depend|rely)\w*\b", re.IGNORECASE)
_LIST_ITEM = r"[A-Za-z][\w-]*(?:\s+[A-Za-z(][\w()-]*){0,3}"
_NEGATED_NOUN_LIST_RE = re.compile(
    r"^\s*(?:(?:any|obvious|apparent|clear|signs?\s+of|evidence\s+of|indications?\s+of)\s+)*"
    rf"(?P<items>{_LIST_ITEM}(?:\s*,\s*{_LIST_ITEM})*\s*,?\s+(?:or|and)\s+{_LIST_ITEM})"
    r"\s+(?:mechanisms?|techniques?|capabilit(?:y|ies)|behaviou?rs?|activit(?:y|ies)"
    r"|functionality|methods?|patterns?)\b",
    re.IGNORECASE,
)
_NOUN_COMPLEMENT_BEFORE_RE = re.compile(
    r"\b(?:for|of|to|with)\s+(?:(?:any|the|its|their|common|typical|such)\s+)?$",
    re.IGNORECASE,
)
_NEGATED_VERB_RE = re.compile(
    r"\b(?:does|do|did|could|can|will|would|should)\s+not\b"
    r"|\b(?:doesn't|don't|didn't|cannot|can't|won't|never)\b",
    re.IGNORECASE,
)
_NEGATED_OBJECT_RE = re.compile(
    r"^\s+[A-Za-z]+\s+(?:[\w./()-]+\s+){0,6}?"
    r"(?:(?:required|needed|necessary|used|associated|related|linked|typical|indicative"
    r"|specific)\s+)?(?:for|of|to|with)\s+(?:(?:any|the|its|their|common|typical|such)\s+)?$",
    re.IGNORECASE,
)
_CLAUSE_BREAK_RE = re.compile(r"[.;:!?\n]|\bbut\b|\bhowever\b|\bwhereas\b", re.IGNORECASE)
_NEGATION_RE = re.compile(
    r"\b(?:no|not|never|without|lack(?:s|ed|ing)?|absence|none)\b|n't\b|\bfailed to\b"
    r"|\brather\s+than\b|\binstead\s+of\b"
    r"|\b(?:prevents?|precludes?)\s+(?:any\s+)?(?:confirmation|observation)\s+of\b",
    re.IGNORECASE,
)
_NEVER_ADJECTIVES = ("exercised", "executed", "used", "called", "invoked", "triggered")
_NOT_A_NEGATION = ("no doubt", "not only", *(f"never-{word}" for word in _NEVER_ADJECTIVES))
_NEGATION_WINDOW = 40
_NEGATION_REACH_END_RE = re.compile(
    r"\b(?:which|that|as|while|whereas)\b|\band\s+(?:the|it|this|its|then)\b|,\s*then\b",
    re.IGNORECASE,
)
_INSIDE_A_NEGATION_RE = re.compile(
    r"^\s*(?:evidence|indications?|signs?|traces?)\s+that\b|\bsuch\s+as\b", re.IGNORECASE
)
_NOUN_NEGATION_RE = re.compile(
    r"\b(?:no|without(?:\s+any)?)\s+(?:evidence|indications?|signs?|traces?)\s+of\b",
    re.IGNORECASE,
)
_LIST_END_RE = re.compile(
    r",(?!\s*(?:or|and)\b)|\b(?:yet|although|though|so|but)\b"
    r"|\band\s+\w+\s+(?:is|are|was|were|has|have|had)\b",
    re.IGNORECASE,
)
_PURPOSE_OBJECT_RE = re.compile(
    r"\bto\s+(?:prevent|avoid|stop|block)\s+(?:(?:any|the|a|an|further|its|their)\s+)?$",
    re.IGNORECASE,
)
_SUBJECT_ABSENT_RE = re.compile(
    r"^(?:\s+(?:mechanisms?|techniques?|capabilit(?:y|ies)|behaviou?rs?|activit(?:y|ies)"
    r"|functionality|methods?|patterns?))?"
    r"\s+(?:is|was|are|were|remains?)\s+"
    r"(?:absent\b|missing\s+from\b"
    r"|not\s+(?:present|observed|seen|found|detected|supported|established|confirmed)\b)",
    re.IGNORECASE,
)
_STATEMENT_END_RE = re.compile(r"(?<=[.!?])\s+|\n+")


def old_read_dashes(text: str) -> str:
    chars = list(text)
    dashes = [found.start() for found in _DASH_RE.finditer(text)]
    paired: set[int] = set()
    for first, second in zip(dashes, dashes[1:], strict=False):
        if first in paired:
            continue
        if not _CLAUSE_BREAK_RE.search(text[first + 1 : second]):
            for at in range(first, second + 1):
                chars[at] = " "
            paired.update({first, second})
    for at in dashes:
        if at in paired:
            continue
        rest = text[at + 1 :]
        stop = _CLAUSE_BREAK_RE.search(rest)
        after = rest[: stop.start()] if stop else rest
        if _OWN_VERB_RE.search(after) or _SET_ASIDE_CUE_RE.search(text[:at]):
            chars[at] = ";"
    return "".join(chars)


def old_governed_absence(text: str, start: int) -> bool:
    window = text[max(0, start - _NEGATION_WINDOW) : start]
    breaks = list(_CLAUSE_BREAK_RE.finditer(window))
    if breaks:
        window = window[breaks[-1].end() :]
    lowered = window.lower()
    for cue in _NEGATION_RE.finditer(window):
        if lowered.startswith(_NOT_A_NEGATION, cue.start()):
            continue
        after = window[cue.end() :]
        if _CUE_THAT_ASSERTS_RE.match(after) or _NEED_VERB_RE.match(after):
            continue
        if _ASSERTION_BETWEEN_RE.search(after) or old_reach_ends(after):
            continue
        return True
    return False


def old_absent_by_its_own_statement(text: str, start: int, end: int) -> bool:
    if old_subject_is_absent(text, start, end):
        return True
    if old_in_a_negated_object(text, start):
        return True
    head = text[:start]
    breaks = list(_CLAUSE_BREAK_RE.finditer(head))
    clause_start = breaks[-1].end() if breaks else 0
    tail_break = _CLAUSE_BREAK_RE.search(text, end)
    clause = text[clause_start : tail_break.start() if tail_break else len(text)]
    at = start - clause_start
    lowered = clause.lower()
    for cue in _NEGATION_RE.finditer(clause[:at]):
        if lowered.startswith(_NOT_A_NEGATION, cue.start()):
            continue
        rest = clause[cue.end() :]
        if _CUE_THAT_ASSERTS_RE.match(rest):
            continue
        listed = _NEGATED_NOUN_LIST_RE.match(rest)
        if listed and cue.end() + listed.start("items") <= at < cue.end() + listed.end("items"):
            return True
    return False


def old_subject_is_absent(text: str, start: int, end: int) -> bool:
    if not _SUBJECT_ABSENT_RE.match(text[end:]):
        return False
    return old_starts_its_clause(text, start) or bool(
        _NOUN_COMPLEMENT_BEFORE_RE.search(text[max(0, start - _NEGATION_WINDOW) : start])
    )


def old_in_a_negated_object(text: str, start: int) -> bool:
    head = text[:start]
    breaks = list(_CLAUSE_BREAK_RE.finditer(head))
    clause = head[breaks[-1].end() :] if breaks else head
    cues = list(_NEGATED_VERB_RE.finditer(clause))
    if not cues:
        return False
    after = clause[cues[-1].end() :]
    if _CUE_THAT_ASSERTS_RE.match(after) or _NEED_VERB_RE.match(after):
        return False
    if "," in after or _ASSERTION_BETWEEN_RE.search(after) or old_reach_ends(after):
        return False
    return bool(_NEGATED_OBJECT_RE.match(after))


def old_states_absence(text: str, pattern: re.Pattern[str] | None) -> bool:
    if not text or pattern is None:
        return False
    text = old_read_dashes(text)
    matches = list(pattern.finditer(text))
    if not matches:
        return False
    negated_to: int | None = None
    for match in matches:
        if (
            old_is_negated(text, match.start(), match.end())
            and old_governed_absence(text, match.start())
        ) or old_absent_by_its_own_statement(text, match.start(), match.end()):
            negated_to = match.end()
            continue
        if negated_to is not None:
            between = text[negated_to : match.start()]
            if (
                not _CLAUSE_BREAK_RE.search(between)
                and not old_reach_ends(between)
                and not _ASSERTION_BETWEEN_RE.search(between)
            ):
                negated_to = match.end()
                continue
        return False
    return True


def old_named_as_absent(text: str, start: int, end: int) -> bool:
    return (
        old_is_negated(text, start, end) and old_governed_absence(text, start)
    ) or old_absent_by_its_own_statement(text, start, end)


def old_reach_ends(after_cue: str) -> bool:
    return _NEGATION_REACH_END_RE.search(_INSIDE_A_NEGATION_RE.sub(" ", after_cue)) is not None


def old_in_a_named_list(text: str, start: int) -> bool:
    head = text[:start]
    breaks = list(_CLAUSE_BREAK_RE.finditer(head))
    clause = head[breaks[-1].end() :] if breaks else head
    cues = list(_NOUN_NEGATION_RE.finditer(clause))
    if not cues:
        return False
    after = clause[cues[-1].end() :]
    named = re.search(r",\s*such\s+as\b", after, re.IGNORECASE)
    if named is None or old_reach_ends(after):
        return False
    listed = after[named.end() :]
    if _LIST_END_RE.search(listed):
        return False
    return not (
        re.search(r"\band\s*$", listed, re.IGNORECASE)
        and re.match(r"\w+(?:\s+\w+)?\s+(?:is|are|was|were|has|have|had)\b", text[start:], re.I)
    )


def old_is_negated(text: str, start: int, end: int | None = None) -> bool:
    if _PURPOSE_OBJECT_RE.search(text[max(0, start - _NEGATION_WINDOW) : start]):
        return True
    if end is not None and old_absent_by_its_own_statement(text, start, end):
        return True
    if old_in_a_named_list(text, start):
        return True
    window = text[max(0, start - _NEGATION_WINDOW) : start]
    breaks = list(_CLAUSE_BREAK_RE.finditer(window))
    if breaks:
        window = window[breaks[-1].end() :]
    lowered = window.lower()
    return any(
        not lowered.startswith(_NOT_A_NEGATION, cue.start())
        and not _NEED_VERB_RE.match(window[cue.end() :])
        and not old_reach_ends(window[cue.end() :])
        for cue in _NEGATION_RE.finditer(window)
    )


def old_starts_its_clause(text: str, start: int) -> bool:
    head = text[:start]
    breaks = list(_CLAUSE_BREAK_RE.finditer(head))
    clause = head[breaks[-1].end() :] if breaks else head
    return len(clause.split()) <= 2


def old_sentence_around(text: str, position: int) -> str:
    begin = 0
    for end in _STATEMENT_END_RE.finditer(text):
        if end.start() >= position:
            return text[begin : end.start()].strip()
        begin = end.end()
    return text[begin:].strip()


def old_claiming_sentences(
    pattern: re.Pattern[str], text: str, masked: str | None = None
) -> list[str]:
    read = text if masked is None or len(masked) != len(text) else masked
    found: list[str] = []
    for match in pattern.finditer(read):
        if old_is_negated(read, match.start(), match.end()):
            continue
        sentence = old_sentence_around(text, match.start())
        if sentence and sentence not in found:
            found.append(sentence)
    return found


def old_claimed(pattern: re.Pattern[str], text: str) -> bool:
    return any(
        not old_is_negated(text, match.start(), match.end()) for match in pattern.finditer(text)
    )


# --- The cases ---------------------------------------------------------------

# Every word a reading turns on, its near misses, and words a mention is made of.
_WORDS = (
    "no not never without lack lacks lacked lacking absence none n't doesn't don't didn't "
    "cannot can't won't does do did could can will would should failed to rather than "
    "instead of prevents prevent precludes preclude any confirmation observation evidence "
    "indication indications sign signs trace traces that which as while whereas such and "
    "the it this its then but however yet although though so only merely longer just simply "
    "stops stop ceases fails end require requires needs depend rely required needed "
    "necessary used associated related linked typical indicative specific for with common "
    "their is was are were remains remain absent missing from present observed seen found "
    "detected supported established confirmed mechanisms mechanism techniques capability "
    "capabilities behaviour behaviors activity activities functionality methods patterns "
    "obvious apparent clear avoid block further a an doubt never-used never-exercised "
    "never-ever has have had be exists appears occurs persistence persist persists "
    "unpersisted nonpersistent encryption encrypt unencrypted injection inject reinjects c2 "
    "C2 command control command-and-control lateral movement keylogging exfiltration "
    "credential credentials discovery notification nothing nobody noencrypt nopersist offer "
    "tox thanks asx thatx andthe isn soon although; x foo bar data sample registry APIs "
    "explorer.exe settings.ini (persistence) [c2] İ ΣΑΣ ſuch K é 2026 _x"
).split()
_SEPARATORS = (
    " ",
    " ",
    " ",
    " ",
    "  ",
    "\t",
    "\n",
    ", ",
    ",",
    ". ",
    "; ",
    ": ",
    "! ",
    "? ",
    "—",
    " — ",
    " – ",
    "–",
    "-",
    "(",
    ")",
    "'",
    "\x1c",
    "\u2028",
    "\xa0",
    "",
)
# Shapes the readings were written for, to be cut and joined at random.
_TEMPLATES = (
    "does not contain persistence, lateral movement, or exfiltration mechanisms",
    "the specific APIs required for persistence are absent",
    "It does not import the registry APIs required for persistence.",
    "no evidence of keylogging, such as hooks or persistence and c2",
    "no evidence of c2, such as beacons, or persistence",
    "There is no evidence that the sample exfiltrates data",
    "no network activity such as exfiltration",
    "Persistence mechanisms were not observed; it injects code",
    "to prevent lateral movement and encrypts every document",
    "does not require administrator rights for persistence",
    "no longer checks for persistence",
    "not only does it persist",
    "a complete, never-exercised web C2",
    "does not — in any run — inject",
    "loops instead of exiting visibly — sandbox evasion",
    "no persistence was observed and the sample injects code into explorer.exe",
    "without any sign of credential theft, such as keylogging",
    "and credentials are stolen",
    "is missing from the evidence",
    "lacks persistence and instead injects",
    "no persistence, no c2, not encryption, or injection techniques",
    "never inject, any obvious persistence or c2 mechanisms",
    "the sample does not, in any sandbox run, establish command-and-control",
    # A mention that starts inside a word, so the copy ends a cue, a list's
    # words or a lookahead at the cut.
    "noencryption, keylogging, or c2 mechanisms",
    "lackinjection or persistence techniques",
    "can'tencrypt, inject, or persist capabilities",
    "rather thanencryption, or c2 methods",
    "instead ofpersistence and c2 patterns",
    "failed toinject or exfiltrate data behaviours",
    "prevents any confirmation ofpersistence, c2, or encryption mechanisms",
    "no evidence ofpersistence",
    "no evidence of c2, such aspersistence",
    "no evidence of x, such as a, orpersistence",
    "no evidence of x, such as a and thepersistence",
    "no evidence of x, such as a, thenpersistence",
    "no evidence of x, such as y soinjection",
    "no evidence of x, such as y and data isencrypted",
    "no evidence of x, such as a and persistence is used",
    "no evidence of x, such as a andpersistence was seen",
    "no evidence thatpersistence",
    "does not import evidence thatpersistence",
    "does not import the APIs for evidence that persistence",
    "no evidence of x, such suchas persistence",
    "no evidence of x, such as y, such a",
    "İ no doubt, persistence, or c2 mechanisms",
    "İİ never-used persistence or c2 techniques",
    "Xİ not only persistence, c2, or injection mechanisms",
    "persistence is not observedx",
    "persistence mechanisms are missing from",
    "notpersistence, c2, or injection mechanisms",
    # Runs of space and "such as" before the cut.
    "no evidence of x, such as a and such as  such as the persistence",
    "does not import, such as such as then persistence",
    "no evidence of x, such as a such as\nsuch as which c2",
    "never such as such assuch as that persistence",
)
_PATTERNS = (
    re.compile(r"\bpersist\w*", re.IGNORECASE),
    re.compile(r"persist\w*|inject\w*|encrypt\w*", re.IGNORECASE),
    re.compile(r"command[\s-]and[\s-]control|\bc2\b|\bc&c\b|\bcnc\b", re.IGNORECASE),
    re.compile(r"lateral[\s-]movement|credential\w*", re.IGNORECASE),
    re.compile(r"\bdiscovery[\s-]+mechanisms\b|exfiltrat\w*", re.IGNORECASE),
    re.compile(r"ion|ence|s", re.IGNORECASE),
    re.compile(r"such|as", re.IGNORECASE),
)


def _soup(rng: random.Random) -> str:
    parts: list[str] = []
    for _ in range(rng.randint(0, 40)):
        roll = rng.random()
        if roll < 0.12:
            template = rng.choice(_TEMPLATES)
            cut = sorted(rng.randint(0, len(template)) for _ in range(2))
            parts.append(template if rng.random() < 0.6 else template[cut[0] : cut[1]])
        elif roll < 0.2:
            word = rng.choice(_WORDS)
            parts.append(word[: rng.randint(0, len(word))] + rng.choice(_WORDS))
        else:
            parts.append(rng.choice(_WORDS))
        parts.append(rng.choice(_SEPARATORS))
    text = "".join(parts)
    if rng.random() < 0.2:
        text = text.upper()
    return text


def _cases(seed: int, count: int) -> Iterator[str]:
    rng = random.Random(seed)
    for _ in range(count):
        yield _soup(rng)


def _spans(text: str, rng: random.Random) -> list[tuple[int, int]]:
    """The places asked about: every mention of each pattern, and places at random."""
    spans = [m.span() for pattern in _PATTERNS for m in pattern.finditer(text)]
    for _ in range(4):
        start = rng.randint(0, len(text))
        spans.append((start, rng.randint(start, len(text))))
    return spans


_CASES = 12_000


@pytest.mark.slow
@pytest.mark.parametrize("seed", range(4))
def test_every_reading_answers_as_the_old_one_did(seed: int) -> None:
    rng = random.Random(1000 + seed)
    differences: list[tuple[str, str, int, int]] = []
    for text in _cases(seed, _CASES // 4):
        reader = validation._NegationReader(text)
        for start, end in _spans(text, rng):
            pairs: tuple[tuple[str, bool, bool], ...] = (
                ("is_negated", reader.is_negated(start, end), old_is_negated(text, start, end)),
                ("is_negated/no end", reader.is_negated(start), old_is_negated(text, start)),
                (
                    "absent",
                    reader.absent_by_its_own_statement(start, end),
                    old_absent_by_its_own_statement(text, start, end),
                ),
                (
                    "named_as_absent",
                    reader.named_as_absent(start, end),
                    old_named_as_absent(text, start, end),
                ),
                (
                    "negated_object",
                    validation._in_a_negated_object(text, start),
                    old_in_a_negated_object(text, start),
                ),
                (
                    "named_list",
                    validation._in_a_named_list(text, start),
                    old_in_a_named_list(text, start),
                ),
                (
                    "starts_clause",
                    validation._starts_its_clause(text, start),
                    old_starts_its_clause(text, start),
                ),
            )
            differences.extend((name, text, start, end) for name, new, old in pairs if new != old)
    assert differences[:5] == []


@pytest.mark.slow
@pytest.mark.parametrize("seed", range(4))
def test_every_text_level_reading_answers_as_the_old_one_did(seed: int) -> None:
    differences: list[tuple[str, str]] = []
    for text in _cases(100 + seed, _CASES // 4):
        if validation._read_dashes(text) != old_read_dashes(text):
            differences.append(("read_dashes", text))
        for pattern in _PATTERNS:
            if validation.states_absence(text, pattern) != old_states_absence(text, pattern):
                differences.append(("states_absence", text))
            if validation._claimed(pattern, text) != old_claimed(pattern, text):
                differences.append(("claimed", text))
            if validation._claiming_sentences(pattern, text) != old_claiming_sentences(
                pattern, text
            ):
                differences.append(("claiming_sentences", text))
    assert differences[:5] == []


def test_the_noun_list_is_read_as_the_pattern_reads_it() -> None:
    rng = random.Random(7)
    pattern = re.compile(_NEGATED_NOUN_LIST_RE.pattern.removeprefix("^"), re.IGNORECASE)
    differences: list[tuple[str, int, int]] = []
    words = [*_WORDS, "or", "and", ",", "(a)", "b-c", "x(y)", "signs of", "evidence of"]
    for _ in range(6000):
        text = "".join(
            rng.choice(words) + rng.choice((" ", " ", ", ", ",", "  ", "\n", " , ", "-"))
            for _ in range(rng.randint(0, 30))
        )
        reader = validation._NegationReader(text)
        for _ in range(6):
            at = rng.randint(0, len(text))
            finish = rng.randint(at, len(text))
            found = pattern.match(text, at, finish)
            old = (found.start("items"), found.end("items")) if found else None
            if reader._noun_list(at, finish) != old:
                differences.append((text, at, finish))
    assert differences[:5] == []


def test_the_patterns_read_as_they_did() -> None:
    """The patterns are built from named parts now; each reads exactly as its old literal."""
    for name in (
        "_SET_ASIDE_CUE_RE",
        "_NEGATED_NOUN_LIST_RE",
        "_CLAUSE_BREAK_RE",
        "_NEGATION_RE",
        "_INSIDE_A_NEGATION_RE",
        "_SUBJECT_ABSENT_RE",
    ):
        new, old = getattr(validation, name), globals()[name]
        assert (new.pattern, new.flags) == (old.pattern, old.flags), name


# --- The work, counted -------------------------------------------------------


class _Counted:
    """A pattern that adds what each call may read (its end position less its start) to a tally."""

    def __init__(self, pattern: re.Pattern[str], tally: list[int]) -> None:
        self._pattern = pattern
        self._tally = tally

    def _add(self, string: str, pos: int = 0, endpos: int = sys.maxsize) -> None:
        self._tally[0] += max(0, min(endpos, len(string)) - pos) + 1

    def match(self, string: str, pos: int = 0, endpos: int = sys.maxsize) -> Any:
        self._add(string, pos, endpos)
        return self._pattern.match(string, pos, endpos)

    def fullmatch(self, string: str, pos: int = 0, endpos: int = sys.maxsize) -> Any:
        self._add(string, pos, endpos)
        return self._pattern.fullmatch(string, pos, endpos)

    def search(self, string: str, pos: int = 0, endpos: int = sys.maxsize) -> Any:
        self._add(string, pos, endpos)
        return self._pattern.search(string, pos, endpos)

    def finditer(self, string: str, pos: int = 0, endpos: int = sys.maxsize) -> Any:
        self._add(string, pos, endpos)
        return self._pattern.finditer(string, pos, endpos)

    def findall(self, string: str, pos: int = 0, endpos: int = sys.maxsize) -> Any:
        self._add(string, pos, endpos)
        return self._pattern.findall(string, pos, endpos)

    def sub(self, repl: Any, string: str, count: int = 0) -> str:
        self._add(string)
        return self._pattern.sub(repl, string, count)

    def split(self, string: str, maxsplit: int = 0) -> list[str]:
        self._add(string)
        return self._pattern.split(string, maxsplit)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._pattern, name)


def _work(monkeypatch: pytest.MonkeyPatch, call: Callable[[], object]) -> int:
    """The characters every pattern of the module may read while ``call`` runs."""
    tally = [0]
    with monkeypatch.context() as patched:
        for name, value in vars(validation).items():
            if isinstance(value, re.Pattern):
                patched.setattr(validation, name, _Counted(value, tally))
        call()
    return tally[0]


# Texts of one shape at any length: many mentions, each read as negated.
_SHAPES: dict[str, Callable[[int], str]] = {
    "one mention per line": lambda n: "process cmdline: no c2 here\n" * n,
    "one clause": lambda n: "no persistence " * n,
    "inside words": lambda n: "noencrypted unpersisted " * n,
    "a negated list": lambda n: "not persistence, " * n + "or persistence mechanisms",
    "a named list": lambda n: "no evidence of x, such as " + "persistence or " * n + "c2",
    "a negated object": lambda n: "does not import the APIs for " + "persistence " * n,
    "dashes": lambda n: "rather than persistence — " * n,
    "absent subjects": lambda n: "persistence is not observed and " * n,
    # A term inside "such as": each mention stands at the end of a run of them.
    "a run of such as": lambda n: "no evidence of x, such as a and " + "such as " * n + "the",
}
# The terms a shape is read for, where not the default.
_SHAPE_TERMS = {"a run of such as": re.compile(r"such|as", re.IGNORECASE)}


@pytest.mark.parametrize("shape", sorted(_SHAPES))
def test_the_work_grows_with_the_text_not_its_square(
    shape: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    pattern = _SHAPE_TERMS.get(shape, re.compile(r"persist\w*|\bc2\b", re.IGNORECASE))

    def read(text: str) -> Callable[[], object]:
        return lambda: (
            validation.states_absence(text, pattern),
            validation._claimed(pattern, text),
            validation._claiming_sentences(pattern, text),
        )

    work = [_work(monkeypatch, read(_SHAPES[shape](size))) for size in (200, 400, 800)]
    # Twice the text, at most a little over twice the work.
    assert work[1] <= 2.2 * work[0] and work[2] <= 2.2 * work[1], work
