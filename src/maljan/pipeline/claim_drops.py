"""Values a revision no longer states, and whether a revision is the answer in force again.

A revision replaces the analyst's answer in force, and what it no longer said
was gone without a trace. The platform records, per analyst, round and claim,
the values of the answer in force that appear nowhere in the revision's whole
text: its answer as written, its claims, their evidence and techniques, its
findings and its disputes. Nothing is asked; the model decides what its
answer is, and the record says what left it.

A claim's values:

- a number in hex (``0x…``) or in decimal, compared as one number, so ``0xf``
  and ``15`` are the same value;
- an ATT&CK technique id, in the claim text or on its technique line;
- a quoted value with no space inside (in backticks or double quotes); quoted
  prose is words, not a value.

The search is generous about spelling, because the record must be right
whenever it says a value is gone: a decompiler's name (``FUN_``, ``sub_``,
``fcn.``, ``LAB_``, ``loc_``) carries its address under any image base aligned
to 64 KiB, and a defanged host or URL is the value it defangs.

``answer_unchanged`` is the debate's convergence test, a fact of the same
kind: a revision whose text is the answer in force again after whitespace
changed nothing.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from maljan.analysis.technique_ids import TECHNIQUE_WORD_RE, is_technique_id

_HEX = re.compile(r"(?<![0-9A-Za-z_])0x([0-9a-fA-F]+)(?![0-9A-Za-z_])")
_DECIMAL = re.compile(r"(?<![\w.%-])(\d+)(?![\w%]|\.\d)")
_QUOTED = re.compile(r"`([^`\s]{2,})`|\"([^\"\s]{2,})\"")
# A decompiler's own name for a function or a label: a fixed prefix and the
# address in hex.
_DECOMPILER_NAME = re.compile(
    r"(?<![0-9A-Za-z_])(?:fun|sub|fcn|lab|loc|func)[_.]([0-9a-fA-F]{1,16})(?![0-9A-Za-z_])",
    re.IGNORECASE,
)
# Where a loaded image's base may sit: a multiple of 64 KiB. A decompiler's
# name and a claim's address are one address when they differ by a positive
# multiple of it.
_IMAGE_BASE_ALIGNMENT = 0x10000


def _refanged(text: str) -> str:
    """``text`` with the usual defanging undone: ``[.]``, ``(.)``, ``[:]``, ``hxxp``."""
    out = re.sub(r"\[(\.|:)\]|\((\.)\)", lambda m: m.group(1) or m.group(2), str(text or ""))
    return re.sub(r"\bhxxp", "http", out, flags=re.IGNORECASE)


# A number that names a place in the debate rather than states a value: a
# claim, round, step, stage or phase reference ("Claim 14/15", "round 2"), a
# cross-reference to an entry of the answer's own numbering ("#3", "item 3",
# "see #2"), all of which a revision renumbers, and the list number a claim
# opens with ("1." or "(1)"). A number after any other word ("line 75",
# "section 4", "no. 5") is compared as a value, because it may be one:
# recorded only when the revision states that number nowhere.
_REFERENCE_NUMBER = re.compile(
    r"(?i)(?:\b(?:claims?|rounds?|steps?|stages?|phases?|items?)\s*#?|#)\d+"
    r"(?:\s*(?:/|,|&|\+|and|to|-|–)\s*#?\d+)*"
)
_LIST_NUMBER = re.compile(r"(?m)^\s*\(?\d+[.)](?=\s)")


def _without_hex_and_ids(text: str) -> str:
    text = _HEX.sub(" ", text)
    text = _DECOMPILER_NAME.sub(" ", text)
    text = TECHNIQUE_WORD_RE.sub(" ", text)
    return re.sub(r"\bev_\d+\b", " ", text)


def _stated_decimals(text: str) -> set[str]:
    """The decimal numbers a claim states as values, references and list numbers aside."""
    plain = _LIST_NUMBER.sub(" ", _REFERENCE_NUMBER.sub(" ", _without_hex_and_ids(text)))
    return {str(int(n)) for n in _DECIMAL.findall(plain)}


def claim_values(text: str, technique_id: str | None = "") -> frozenset[str]:
    """The values a claim states: numbers (hex as ``0x…``), technique ids, quoted values."""
    plain = _refanged(text)
    values: set[str] = {f"0x{int(m.group(1), 16):x}" for m in _HEX.finditer(plain)}
    values.update(TECHNIQUE_WORD_RE.findall(plain))
    if technique_id and is_technique_id(str(technique_id).strip()):
        values.add(str(technique_id).strip())
    for match in _QUOTED.finditer(plain):
        quoted = (match.group(1) or match.group(2) or "").strip().casefold()
        if len(quoted) >= 2:
            values.add(quoted)
    values.update(_stated_decimals(plain))
    return frozenset(values)


@dataclass(frozen=True)
class _Searched:
    numbers: set[int]
    names: set[int]
    techniques: set[str]
    folded: str


def _searched(text: str) -> _Searched:
    plain = _refanged(text)
    numbers = {int(m.group(1), 16) for m in _HEX.finditer(plain)}
    names = {int(m.group(1), 16) for m in _DECOMPILER_NAME.finditer(plain)}
    numbers.update(int(n) for n in _DECIMAL.findall(_without_hex_and_ids(plain)))
    return _Searched(
        numbers=numbers | names,
        names=names,
        techniques=set(TECHNIQUE_WORD_RE.findall(plain)),
        folded=plain.casefold(),
    )


def _is_stated(value: str, searched: _Searched) -> bool:
    if is_technique_id(value):
        return value in searched.techniques
    number: int | None = None
    if re.fullmatch(r"0x[0-9a-f]+", value):
        number = int(value, 16)
    elif value.isdigit():
        number = int(value)
    if number is not None:
        if number in searched.numbers:
            return True
        return any(
            name > number and (name - number) % _IMAGE_BASE_ALIGNMENT == 0
            for name in searched.names
        )
    return value in searched.folded


def _whole_text(revision: Any, answer: str) -> str:
    """Everything a revision states: answer, claims, evidence, techniques, findings, disputes."""
    parts: list[str] = [str(answer or ""), str(getattr(revision, "answer_text", "") or "")]
    for claim in getattr(revision, "claims", None) or []:
        parts.append(str(getattr(claim, "claim", "") or ""))
        parts.append(str(getattr(claim, "evidence_ref", "") or ""))
        parts.append(str(getattr(claim, "technique_id", "") or ""))
    for finding in getattr(revision, "findings", None) or []:
        parts.append(str(getattr(finding, "title", "") or ""))
        parts.append(str(getattr(finding, "detail", "") or ""))
        parts.extend(str(t) for t in getattr(finding, "technique_ids", None) or [])
    parts.extend(str(item) for item in getattr(revision, "dissent_items", None) or [])
    return "\n".join(parts)


@dataclass(frozen=True)
class DroppedValues:
    """The values of one claim of the answer in force a revision states nowhere."""

    claim: str
    missing: tuple[str, ...]


def values_as_written(text: str, technique_id: str | None = "") -> dict[str, str]:
    """``{value: as the claim wrote it}`` for each value :func:`claim_values` reads.

    A quoted value is compared without case, and the record writes it as the
    claim did: a value folded to lower case is a different string to every
    mask that matches a configured value exactly.
    """
    written: dict[str, str] = {value: value for value in claim_values(text, technique_id)}
    for match in _QUOTED.finditer(_refanged(text)):
        quoted = (match.group(1) or match.group(2) or "").strip()
        if quoted.casefold() in written:
            written[quoted.casefold()] = quoted
    return written


def dropped_claims(
    in_force: Any, revision: Any, answer: str = "", revision_round: int | None = None
) -> list[tuple[Any, tuple[str, ...]]]:
    """Each claim of ``in_force``, by itself, with the values ``revision`` states nowhere.

    The claim object, never its sentence alone: a technique list split on
    commas gives several claims one sentence, and each is its own claim with
    its own id. The values are as the claim wrote them (:func:`values_as_written`).
    """
    if in_force is None or revision is None:
        return []
    searched = _searched(_whole_text(revision, answer))
    out: list[tuple[Any, tuple[str, ...]]] = []
    for claim in getattr(in_force, "claims", None) or []:
        written = values_as_written(
            str(getattr(claim, "claim", "") or ""), getattr(claim, "technique_id", None) or ""
        )
        if revision_round is not None:
            written.pop(str(int(revision_round)), None)
        missing = tuple(written[v] for v in sorted(written) if not _is_stated(v, searched))
        if missing:
            out.append((claim, missing))
    return out


def dropped_values(
    in_force: Any, revision: Any, answer: str = "", revision_round: int | None = None
) -> list[DroppedValues]:
    """Each claim of ``in_force`` with values ``revision`` states nowhere, in order.

    The round's own number is never one of them: a claim that names its round
    states no value by it.
    """
    if in_force is None or revision is None:
        return []
    searched = _searched(_whole_text(revision, answer))
    dropped: list[DroppedValues] = []
    for claim in getattr(in_force, "claims", None) or []:
        values = claim_values(
            str(getattr(claim, "claim", "") or ""), getattr(claim, "technique_id", None) or ""
        )
        if revision_round is not None:
            values = values - {str(int(revision_round))}
        missing = tuple(sorted(v for v in values if not _is_stated(v, searched)))
        if missing:
            dropped.append(
                DroppedValues(claim=str(getattr(claim, "claim", "") or ""), missing=missing)
            )
    return dropped


def defanged(text: str) -> str:
    """``text`` with the network values it names written defanged, for a sentence a reader sees."""
    from maljan.pipeline.validation import network_values_in
    from maljan.reporting.defang import defang_text

    return defang_text(text, [(value, kind) for kind, value in network_values_in(text)])


def dropped_values_sentence(name: str, revision_round: int, dropped: DroppedValues) -> str:
    """The run summary's sentence for one claim's values, its network values defanged."""
    return defanged(
        f"The {name} analyst's round-{int(revision_round)} revision states nowhere "
        f"{', '.join(dropped.missing)}, which its answer in force stated in the claim "
        f'"{dropped.claim}".'
    )


_EVIDENCE_ID = re.compile(r"\bev_\d+\b", re.IGNORECASE)
# The words a claim says something is not so with: two claims that differ in
# them differ in what they claim, whatever else they share.
_NEGATORS = frozenset(
    {
        "not",
        "no",
        "never",
        "none",
        "nor",
        "neither",
        "without",
        "absent",
        "unconfirmed",
        "unobserved",
        "cannot",
        "nothing",
        "nowhere",
    }
)
# A word as a claim writes it: letters, digits and the joiners an identifier,
# a file name or a host name holds inside it.
_WORD = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.\-']*[A-Za-z0-9])?")
# Confidence is compared in steps of this size: two values in one step are the
# same confidence, any other two a change.
CONFIDENCE_STEP = 0.05
# The key of one claim: values, entry ids, technique, negators, confidence
# step and technical terms.
ClaimKey = tuple[
    frozenset[str], frozenset[str], str, tuple[str, ...], int | None, frozenset[str], frozenset[str]
]
# Words that carry no fact of a claim: articles, prepositions, conjunctions,
# pronouns and forms of "be", "have" and "do". Anything else a claim writes
# (a noun, a verb, an adjective, a number word, a modal, a polarity word) is
# a content word, and a change of one is a change of the claim. "or", "nor"
# and "but" are content words: "RC4 and XOR" against "RC4 or XOR" is a change.
_STOPWORDS = frozenset(
    {
        "a", "an", "the", "of", "to", "in", "on", "at", "by", "for", "with", "from",
        "into", "onto", "as", "and", "so", "than", "then", "also",
        "is", "are", "was", "were", "be", "been", "being", "am",
        "has", "have", "had", "having", "do", "does", "did",
        "it", "its", "this", "that", "these", "those", "which", "who", "whom", "whose",
        "there", "here", "they", "them", "their", "he", "she", "his", "her", "we", "our",
        "us", "i", "you", "your", "itself", "themselves",
    }
)  # fmt: skip


def _folded_word(word: str) -> str:
    """A word lower-cased, its plural ending off ("strings" is "string", "entries" "entry")."""
    w = word.lower()
    if len(w) > 3 and w.endswith("ies"):
        return w[:-3] + "y"
    if len(w) > 3 and w.endswith(("ches", "shes", "sses", "xes", "zes")):
        return w[:-2]
    if len(w) > 2 and w.endswith("s") and not w.endswith(("ss", "us", "is")):
        return w[:-1]
    return w


def content_words(text: str) -> frozenset[str]:
    """A claim's content words: every word, folded, but the stopwords (:data:`_STOPWORDS`)."""
    found: set[str] = set()
    for word in _WORD.findall(text):
        lower = word.lower()
        # The stopword test reads the word as written first: "was", "has"
        # and "does" are stopwords, and folded they would not be.
        if lower in _STOPWORDS:
            continue
        folded = _folded_word(lower)
        if folded not in _STOPWORDS:
            found.add(folded)
    return frozenset(found)


def _technical(word: str) -> bool:
    """Whether a word names a technical thing: an acronym, an identifier, a name with a digit.

    "RC4", "XOR", "CreateMutexW", "FUN_1400", "a.dll" are; "Strings",
    "decodes" are not.
    """
    if any(c.isdigit() for c in word) or any(c in "_." for c in word):
        return True
    letters = [c for c in word if c.isalpha()]
    if len(letters) >= 2 and all(c.isupper() for c in letters):
        return True
    return any(c.isupper() for c in word[1:])


def _negators(text: str) -> tuple[str, ...]:
    words = [w.lower() for w in _WORD.findall(text)]
    found = [w for w in words if w in _NEGATORS or w.endswith("n't")]
    return tuple(sorted(found))


def _confidence_step(claim: Any) -> int | None:
    value = getattr(claim, "confidence", None)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return int(round(float(value) / CONFIDENCE_STEP))


def claim_substance(isr: Any) -> Counter[ClaimKey]:
    """What an answer's claims state, wording aside, one key per claim.

    A claim's key holds everything that changes what it claims:
    :func:`claim_values` (numbers, hex addresses, technique ids, quoted
    values), the entry ids its evidence line cites, its technique, the
    negators it writes ("not", "no", "never", "without", a word ending
    "n't"), its confidence in steps of :data:`CONFIDENCE_STEP`, and its
    technical terms (acronyms, identifiers, names holding a digit, folded:
    "RC4" against "XOR"), and its content words (:func:`content_words`:
    every word but the stopwords, case and plural folded, so "three" against
    "four", "explorer" against "svchost" or "packed" against "unpacked" is a
    change). Two claims are one key only when all of these are equal: a
    reordering, punctuation or a stopword is wording.
    """
    keys: Counter[ClaimKey] = Counter()
    for claim in getattr(isr, "claims", None) or []:
        text = str(getattr(claim, "claim", "") or "")
        technique = str(getattr(claim, "technique_id", "") or "").strip()
        keys[
            (
                claim_values(text, technique),
                frozenset(
                    i.lower() for i in _EVIDENCE_ID.findall(str(getattr(claim, "evidence_ref", "")))
                ),
                technique,
                _negators(text),
                _confidence_step(claim),
                frozenset(w.lower() for w in _WORD.findall(text) if _technical(w)),
                content_words(text),
            )
        ] += 1
    return keys


def unchanged_in_substance(in_force: Any, revision: Any) -> bool:
    """Whether a revision states the claims in force again, wording aside (:func:`claim_substance`).

    An answer with no claim is not one: it states nothing to compare. Any
    claim whose key cannot be read makes the round not reworded.
    """
    try:
        before = claim_substance(in_force)
        return bool(before) and before == claim_substance(revision)
    except Exception:  # noqa: BLE001 — unsure is a change
        return False


def answer_unchanged(in_force: str, revision: str) -> bool:
    """Whether a revision's text is the answer in force again, whitespace aside."""
    before = " ".join(str(in_force or "").split())
    after = " ".join(str(revision or "").split())
    return bool(before) and before == after
