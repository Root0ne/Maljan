"""One reasoning card per ATT&CK technique, read from the data file beside the vendored table.

A card says what the evidence for a technique has to show: its required
components; its kind — behaviour-focused, where the action alone is the
technique, or intent-critical, where the technique also needs a stated
adversarial purpose; the indicators a reader looks for; and the sibling
techniques it is confused with, each with the criterion that tells the two
apart. The cards are written from the vendored table's rows
(``data/attck_techniques.json``) and each names the row fields it was written
from.

Two readers use them. The technique check shows the named technique's card
with its questions, and the judge's technique question shows it under each
technique it asks about. Both state facts read off a card, never a decision:
which required component no supporting claim or cited entry shows, which
sibling's criterion the claim sentences fit and the named card's words do not,
and whether a cited entry holds the behaviour at all. The model answers; the
answer stands.

A card also carries match words, which are never shown to a model: the words a
requirement, a sibling or the behaviour is recognised by in a claim or in a
ledger entry (``terms``), and the words only the card's own behaviour is
written with (``distinct``). A term is matched without case from a word start, so ``inject``
reads "injects" and "injection".
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from maljan.core.logger import logger

CARDS_FILE = Path(__file__).resolve().parents[3] / "data" / "attck_technique_cards.json"

# The kinds a card may be, and how the card line says each.
BEHAVIOUR_KIND = "behaviour"
INTENT_KIND = "intent"
KIND_WORDS: dict[str, str] = {
    BEHAVIOUR_KIND: "behaviour-focused: the action alone is the technique",
    INTENT_KIND: "intent-critical: the action needs a stated adversarial purpose",
}

# The vendored table's row fields a card may name as its source.
SOURCE_FIELDS: frozenset[str] = frozenset({"name", "tactics", "platforms", "domain"})

# The most lines one card renders to.
MAX_CARD_LINES = 8


@dataclass(frozen=True)
class Requirement:
    """One component the evidence for a technique has to show.

    ``claim_only`` is a component only the analyst's own sentence can show —
    a stated purpose — so a ledger entry does not meet it.
    """

    what: str
    terms: tuple[str, ...]
    claim_only: bool = False


@dataclass(frozen=True)
class Sibling:
    """A technique the card's own is confused with, and what tells the two apart."""

    technique_id: str
    criterion: str
    terms: tuple[str, ...]


@dataclass(frozen=True)
class TechniqueCard:
    """One technique's card, as the data file holds it."""

    technique_id: str
    name: str
    kind: str
    source: tuple[str, ...]
    requires: tuple[Requirement, ...]
    indicators: tuple[str, ...]
    siblings: tuple[Sibling, ...]
    # The words only this technique's behaviour is written with. The sibling
    # reading asks for these, where a card has them, instead of its
    # requirements' words, which a sibling may share ("removes" is said of a
    # deleted file and of a removed hook alike).
    distinct: tuple[str, ...] = ()

    @property
    def vocabulary(self) -> tuple[str, ...]:
        """Every term that names this card's behaviour: its requirements' and its distinct ones."""
        words: list[str] = []
        for requirement in self.requires:
            if not requirement.claim_only:
                words.extend(requirement.terms)
        words.extend(self.distinct)
        return tuple(dict.fromkeys(words))

    @property
    def own_words(self) -> tuple[str, ...]:
        """The words a claim sentence names this card's behaviour with, for the sibling reading."""
        return self.distinct or self.vocabulary


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if str(item).strip())


def _card(technique_id: str, row: dict) -> TechniqueCard:
    return TechniqueCard(
        technique_id=technique_id,
        name=str(row.get("name") or ""),
        kind=str(row.get("kind") or ""),
        source=_strings(row.get("source")),
        requires=tuple(
            Requirement(
                what=str(item.get("what") or ""),
                terms=_strings(item.get("terms")),
                claim_only=bool(item.get("claim_only")),
            )
            for item in row.get("requires") or []
            if isinstance(item, dict)
        ),
        indicators=_strings(row.get("indicators")),
        siblings=tuple(
            Sibling(
                technique_id=str(item.get("id") or "").strip().upper(),
                criterion=str(item.get("criterion") or ""),
                terms=_strings(item.get("terms")),
            )
            for item in row.get("siblings") or []
            if isinstance(item, dict)
        ),
        distinct=_strings(row.get("distinct")),
    )


def read_cards(path: Path) -> dict[str, TechniqueCard]:
    """Every card in the file at ``path``, by technique id; ``{}`` when it cannot be read."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("technique cards: %s could not be read (%s)", path.name, exc)
        return {}
    return {
        str(tid).strip().upper(): _card(str(tid).strip().upper(), row)
        for tid, row in data.items()
        if not str(tid).startswith("_") and isinstance(row, dict)
    }


@lru_cache(maxsize=1)
def load_cards() -> dict[str, TechniqueCard]:
    """The shipped cards, read once."""
    return read_cards(CARDS_FILE)


def technique_card(technique_id: str) -> TechniqueCard | None:
    """The card for an id, a sub-technique without its own read by its parent's; else ``None``."""
    tid = str(technique_id or "").strip().upper()
    if not tid:
        return None
    cards = load_cards()
    card = cards.get(tid)
    if card is None and "." in tid:
        card = cards.get(tid.split(".")[0])
    return card


def _label(technique_id: str) -> str:
    try:
        from maljan.memory.attck_loader import technique_label

        return technique_label(technique_id)
    except Exception:  # noqa: BLE001 — a label unread is the id alone
        return technique_id


def card_lines(card: TechniqueCard, technique_id: str | None = None) -> list[str]:
    """The card as a model reads it, at most :data:`MAX_CARD_LINES` lines.

    ``technique_id`` is the id the card is shown for; a sub-technique read by
    its parent's card says so.
    """
    shown = str(technique_id or card.technique_id).strip().upper()
    head = f"card {_label(card.technique_id)}"
    if shown != card.technique_id:
        head += f" (the parent's card; {shown} has none of its own)"
    kind = KIND_WORDS.get(card.kind, card.kind)
    lines = [f"{head} — {kind}; written from the table's {', '.join(card.source)}"]
    if card.requires:
        lines.append("requires: " + "; ".join(r.what for r in card.requires))
    if card.indicators:
        lines.append("indicators: " + ", ".join(card.indicators))
    lines.extend(
        f"not {_label(sibling.technique_id)} when {sibling.criterion}" for sibling in card.siblings
    )
    return lines[:MAX_CARD_LINES]


def _term_pattern(terms: Iterable[str]) -> re.Pattern[str] | None:
    parts = [
        (r"\b" if term[:1].isalnum() else "") + re.escape(term.lower())
        for term in terms
        if term.strip()
    ]
    return re.compile("|".join(parts), re.IGNORECASE) if parts else None


def mentions(terms: Iterable[str], text: str) -> bool:
    """Whether ``text`` holds any of ``terms``, each read from a word start without case."""
    pattern = _term_pattern(terms)
    return bool(pattern and text and pattern.search(text))


@dataclass(frozen=True)
class CardReading:
    """What a card says of the claims naming its technique: facts, never a decision.

    ``unmet`` are the required components no claim sentence and no cited entry
    shows. ``siblings`` are the confusable techniques whose words every claim
    sentence carries while none carries the card's own.
    """

    unmet: tuple[Requirement, ...] = ()
    siblings: tuple[Sibling, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.unmet or self.siblings)


def read_card(
    card: TechniqueCard,
    sentences: Sequence[str],
    cited: Sequence[str | None],
) -> CardReading:
    """What ``card`` says of the claims naming its technique.

    ``sentences`` are the claims' own sentences; ``cited`` the text of every
    ledger entry they cite, ``None`` for an entry whose text is not known. A
    component is unmet only when it is decided: no sentence shows it and every
    cited entry is known and none shows it (a stated purpose is read from the
    sentences alone). A sibling fits when every sentence carries its words
    while no sentence and no cited entry carries the card's own
    (:attr:`TechniqueCard.own_words`); with an unknown entry it is not decided.
    """
    said = [str(s or "") for s in sentences if str(s or "").strip()]
    if not said:
        return CardReading()
    known = all(text is not None for text in cited)
    texts = [str(text) for text in cited if text]
    unmet: list[Requirement] = []
    for requirement in card.requires:
        if any(mentions(requirement.terms, s) for s in said):
            continue
        if requirement.claim_only:
            unmet.append(requirement)
            continue
        if not known:
            continue
        if any(mentions(requirement.terms, text) for text in texts):
            continue
        unmet.append(requirement)
    own = card.own_words
    siblings = [
        sibling
        for sibling in card.siblings
        if sibling.terms
        and known
        and all(mentions(sibling.terms, s) for s in said)
        and not any(mentions(own, text) for text in [*said, *texts])
    ]
    return CardReading(unmet=tuple(unmet), siblings=tuple(siblings))


def holds_behaviour(card: TechniqueCard | None, text: str, extra: re.Pattern[str] | None) -> bool:
    """Whether a ledger entry's text holds the behaviour: a term of the card or of ``extra``."""
    if not text:
        return False
    if card is not None and mentions(card.vocabulary, text):
        return True
    return bool(extra is not None and extra.search(text))
