"""One reasoning card per ATT&CK technique, read from the data file beside the vendored table.

A card says what the evidence for a technique has to show: its required
components; its kind — behaviour-focused, where the action alone is the
technique, or intent-critical, where the technique also needs a stated
adversarial purpose; the indicators a reader looks for; and the sibling
techniques it is confused with, each with the criterion that tells the two
apart. The cards are written from the ATT&CK definitions of techniques the
vendored table (``data/attck_techniques.json``) carries, and each names the
table fields its head is held to.

A card is reference, shown beside a technique a model already named: the
analysts' does-not-describe question ends with it, and the judge's technique
question shows it under each technique it asks about. Nothing is decided from
a card and no question is asked because of one; the model reads it and
answers. A sub-technique without a card of its own is shown none: its parent's
kind and requirements need not be its own.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from maljan.core.logger import logger

CARDS_FILE = Path(__file__).resolve().parents[3] / "data" / "attck_technique_cards.json"

# The kinds a card may be, and how the card line says each.
BEHAVIOUR_KIND = "behaviour"
INTENT_KIND = "intent"
KIND_WORDS: dict[str, str] = {
    BEHAVIOUR_KIND: "behaviour-focused, the action alone is the technique",
    INTENT_KIND: "intent-critical, the action needs a stated adversarial purpose",
}

# The vendored table's row fields a card may name as its source.
SOURCE_FIELDS: frozenset[str] = frozenset({"name", "tactics", "platforms", "domain"})


@dataclass(frozen=True)
class Sibling:
    """A technique the card's own is confused with, and what tells the two apart."""

    technique_id: str
    criterion: str


@dataclass(frozen=True)
class TechniqueCard:
    """One technique's card, as the data file holds it."""

    technique_id: str
    name: str
    kind: str
    source: tuple[str, ...]
    requires: tuple[str, ...]
    indicators: tuple[str, ...]
    siblings: tuple[Sibling, ...]


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
        requires=_strings(row.get("requires")),
        indicators=_strings(row.get("indicators")),
        siblings=tuple(
            Sibling(
                technique_id=str(item.get("id") or "").strip().upper(),
                criterion=str(item.get("criterion") or ""),
            )
            for item in row.get("siblings") or []
            if isinstance(item, dict)
        ),
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
    """The card for exactly this id, or ``None``."""
    tid = str(technique_id or "").strip().upper()
    return load_cards().get(tid) if tid else None


def _label(technique_id: str) -> str:
    try:
        from maljan.memory.attck_loader import technique_label

        return technique_label(technique_id)
    except Exception:  # noqa: BLE001 — a label unread is the id alone
        return technique_id


def card_lines(card: TechniqueCard) -> list[str]:
    """The card as a model reads it: its kind, requirements, indicators and siblings.

    The technique itself is not written: the card is shown beside the line
    that names it.
    """
    lines = [f"card: {KIND_WORDS.get(card.kind, card.kind)}"]
    if card.requires:
        lines.append("requires: " + "; ".join(card.requires))
    if card.indicators:
        lines.append("indicators: " + "; ".join(card.indicators))
    lines.extend(
        f"not {_label(sibling.technique_id)} when {sibling.criterion}" for sibling in card.siblings
    )
    return lines


def technique_card_lines(technique_id: str) -> list[str]:
    """The lines of the card for ``technique_id`` (:func:`card_lines`), or none without one."""
    try:
        card = technique_card(technique_id)
        return card_lines(card) if card is not None else []
    except Exception as exc:  # noqa: BLE001 — a card unread is a question without it
        logger.debug("technique cards: the card for %s was not read (%s)", technique_id, exc)
        return []
