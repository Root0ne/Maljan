"""The catalogue facts of every technique id a conversation names, handed to the model in it.

An analyst that names a technique id in its answer, or reads one in its task or
in a question, asked the knowledge tools for that id's name, tactics and parent
before it wrote about it: in one paid run the dynamic analyst spent 26 of its 38
tool calls on such look-ups of ids it had already claimed. The answers are the
platform's own deterministic data (the vendored catalogue the look-up tools
read, ``tools.knowledge``), so a request carries them: each technique id a
human turn or a model turn of the conversation writes is stated once, with its
name, its parent, its tactics and its card's requirement, or why the catalogue
has no such technique (:func:`with_technique_facts`). The look-up tools stay
attached and answer as before.

**Where.** A note rides at the end of the user turn that closes each stretch of
the conversation (a human turn or the last tool answer before a model turn,
and the conversation's last turn), and states the ids named up to there that no
earlier note, nor a retry's catalogue facts (``validation.TECHNIQUE_FACTS_LEAD``),
stated. It is a function of the turns before it alone, so every later request
carries the same note at the same place: the front of each request is the
front of the one before it, byte for byte, and a provider's prefix cache, a
continued question's cached prefix and a replayed thinking block's binding all
hold. A conversation that names no technique id is sent as it always was.

**What counts as named.** Ids written, in the case the platform writes them
(``technique_ids.TECHNIQUE_WORD_RE``), in a model turn's text, which are what
the model claimed, and in a human turn (the task, its pack, the agent's earlier
answer, a question; not a format example's claim block, whose claim and
evidence are "...") where the catalogue knows the id, active or retired: a
human turn can quote a sample's own strings, and an id no catalogue had is
stated only where the model wrote it, so no sample text sizes the note. A tool
answer is data and names nothing here, and a model's reasoning and its tool
requests are not what it claimed.

**Cleared answers.** A tool answer cleared to a reference
(``tool_answer_clearing``) loses its text; the note it carried is put back
after the reference (:func:`notes_kept_after_clearing`), from the note on the
message, so the facts stay where they were stated.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from functools import lru_cache
from typing import Any

from maljan.analysis.technique_ids import ID_BODY, TECHNIQUE_WORD_RE
from maljan.core.logger import logger

__all__ = [
    "TECHNIQUE_FACTS_ATTACHED",
    "TECHNIQUE_FACTS_TURN_LEAD",
    "notes_kept_after_clearing",
    "with_technique_facts",
]

# The note the platform put on a turn, noted in its ``response_metadata``
# (which no client sends): known by this, never by its words, which a sample's
# text can carry.
TECHNIQUE_FACTS_ATTACHED = "maljan_technique_facts_attached"

# The head of the note a turn carries.
TECHNIQUE_FACTS_TURN_LEAD = (
    "What the platform's ATT&CK catalogue holds for each technique id named so far that this "
    "conversation has not stated, so none of them needs a look-up:"
)

# One stated id: a note line opens with it.
_FACT_LINE = re.compile(rf"- ({ID_BODY})(?![\w.])")

# A claim block written as a format example, its claim and evidence left as
# "...": the platform's own instructions carry one, and the id on its
# TECHNIQUE line is the example's, named by no one.
_EXAMPLE_BLOCK = re.compile(
    r"CLAIM: \.\.\.\nEVIDENCE: \.\.\.\n(?:CONFIDENCE: [^\n]*\n)?TECHNIQUE: [^\n]*"
)

# The message types a technique id is named in, and those a note rides on.
_NAMING_TYPES = frozenset({"human", "ai", "AIMessageChunk"})
_CARRYING_TYPES = frozenset({"human", "tool"})
_MODEL_TYPES = frozenset({"ai", "AIMessageChunk"})


def _text(content: Any) -> str:
    """The text a turn shows: a string, or its text parts joined; reasoning left out."""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text") or ""))
    return "\n".join(parts)


def _note_of(message: Any) -> str:
    """The note the platform put on ``message``, or ``""``."""
    noted = getattr(message, "response_metadata", None) or {}
    note = noted.get(TECHNIQUE_FACTS_ATTACHED) if isinstance(noted, dict) else None
    return note if isinstance(note, str) else ""


def _stated_in(lines: Sequence[str]) -> list[str]:
    """The ids the fact lines under a lead state, in order, up to the first other line."""
    stated: list[str] = []
    for line in lines:
        opening = _FACT_LINE.match(line)
        if opening is None:
            break
        stated.append(opening.group(1))
    return stated


def _retry_facts(text: str) -> tuple[str, list[str]]:
    """``text`` without a retry's catalogue facts, and the ids those facts state.

    The retry's lines name a parent and the catalogue's nearest ids beside each
    id; those are not ids the turn names, so the block is read apart.
    """
    from maljan.pipeline.validation import TECHNIQUE_FACTS_LEAD

    if TECHNIQUE_FACTS_LEAD not in text:
        return text, []
    lines = text.split("\n")
    kept: list[str] = []
    stated: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.strip() == TECHNIQUE_FACTS_LEAD:
            ids = _stated_in(lines[index + 1 :])
            stated.extend(ids)
            index += 1 + len(ids)
            continue
        kept.append(line)
        index += 1
    return "\n".join(kept), stated


@lru_cache(maxsize=4096)
def catalogue_knows(technique_id: str) -> bool:
    """Whether the vendored catalogue has the id, as an active technique or a retired one."""
    try:
        from maljan.memory.attck_loader import retired_in, valid_ids

        return technique_id in valid_ids() or bool(retired_in(technique_id))
    except Exception as exc:  # noqa: BLE001 — an id the catalogue cannot answer is left out
        logger.debug("technique facts: %s was not checked (%s)", technique_id, exc)
        return False


@lru_cache(maxsize=4096)
def catalogue_fact(technique_id: str) -> str:
    """One id's note line from the vendored catalogue, or ``""`` where none is read.

    The line a retry carries (``validation.technique_fact_line``: name,
    parent and tactics, or why the catalogue has no such technique and its
    nearest ids), with the requirement of the id's card where it has one
    (``memory.technique_cards``), the catalogue's own short account of what
    the technique is.
    """
    try:
        from maljan.pipeline.validation import technique_fact_line
        from maljan.tools import knowledge

        line = technique_fact_line(knowledge, technique_id)
    except Exception as exc:  # noqa: BLE001 — an id the catalogue cannot answer is left out
        logger.debug("technique facts: %s was not read (%s)", technique_id, exc)
        return ""
    try:
        from maljan.memory.technique_cards import technique_card

        card = technique_card(technique_id)
    except Exception as exc:  # noqa: BLE001 — a card unread is a line without it
        logger.debug("technique facts: the card for %s was not read (%s)", technique_id, exc)
        card = None
    if card is not None and card.requires:
        line = f"{line}; requires: {'; '.join(card.requires)}"
    return line


def _with_text(message: Any, note: str, *, noted: bool) -> Any:
    """``message`` with ``note`` at its end: text appended, or a text part."""
    update: dict[str, Any] = {}
    if noted:
        update["response_metadata"] = {
            **(getattr(message, "response_metadata", None) or {}),
            TECHNIQUE_FACTS_ATTACHED: note,
        }
    content = message.content
    if isinstance(content, list):
        update["content"] = [*content, {"type": "text", "text": note}]
    else:
        text = str(content or "")
        update["content"] = f"{text}\n\n{note}" if text else note
    return message.model_copy(update=update)


def _carries_a_note(messages: Sequence[Any], index: int) -> bool:
    """Whether the turn at ``index`` closes a stretch: a user turn last or before a model turn."""
    if getattr(messages[index], "type", "") not in _CARRYING_TYPES:
        return False
    if index == len(messages) - 1:
        return True
    return getattr(messages[index + 1], "type", "") in _MODEL_TYPES


def with_technique_facts(
    messages: Sequence[Any],
    fact: Callable[[str], str] | None = None,
    known: Callable[[str], bool] | None = None,
) -> list[Any]:
    """``messages`` with each closing user turn carrying the facts of the ids named up to it.

    ``fact`` gives one id's note line (:func:`catalogue_fact` by default; an
    empty line leaves the id out), ``known`` whether the catalogue has an id
    a human turn writes (:func:`catalogue_knows`). A turn that already carries the platform's
    note keeps it as it is, and the ids it states count as stated. The
    messages are never changed; a turn that gains a note is a copy. Never
    raises: a conversation this cannot read is returned as it was.
    """
    out = list(messages)
    try:
        line_of = fact or catalogue_fact
        knows = known or catalogue_knows
        named: list[str] = []
        stated: set[str] = set()
        for index, message in enumerate(out):
            kind = getattr(message, "type", "")
            note = _note_of(message)
            if note:
                stated.update(_stated_in(note.split("\n")[1:]))
            if kind in _NAMING_TYPES:
                text = _text(getattr(message, "content", ""))
                if note:
                    head, found, tail = text.rpartition(note)
                    text = f"{head}{tail}" if found else text
                if kind == "human":
                    text, given = _retry_facts(_EXAMPLE_BLOCK.sub("", text))
                    stated.update(given)
                for match in TECHNIQUE_WORD_RE.findall(text):
                    if match not in named and (kind != "human" or knows(match)):
                        named.append(match)
            if note or not _carries_a_note(out, index):
                continue
            lines: list[str] = []
            for tid in named:
                if tid in stated:
                    continue
                stated.add(tid)
                line = line_of(tid)
                if line:
                    lines.append(line)
            if lines:
                out[index] = _with_text(
                    message, "\n".join([TECHNIQUE_FACTS_TURN_LEAD, *lines]), noted=True
                )
    except Exception as exc:  # noqa: BLE001 — the facts never cost a turn
        logger.debug("technique facts: left out (%s)", exc)
        return list(messages)
    return out


def notes_kept_after_clearing(messages: Sequence[Any]) -> list[Any]:
    """``messages`` with each note a clear took off a turn put back after its reference."""
    out = list(messages)
    for index, message in enumerate(out):
        note = _note_of(message)
        if note and note not in _text(getattr(message, "content", "")):
            try:
                out[index] = _with_text(message, note, noted=False)
            except Exception as exc:  # noqa: BLE001 — a note not restored costs a look-up
                logger.debug("technique facts: a cleared turn's note not restored (%s)", exc)
    return out
