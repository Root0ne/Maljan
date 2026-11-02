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
the model claimed, and in a human turn (the task, the agent's earlier answer,
the peer reports, a question) where the catalogue knows the id, active,
retired or revoked: a human turn can quote a sample's own strings, and an id no catalogue
had is stated only where the model wrote it. Tool-derived data names nothing:
a tool answer, the triage pack at the head of the task and the earlier run's
block (``long_term_memory.EARLIER_RUN_HEADING``), nor a format example's claim
block, whose claim and evidence are "...". A model's reasoning and its tool
requests are not what it claimed.

**Bounded.** A note details at most :data:`MAX_IDS_PER_NOTE` ids, the first
named first; past that it ends with one line saying how many named ids it did
not detail and that the knowledge look-up tool gives them. Those ids count as
stated, so the bound holds on every later request alike.

**Continued questions.** A question continued over the loop's conversation
(T-489) carries the facts of every id its answer and question name; an id the
rebuilt question names only inside evidence text it quotes is stated there and
not in the continued one, where that evidence is a tool answer.

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
    "MAX_IDS_PER_NOTE",
    "STANDING_FACTS_CHARS",
    "TECHNIQUE_FACTS_ATTACHED",
    "TECHNIQUE_FACTS_STATED",
    "TECHNIQUE_FACTS_TURN_LEAD",
    "notes_kept_after_clearing",
    "without_tool_answer_notes",
    "with_technique_facts",
]

# The note the platform put on a turn, noted in its ``response_metadata``
# (which no client sends): known by this, never by its words, which a sample's
# text can carry.
TECHNIQUE_FACTS_ATTACHED = "maljan_technique_facts_attached"
# Every id the note counts as stated, those it details and those past its
# bound, so a turn read again states the same ids as when it was noted.
TECHNIQUE_FACTS_STATED = "maljan_technique_facts_stated"
# How many characters at the head of a human turn the platform's standing
# facts block (the triage pack and the earlier run) takes, noted where it is
# put there (``base_agent.frame_messages``): data, which names no id here.
STANDING_FACTS_CHARS = "maljan_standing_facts_chars"

# The most ids one note details. A bound, stated in the note where it holds.
MAX_IDS_PER_NOTE = 64

# The head of the note a turn carries.
TECHNIQUE_FACTS_TURN_LEAD = (
    "What the platform's ATT&CK catalogue holds for each technique id named so far that this "
    "conversation has not stated, so none of them needs a look-up:"
)

# The note's last line when ids were left past the bound.
NOT_DETAILED_LINE = (
    "{count} more technique id(s) named so far are not detailed here; the knowledge look-up "
    "tool gives each one's facts."
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


def _stated_by(message: Any, note: str) -> list[str]:
    """The ids the platform's note on ``message`` counts as stated."""
    noted = getattr(message, "response_metadata", None) or {}
    stated = noted.get(TECHNIQUE_FACTS_STATED) if isinstance(noted, dict) else None
    if isinstance(stated, list | tuple):
        return [str(tid) for tid in stated]
    return _stated_in(note.split("\n")[1:])


def _without_standing_facts(message: Any, text: str) -> str:
    """A human turn's text without the standing facts block at its head and the earlier run."""
    from maljan.memory.long_term_memory import EARLIER_RUN_END, EARLIER_RUN_HEADING
    from maljan.pipeline.triage_pack import PACK_HEADING

    noted = getattr(message, "response_metadata", None) or {}
    size = noted.get(STANDING_FACTS_CHARS) if isinstance(noted, dict) else None
    if isinstance(size, int) and not isinstance(size, bool) and size > 0:
        text = text[size:]
    elif text.startswith(PACK_HEADING):
        # A turn carrying the pack without the note (rebuilt without its
        # metadata): the pack's lines run to its first blank line.
        _pack, _gap, text = text.partition("\n\n")
    while EARLIER_RUN_HEADING in text:
        head, _found, rest = text.partition(EARLIER_RUN_HEADING)
        _block, ended, tail = rest.partition(EARLIER_RUN_END)
        if not ended:
            # A heading no end follows is text quoting it, not the block:
            # what comes after it still names its ids.
            break
        text = f"{head}{tail}"
    return text


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
def _known(technique_id: str) -> bool:
    from maljan.memory.attck_loader import retired_in, revoked_by, valid_ids

    return technique_id in valid_ids() or bool(retired_in(technique_id) or revoked_by(technique_id))


def catalogue_knows(technique_id: str) -> bool:
    """Whether the vendored catalogue has the id: active, retired or revoked.

    Only an answer is kept (``_known``): a read that failed is tried again.
    """
    try:
        return _known(technique_id)
    except Exception as exc:  # noqa: BLE001 — an id the catalogue cannot answer is left out
        logger.debug("technique facts: %s was not checked (%s)", technique_id, exc)
        return False


def catalogue_fact(technique_id: str) -> str:
    """One id's note line from the vendored catalogue, or ``""`` where none is read.

    Only an answer is kept (``_fact``): a read that failed is tried again.
    """
    try:
        return _fact(technique_id)
    except Exception as exc:  # noqa: BLE001 — an id the catalogue cannot answer is left out
        logger.debug("technique facts: %s was not read (%s)", technique_id, exc)
        return ""


@lru_cache(maxsize=4096)
def _fact(technique_id: str) -> str:
    """:func:`catalogue_fact`'s line; raises where the catalogue cannot be read.

    The line a retry carries (``validation.technique_fact_line``: name,
    parent and tactics, or why the catalogue has no such technique and its
    nearest ids), with the requirement of the id's card where it has one
    (``memory.technique_cards``), the catalogue's own short account of what
    the technique is.
    """
    from maljan.memory.technique_cards import technique_card
    from maljan.pipeline.validation import technique_fact_line
    from maljan.tools import knowledge

    line = technique_fact_line(knowledge, technique_id)
    card = technique_card(technique_id)
    if card is not None and card.requires:
        line = f"{line}; requires: {'; '.join(card.requires)}"
    return line


def _with_text(message: Any, note: str, *, stated: Sequence[str] | None = None) -> Any:
    """``message`` with ``note`` at its end: text appended, or a text part.

    With ``stated``, the message is noted as carrying the note, stating those ids.
    """
    update: dict[str, Any] = {}
    if stated is not None:
        update["response_metadata"] = {
            **(getattr(message, "response_metadata", None) or {}),
            TECHNIQUE_FACTS_ATTACHED: note,
            TECHNIQUE_FACTS_STATED: list(stated),
        }
    content = message.content
    if isinstance(content, list):
        update["content"] = [*content, {"type": "text", "text": note}]
    else:
        text = str(content or "")
        update["content"] = f"{text}\n\n{note}" if text else note
    return message.model_copy(update=update)


def _carries_a_note(messages: Sequence[Any], index: int) -> bool:
    """Whether the turn at ``index`` closes a stretch.

    The conversation's last turn, a human turn before a model turn, and a
    tool answer no other tool answer follows: a tool round's last answer keeps
    its note when a human turn comes after it (the salvage's directive), so a
    note never moves off the turn an earlier request carried it on.
    """
    kind = getattr(messages[index], "type", "")
    if kind not in _CARRYING_TYPES:
        return False
    if index == len(messages) - 1:
        return True
    following = getattr(messages[index + 1], "type", "")
    if kind == "tool":
        return following != "tool"
    return following in _MODEL_TYPES


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
                stated.update(_stated_by(message, note))
            if kind in _NAMING_TYPES:
                text = _text(getattr(message, "content", ""))
                if note:
                    head, found, tail = text.rpartition(note)
                    text = f"{head}{tail}" if found else text
                if kind == "human":
                    text = _without_standing_facts(message, text)
                    text, given = _retry_facts(_EXAMPLE_BLOCK.sub("", text))
                    stated.update(given)
                for match in TECHNIQUE_WORD_RE.findall(text):
                    if match not in named and (kind != "human" or knows(match)):
                        named.append(match)
            if note or not _carries_a_note(out, index):
                continue
            fresh = [tid for tid in named if tid not in stated]
            stated.update(fresh)
            lines = [line for line in (line_of(tid) for tid in fresh[:MAX_IDS_PER_NOTE]) if line]
            if len(fresh) > MAX_IDS_PER_NOTE:
                lines.append(NOT_DETAILED_LINE.format(count=len(fresh) - MAX_IDS_PER_NOTE))
            if lines:
                out[index] = _with_text(
                    message, "\n".join([TECHNIQUE_FACTS_TURN_LEAD, *lines]), stated=fresh
                )
    except Exception as exc:  # noqa: BLE001 — the facts never cost a turn
        logger.debug("technique facts: left out (%s)", exc)
        return list(messages)
    return out


def without_tool_answer_notes(messages: Sequence[Any]) -> tuple[list[Any], int]:
    """``messages`` with the notes taken off every tool answer before the last model turn.

    And the characters taken off. Those answers are what a clear may take
    (``tool_answer_clearing``): it measures each answer and names its length
    without the platform's note, and :func:`notes_kept_after_clearing` puts
    each note back after it, the answer cleared or not, byte for byte.
    """
    out = list(messages)
    last_turn = max(
        (i for i, m in enumerate(out) if getattr(m, "type", "") in _MODEL_TYPES), default=-1
    )
    taken = 0
    for index in range(max(0, last_turn)):
        message = out[index]
        note = _note_of(message)
        if not note or getattr(message, "type", "") != "tool":
            continue
        content = message.content
        if isinstance(content, list):
            last = content[-1] if content else None
            if isinstance(last, dict) and last.get("type") == "text" and last.get("text") == note:
                out[index] = message.model_copy(update={"content": content[:-1]})
                taken += len(note)
        elif isinstance(content, str) and content.endswith(note):
            bare = content[: -len(note)]
            bare = bare[:-2] if bare.endswith("\n\n") else bare
            out[index] = message.model_copy(update={"content": bare})
            taken += len(content) - len(bare)
    return out, taken


def notes_kept_after_clearing(messages: Sequence[Any]) -> list[Any]:
    """``messages`` with each note taken off a turn, or cleared with it, put back at its end."""
    out = list(messages)
    for index, message in enumerate(out):
        note = _note_of(message)
        if note and note not in _text(getattr(message, "content", "")):
            try:
                out[index] = _with_text(message, note)
            except Exception as exc:  # noqa: BLE001 — a note not restored costs a look-up
                logger.debug("technique facts: a cleared turn's note not restored (%s)", exc)
    return out
