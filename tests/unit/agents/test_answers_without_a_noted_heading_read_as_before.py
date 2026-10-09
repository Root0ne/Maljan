"""Every stored answer reads as it did, except where a heading carries a note.

The heading rule before notes were read is pinned here (``_EARLIER_HEAD_RE``:
a round-bracketed note before the delimiter was allowed and dropped, a square
one was no heading, and a heading needed its delimiter). Each answer in the
repository's claim fixtures is read under that rule and under the rule in
force. An answer with no noted heading reads the same in every field; one with
a noted heading reads every claim it read before with the same sentence, the
note in ``heading_note``, and may read more. The answers that change are listed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from maljan.agents import claim_headings
from maljan.agents.base_agent import read_claim_blocks
from maljan.agents.claim_headings import LINE_PREFIX

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "claims"

_EARLIER_HEAD_RE = re.compile(
    r"^" + LINE_PREFIX + r"CLAIM(?:[ \t]*#?\d+)?(?:[ \t]*\([^)\n]*\))?[ \t]*(?:\*\*)?[ \t]*"
    r"(?::|—|–|-(?=\s))[ \t]*(?:\*\*)?[ \t]*"
)
# A heading with a note, as an answer writes it: the label, a number, a bracket.
_NOTED = re.compile(r"^" + LINE_PREFIX + r"CLAIM(?:[ \t]*#?\d+)?[ \t]*[\[(]", re.MULTILINE)


def _strings(value: Any, where: str) -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(where, value)] if "CLAIM" in value else []
    if isinstance(value, dict):
        return [row for key, item in value.items() for row in _strings(item, f"{where}/{key}")]
    if isinstance(value, list):
        return [row for n, item in enumerate(value) for row in _strings(item, f"{where}/{n}")]
    return []


def _answers() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for path in sorted(FIXTURES.iterdir()):
        raw = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            out.extend(_strings(json.loads(raw), path.name))
        else:
            out.append((path.name, raw))
    return out


ANSWERS = _answers()

# The fixture answers whose claims change: each writes noted headings, read
# before with the note dropped and now with it kept.
CHANGED = [
    "every_answer_of_one_run.json/static final answer",
    "every_answer_of_one_run.json/dynamic final answer",
    "every_answer_of_one_run.json/network final answer",
    "every_answer_of_one_run.json/dynamic round 1 answer, cut at the event bound",
    "every_answer_of_one_run.json/network round 1 answer, cut at the event bound",
    "every_answer_of_one_run.json/static round 2 answer, cut at the event bound",
    "every_answer_of_one_run.json/dynamic round 2 answer, cut at the event bound",
    "every_answer_of_one_run.json/network round 2 answer, cut at the event bound",
]


def _read(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for strict in (False, True):
        read = read_claim_blocks(text, require_evidence=strict)
        out[f"claims{strict}"] = [c.model_dump(mode="json") for c in read.claims]
        out[f"rest{strict}"] = (
            read.without_confidence,
            read.begun,
            read.after_disputes,
            read.confidence_unreadable,
            read.blocks_read,
        )
    out["counts"] = claim_headings.claim_heading_counts(text)
    return out


def _earlier(text: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    with monkeypatch.context() as patched:
        patched.setattr(claim_headings, "CLAIM_HEAD_RE", _EARLIER_HEAD_RE)
        patched.setattr(
            claim_headings, "heading_sentence", lambda line, heading: line[heading.end() :]
        )
        patched.setattr(claim_headings, "heading_note", lambda heading: None)
        return _read(text)


def _kept_with_a_note(before: dict[str, Any], now: dict[str, Any]) -> bool:
    """The same claim, with at most the heading's note beside it."""
    return {key: value for key, value in now.items() if key != "heading_note"} == before


def test_the_fixtures_hold_answers() -> None:
    assert len(ANSWERS) >= 20


def test_answers_without_a_noted_heading_read_the_same(monkeypatch: pytest.MonkeyPatch) -> None:
    changed = []
    for where, text in ANSWERS:
        before, now = _earlier(text, monkeypatch), _read(text)
        if before == now:
            continue
        changed.append(where)
        assert _NOTED.search(text), where
        for strict in (False, True):
            remaining = iter(now[f"claims{strict}"])
            assert all(
                any(_kept_with_a_note(claim, later) for later in remaining)
                for claim in before[f"claims{strict}"]
            ), where

    assert changed == CHANGED


def test_the_changed_answers_change_only_by_the_note(monkeypatch: pytest.MonkeyPatch) -> None:
    for where, text in ANSWERS:
        if where not in CHANGED:
            continue
        before, now = _earlier(text, monkeypatch), _read(text)
        for strict in (False, True):
            assert before[f"rest{strict}"] == now[f"rest{strict}"], where
            pairs = zip(before[f"claims{strict}"], now[f"claims{strict}"], strict=True)
            assert all(_kept_with_a_note(old, new) for old, new in pairs), where
