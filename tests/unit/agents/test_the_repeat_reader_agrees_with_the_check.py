"""The line-by-line repeat reader gives the check's own verdict for every prefix of an answer.

The check on a finished answer counts the claim blocks of the answer without
its tool-call scaffolding (``claims_repeated(strip_tool_call_scaffolding(text))``).
The reader keeps that count as the answer streams, without reading the whole
answer again. Compared here at every piece of random answers built from every
shape the check reads — headings in each spelling, field lines, separators,
prose, DISPUTES labels, tool-call blocks closed and open, fenced JSON that is a
tool call and fenced JSON that is evidence, each line ending ``str.splitlines``
knows, and leading and trailing whitespace — and of answers shaped like an
analyst's, cut into pieces of random size.
"""

from __future__ import annotations

import random
import time

import pytest

from maljan.agents.base_agent import strip_tool_call_scaffolding
from maljan.agents.claim_headings import claim_heading_counts
from maljan.agents.repeat_watch import ClaimRepeatReader
from maljan.pipeline.validation import claims_repeated

SENTENCES = [
    "The file reads its configuration from a resource.",
    "the file reads its configuration from a resource",
    "It resolves imports by hash.",
    "It writes a Run key...",
    "It opens a window",
    "",
]
FIELDS = [
    "EVIDENCE: [ev_0001] strings",
    "EVIDENCE: ev_0002;",
    "CONFIDENCE: 0.8",
    "**CONFIDENCE:** 0.6.",
    "TECHNIQUE: T1027",
    "TECHNIQUE: NONE ...",
    "DISSENT: none",
    "- EVIDENCE: ev_0003 :",
]
HEADINGS = [
    "CLAIM: ",
    "CLAIM 3: ",
    "**CLAIM 4 (REVISED):** ",
    "- CLAIM: ",
    "1. CLAIM — ",
    "CLAIM - ",
    "CLAIM -",
    "   CLAIM: ",
    "\xa0CLAIM: ",
    "> CLAIM #7: ",
    "claim: ",
]
PROSE = [
    "Summary: the sample is a loader.",
    "The analysis continues below.",
    "   ",
    "",
    "---",
    "  ----  ",
    "...",
    "Disputes the static analyst's reading.",
]
DISPUTES = ["DISPUTES:", "DISPUTES: NONE", "## DISPUTES", "  ## DISPUTES", "**DISPUTES**: x"]
SCAFFOLD = [
    '<tool_call>{"name": "strings", "arguments": {}}</tool_call>',
    "<tool_call>\nCLAIM: inside a call\nEVIDENCE: ev_0009\n</tool_call>",
    '<TOOL_USE id="1">\nCLAIM: also inside\n</tool_use >',
    '<tool_call>{"name": "cut',
    "<tool_calls> are not scaffolding",
    "<tool_call",
    "a <function_call x>y</function_call> b",
    "<tool_response>",
]
FENCES = [
    '```json\n{"name": "strings", "arguments": {"path": "x"}}\n```',
    '```json\n{"imports": ["a.dll"]}\n```',
    '```\n{"tool": "x", "arguments": 1}```',
    "```c\nint main() {}\n```",
    '```json\n{"name": "open',
    '```tool_code {"name": "a", "parameters": {}} ```',
    "``",
]
ENDINGS = ["\n", "\n", "\n", "\r\n", "\r", "\x0c", " ", "  \n", "\n\n\n"]


def _line(rng: random.Random) -> str:
    kind = rng.random()
    if kind < 0.30:
        return rng.choice(HEADINGS) + rng.choice(SENTENCES)
    if kind < 0.60:
        return rng.choice(FIELDS)
    if kind < 0.75:
        return rng.choice(PROSE)
    if kind < 0.82:
        return rng.choice(SCAFFOLD)
    if kind < 0.89:
        return rng.choice(FENCES)
    if kind < 0.92:
        return rng.choice(DISPUTES)
    return rng.choice(SENTENCES)


def _random_answer(rng: random.Random, lines: int) -> str:
    lead = rng.choice(["", "  ", "\n\n", " \t"])
    body = "".join(_line(rng) + rng.choice(ENDINGS) for _ in range(lines))
    trail = rng.choice(["", " ", "\n", "  \n  "])
    return lead + body + trail


def _analyst_answer(rng: random.Random, distinct: int, copies: int) -> str:
    blocks = [
        f"CLAIM: The file carries configuration string number {n}.\n"
        f"EVIDENCE: [ev_{n:04d}] strings\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n"
        for n in range(distinct)
    ]
    out = ["Here is my analysis.\n\n"]
    for copy in range(copies):
        for n, block in enumerate(blocks):
            heading = f"CLAIM {copy * distinct + n + 1}:" if rng.random() < 0.5 else "CLAIM:"
            out.append(block.replace("CLAIM:", heading, 1))
            out.append(rng.choice(["---\n", "\n", ""]))
    out.append("DISPUTES: NONE\n")
    return "".join(out)


def _pieces(rng: random.Random, text: str) -> list[str]:
    out, at = [], 0
    while at < len(text):
        size = rng.choice([1, 1, 2, 3, 4, 7, 16, 40])
        out.append(text[at : at + size])
        at += size
    return out


def _expected(prefix: str, margin: int | None) -> tuple[int, int, bool]:
    stripped = strip_tool_call_scaffolding(prefix)
    begun, distinct = claim_heading_counts(stripped)
    return begun, distinct, claims_repeated(stripped, margin) is not None


def _agree(text: str, rng: random.Random, margin: int | None) -> None:
    reader = ClaimRepeatReader(margin)
    written = ""
    for piece in _pieces(rng, text):
        reader.feed(piece)
        written += piece
        got = reader.count()
        assert (got.begun, got.distinct, got.crossed) == _expected(written, margin), repr(
            written[-200:]
        )


@pytest.mark.parametrize("seed", range(160))
def test_random_answers_agree_at_every_piece(seed: int) -> None:
    rng = random.Random(seed)
    margin = rng.choice([None, None, 0, 1, 3])
    _agree(_random_answer(rng, rng.randint(1, 60)), rng, margin)


@pytest.mark.parametrize("seed", range(12))
def test_analyst_shaped_answers_agree_at_every_piece(seed: int) -> None:
    rng = random.Random(1000 + seed)
    text = _analyst_answer(rng, rng.randint(1, 8), rng.randint(1, 4))
    _agree(text, rng, rng.choice([None, 0, 2]))


def test_a_runaway_crosses_where_the_check_does() -> None:
    rng = random.Random(7)
    text = _analyst_answer(rng, 3, 5)
    reader = ClaimRepeatReader(None)
    written = ""
    for piece in _pieces(rng, text):
        reader.feed(piece)
        written += piece
        if reader.count().crossed:
            break
    assert claims_repeated(strip_tool_call_scaffolding(written)) is not None
    assert written.startswith(_analyst_answer(random.Random(7), 3, 1)[:40])


def _seconds_per_line(chars: int) -> tuple[float, float, int]:
    """CPU seconds for an answer of distinct claims, read in four-character pieces."""
    line = "CLAIM: The file carries configuration string number {n}.\nEVIDENCE: [ev_0001]\n"
    parts, size, n = [], 0, 0
    while size < chars:
        block = line.format(n=n)
        parts.append(block)
        size += len(block)
        n += 1
    text = "".join(parts)
    reader = ClaimRepeatReader(None)
    started = time.process_time()
    for at in range(0, len(text), 4):
        piece = text[at : at + 4]
        reader.feed(piece)
        if "\n" in piece:
            assert not reader.count().crossed
    return time.process_time() - started, len(text), text.count("\n")


def test_the_cost_per_line_does_not_grow_with_the_answer() -> None:
    short, _chars, short_lines = _seconds_per_line(100_000)
    long, _chars, long_lines = _seconds_per_line(400_000)
    per_short = short / short_lines
    per_long = long / long_lines
    # Linear: four times the answer costs about four times as much, so the
    # cost of a line stays flat. A re-read of the whole answer at every line
    # would make it sixteen times.
    assert per_long < per_short * 2.5
