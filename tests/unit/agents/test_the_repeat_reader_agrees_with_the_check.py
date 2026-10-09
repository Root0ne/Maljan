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
    "CLAIM 2 [REVISED — retracts claim 5]: ",
    "CLAIM [NEW] — ",
    "CLAIM 6 (REVISED — not observed)\n",
    "**CLAIM 7 [KEPT]** \n",
    "CLAIM 8 [",
    "CLAIM 9 (a) ",
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
    # A tag whose own opening holds its closing tag before its ``>``, a tag
    # left open that a later ``>`` resolves, and a stray closing tag.
    '<tool_call\n{"name": "x"}\n</tool_call>',
    "a <tool_call name=x",
    "so a > b here",
    "</tool_call>",
    "<TOOL_cAll",
    # Lines that close a fence opened earlier, as a tool call or as evidence.
    "}\n```",
    '"}}\n```',
    "} ``",
    "`",
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


# The shapes a repeat may be varied in, and lines no buffer may hold whole:
# whitespace, case and numbering changes of one claim; claims written one after
# another on a single line; long runs before a heading's label, inside its
# parenthesis and around a DISPUTES rest; Greek capital sigmas, whose lowercase
# depends on what follows; digits and letters the patterns read by their
# Unicode class.
VARIED = [
    "CLAIM 12:   The   FILE reads its configuration   from a resource",
    "CLAIM:\tthe file reads its configuration from a resource.",
    "claim: the file reads its configuration from a resource",
    "Claim 3: it resolves imports by hash",
    "CLAIM 1. it resolves imports by hash",
    "CLAIM: it reads a file CLAIM: it reads a file CLAIM: it reads a file",
    " " * 300 + "CLAIM: it reads a file",
    "> * # " * 60 + "CLAIM 7: it reads a file",
    "CLAIM (" + "a:b - c " * 80 + "): it reads a file",
    "CLAIM [" + "a:b - c ( " * 80 + "]: it reads a file",
    "CLAIM 3 [" + "a:b - c " * 80 + "]",
    "CLAIM 3 (" + "a:b - c " * 80 + ")  ** ",
    "CLAIM 4 [" + "a:b - c " * 80,
    "DISPUTES:" + " " * 120 + "NONE" + " ." * 40,
    "DISPUTES: " + "*_` " * 30 + "n/a" + "..." * 20,
    "# * DISPUTES" + " " * 50,
    "CLAIM: ΟΔΥΣΣΕΥΣ ΑΣ. ΑΣ' Β ΑΣ\u0301 b Σ",
    # The same claims in the lowercase ``str.lower`` gives them: a final
    # sigma, including one followed by a case-ignorable mark or quote.
    "CLAIM: οδυσσευς ασ. ας' β ας\u0301 b σ",
    "CLAIM: ΑΣ.Β",
    "CLAIM: ασ.β",
    "CLAIM \u0661\u0662: it reads a file",
    "DIſſENT: none",
    "EvIdEnCe: ev_0001",
    "CLAIM: " + "it reads a file and " * 200,
    "x" * 2000,
]


def _line(rng: random.Random) -> str:
    kind = rng.random()
    if kind < 0.08:
        return rng.choice(VARIED)
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


def _agree_in_pieces_of(text: str, size: int, margin: int | None) -> None:
    reader = ClaimRepeatReader(margin)
    for at in range(0, len(text), size):
        reader.feed(text[at : at + size])
        got = reader.count()
        assert (got.begun, got.distinct, got.crossed) == _expected(text[: at + size], margin), repr(
            text[: at + size][-200:]
        )


@pytest.mark.parametrize("first", range(len(VARIED)))
def test_each_varied_shape_agrees_beside_every_other(first: int) -> None:
    for second in range(len(VARIED)):
        text = "\n".join([VARIED[first], VARIED[second], VARIED[first], VARIED[second]]) + "\n"
        _agree_in_pieces_of(text, 97, None)


def _peak_bytes(text: str, piece: int = 256) -> tuple[int, ClaimRepeatReader]:
    import tracemalloc

    reader = ClaimRepeatReader(None)
    tracemalloc.start()
    try:
        for at in range(0, len(text), piece):
            reader.feed(text[at : at + piece])
            if "\n" in text[at : at + piece]:
                reader.count()
        return tracemalloc.get_traced_memory()[1], reader
    finally:
        tracemalloc.stop()


class TestWhatTheReaderKeeps:
    """Nothing it keeps grows with the text, but one hash per distinct claim."""

    def test_a_closed_claim_is_kept_as_a_sixteen_byte_hash(self) -> None:
        reader = ClaimRepeatReader(None)
        reader.feed("CLAIM: " + "a long sentence " * 1000 + "\nCLAIM: b\nCLAIM: c")
        reader.count()

        kept = reader._pipeline.machines[0].seen._own
        assert len(kept) == 1
        assert all(isinstance(digest, bytes) and len(digest) == 16 for digest in kept)

    def test_one_long_line_holds_nothing_of_itself(self) -> None:
        short, _reader = _peak_bytes("CLAIM: " + "it reads a value and writes it back " * 300)
        long, _reader = _peak_bytes("CLAIM: " + "it reads a value and writes it back " * 12_000)

        # Forty times the line, and what the reader held stays where it was.
        assert long < max(short * 2, 64 * 1024)

    def test_a_long_run_of_trailing_dots_is_held_as_its_hash(self) -> None:
        long, _reader = _peak_bytes("CLAIM: it reads a file" + " ." * 200_000)

        assert long < 64 * 1024

    def test_distinct_claims_cost_a_hash_each(self) -> None:
        text = "".join(f"CLAIM: claim number {n}\n" for n in range(2_000))
        peak, reader = _peak_bytes(text)

        assert reader.count().distinct == 2_000
        assert peak < 2_000 * 200 + 64 * 1024


@pytest.mark.parametrize(
    ("text", "begun", "distinct"),
    [
        # Whitespace, case and marks: one claim, repeated.
        ("CLAIM: The file reads a key.\nCLAIM:   the FILE  reads a **key**\n", 2, 1),
        # Its number is not part of a claim.
        ("CLAIM 1: it reads a key\nCLAIM 2: it reads a key\nCLAIM 3: it reads a key\n", 3, 1),
        # Claims written one after another on one line are one block to the check.
        ("CLAIM: it reads a key CLAIM: it reads a key CLAIM: it reads a key\n", 1, 1),
        # A label in lowercase, or ended with a dot, heads no claim for the check.
        ("claim: it reads a key\nclaim: it reads a key\n", 0, 0),
        ("CLAIM 1. it reads a key\nCLAIM 2. it reads a key\n", 0, 0),
        # A different evidence line makes a different claim.
        (
            "CLAIM: it reads a key\nEVIDENCE: ev_0001\nCLAIM: it reads a key\nEVIDENCE: ev_0002\n",
            2,
            2,
        ),
    ],
    ids=[
        "whitespace-and-case",
        "numbering",
        "one-line",
        "lowercase-label",
        "dot-label",
        "evidence",
    ],
)
def test_varied_repeats_count_as_the_check_counts_them(
    text: str, begun: int, distinct: int
) -> None:
    assert _expected(text, None)[:2] == (begun, distinct)
    _agree_in_pieces_of(text, 3, None)


def test_the_automata_are_built_from_the_patterns_the_check_reads() -> None:
    """The heading patterns, as the automata in ``repeat_watch`` mirror them."""
    from maljan.agents import claim_headings

    prefix = "[ \\t>*_#]*(?:(?:[-+]|\\d+[.)])[ \\t]+)?[ \\t>*_#]*"
    assert claim_headings.LINE_PREFIX == prefix
    assert claim_headings.CLAIM_HEAD_RE.pattern == (
        "^" + prefix + "CLAIM(?:[ \\t]*#?\\d+)?"
        "(?:[ \\t]*(?P<note>\\([^)\\n]*\\)|\\[[^\\]\\n]*\\]))?[ \\t]*(?:\\*\\*)?[ \\t]*"
        "(?:(?::|\u2014|\u2013|-(?=\\s))[ \\t]*(?:\\*\\*)?[ \\t]*|(?(note)$|(?!)))"
    )
    assert claim_headings._SEPARATOR_RE.pattern == "^[ \\t]*-{3,}[ \\t]*$"
    assert claim_headings._FIELD_LABEL_RE.pattern == (
        "^" + prefix + "(?:EVIDENCE|CONFIDENCE|TECHNIQUE|DISSENT)\\b"
    )
    assert claim_headings._DISPUTES_LABEL_RE.pattern == (
        "^" + prefix + "DISPUTES[ \\t]*(?:\\*\\*)?[ \\t]*:(?P<rest>.*)$"
        "|^#+[ \\t]*\\**[ \\t]*DISPUTES\\b(?P<heading_rest>.*)$"
    )
    assert claim_headings._NO_DISPUTE == frozenset({"NONE", "N/A", "\u2014", "\u2013", "-"})


def test_a_fence_nested_past_the_parser_s_depth_agrees_and_is_kept() -> None:
    depth = 20_000
    fence = '```json\n{"name": "x", "arguments": ' + "[" * depth + "]" * depth + "}\n```\n"
    text = "CLAIM: it reads a key\n" + fence + "CLAIM: it reads a key\n" * 3
    _agree_in_pieces_of(text, 4096, None)


@pytest.mark.parametrize(
    "text",
    [
        '<tool_call\n{"name": "x"}\n</tool_call>\nCLAIM: a\n' * 3,
        '<tool_call\n{"name": "x"}\n</tool_call>\nCLAIM: a\n</tool_call>\n' + "CLAIM: b\n" * 3,
    ],
    ids=["never-closed", "closed-later"],
)
def test_a_tag_holding_its_closing_tag_before_its_bracket_agrees(text: str) -> None:
    """The closing is read only after the opening tag's ``>``, as the check reads it."""
    _agree_in_pieces_of(text, 1, None)


def _seconds_after(opening: str, chars: int) -> float:
    """CPU for an answer that opens ``opening`` and never resolves it, read in 4-char pieces."""
    claim = "CLAIM: the file carries configuration string number {n}.\nEVIDENCE: [ev_0001]\n"
    parts, size, n = [opening], len(opening), 0
    while size < chars:
        block = claim.format(n=n)
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
    return time.process_time() - started


@pytest.mark.parametrize("opening", ["```json\n{", "<tool_call"], ids=["fence", "tag"])
def test_an_opening_that_never_resolves_costs_the_same_per_line(opening: str) -> None:
    short = _seconds_after(opening, 100_000)
    long = _seconds_after(opening, 400_000)

    # Four times the answer, about four times the time: the held block is
    # read once, as it arrives, not again at every line.
    assert long < short * 4 * 2.5
