"""Every chunk an analyst is sent fits the room it was sized at, with what is sent beside it.

In a list of more than one chunk each is sent behind its header, and a later
chunk behind the earlier chunks' calls. The chunker keeps the header out of
every piece it cuts, a packed bin counts its line breaks and the overlap it
carries, the overlap is held below the chunk, and the node's last pass cuts any
whole chunk the header would take past the room. The earlier calls take what is
left, the rest counted in one line. A JSON head another source follows is split
as dev split it; one that is the agent's only source stays the single chunk.

Seeded property runs pin the edges: a JSON head exactly at the room, multi-byte
text, an overlap above the room. Their bounds are kept realistic (rooms of at
least 2,000 characters, texts of at most 300,000).

Every value is synthetic.
"""

from __future__ import annotations

import json
import logging
import random
import re
from types import SimpleNamespace
from typing import Any

import pytest

from maljan.agents.base_agent import (
    ARGUMENTS_HELD,
    EARLIER_CALLS_BY_TOOL,
    EARLIER_CHUNKS_COMPACT_HEAD,
    EARLIER_CHUNKS_HEAD,
    BaseAnalyst,
    earlier_chunks_block,
    earlier_chunks_compact,
    fitted_chunk,
)
from maljan.core.config import ChunkingConfig
from maljan.loaders.binary_chunker import (
    CHUNK_CHARS,
    SIZED_BY,
    SIZED_BY_ROOM,
    BinaryChunker,
    HeadRoom,
    head_room,
    header_chars,
    joined_when_it_fits,
    within_the_room,
)
from maljan.schemas.isr_models import AgentISR
from tests.unit._chunking_doubles import _chunk, _room

DOMAINS = ("triage", "network", "static", "dynamic")


def _sent(chunks: list) -> list[int]:
    """What each chunk takes in its prompt: with its header where the list has more than one."""
    if len(chunks) == 1:
        return [chunks[0].char_count]
    total = len(chunks)
    return [
        len(
            f"[CHUNK {i + 1}/{total} | domain={c.domain} | strategy={c.strategy.name} | "
            f"~{c.token_estimate} tokens]"
        )
        + 2
        + c.char_count
        for i, c in enumerate(chunks)
    ]


def _text(rng: random.Random, size: int) -> str:
    lines: list[str] = []
    used = 0
    while used < size:
        kind = rng.randrange(5)
        line = (
            f"PID: {used}\n",
            f"Flow {used}:\n",
            f"void f{used}(\n",
            "é" * rng.randrange(1, 40) + "\n",
            "z" * rng.randrange(1, 3_000) + "\n",
        )[kind]
        lines.append(line)
        used += len(line)
    return "".join(lines)[:size]


# ---------------------------------------------------------------------------
# Packing and overlap
# ---------------------------------------------------------------------------


class TestABinNeverPassesItsSize:
    @pytest.mark.parametrize("overlap_tokens", [0, 200, 501, 2_000])
    def test_flows_at_a_small_room(self, overlap_tokens: int) -> None:
        text = "".join(f"Flow {i}:\n" + "x" * (i % 1_990) + "\n" for i in range(200))
        chunks = BinaryChunker(ChunkingConfig(overlap_tokens=overlap_tokens)).chunk(
            "network", text, room=_room(2_000)
        )
        assert len(chunks) > 1
        assert all(size <= 2_000 for size in _sent(chunks))

    def test_an_overlap_above_the_chunk_is_held_and_said(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        chunker = BinaryChunker(ChunkingConfig(overlap_tokens=1_000))
        with caplog.at_level(logging.WARNING, logger="maljan"):
            chunks = chunker.chunk(
                "network",
                "".join(f"Flow {i}:\n" + "y" * 900 + "\n" for i in range(20)),
                room=_room(2_000),
            )
        assert all(size <= 2_000 for size in _sent(chunks))
        said = [r.getMessage() for r in caplog.records]
        assert any("held to" in m or "clamping step" in m for m in said)


# ---------------------------------------------------------------------------
# The header and the earlier calls
# ---------------------------------------------------------------------------


class TestTheHeaderIsKeptOutOfTheRoom:
    def test_the_bound_holds_the_header_it_is_for(self) -> None:
        chunks = BinaryChunker(ChunkingConfig(overlap_tokens=0)).chunk(
            "dynamic", "d" * 50_000, room=_room(5_000)
        )
        bound = header_chars("dynamic", 10 * 50_000, 5_000)
        assert all(len(c.to_prompt_header()) + 2 <= bound for c in chunks)

    def test_a_whole_source_the_header_would_take_past_the_room_is_cut(self) -> None:
        whole = _chunk("w" * 9_990)
        whole.metadata.update({SIZED_BY: SIZED_BY_ROOM, CHUNK_CHARS: 10_000})
        other = _chunk("o" * 100)
        out = within_the_room([whole, other], ChunkingConfig(overlap_tokens=0))
        assert len(out) == 3
        assert "".join(c.content for c in out[:2]) == "w" * 9_990
        assert all(c.char_count + header_chars("triage", 10_100, 10_000) <= 10_000 for c in out[:2])

    def test_a_single_chunk_has_no_header_and_is_left_whole(self) -> None:
        only = _chunk("w" * 10_000)
        only.metadata.update({SIZED_BY: SIZED_BY_ROOM, CHUNK_CHARS: 10_000})
        assert within_the_room([only], ChunkingConfig()) == [only]

    def test_a_later_chunk_gives_way_to_the_full_list_where_it_costs_no_loop(self) -> None:
        entries = _entries(12)
        whole = earlier_chunks_block(entries)
        agent = SimpleNamespace(_input_room_chars=lambda _text: 25_832)
        block, sent, rest = fitted_chunk(agent, "h" * 80, "c" * 25_745, entries)
        assert block == whole
        assert len(sent) + len(rest) == 25_745
        assert 80 + 4 + len(block) + len(sent) <= 25_832

    def test_the_compact_list_where_the_full_one_would_cost_a_loop(self) -> None:
        # The full list takes a third loop over this chunk; with its
        # arguments kept and its results left out it does not.
        entries = _entries(200)
        agent = SimpleNamespace(_input_room_chars=lambda _text: 25_832)
        block, sent, _rest = fitted_chunk(agent, "h" * 80, "c" * 25_745, entries)
        assert block.startswith(EARLIER_CHUNKS_COMPACT_HEAD)
        assert _entry_ids_in(block) >= {f"ev_{i:04d}" for i in range(200)}
        assert all(f'"0x{4096 + i:x}"' in block for i in range(200))
        assert 80 + 4 + len(block) + len(sent) <= 25_832

    def test_never_nothing_while_earlier_calls_exist(self) -> None:
        # Every other id, so no range can shorten the compact list.
        entries = _entries(6_000)[::2]
        agent = SimpleNamespace(_input_room_chars=lambda _text: 2_000)
        block, sent, _rest = fitted_chunk(agent, "h" * 80, "c" * 1_900, entries)
        assert block == EARLIER_CALLS_BY_TOOL.format(
            count=3_000, tools="decompile_function \u00d73000", first="ev_0000", last="ev_5998"
        )
        assert 80 + 4 + len(block) + len(sent) <= 2_000

    def test_with_no_room_measured_the_full_list_and_the_whole_chunk(self) -> None:
        entries = _entries(5)
        block, sent, rest = fitted_chunk(SimpleNamespace(), "h", "c" * 90_000, entries)
        assert (block, sent, rest) == (earlier_chunks_block(entries), "c" * 90_000, "")


def _names_every_call(prompt: str, made: int) -> bool:
    """Whether ``prompt`` lists every one of ``made`` earlier calls, or counts them by span."""
    if _entry_ids_in(prompt) >= {f"ev_{i:04d}" for i in range(made)}:
        return True
    return f"made {made} tool call(s)" in prompt and f"ev_0000 to ev_{made - 1:04d}" in prompt


def _entry_ids_in(text: str) -> set[str]:
    """Every ledger id ``text`` names, a range ``ev_a–ev_b`` read as every id from a to b."""
    ids: set[str] = set()
    for first, last in re.findall(r"(ev_\d{4})(?:\u2013(ev_\d{4}))?", text):
        if not last:
            ids.add(first)
            continue
        ids.update(f"ev_{n:04d}" for n in range(int(first[3:]), int(last[3:]) + 1))
    return ids


def _entries(count: int) -> list[SimpleNamespace]:
    return [
        SimpleNamespace(
            tool="decompile_function",
            id=f"ev_{i:04d}",
            args={"address": f"0x{4096 + i:x}"},
            output="int f(void) { return 0; }",
            ok=True,
        )
        for i in range(count)
    ]


class _Reverser:
    """A chunked analyst on the 64K reverser's room: each chunk's loop makes calls."""

    def __init__(self, room: int, calls_per_chunk: int) -> None:
        self.name = "all_tools_reverser_ghidra"
        self.logger = logging.getLogger("maljan")
        self._room = room
        self._calls = calls_per_chunk
        self._evidence_entries: list = []
        self._findings_buffer: list = []
        self._artifacts_buffer: list = []
        self.validation_findings: list = []
        self.validation_retries = 0
        self.prompts: list[str] = []

    def _input_room_chars(self, _text: str) -> int:
        return self._room

    def analyze_isr(self, data: str) -> AgentISR:
        self.prompts.append(data)
        start = len(self._evidence_entries)
        self._evidence_entries.extend(_entries(start + self._calls)[start:])
        return AgentISR(agent_id=self.name, domain="static", claims=[], dissent_items=[])

    def _validate_isr(self, isr: AgentISR, *_a: Any, **_k: Any) -> AgentISR:
        return isr

    def _apply_consistency_gate(self, isr: AgentISR, _evidence: str) -> AgentISR:
        return isr

    safe_analyze_isr_chunked = BaseAnalyst.safe_analyze_isr_chunked


@pytest.mark.parametrize("domain", ["network", "triage"])
def test_every_later_chunk_reads_every_earlier_call_at_the_64k_reverser_room(domain: str) -> None:
    room = 25_832
    text = "".join(f"- 203.0.{i % 250}.{i % 199}:443 flow {i:07d}\n" for i in range(4_000))[
        :100_000
    ]
    chunks = BinaryChunker(ChunkingConfig(overlap_tokens=0)).chunk(domain, text, room=_room(room))
    assert len(chunks) > 2
    agent = _Reverser(room, calls_per_chunk=12)

    agent.safe_analyze_isr_chunked(chunks)

    for number, prompt in enumerate(agent.prompts):
        assert len(prompt) <= room
        made = 12 * number
        if made:
            assert _names_every_call(prompt, made)
        header, content = prompt.split("\n\n", 1)[0], prompt.rsplit("\n\n", 1)[-1]
        # The header states the token estimate of what it is in front of.
        assert f"~{len(content) // 4} tokens]" in header or number == 0
    sent = "".join(
        p.split("\n\n", 2)[-1] if i else p.split("\n\n", 1)[-1] for i, p in enumerate(agent.prompts)
    )
    assert sent == text


# ---------------------------------------------------------------------------
# A JSON head
# ---------------------------------------------------------------------------


HEAD = json.dumps({f"key_{i:04d}": f"value {i}" for i in range(400)})


class TestAJsonHead:
    def _head(self, alone: bool, extra: int) -> tuple[HeadRoom, int]:
        room = len(HEAD) + extra
        head = head_room(_room(room), lambda text: 3 * len(text) // 10 + 2_000)
        assert isinstance(head, HeadRoom)
        return head.alone_as(alone), room

    @pytest.mark.parametrize("extra", [0, 100, 2_000])
    def test_followed_by_another_source_it_is_split_within_the_room(self, extra: int) -> None:
        head, room = self._head(False, extra)
        chunks = BinaryChunker(ChunkingConfig(overlap_tokens=0)).chunk("static", HEAD, room=head)
        assert len(chunks) > 1
        assert "".join(c.content for c in chunks) == HEAD
        assert chunks[0].char_count + 2_000 <= room

    @pytest.mark.parametrize("extra", [0, 100])
    def test_alone_it_is_the_single_chunk_whole(self, extra: int) -> None:
        head, _room_ = self._head(True, extra)
        (only,) = BinaryChunker(ChunkingConfig(overlap_tokens=0)).chunk("static", HEAD, room=head)
        assert only.content == HEAD


# ---------------------------------------------------------------------------
# Seeded properties
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(40))
def test_every_chunk_fits_and_nothing_is_lost(seed: int) -> None:
    rng = random.Random(seed)
    room = rng.randrange(2_000, 60_000)
    text = _text(rng, rng.randrange(room // 2, min(300_000, room * 12)))
    overlap = rng.choice([0, 50, 200, room // 3])
    added = rng.choice([0, 100, room // 2, room - 1])
    domain = rng.choice(DOMAINS)
    chunker = BinaryChunker(ChunkingConfig(overlap_tokens=overlap))
    head = head_room(_room(room), lambda _text, n=added: n)

    chunks = chunker.chunk(domain, text, room=head)
    at_room = chunker.chunk(domain, text, room=_room(room))
    shown = within_the_room(chunks, ChunkingConfig(overlap_tokens=overlap))

    assert all(c.content.strip() for c in shown) or len(shown) == 1
    if len(shown) > 1:
        assert all(size <= room for size in _sent(shown)[1:])
        if added < room // 2:
            assert _sent(shown)[0] + added <= room
    assert len(chunks) <= len(at_room) + 1
    if overlap == 0:
        # Packing joins boundary segments with a line break, as it always has;
        # nothing of the text is lost either way.
        joined = "".join(c.content for c in chunks)
        assert joined.replace("\n", "") == text.replace("\n", "")


@pytest.mark.parametrize("seed", range(10))
def test_a_head_exactly_at_the_room(seed: int) -> None:
    rng = random.Random(1_000 + seed)
    room = len(HEAD) + rng.choice([0, 1])
    head = head_room(_room(room), lambda text: 2_000)
    assert isinstance(head, HeadRoom)
    for alone in (True, False):
        chunks = BinaryChunker(ChunkingConfig(overlap_tokens=0)).chunk(
            "static", HEAD, room=head.alone_as(alone)
        )
        assert "".join(c.content for c in chunks) == HEAD
        if alone:
            assert len(chunks) == 1
        else:
            assert chunks[0].char_count + 2_000 <= room


def test_multi_byte_text_is_cut_on_characters_and_kept_whole() -> None:
    text = ("é" * 997 + "\n") * 120
    chunks = BinaryChunker(ChunkingConfig(overlap_tokens=0)).chunk(
        "triage", text, room=_room(5_000)
    )
    assert "".join(c.content for c in chunks) == text
    assert all(size <= 5_000 for size in _sent(chunks))


def test_joined_whole_sources_still_fit_behind_their_headers() -> None:
    rng = random.Random(7)
    room = 6_000
    sources: list[Any] = []
    for _ in range(12):
        piece = _chunk("s" * rng.randrange(100, room))
        piece.metadata.update({SIZED_BY: SIZED_BY_ROOM, CHUNK_CHARS: room})
        sources.append(piece)
    joined = joined_when_it_fits(sources, ChunkingConfig(overlap_tokens=0), _room(room))
    assert all(size <= room for size in _sent(joined))


@pytest.mark.parametrize("calls", [12, 40, 80])
def test_many_calls_a_loop_never_starve_a_loop_of_its_content(calls: int) -> None:
    # The reviewer's probe: 300k of flows at the 64K reverser's room. The
    # calls are listed by tool as ranges, and the form that leaves the fewest
    # loops is sent, so the list never squeezes a loop down to a sliver.
    room = 25_832
    flows = (f"- 203.0.{i % 250}.{i % 199}:443 flow {i:07d}\n" for i in range(11_000))
    text = "".join(flows)[:300_000]
    chunks = BinaryChunker(ChunkingConfig()).chunk("network", text, room=_room(room))
    agent = _Reverser(room, calls_per_chunk=calls)

    agent.safe_analyze_isr_chunked(chunks)

    contents = [p.rsplit("\n\n", 1)[-1] for p in agent.prompts]
    assert all(len(p) <= room for p in agent.prompts)
    assert len(agent.prompts) <= len(chunks) + 2
    assert min(len(c) for c in contents[:-1]) > room // 2
    for number, prompt in enumerate(agent.prompts[1:], start=1):
        assert _names_every_call(prompt, calls * number)


def test_a_carried_rest_never_holds_the_overlap_twice() -> None:
    room = 25_832
    flows = (f"- 203.0.{i % 250}.{i % 199}:443 flow {i:07d}\n" for i in range(4_000))
    text = "".join(flows)[:100_000]
    chunks = BinaryChunker(ChunkingConfig(overlap_tokens=200)).chunk(
        "triage", text, room=_room(room)
    )
    agent = _Reverser(room, calls_per_chunk=12)

    agent.safe_analyze_isr_chunked(chunks)

    sent = [p.rsplit("\n\n", 1)[-1] for p in agent.prompts]
    for content in sent:
        for line in content.splitlines():
            assert content.count(line + "\n") <= 1 or not line


@pytest.mark.parametrize(("sources", "room"), [(9, 25_832), (99, 2_500)])
def test_whole_sources_without_line_breaks_stay_within_the_room(sources: int, room: int) -> None:
    # Carries add chunks; the header names the chunk and says more may follow,
    # so no total gains a digit after the chunk was fitted, and each header
    # states the token estimate of what it is in front of.
    chunks = []
    for i in range(sources):
        source = _chunk(chr(ord("a") + i % 26) * (room - 120))
        source.metadata.update({SIZED_BY: SIZED_BY_ROOM, CHUNK_CHARS: room})
        chunks.append(source)
    agent = _Reverser(room, calls_per_chunk=12)

    agent.safe_analyze_isr_chunked(chunks)

    assert "".join(p.rsplit("\n\n", 1)[-1] for p in agent.prompts) == "".join(
        str(c.content) for c in chunks
    )
    for prompt in agent.prompts:
        assert len(prompt) <= room
        header = prompt.split("\n\n", 1)[0]
        assert "(more may follow)" in header
        assert f"~{len(prompt.rsplit(chr(10) * 2, 1)[-1]) // 4} tokens]" in header


class TestTheCompactListKeepsEveryCallsArguments:
    def test_each_call_with_its_arguments_and_entry_without_its_result(self) -> None:
        entries = [
            SimpleNamespace(
                tool="decompile_function",
                id="ev_0001",
                args={"address": "0x10"},
                output="int f(void)",
                ok=True,
            ),
            SimpleNamespace(
                tool="decompile_function",
                id="ev_0002",
                args={"address": "0x20"},
                output="int g(void)",
                ok=True,
            ),
            SimpleNamespace(tool="list_strings", id="ev_0003", args={}, output="a b", ok=True),
            SimpleNamespace(tool="list_strings", id="ev_0004", args={}, output="a b", ok=True),
            SimpleNamespace(
                tool="decompile_function",
                id="ev_0005",
                args={"address": "0x10"},
                output="int f(void)",
                ok=False,
            ),
        ]
        block = earlier_chunks_compact(entries)
        assert block.splitlines()[1:] == [
            '- decompile_function("0x10") \u2192 ev_0001',
            '- decompile_function("0x20") \u2192 ev_0002',
            "- list_strings() \u2192 ev_0003\u2013ev_0004",
            '- decompile_function("0x10") \u2192 ev_0005 (failed)',
        ]
        assert "int f" not in block

    def test_names_are_given_where_the_tool_s_calls_name_different_arguments(self) -> None:
        entries = [
            SimpleNamespace(tool="t", id="ev_0001", args={"a": 1}, output="x", ok=True),
            SimpleNamespace(tool="t", id="ev_0002", args={"b": 1}, output="x", ok=True),
        ]
        assert earlier_chunks_compact(entries).splitlines()[1:] == [
            "- t(a=1) \u2192 ev_0001",
            "- t(b=1) \u2192 ev_0002",
        ]

    def test_an_argument_no_list_could_hold_is_named_by_its_entry_never_cut(self) -> None:
        blob = "A" * 5_000
        entries = [
            SimpleNamespace(tool="t", id="ev_0009", args={"data": blob}, output="x", ok=True)
        ]
        assert earlier_chunks_compact(entries, 4_000).splitlines()[1] == (
            "- t(" + ARGUMENTS_HELD.format(chars=5_002, entry="ev_0009") + ") \u2192 ev_0009"
        )
        assert blob in earlier_chunks_compact(entries, 6_000)


@pytest.mark.parametrize("calls", [12, 40, 80])
@pytest.mark.parametrize("overlap", [0, 200])
def test_the_loops_are_the_count_forms_and_lists_take_only_the_slack(
    calls: int, overlap: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    import maljan.agents.base_agent as base

    room = 25_832
    flows = (f"- 203.0.{i % 250}.{i % 199}:443 flow {i:07d}\n" for i in range(11_000))
    text = "".join(flows)[:300_000]
    chunks = BinaryChunker(ChunkingConfig(overlap_tokens=overlap)).chunk(
        "network", text, room=_room(room)
    )
    sent = _Reverser(room, calls_per_chunk=calls)
    sent.safe_analyze_isr_chunked(chunks)

    # The projection: the same pass with only the count form there to send.
    huge = "x" * 10 * room
    monkeypatch.setattr(base, "earlier_chunks_block", lambda e: huge if e else "")
    monkeypatch.setattr(base, "earlier_chunks_compact", lambda e, held=None: huge)
    monkeypatch.setattr(base, "earlier_calls_by_tool", lambda e: huge)
    projected = _Reverser(room, calls_per_chunk=calls)
    projected.safe_analyze_isr_chunked(chunks)

    assert len(sent.prompts) == len(projected.prompts)
    assert all(len(p) <= room for p in sent.prompts)


def _run_and_project(
    chunks: list, room: int, calls: int, monkeypatch: pytest.MonkeyPatch
) -> tuple[list[str], int]:
    """The prompts a pass sends, and the loops of the same pass with only the count form."""
    import maljan.agents.base_agent as base

    sent = _Reverser(room, calls_per_chunk=calls)
    sent.safe_analyze_isr_chunked(chunks)
    with monkeypatch.context() as patched:
        huge = "x" * 10 * room
        patched.setattr(base, "earlier_chunks_block", lambda e: huge if e else "")
        patched.setattr(base, "earlier_chunks_compact", lambda e, held=None: huge)
        patched.setattr(base, "earlier_calls_by_tool", lambda e: huge)
        projected = _Reverser(room, calls_per_chunk=calls)
        projected.safe_analyze_isr_chunked(chunks)
    return sent.prompts, len(projected.prompts)


def _content_of(prompt: str, first: bool) -> str:
    return prompt.split("\n\n", 1)[-1] if first else prompt.rsplit("\n\n", 1)[-1]


@pytest.mark.parametrize(
    ("domain", "room", "text"),
    [
        (
            "all_tools_reverser_ghidra",
            25_832,
            "".join(f"line {i}\n" for i in range(400))
            + "b" * (25_832 + 5_000)
            + "\n"
            + "".join(f"line {i}\n" for i in range(400, 20_000)),
        ),
        (
            "network",
            25_832,
            "".join(f"Flow {i}:\n" + "x" * (25_832 - 300) + "\n" for i in range(8)),
        ),
        (
            "network",
            25_832,
            "".join(f"Flow {i}:\n" + "x" * (25_832 - 2_000) + "\n" for i in range(12)),
        ),
        (
            "generic",
            102_406,
            "".join(f"line {i}\n" for i in range(300)) + "b" * 107_406 + "\n" + "tail\n" * 20_000,
        ),
    ],
)
def test_a_line_longer_than_the_room_never_sends_a_chunk_past_it(
    domain: str, room: int, text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    chunks = BinaryChunker(ChunkingConfig(overlap_tokens=0)).chunk(domain, text, room=_room(room))
    prompts, projected = _run_and_project(chunks, room, 12, monkeypatch)

    assert all(len(p) <= room for p in prompts)
    assert len(prompts) == projected
    sent = "".join(_content_of(p, i == 0) for i, p in enumerate(prompts))
    if domain != "network":
        assert sent == text
    else:
        assert sent.replace("\n", "") == text.replace("\n", "")
    # No loop runs over a sliver: every loop but the last holds at least what
    # the loops left would hold of what remained.
    contents = [len(_content_of(p, i == 0)) for i, p in enumerate(prompts)]
    assert min(contents[1:-1] or [room]) > 2 * 1_000


@pytest.mark.parametrize("seed", range(20))
def test_long_lines_of_any_length_keep_every_prompt_in_the_room(
    seed: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    rng = random.Random(seed)
    room = 25_832
    parts: list[str] = []
    used = 0
    while used < 120_000:
        size = rng.choice([rng.randrange(1, 80), rng.randrange(1, 40_000)])
        parts.append("q" * size + "\n")
        used += size + 1
    text = "".join(parts)[:120_000]
    domain = rng.choice(["triage", "network", "static"])
    chunks = BinaryChunker(ChunkingConfig(overlap_tokens=rng.choice([0, 200]))).chunk(
        domain, text, room=_room(room)
    )
    prompts, projected = _run_and_project(chunks, room, rng.choice([12, 40]), monkeypatch)
    assert all(len(p) <= room for p in prompts)
    assert len(prompts) == projected


def test_an_operator_figure_sends_its_chunks_as_set() -> None:
    room = 25_832
    flows = (f"- 203.0.{i % 250}.{i % 199}:443 flow {i:07d}\n" for i in range(11_000))
    text = "".join(flows)[:300_000]
    chunks = BinaryChunker(ChunkingConfig(overlap_tokens=0, max_tokens_per_chunk=15_000)).chunk(
        "network", text, room=_room(room)
    )
    agent = _Reverser(room, calls_per_chunk=12)

    agent.safe_analyze_isr_chunked(chunks)

    assert len(agent.prompts) == len(chunks)
    for i, (prompt, chunk) in enumerate(zip(agent.prompts, chunks, strict=True)):
        assert prompt.startswith(chunk.to_prompt_header() if i == 0 else "[CHUNK ")
        assert "(more may follow)" not in prompt
        assert prompt.endswith(str(chunk.content))
        if i:
            assert EARLIER_CHUNKS_HEAD in prompt


def test_near_room_joins_run_one_loop_each() -> None:
    room = 25_832
    sources = []
    for i in range(24):
        source = _chunk(chr(ord("a") + i % 26) * 12_800)
        source.metadata.update({SIZED_BY: SIZED_BY_ROOM, CHUNK_CHARS: room})
        sources.append(source)
    joined = joined_when_it_fits(sources, ChunkingConfig(overlap_tokens=0), _room(room))
    agent = _Reverser(room, calls_per_chunk=12)

    agent.safe_analyze_isr_chunked(joined)

    assert len(agent.prompts) == len(joined)
    assert all(len(p) <= room for p in agent.prompts)


def test_a_carried_rest_shorter_than_the_overlap_holds_nothing_twice() -> None:
    from maljan.agents.base_agent import _past_overlap
    from maljan.loaders.binary_chunker import OVERLAP_IN

    piece = "abcdefghij" * 10
    after = _chunk(piece[-40:] + "NEXT", 1, 2)
    after.metadata[OVERLAP_IN] = 40
    rest = piece[-15:]
    assert rest + _past_overlap(rest, after) == piece[-15:] + "NEXT"
    longer = piece[-60:]
    assert longer + _past_overlap(longer, after) == piece[-60:] + "NEXT"
