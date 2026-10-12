"""A report document is written out and read back at any nesting depth, never raising.

``core.safe_json.dumps`` writes the bytes ``json.dumps`` writes for every value
nested no deeper than the guard, and a marked placeholder below it;
``core.safe_json.loads`` reads the values ``json.loads`` reads, at any depth.
"""

from __future__ import annotations

import gc
import json
import math
import random
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from maljan.core import safe_json
from maljan.core.safe_json import (
    CYCLE_MARK,
    DEEPER_MARK,
    DEPTH_GUARD,
    SHARED_MARK,
    dumps,
    exceeds_depth,
    loads,
    within_depth,
)


def _deep_list(depth: int, leaf: Any = 1) -> Any:
    node: Any = leaf
    for _ in range(depth):
        node = [node]
    return node


def _deep_object(depth: int, leaf: Any = 1) -> Any:
    node: Any = leaf
    for _ in range(depth):
        node = {"x": node, "n": 1}
    return node


def _depth(value: Any) -> int:
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict | list):
            deepest = max(deepest, depth)
            children = node.values() if isinstance(node, dict) else node
            stack.extend((child, depth + 1) for child in children)
    return deepest


def _random_value(rng: random.Random, depth: int = 0) -> Any:
    roll = rng.random()
    if depth > 6 or roll < 0.35:
        return rng.choice(
            [
                None,
                True,
                False,
                0,
                -7,
                3.25,
                1e-9,
                12345678901234567890,
                "",
                "plain",
                "ünïcödé ☃",
                'quote " back \\ slash',
                "\u0000\u001f control",
                "😀",
            ]
        )
    if roll < 0.7:
        return [_random_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    width = rng.randint(0, 4)
    return {f"k{rng.randint(0, 9)}": _random_value(rng, depth + 1) for _ in range(width)}


_KWARGS: tuple[dict[str, Any], ...] = (
    {},
    {"default": str},
    {"separators": (",", ":"), "default": str},
    {"indent": 2},
    {"sort_keys": True, "ensure_ascii": False},
)


class TestTheBytesAreJsonDumpsBytes:
    @pytest.mark.parametrize("kwargs", _KWARGS)
    def test_random_values_write_as_json_dumps_writes_them(self, kwargs: dict[str, Any]) -> None:
        rng = random.Random(7)
        for _ in range(300):
            value = _random_value(rng)
            assert dumps(value, **kwargs) == json.dumps(value, **kwargs)

    def test_a_value_at_the_guard_is_handed_over_itself(self) -> None:
        value = _deep_object(DEPTH_GUARD)
        assert _depth(value) == DEPTH_GUARD
        assert not exceeds_depth(value)
        assert safe_json.within_depth(value) is value
        assert dumps(value) == json.dumps(value)

    def test_one_level_past_the_guard_is_marked(self) -> None:
        value = _deep_list(DEPTH_GUARD + 1, leaf=[])
        assert exceeds_depth(value)
        text = dumps(value)
        assert DEEPER_MARK in text
        assert _depth(json.loads(text)) == DEPTH_GUARD


class TestADeepValueNeverRaises:
    @pytest.mark.parametrize("make", [_deep_list, _deep_object])
    @pytest.mark.parametrize("depth", [DEPTH_GUARD + 1, 1_000, 10_000, 100_000])
    def test_it_is_written_marked_and_read_back_by_every_reader(
        self, make: Callable[[int], Any], depth: int
    ) -> None:
        value = make(depth)
        with pytest.raises(RecursionError):
            json.dumps(make(20_000))
        text = dumps(value, default=str)
        assert DEEPER_MARK in text
        back = json.loads(text)
        assert _depth(back) <= DEPTH_GUARD

        class Holder(BaseModel):
            held: Any = None

        # The ledger and the report are pydantic models, holding an answer some
        # levels down: they read it back and write it again.
        wrapped: Any = back
        for _ in range(18):
            wrapped = {"entries": [wrapped]}  # two levels each
        holder = Holder.model_validate_json(json.dumps({"held": wrapped}))
        assert holder.model_dump_json()

    def test_the_mark_is_written_where_the_value_went_on(self) -> None:
        value = {"a": 1, "deep": _deep_list(DEPTH_GUARD + 5), "z": [1, 2]}
        back = json.loads(dumps(value))
        assert list(back) == ["a", "deep", "z"]
        assert back["a"] == 1
        assert back["z"] == [1, 2]
        node = back["deep"]
        for _ in range(DEPTH_GUARD - 2):
            node = node[0]
        assert node == [DEEPER_MARK]


class TestAnyDepthIsRead:
    @pytest.mark.parametrize("depth", [DEPTH_GUARD + 1, 3_000, 10_000, 200_000])
    def test_a_deep_body_is_read_marked_below_the_guard(self, depth: int) -> None:
        text = "[" * depth + '{"k": "v"}' + "]" * depth
        value = loads(text)
        assert _depth(value) == DEPTH_GUARD
        node = value
        for _ in range(DEPTH_GUARD - 1):
            assert isinstance(node, list)
            assert len(node) == 1
            node = node[0]
        assert node == [DEEPER_MARK]

    def test_a_body_within_the_guard_is_read_whole(self) -> None:
        text = "[" * (DEPTH_GUARD - 1) + '{"k": "v"}' + "]" * (DEPTH_GUARD - 1)
        assert loads(text) == json.loads(text)
        assert safe_json._loads_iteratively(text) == json.loads(text)

    def test_a_deep_object_body_keeps_its_keys_down_to_the_guard(self) -> None:
        depth = 5_000
        text = '{"a": ' * depth + "1" + ', "b": [true, null]}' * depth
        for value in (loads(text), safe_json._loads_iteratively(text)):
            node = value
            for _ in range(DEPTH_GUARD - 1):
                assert list(node) == ["a", "b"]
                assert node["b"] == [True, None]
                node = node["a"]
            assert node == {"a": DEEPER_MARK, "b": DEEPER_MARK}

    def test_the_iterative_reader_gives_what_json_loads_marked_gives(self) -> None:
        text = '{"x": ' + "[" * 400 + "1" + "]" * 400 + ', "y": [1, {"z": []}]}'
        assert safe_json._loads_iteratively(text) == within_depth(json.loads(text))

    def test_bytes_are_read_as_json_loads_reads_them(self) -> None:
        text = "[" * 3_000 + '"\\u00e9"' + "]" * 3_000
        for encoding in ("utf-8", "utf-16"):
            assert loads(text.encode(encoding)) == loads(text)

    def test_the_iterative_reader_reads_what_json_loads_reads(self) -> None:
        rng = random.Random(11)
        cases = [json.dumps(_random_value(rng), indent=rng.choice([None, 1])) for _ in range(400)]
        cases += [
            "  [1, 2.5, -0, -0.0, 1e5, 1E-2, 3e+2]  ",
            '{"a": NaN, "b": Infinity, "c": -Infinity}',
            '{"dup": 1, "dup": 2}',
            '"\\ud83d\\ude00 \\n \\t \\" \\\\ \\/"',
            "{}",
            "[]",
            "[[], {}, [[]]]",
            '\n\t{ "k" :\r [ ] }\n',
        ]
        for text in cases:
            expected = json.loads(text)
            got = safe_json._loads_iteratively(text)
            if isinstance(expected, dict) and isinstance(expected.get("a"), float):
                assert math.isnan(got["a"])
                assert got["b"] == expected["b"]
                assert got["c"] == expected["c"]
                continue
            assert got == expected
            assert json.dumps(got) == json.dumps(expected)

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "   ",
            "[1, 2",
            "[1 2]",
            '{"a" 1}',
            '{"a": 1,}',
            "[1,]",
            "{1: 2}",
            "[1] x",
            "tru",
            '"open',
            "[}",
            "{]",
        ],
    )
    def test_a_malformed_body_is_refused_as_json_loads_refuses_it(self, text: str) -> None:
        with pytest.raises(json.JSONDecodeError):
            json.loads(text)
        with pytest.raises(json.JSONDecodeError):
            safe_json._loads_iteratively(text)


def _seconds(make: Callable[[int], Any], run: Callable[[Any], Any], n: int) -> float:
    subject = make(n)
    best = float("inf")
    for _ in range(2):
        gc.collect()
        gc.disable()
        try:
            started = time.perf_counter()
            run(subject)
            best = min(best, time.perf_counter() - started)
        finally:
            gc.enable()
    return best


def _linear(make: Callable[[int], Any], run: Callable[[Any], Any], small: int) -> None:
    once, tenfold = _seconds(make, run, small), _seconds(make, run, small * 10)
    assert tenfold <= 10 * once * 1.5 + 0.05, (once, tenfold)


class TestLinearTime:
    def test_writing_a_deep_value_is_linear(self) -> None:
        _linear(_deep_list, dumps, 20_000)

    def test_writing_a_wide_shallow_value_is_linear(self) -> None:
        _linear(lambda n: [{"k": [i, str(i)]} for i in range(n)], dumps, 20_000)

    def test_reading_a_deep_body_is_linear(self) -> None:
        _linear(lambda n: "[" * n + "]" * n, safe_json._loads_iteratively, 20_000)

    def test_reading_a_wide_body_is_linear(self) -> None:
        _linear(
            lambda n: json.dumps([{"k": [i, "v"]} for i in range(n)]),
            safe_json._loads_iteratively,
            5_000,
        )


def _shared_chain(n: int) -> Any:
    """``n`` levels, each a list holding the level below twice: 2**n paths, n containers."""
    node: Any = [1]
    for _ in range(n):
        node = [node, node]
    return node


def _cycle(n: int) -> Any:
    """``n`` levels of shared lists whose innermost holds the outermost."""
    innermost: list[Any] = [1]
    node: Any = innermost
    for _ in range(n):
        node = [node, node, {"k": node}]
    innermost.append(node)
    return node


def _peak(run: Callable[[], Any]) -> int:
    import tracemalloc

    gc.collect()
    tracemalloc.start()
    try:
        run()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


class TestSharedContainersAndCycles:
    def test_a_shared_chain_within_the_guard_is_measured_once(self) -> None:
        # 2**100 paths: walked path by path it would never end.
        value = _shared_chain(100)
        assert not exceeds_depth(value)
        assert within_depth(value) is value

    def test_a_shared_chain_past_the_guard_is_copied_once_and_written_linearly(self) -> None:
        value = _shared_chain(5_000)
        assert exceeds_depth(value)
        text = dumps(value)
        assert len(text) < 200 * 5_000
        assert SHARED_MARK in text
        assert _depth(json.loads(text)) <= DEPTH_GUARD

    def test_a_cycle_is_written_once_and_marked(self) -> None:
        for value in (_cycle(3), _cycle(400)):
            with pytest.raises(ValueError):
                json.dumps(value)
            text = dumps(value)
            # The return is a cycle within the guard, and below it a deeper container.
            assert CYCLE_MARK in text or DEEPER_MARK in text
            assert _depth(json.loads(text)) <= DEPTH_GUARD
        assert CYCLE_MARK in dumps(_cycle(3))
        holder: dict[str, Any] = {"a": 1}
        holder["self"] = holder
        assert json.loads(dumps(holder)) == {"a": 1, "self": CYCLE_MARK}

    def test_the_shared_and_cyclic_walks_are_linear(self) -> None:
        _linear(_shared_chain, exceeds_depth, 20_000)
        _linear(_shared_chain, dumps, 20_000)
        _linear(_cycle, dumps, 5_000)

    def test_the_shared_walk_holds_memory_linear_in_the_containers(self) -> None:
        small = _peak(lambda: dumps(_shared_chain(5_000)))
        large = _peak(lambda: dumps(_shared_chain(50_000)))
        assert large <= 10 * small * 1.5, (small, large)


class TestAHostileDeepBody:
    def test_a_ten_million_character_body_is_read_linearly_in_time_and_memory(self) -> None:
        depth = 5_000_000
        text = "[" * depth + "]" * depth
        assert len(text) == 10_000_000
        value = loads(text)
        assert _depth(value) == DEPTH_GUARD
        small_text = "[" * (depth // 10) + "]" * (depth // 10)
        small = _peak(lambda: loads(small_text))
        large = _peak(lambda: loads(text))
        # The dropped levels are held as one byte each: never more than the body.
        assert large <= len(text), (small, large)
        assert large <= 10 * small * 1.5 + 65_536, (small, large)
        _linear(lambda n: "[" * n + "]" * n, loads, 500_000)

    def test_a_deep_body_of_mixed_brackets_is_read_linearly(self) -> None:
        def body(n: int) -> str:
            return '[{"a": ' * n + "1" + "}]" * n

        assert _depth(loads(body(50_000))) == DEPTH_GUARD
        _linear(body, loads, 20_000)

    @pytest.mark.parametrize(
        "unit",
        ['[{"":', '{"":['],
        ids=["array-object", "object-array"],
    )
    def test_an_alternating_deep_body_costs_no_more_memory_than_a_shallow_one(
        self, unit: str
    ) -> None:
        """Peak memory within a small constant factor of ``json.loads`` on a shallow body.

        Alternating brackets make every level a run of its own; each still
        costs one byte, so a deep body never costs more than a shallow body of
        the same size read by ``json.loads``. Measured as the peak resident
        size a fresh process adds while reading, one process per reading.
        """
        held = _added_peak("deep", unit, 1_000_000)
        size = len(unit) * 1_000_000
        baseline = _added_peak("shallow", unit, size)
        assert held <= 2 * baseline, (held, baseline)
        assert held <= size, (held, size)
        small = _added_peak("deep", unit, 100_000)
        assert held <= 10 * small * 1.5 + 8 * 2**20, (small, held)

    def test_an_alternating_deep_body_is_read_linearly(self) -> None:
        _linear(lambda n: '[{"":' * n + "0" + "}]" * n, loads, 20_000)

    def test_a_shallow_body_is_measured_without_a_record_per_container(self) -> None:
        text = json.dumps([{"k": [i, {"v": i}]} for i in range(20_000)])
        read = _peak(lambda: json.loads(text))
        held = _peak(lambda: loads(text))
        # What ``json.loads`` builds, and a walk holding one iterator per level.
        assert held <= read * 1.05 + 65_536, (read, held)

    def test_the_guard_says_how_many_containers_it_marked(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level("WARNING", logger="maljan.core.safe_json")
        loads('{"a": ' + "[" * 10_000 + "]" * 10_000 + ', "b": ' + "[" * 300 + "]" * 300 + "}")
        loads("[" * 300 + "]" * 300)
        said = [r.getMessage() for r in caplog.records]
        assert len(said) == 2
        assert "2 containers" in said[0]
        assert "1 containers" in said[1]
        caplog.clear()
        loads(json.dumps({"a": [[1]]}))
        assert not caplog.records

    def test_a_deep_object_body_is_validated_while_dropped(self) -> None:
        bad = '{"a": ' * 10_000 + "1" + "}" * 9_999 + ","
        with pytest.raises(json.JSONDecodeError):
            loads(bad)


_PEAK_SCRIPT = """
import json, resource, sys
from maljan.core.safe_json import loads
kind, unit, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
closer = "}]" if unit.startswith("[") else "]}"
if kind == "deep":
    text, read = unit * n + "0" + closer * n, loads
else:
    text, read = "[" + ",".join(['{"":0}'] * (n // 7)) + "]", json.loads
base = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
value = read(text)
print((resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - base) * 1024)
"""


def _added_peak(kind: str, unit: str, n: int) -> int:
    """The peak resident bytes a fresh process adds reading the body (``ru_maxrss``)."""
    import os
    import subprocess
    import sys

    import maljan

    env = {**os.environ, "PYTHONPATH": str(Path(maljan.__file__).resolve().parents[1])}
    done = subprocess.run(
        [sys.executable, "-c", _PEAK_SCRIPT, kind, unit, str(n)],
        capture_output=True,
        text=True,
        check=True,
        env=env,
        timeout=300,
    )
    return int(done.stdout.strip().splitlines()[-1])


def _stored_report_paths() -> list[Any]:
    from tests.unit.providers.test_sandbox_tools_golden import ROOT, _globs

    return [path for pattern in _globs() for path in sorted(ROOT.glob(pattern))]


class TestEveryStoredReportIsWrittenAsBefore:
    """Every stored CAPE report and its document are written by ``json.dumps`` itself."""

    @pytest.mark.parametrize("path", _stored_report_paths(), ids=lambda path: path.stem)
    def test_the_report_and_its_document_are_handed_to_json_dumps_unchanged(
        self, path: Any
    ) -> None:
        from maljan.providers.sandbox.readers import required_reader
        from maljan.schemas.sandbox_document import sandbox_document

        text = path.read_text(encoding="utf-8")
        raw = json.loads(text)
        assert loads(text) == raw
        document = sandbox_document(required_reader("cape2").read(raw, provider="upload"))
        for value in (raw, document):
            assert safe_json.within_depth(value) is value
            assert dumps(value, separators=(",", ":"), default=str) == json.dumps(
                value, separators=(",", ":"), default=str
            )
