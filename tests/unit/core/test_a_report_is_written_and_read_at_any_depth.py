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
from typing import Any

import pytest
from pydantic import BaseModel

from maljan.core import safe_json
from maljan.core.safe_json import DEEPER_MARK, DEPTH_GUARD, dumps, exceeds_depth, loads


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
    @pytest.mark.parametrize("depth", [10_000, 200_000])
    def test_a_body_too_deep_for_json_loads_is_read(self, depth: int) -> None:
        text = "[" * depth + '{"k": "v"}' + "]" * depth
        with pytest.raises(RecursionError):
            json.loads(text)
        value = loads(text)
        assert _depth(value) == depth + 1
        node = value
        for _ in range(depth):
            assert isinstance(node, list)
            assert len(node) == 1
            node = node[0]
        assert node == {"k": "v"}

    def test_a_deep_object_body_keeps_its_keys(self) -> None:
        depth = 5_000
        text = '{"a": ' * depth + "1" + ', "b": [true, null]}' * depth
        value = loads(text)
        node = value
        for _ in range(depth - 1):
            assert list(node) == ["a", "b"]
            assert node["b"] == [True, None]
            node = node["a"]
        assert node == {"a": 1, "b": [True, None]}

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
