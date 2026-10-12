"""A hostile report costs time and memory linear in its size, on every walk the readers make.

Each shape here is ten times larger in the second run than in the first, and
the second run may cost at most ten times the first (with the same margin
every other linear-time test of the platform allows). Each timing holds the
collector off and keeps the best of two runs, so a sweep that happens to land
in one run is not what is measured. No walk recurses, so depth costs no stack.
"""

from __future__ import annotations

import gc
import time
import tracemalloc
from collections.abc import Callable
from typing import Any

import pytest

from maljan.core.config import RestMappingConfig
from maljan.providers.sandbox.readers import required_reader
from maljan.providers.sandbox.rest_mapping import node_count, unnamed_blocks
from maljan.schemas.sandbox_document import sandbox_document
from maljan.schemas.sandbox_report import (
    cape_report_to_sandbox_report,
    stored_place,
    triage_overview_to_sandbox_report,
)


def _seconds(make: Callable[[int], Any], run: Callable[[Any], Any], n: int) -> float:
    """The best of two timed runs of ``run`` on ``make(n)``, the collector held."""
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


def _deep(depth: int, leaf: Any = 1) -> Any:
    """``depth`` objects nested one in the next, built without recursion."""
    node: Any = leaf
    for _ in range(depth):
        node = {"x": node}
    return node


def _mapped(payload: dict[str, Any], mapping: RestMappingConfig) -> dict[str, Any]:
    report = required_reader("generic").read(payload, provider="rest", mapping=mapping)
    return sandbox_document(report)


class TestTheTriageReader:
    def test_one_long_parent_chain(self) -> None:
        def make(n: int) -> tuple[dict[str, Any], dict[str, Any]]:
            processes = [
                {"procid": i + 1, "procid_parent": i, "image": f"p{i}.exe", "orig": i == 0}
                for i in range(n)
            ]
            flows = [{"proto": "tcp", "dst": "192.0.2.1:443", "procid": n} for _ in range(10)]
            return {"sample": {"target": "s.exe"}}, {
                "processes": processes,
                "network": {"flows": flows},
            }

        def run(subject: tuple[dict[str, Any], dict[str, Any]]) -> Any:
            overview, task = subject
            return triage_overview_to_sandbox_report(overview, task_reports={"t": task})

        _linear(make, run, 2_000)

    def test_many_tasks_each_extracting_many_rows(self) -> None:
        def make(n: int) -> dict[str, dict[str, Any]]:
            rows = [{"config": {"c2": [f"192.0.2.{i % 250}:443"]}} for i in range(n)]
            return {f"t{i}": {"extracted": rows, "signatures": rows} for i in range(10)}

        def run(tasks: dict[str, dict[str, Any]]) -> Any:
            return triage_overview_to_sandbox_report({"extracted": []}, task_reports=tasks)

        _linear(make, run, 2_000)


class TestTheDocument:
    def test_many_tiny_items_and_wide_sections(self) -> None:
        def make(n: int) -> dict[str, Any]:
            return {
                **{f"b{i}": i for i in range(n)},
                "behavior": {
                    "processes": [{"pid": i} for i in range(n)],
                    **{f"e{i}": [i] for i in range(n)},
                },
                "CAPE": {"payloads": [{} for _ in range(n)]},
            }

        def run(raw: dict[str, Any]) -> Any:
            return sandbox_document(cape_report_to_sandbox_report(raw, provider="x"))

        _linear(make, run, 5_000)

    def test_deep_nesting_costs_no_stack(self) -> None:
        raw = {"behavior": {"processes": [], "enhanced": _deep(200_000)}, "CAPE": _deep(200_000)}
        document = sandbox_document(cape_report_to_sandbox_report(raw, provider="x"))
        assert document["extracted"] is raw["CAPE"]
        assert stored_place(raw, "extracted") is raw["CAPE"]

    def test_a_long_string_is_carried_not_read(self) -> None:
        def make(n: int) -> dict[str, Any]:
            return {"blob": "A" * (n * 1_000), "behavior": {"processes": []}}

        def run(raw: dict[str, Any]) -> Any:
            return sandbox_document(cape_report_to_sandbox_report(raw, provider="x"))

        _linear(make, run, 1_000)


class TestAHostileMappedReport:
    def test_a_huge_unnamed_block(self) -> None:
        def make(n: int) -> dict[str, Any]:
            return {
                "run": {"procs": []},
                "huge": [{"k": i} for i in range(n)],
                "bare": list(range(n)),
            }

        mapping = RestMappingConfig(processes="$.run.procs[*]")
        _linear(make, lambda payload: unnamed_blocks(mapping, payload), 20_000)
        document = _mapped(make(1_000), mapping)
        assert len(document["channels"]["report.huge"]) == 1_000

    @staticmethod
    def _every_node(n: int) -> dict[str, Any]:
        return {"blob": [{"a": i, "b": [i, i]} for i in range(n)]}

    EVERY_NODE = RestMappingConfig(target_sha256="", places={"memory": "$..*"})

    def test_a_path_that_matches_every_node_costs_linear_time(self) -> None:
        _linear(self._every_node, lambda payload: _mapped(payload, self.EVERY_NODE), 2_000)

    @pytest.mark.slow
    def test_a_path_that_matches_millions_of_nodes_holds_memory_in_step(self) -> None:
        mapping = self.EVERY_NODE
        payload = self._every_node(250_000)  # over a million values
        tracemalloc.start()
        try:
            document = _mapped(payload, mapping)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        # Never more rows than the report holds values, and memory in step.
        assert len(document["memory"]) <= node_count(payload)
        assert peak < 400 * node_count(payload)

    def test_a_path_that_repeats_nodes_is_cut_at_the_report_s_size(self) -> None:
        payload = {"chain": _deep(300)}
        mapping = RestMappingConfig(target_sha256="", places={"memory": "$..*..*"})
        document = _mapped(payload, mapping)
        assert len(document.get("memory", [])) <= node_count(payload)

    def test_deep_nesting_is_counted_without_recursion(self) -> None:
        payload = {"deep": _deep(300_000)}
        assert node_count(payload) == 300_002
        mapping = RestMappingConfig(target_sha256="", places={"memory": "$..x"})
        # A path the library cannot walk this deep is that place's error, not the run's.
        document = _mapped(payload, mapping)
        assert "report.deep" not in document.get("channels", {})


def _reach_by_walking_each_chain(parent: dict[Any, Any], roots: set[Any]) -> set[Any]:
    """The lineage answer read the plain way, one whole chain per process."""
    tree: set[Any] = set()
    for procid in parent:
        seen: set[Any] = set()
        current = procid
        while current and current not in seen:
            if current in roots:
                tree.add(procid)
                break
            seen.add(current)
            current = parent.get(current)
    return tree


def test_the_settled_lineage_answers_as_the_plain_walk_does() -> None:
    import random

    from maljan.schemas.sandbox_report import _reach

    rng = random.Random(7)
    for _ in range(500):
        size = rng.randint(1, 30)
        ids = list(range(size + 1))
        parent = {i: rng.choice([*ids, None, size + 5]) for i in range(1, size + 1)}
        roots = set(rng.sample(ids, rng.randint(0, min(4, len(ids)))))
        assert _reach(parent, roots) == _reach_by_walking_each_chain(parent, roots)


def _questions_and_keys(n: int) -> dict[str, Any]:
    """A Triage task body: one request with ``n`` questions and ``n`` keys of its own."""
    request: dict[str, Any] = {f"k{i}": i for i in range(n)}
    request["domain_req"] = {
        "questions": [{"name": f"q{i}.example", "type": "A"} for i in range(n)]
    }
    return {"network": {"requests": [request]}}


def _held(build: Callable[[], Any]) -> tuple[int, Any]:
    """The bytes ``build`` leaves allocated, measured with the collector held."""
    gc.collect()
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        built = build()
        after = tracemalloc.get_traced_memory()[0]
    finally:
        tracemalloc.stop()
    return after - before, built


class TestEachRequestSFieldsAreHeldOnce:
    def test_many_questions_times_many_keys_costs_linear_time(self) -> None:
        _linear(
            _questions_and_keys,
            lambda task: triage_overview_to_sandbox_report({}, task_reports={"t": task}),
            200,
        )

    def test_and_memory_in_step_with_the_body(self) -> None:
        import json

        body = json.dumps(_questions_and_keys(1_500))
        parsed_bytes, task = _held(lambda: json.loads(body))
        held, report = _held(
            lambda: triage_overview_to_sandbox_report({}, task_reports={"t": task})
        )
        assert len(report.network.dns) == 1_500
        assert held <= 2 * parsed_bytes, (held, parsed_bytes)


class TestABlockIsHeldOnceByReference:
    """A long scalar list costs at most twice the parsed payload, on each path that keeps it."""

    N = 200_000

    def _check(self, payload: dict[str, Any], read: Callable[[dict[str, Any]], Any]) -> None:
        import json

        body = json.dumps(payload)
        parsed_bytes, parsed = _held(lambda: json.loads(body))
        held, document = _held(lambda: read(parsed))
        assert held <= 2 * parsed_bytes, (held, parsed_bytes)
        assert len(json.dumps(document)) <= 2 * len(body) + 4_096

    def test_an_unnamed_block(self) -> None:
        mapping = RestMappingConfig(processes="$.run.procs[*]")
        self._check(
            {"run": {"procs": []}, "blk": list(range(self.N))},
            lambda payload: _mapped(payload, mapping),
        )

    def test_a_mapped_place(self) -> None:
        mapping = RestMappingConfig(target_sha256="", places={"memory": "$.x[*]"})
        self._check({"x": list(range(self.N // 2))}, lambda payload: _mapped(payload, mapping))

    def test_a_kept_task_block(self) -> None:
        self._check(
            {"foo": list(range(self.N))},
            lambda task: sandbox_document(
                triage_overview_to_sandbox_report({}, task_reports={"t": task})
            ),
        )
