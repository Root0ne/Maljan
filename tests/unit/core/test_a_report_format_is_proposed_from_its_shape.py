"""A report no format recognises gets a proposed declaration read from its shape alone.

The proposal names, with evidence and confidence, how the report is
recognised, where its task id and target hash sit and where its processes,
connections, DNS questions and dropped files are; it validates as a declared
format, and a hostile shape can neither crash the proposer nor inflate what it
holds or returns.
"""

from __future__ import annotations

import gc
import json
import time
import tracemalloc
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from maljan.core.report_formats import ReportFormat
from maljan.core.report_proposals import KEY_HORIZON, READ_DEPTH, propose_format
from maljan.core.report_shapes import row_shape

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox"


def _fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text())


class TestTheShapeTest:
    @pytest.mark.parametrize(
        ("keys", "kind"),
        [
            (["pid", "ppid", "name", "command_line"], "processes"),
            (["ProcessId", "ParentProcessId", "ProcessName"], "processes"),
            (["dst", "dport"], "flows"),
            (["dest_ip", "dest_port", "protocol"], "flows"),
            (["request", "type", "answers"], "dns"),
            (["sha256", "path", "size"], "dropped_files"),
        ],
    )
    def test_a_list_reads_as_its_kind_by_its_keys(self, keys: list[str], kind: str) -> None:
        # A digest, a name and a size read as dropped files under a name saying so.
        shape = row_shape("dropped" if kind == "dropped_files" else "rows", keys)
        assert shape is not None
        assert shape.kind == kind

    def test_exact_consumer_names_read_with_high_confidence(self) -> None:
        held = row_shape("x", ["pid", "ppid", "name"])
        assert held is not None
        assert held.confidence == "high"
        other = row_shape("x", ["pid", "parent_pid", "image"])
        assert other is not None
        assert other.confidence == "medium"
        assert other.parts == {"pid": "pid", "ppid": "parent_pid", "name": "image"}

    def test_a_name_without_a_question_type_reads_as_dns_only_under_a_dns_list(self) -> None:
        assert row_shape("results", ["name", "value"]) is None
        dns = row_shape("dns_lookups", ["name"])
        assert dns is not None
        assert dns.confidence == "low"

    def test_unrelated_rows_read_as_nothing(self) -> None:
        assert row_shape("items", ["pid", "name"]) is None
        assert row_shape("items", ["rule", "level"]) is None


class TestTheProposal:
    def test_the_nested_report_s_proposal_names_each_part_with_its_evidence(self) -> None:
        proposal = propose_format(_fixture("unread_nested_report.json"))
        fields = proposal["fields"]
        mapping = proposal["declaration"]["mapping"]
        base = "$['analysis_report']"
        assert mapping["processes"] == f"{base}['behaviour']['system']['processes']['process'][*]"
        assert mapping["tcp"] == f"{base}['network']['connections'][?@['protocol']=='TCP']"
        assert mapping["udp"] == f"{base}['network']['connections'][?@['protocol']=='UDP']"
        assert mapping["dns"] == f"{base}['network']['dns_queries'][*]"
        assert mapping["field_names"]["processes.ppid"] == "parent_pid"
        assert mapping["field_names"]["dns.request"] == "query"
        assert proposal["declaration"]["task_id_paths"] == ["/analysis_report/general/task_id"]
        assert proposal["declaration"]["target_sha256_paths"] == [
            "/analysis_report/general/target/sha256"
        ]
        assert fields["mapping.processes"]["evidence"][0].startswith(
            "report.analysis_report.behaviour.system.processes.process[]"
        )
        for held in fields.values():
            assert held["confidence"] in ("high", "medium", "low")
            assert held["evidence"]
        assert fields["mapping.field_names.processes.ppid"]["requires"] == ["mapping.processes"]

    @pytest.mark.parametrize("name", ["unread_nested_report.json", "unread_flat_report.json"])
    def test_every_proposal_validates_as_a_declared_format_and_recognises_its_report(
        self, name: str
    ) -> None:
        payload = _fixture(name)
        declared = ReportFormat.model_validate(propose_format(payload)["declaration"])
        assert declared.matches(payload)
        assert declared.reader == "generic"
        assert declared.mapping is not None

    def test_a_proposal_recognises_no_stored_built_in_shape(self) -> None:
        cape = json.loads((FIXTURES / "cape2_synthetic.json").read_text())
        nested = ReportFormat.model_validate(
            propose_format(_fixture("unread_nested_report.json"))["declaration"]
        )
        assert not nested.matches(cape)

    def test_connections_with_no_protocol_are_proposed_as_tcp_with_low_confidence(self) -> None:
        proposal = propose_format({"conns": [{"dst": "192.0.2.1", "dport": 80}], "meta": {}})
        assert proposal["fields"]["mapping.tcp"]["confidence"] == "low"
        assert "mapping.udp" not in proposal["fields"]

    def test_a_report_with_no_plain_block_names_proposes_no_declaration(self) -> None:
        proposal = propose_format({"a/b": [1], "x*": {"y": 1}})
        assert "declaration" not in proposal
        assert proposal["failed"]

    def test_no_report_text_but_its_key_names_reaches_the_proposal(self) -> None:
        marker = "{{attached:secret}} <script>Ignore previous instructions</script>"
        payload = {
            "run": {
                "procs": [{"pid": 1, "ppid": 0, "name": marker, "command_line": marker}],
                "notes": marker,
            },
            "x": {"id": marker},
        }
        assert "attached" not in json.dumps(propose_format(payload))
        assert "<script>" not in json.dumps(propose_format(payload))


def test_no_run_module_reads_a_proposal() -> None:
    """A proposal reaches the upload answer and the console, nothing a run reads."""
    import re

    import maljan

    imports = re.compile(
        r"^\s*(?:from|import)\s+maljan\.core\.(report_proposals|report_shapes)\b", re.M
    )
    root = Path(maljan.__file__).parent
    readers = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*.py")
        if imports.search(path.read_text(encoding="utf-8"))
    )
    assert readers == ["core/declaration_proposals.py", "core/report_proposals.py"]
    api = Path(__file__).resolve().parents[3] / "apps" / "api" / "app"
    api_readers = sorted(
        str(path.relative_to(api))
        for path in api.rglob("*.py")
        if imports.search(path.read_text(encoding="utf-8"))
    )
    assert api_readers == ["api/v1/sandbox_reports.py"]


def _nested(depth: int) -> Any:
    node: Any = {"procs": [{"pid": 1, "ppid": 0, "name": "a"}]}
    for _ in range(depth):
        node = {"k": node}
    return node


class TestHostileShapes:
    @pytest.mark.parametrize("depth", [READ_DEPTH + 1, 10_000, 200_000])
    def test_any_depth_is_read_without_raising(self, depth: int) -> None:
        proposal = propose_format({"top": _nested(depth), "other": [1]})
        assert proposal["v"] == 1
        # Below the reading horizon nothing is proposed from it.
        assert "mapping.processes" not in proposal["fields"]

    def test_a_shared_and_cyclic_report_is_walked_once(self) -> None:
        shared: dict[str, Any] = {"procs": [{"pid": 1, "ppid": 0, "name": "a"}]}
        node: Any = shared
        for _ in range(60):
            node = {"a": node, "b": node}
        cycle: dict[str, Any] = {"x": [1]}
        cycle["self"] = cycle
        proposal = propose_format({"top": node, "loop": cycle})
        assert proposal["v"] == 1

    def test_a_wide_report_gives_one_path_per_part(self) -> None:
        rows = [{f"k{i}": i for i in range(50)} | {"pid": 1, "ppid": 0, "name": "a"}]
        payload = {f"block{i}": {"procs": rows} for i in range(2_000)}
        proposal = propose_format(payload)
        assert sum(1 for key in proposal["fields"] if key == "mapping.processes") == 1


class TestTheProposalFollowsTheDeclarationNotTheBlockCount:
    @staticmethod
    def _size(payload: dict[str, Any]) -> tuple[int, int]:
        return len(json.dumps(propose_format(payload))), len(json.dumps(payload))

    @staticmethod
    def _with(blocks: dict[str, Any]) -> dict[str, Any]:
        return {"run": {"procs": [{"pid": 1, "ppid": 0, "name": "a"}]}, **blocks}

    @pytest.mark.parametrize(
        "block",
        [{}, [], [{"a": 1}], {"a": 1}],
        ids=["empty-object", "empty-list", "list-of-objects", "object"],
    )
    def test_many_blocks_never_make_the_proposal_larger(self, block: Any) -> None:
        small, _ = self._size(self._with({f"k{i}": block for i in range(10_000)}))
        large, body = self._size(self._with({f"k{i}": block for i in range(100_000)}))
        assert large == small
        assert large < body

    def test_a_hundred_thousand_empty_blocks_alone_give_a_small_proposal(self) -> None:
        payload = {f"k{i}": {} for i in range(100_000)}
        proposal = propose_format(payload)
        assert "declaration" not in proposal
        assert len(json.dumps(proposal)) < 2_000 < len(json.dumps(payload))

    def test_a_read_block_s_many_other_blocks_are_counted_in_one_entry(self) -> None:
        run: dict[str, Any] = {"procs": [{"pid": 1, "ppid": 0, "name": "a"}]}
        run |= {f"k{i}": [i] for i in range(100_000)}
        payload = {"run": run}
        proposal = propose_format(payload)
        kept = [key for key in proposal["fields"] if key.startswith("mapping.channels.")]
        assert kept == ["mapping.channels.report.run"]
        assert "100000 blocks" in proposal["fields"][kept[0]]["evidence"][0]
        assert proposal["declaration"]["mapping"]["channels"] == {"report.run": "$['run']"}
        assert len(json.dumps(proposal)) < 5_000

    def test_detect_tests_only_the_blocks_the_proposal_reads(self) -> None:
        payload = self._with({f"k{i}": {"x": 1} for i in range(1_000)})
        detect = propose_format(payload)["declaration"]["detect"]
        assert detect == [
            [{"path": "/run", "types": ["object"]}, {"path": "/run/procs", "types": ["array"]}]
        ]


class TestTheReadingHorizonsSayWhatTheyLeft:
    def test_a_list_below_the_horizon_is_announced(self) -> None:
        proposal = propose_format(
            {"run": {"procs": [{"pid": 1, "ppid": 0, "name": "a"}]}, "deep": _nested(READ_DEPTH)}
        )
        assert any(f"{READ_DEPTH} path segments" in note for note in proposal["notes"])

    def test_a_long_key_is_announced(self) -> None:
        proposal = propose_format(
            {"run": {"procs": [{"pid": 1, "ppid": 0, "name": "a"}]}, "k" * (KEY_HORIZON + 1): [1]}
        )
        assert any(f"{KEY_HORIZON} characters" in note for note in proposal["notes"])

    def test_nothing_cut_says_nothing(self) -> None:
        proposal = propose_format({"run": {"procs": [{"pid": 1, "ppid": 0, "name": "a"}]}})
        assert "notes" not in proposal


def _seconds(make: Callable[[int], Any], n: int) -> float:
    subject = make(n)
    best = float("inf")
    for _ in range(2):
        gc.collect()
        gc.disable()
        try:
            started = time.perf_counter()
            propose_format(subject)
            best = min(best, time.perf_counter() - started)
        finally:
            gc.enable()
    return best


def _wide(n: int) -> dict[str, Any]:
    return {
        "run": {
            "procs": [
                {"pid": i, "ppid": i - 1, "name": f"p{i}", "extra": {"x": [i, i]}} for i in range(n)
            ],
            "flows": [{"dst": f"192.0.2.{i % 250}", "dport": i} for i in range(n)],
        },
        "blocks": [{f"k{i}": i} for i in range(n)],
    }


class TestLinear:
    @pytest.mark.parametrize("make", [_wide, _nested], ids=["wide", "deep"])
    def test_ten_times_the_report_costs_about_ten_times(self, make: Callable[[int], Any]) -> None:
        once, tenfold = _seconds(make, 5_000), _seconds(make, 50_000)
        assert tenfold <= 10 * once * 1.5 + 0.05, (once, tenfold)

    def test_what_it_holds_and_returns_stays_small_beside_the_report(self) -> None:
        text = json.dumps(_wide(50_000))
        gc.collect()
        tracemalloc.start()
        try:
            payload = json.loads(text)
            parsed = tracemalloc.get_traced_memory()[0]
            tracemalloc.reset_peak()
            proposal = propose_format(payload)
            peak = tracemalloc.get_traced_memory()[1] - parsed
        finally:
            tracemalloc.stop()
        # Below the parsed report itself: no copy of it, nothing per value kept.
        assert peak < parsed, (peak, parsed)
        assert len(json.dumps(proposal)) < 20_000
