"""A platform name table reads only the platform's own tools, never an operator's of the same name.

Three readers once took a bare tool name for the platform's tool: whether the
routed format's own reader answered (``extractors.sample_identity``), which
format a missing parser is for (``pipeline.nodes``), and which pack lines the
run-state block carries (``pipeline.run_state``). An operator's server whose
tool shares one of those names was credited with the platform's meaning. Each
now reads by the entry's recorded source, its declared kind or the renderer its
pack step declared; a stored entry with no source is read as before.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from maljan.extractors.sample_identity import unparsed_container_reason
from maljan.pipeline.nodes import reason_applies_to_format
from maljan.pipeline.run_state import render_run_state
from maljan.pipeline.triage_pack import PIPELINE
from maljan.schemas.evidence import build_entry, format_entry_id
from tests.linear_cost import assert_scales

PARSED = {"pages": 2, "objects": 14}


def _pdf(tmp_path: Path) -> Path:
    path = tmp_path / "doc.bin"
    path.write_bytes(b"%PDF-1.7" + b"\x00" * 64)
    return path


def _entry(tool: str, *, source: str | None, facts: dict[str, Any] | None) -> dict[str, Any]:
    row = {"tool": tool, "ok": True, "structured": dict(PARSED), "output": json.dumps(PARSED)}
    if source is not None:
        row["source"] = source
    if facts is not None:
        row["facts"] = facts
    return row


class TestTheRoutedFormatsOwnReader:
    def test_the_platform_s_reader_counts(self, tmp_path: Path) -> None:
        ledger = [_entry("document_info", source="mcp:analysis", facts={"v": 1})]
        assert unparsed_container_reason(_pdf(tmp_path), ledger) is None

    def test_the_pack_s_reader_counts(self, tmp_path: Path) -> None:
        ledger = [_entry("document_info", source="pack", facts={"v": 1})]
        assert unparsed_container_reason(_pdf(tmp_path), ledger) is None

    def test_a_stored_entry_with_no_source_reads_by_its_name(self, tmp_path: Path) -> None:
        ledger = [_entry("document_info", source=None, facts=None)]
        assert unparsed_container_reason(_pdf(tmp_path), ledger) is None

    def test_an_operator_s_tool_only_named_like_it_never_counts(self, tmp_path: Path) -> None:
        ledger = [_entry("document_info", source="mcp:kit", facts={"v": 1})]
        reason = unparsed_container_reason(_pdf(tmp_path), ledger)
        assert reason is not None and "PDF" in reason

    def test_an_operator_s_reader_declared_of_the_kind_counts(self, tmp_path: Path) -> None:
        ledger = [_entry("read_pdf", source="mcp:kit", facts={"v": 1, "kind": "document_info"})]
        assert unparsed_container_reason(_pdf(tmp_path), ledger) is None

    def test_a_reader_of_another_kind_never_counts(self, tmp_path: Path) -> None:
        ledger = [_entry("list_zip", source="mcp:kit", facts={"v": 1, "kind": "archive_listing"})]
        assert unparsed_container_reason(_pdf(tmp_path), ledger) is not None

    def test_a_platform_reader_of_another_format_never_counts(self, tmp_path: Path) -> None:
        ledger = [_entry("archive_list", source="mcp:analysis", facts={"v": 1})]
        assert unparsed_container_reason(_pdf(tmp_path), ledger) is not None


class TestAMissingParsersFormat:
    MACHO = "server.{server}.macho_info_unavailable(macholib is not installed); install it"

    def test_the_platform_s_parser_is_read_by_its_format(self) -> None:
        reason = self.MACHO.format(server="analysis")
        assert reason_applies_to_format(reason, "pe") is False
        assert reason_applies_to_format(reason, "mach-o") is True

    def test_an_operator_s_tool_of_the_same_name_keeps_its_reason(self) -> None:
        reason = self.MACHO.format(server="kit")
        assert reason_applies_to_format(reason, "pe") is True


def _pack_row(
    tool: str, payload: dict[str, Any], seq: int, *, server: str = PIPELINE, step: Any = None
) -> dict[str, Any]:
    row = build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent=PIPELINE,
        tool=tool,
        args={},
        server=server,
        output=json.dumps(payload),
    ).model_dump(mode="json")
    if step is not None:
        row["pack_step"] = step
    return row


class TestTheRunStatePackLines:
    def _state(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        return {"file_hash": "c" * 64, "file_type": "pe", "evidence_ledger": rows}

    def test_the_shipped_steps_lines_are_carried(self) -> None:
        rows = [
            _pack_row("identify_file", {"file_type": "pe", "size": 10}, 1),
            _pack_row("hashes", {"sha256": "c" * 64}, 2),
        ]
        body = render_run_state(self._state(rows))
        assert "[ev_0001]" in body and "[ev_0002]" in body

    def test_an_operator_step_named_like_one_is_not_an_identity_line(self) -> None:
        # An operator's step running its own server's tool called "hashes",
        # declaring no renderer: its line is the pack's, never the block's.
        step = {"v": 1, "id": "kit_hashes", "label": "kit hashes"}
        rows = [_pack_row("hashes", {"sha256": "e" * 64}, 1, server="kit", step=step)]
        body = render_run_state(self._state(rows))
        assert "[ev_0001]" not in body

    def test_an_operator_step_declaring_the_renderer_is_carried(self) -> None:
        step = {"v": 1, "id": "kit_digests", "label": "digests", "renderer": "digests"}
        rows = [_pack_row("digest_file", {"sha256": "e" * 64}, 1, server="kit", step=step)]
        body = render_run_state(self._state(rows))
        assert "[ev_0001]" in body


def test_the_readers_take_one_pass(tmp_path: Path) -> None:
    pdf = _pdf(tmp_path)

    def read(count: int) -> Callable[[], Any]:
        ledger = [_entry("document_info", source="mcp:kit", facts={"v": 1}) for _ in range(count)]
        return lambda: unparsed_container_reason(pdf, ledger)

    assert read(1_000)() is not None
    assert_scales(read, 1_250)
