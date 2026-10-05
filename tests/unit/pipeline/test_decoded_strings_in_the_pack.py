"""A PE's decoded strings are a pack entry every agent reads.

A sample that keeps its strings encrypted shows a plain strings pass nothing,
and an analyst offered the emulating decoder among thirty-six tools may never
call it. So the pack runs it, once, for every PE, through the same function
the analysis sidecar serves, and renders what came back as one bounded line:
each string with the routine that produced it and its offset, the bound and
its reason said when it cut, and a sentence rather than nothing when the tool
was not there, ran out of time or hit its memory limit.

FLOSS itself is faked here; its own behaviour is ``tests/unit/tools``'s.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.pipeline import triage_pack
from maljan.pipeline.nodes import make_triage_node
from maljan.pipeline.triage_pack import (
    PIPELINE,
    CapaSettings,
    FlossSettings,
    PackInputs,
    degrades_run,
    render_pack,
    run_pack,
)
from maljan.schemas.evidence import EvidenceCounter, build_entry, format_entry_id
from maljan.tools import emulated_strings, rules, staging
from tests.unit.pipeline.test_stage_events import _state
from tests.unit.tools.test_binary import _elf, _pe

CAPA = CapaSettings(rules_dir="data/capa-rules", signatures_dir="data/capa-signatures", timeout_s=5)


def _row(text: str, routine: str, site: str, kind: str = "decoded") -> dict[str, Any]:
    if kind == "decoded":
        return {
            "kind": "decoded",
            "string": text,
            "encoding": "ASCII",
            "function": "0x1360bc0ae78",
            "function_rva": routine,
            "called_at": "0x1360bc05c02",
            "called_at_rva": site,
            "address": "0x1000",
            "address_type": "GLOBAL",
        }
    return {
        "kind": kind,
        "string": text,
        "encoding": "ASCII",
        "function": "0x1360bc08c4c",
        "function_rva": routine,
        "program_counter": "0x1360bc08c90",
        "frame_offset": 32,
    }


ROWS = [
    _row("runnung", "0xae78", "0x3939"),
    _row("Custom_update", "0xae78", "0x312f"),
    _row("https://example.test/live/", "0xae78", "0x6a1f"),
    _row("Mozilla/4.0 (compatible; MSIE 7.0)", "0xae78", "0x4e47"),
    _row("scub", "0x8c4c", "", kind="stack"),
]


def _answer(rows: list[dict[str, Any]], total: int | None = None) -> dict[str, Any]:
    counts = {kind: sum(1 for r in rows if r["kind"] == kind) for kind in emulated_strings.KINDS}
    return {
        "strings": rows,
        "counts": counts,
        "total": len(rows) if total is None else total,
        "total_matched": len(rows) if total is None else total,
        "page_offset": 0,
        "page_limit": 200,
        "kinds": list(emulated_strings.KINDS),
        "pattern": None,
        "next_offset": None if total is None else len(rows),
        "truncated": total is not None,
        "meta": {
            "floss_version": "v3.1.1",
            "imagebase": "0x1360bc00000",
            "language": "unknown",
            "functions_discovered": 150,
            "functions_emulated_for_decoding": 20,
            "runtime_s": 26.7,
        },
    }


@pytest.fixture(autouse=True)
def _fake_capa(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rules, "capa", lambda path, **_: {"capabilities": [], "meta": {}})


class _Floss:
    """Stands in for ``emulated_strings.floss`` and keeps what it was asked."""

    def __init__(self, answer: dict[str, Any]) -> None:
        self.answer = answer
        self.calls: list[dict[str, Any]] = []

    def __call__(self, path: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append({"path": path, **kwargs})
        return self.answer


def _installed(monkeypatch: pytest.MonkeyPatch, answer: dict[str, Any]) -> _Floss:
    fake = _Floss(answer)
    monkeypatch.setattr(emulated_strings, "floss_unavailable", lambda environ=None: None)
    monkeypatch.setattr(emulated_strings, "floss", fake)
    return fake


def _pack(tmp_path: Path, blob: bytes = b"", file_type: str = "pe", **over: Any) -> Any:
    sample = tmp_path / "s.bin"
    sample.write_bytes(blob or _pe())
    values: dict[str, Any] = {
        "sample_path": str(sample),
        "sha256": "a" * 64,
        "file_type": file_type,
        "strings_head": 20,
        "capa": CAPA,
    }
    values.update(over)
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    return run_pack(recorder, PackInputs(**values))


def _floss_entry(result: Any) -> Any:
    (entry,) = [e for e in result.entries if e.tool == "floss"]
    return entry


def _bounded_line(tool: str, payload: Any, max_chars: int) -> str:
    """The entry's line in a pack bounded at ``max_chars``."""
    entry = build_entry(
        entry_id=format_entry_id(12),
        seq=12,
        agent=PIPELINE,
        tool=tool,
        args={},
        server=PIPELINE,
        output=json.dumps(payload),
        stage="triage_pack",
    )
    return render_pack([entry], max_chars)


def _line(tool: str, payload: Any, *, ok: bool = True, error: str | None = None) -> str:
    entry = build_entry(
        entry_id=format_entry_id(12),
        seq=12,
        agent=PIPELINE,
        tool=tool,
        args={},
        server=PIPELINE,
        output=payload if isinstance(payload, str) else json.dumps(payload),
        ok=ok,
        error=error,
        stage="triage_pack",
    )
    return render_pack([entry], 0)


class TestTheStep:
    def test_a_pe_s_pack_ends_with_the_decoded_strings(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After every other tool, so every id the pack issued before it is the id it
        always was; only the platform's own readings of the bytes follow it."""
        _installed(monkeypatch, _answer(ROWS))
        result = _pack(tmp_path)
        assert [entry.tool for entry in result.entries[-4:]] == [
            "sandbox_status",
            "floss",
            "resolve_api_hashes",
            "decode_string_blobs",
        ]
        entry = _floss_entry(result)
        assert entry.ok is True
        assert entry.structured["counts"] == {"decoded": 4, "stack": 1, "tight": 0}
        assert result.failed == []

    def test_the_call_is_the_sidecar_s_function_with_the_pack_s_bound(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _installed(monkeypatch, _answer(ROWS))
        entry = _floss_entry(_pack(tmp_path, budget_s=600.0))
        (call,) = fake.calls
        assert call["limit"] == triage_pack.DECODED_STRINGS_ROWS
        # What is left of the pack's own budget, never a fixed number.
        assert 1 <= call["timeout_s"] <= 600
        assert entry.args == {
            "path": call["path"],
            "limit": triage_pack.DECODED_STRINGS_ROWS,
            "timeout_s": call["timeout_s"],
        }

    def test_a_pack_with_no_budget_gives_floss_no_wall_clock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _installed(monkeypatch, _answer(ROWS))
        _floss_entry(_pack(tmp_path, budget_s=0.0))
        (call,) = fake.calls
        assert call["timeout_s"] is None

    def test_it_runs_in_the_job_s_staging_directory_with_the_server_s_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _installed(monkeypatch, _answer(ROWS))
        environ = {
            staging.STAGING_DIR_ENV: str(tmp_path / "staging"),
            emulated_strings.FLOSS_PATH_ENV: "/opt/floss/floss",
        }
        try:
            _pack(tmp_path, floss=FlossSettings(environ=environ, job_id="job-under-test"))
            (call,) = fake.calls
            expected = tmp_path / "staging" / staging.job_directory_name("job-under-test")
            assert call["environ"] == environ
            assert Path(call["scratch"]) == expected / "floss"
            assert (expected / "floss").is_dir()
            # Recorded, so the job's teardown removes it with the rest.
            assert expected in staging.job_directories("job-under-test")
        finally:
            staging.remove_job_staging("job-under-test")

    def test_a_format_floss_does_not_read_gets_no_entry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _installed(monkeypatch, _answer(ROWS))
        result = _pack(tmp_path, _elf(), file_type="elf")
        assert "floss" not in [e.tool for e in result.entries]
        assert fake.calls == []


class TestWhenThereIsNothingToShow:
    def test_an_absent_build_is_an_entry_that_says_so_and_how_to_install_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reason = (
            "floss is not installed: no floss executable in the user tools directory or on PATH"
        )
        monkeypatch.setattr(emulated_strings, "floss_unavailable", lambda environ=None: reason)

        def _never(*_: Any, **__: Any) -> dict[str, Any]:
            raise AssertionError("an absent build is not run")

        monkeypatch.setattr(emulated_strings, "floss", _never)
        result = _pack(tmp_path)
        entry = _floss_entry(result)
        assert entry.ok is False
        assert entry.error == f"not run: {reason}"
        assert entry.remediation == emulated_strings.FLOSS_REMEDIATION
        # A tool this host does not have is an absence the reader is told
        # about, not a failure of the run.
        assert result.failed == []
        assert result.degradation_reasons == []
        assert f"decoded strings: not done (not run: {reason[:40]}" in render_pack([entry], 0)

    @pytest.mark.parametrize(
        "message",
        [
            "FLOSS produced no result within its budget (600 s) and was stopped",
            (
                "FLOSS produced no result within its budget (4096 MiB of address space) "
                "and was stopped"
            ),
        ],
    )
    def test_a_run_that_hit_its_clock_or_its_memory_says_which(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, message: str
    ) -> None:
        _installed(monkeypatch, {"error": message, "tool": "floss"})
        result = _pack(tmp_path)
        entry = _floss_entry(result)
        assert entry.ok is False
        assert entry.error == message
        assert result.degradation_reasons == ["triage.floss_failed"]
        assert not degrades_run("triage.floss_failed")
        assert f"decoded strings: failed ({message})" in render_pack([entry], 0)

    def test_a_pe_with_no_emulated_strings_says_so(self) -> None:
        line = _line("floss", _answer([]))
        assert "decoded strings: FLOSS recovered no decoded, stack or tight strings" in line
        assert "150 functions, 20 emulated for decoding" in line


class TestTheLine:
    def test_each_string_carries_its_routine_and_its_offset(self) -> None:
        line = _line("floss", _answer(ROWS))
        assert line.startswith("[ev_0012] decoded strings: 5 recovered by emulation")
        assert "(4 decoded, 1 stack, 0 tight" in line
        assert "all 5 shown" in line
        assert 'routine 0xae78: "runnung"@0x3939, "Custom_update"@0x312f' in line
        assert '"https://example.test/live/"@0x6a1f' in line
        assert 'routine 0x8c4c: "scub"' in line

    def test_every_string_is_shown_whole_with_no_bound(self) -> None:
        many = [_row(f"s{i:03d}", "0xae78", hex(0x1000 + i)) for i in range(150)]
        line = _line("floss", _answer(many))
        assert "all 150 shown" in line
        assert '"s149"' in line

    def test_the_room_bound_is_stated_with_its_reason_and_where_the_rest_is(self) -> None:
        many = [_row(f"s{i:03d}", "0xae78", hex(0x1000 + i)) for i in range(150)]
        whole = _line("floss", _answer(many))
        line = _bounded_line("floss", _answer(many), len(whole) // 3)
        assert len(line) <= len(whole) // 3
        shown = int(line.split(" of 150 shown", 1)[0].rsplit(" ", 1)[1])
        assert 0 < shown < 150
        assert "every agent reads the pack" in line
        assert f"offset {shown}" in line
        assert f'"s{shown - 1:03d}"' in line
        assert f'"s{shown:03d}"' not in line

    def test_a_long_string_is_whole_with_no_bound_and_cut_said_within_one(self) -> None:
        answer = _answer([_row("A" * 3000, "0xae78", "0x10")])
        assert '"' + "A" * 3000 + '"' in _line("floss", answer)
        line = _bounded_line("floss", answer, 1500)
        assert len(line) <= 1500
        assert 'A…"' in line

    def test_a_string_s_control_characters_are_written_out(self) -> None:
        line = _line("floss", _answer([_row('say "hi"\r\n', "0xae78", "0x10")]))
        assert '"say \\"hi\\"\\r\\n"@0x10' in line
        assert "\n" not in line

    def test_more_rows_than_the_entry_holds_is_said(self) -> None:
        line = _line("floss", _answer(ROWS, total=400))
        assert "5 of 400 shown" in line


class TestTheBlock:
    def test_a_long_decoded_strings_line_shrinks_to_the_room_left_rather_than_going(
        self,
    ) -> None:
        many = [_row(f"string number {i:03d}", "0xae78", hex(0x1000 + i)) for i in range(150)]
        head = build_entry(
            entry_id=format_entry_id(1),
            seq=1,
            agent=PIPELINE,
            tool="hashes",
            args={},
            server=PIPELINE,
            output=json.dumps({"sha256": "a" * 64}),
            stage="triage_pack",
        )
        tail = build_entry(
            entry_id=format_entry_id(2),
            seq=2,
            agent=PIPELINE,
            tool="floss",
            args={},
            server=PIPELINE,
            output=json.dumps(_answer(many)),
            stage="triage_pack",
        )
        block = render_pack([head, tail], 900)
        assert len(block) <= 900
        assert "[ev_0002] decoded strings:" in block
        assert "more pack entr" not in block


class TestTheNode:
    def test_the_node_hands_the_step_the_analysis_server_s_environment_and_the_job(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _installed(monkeypatch, _answer(ROWS))
        settings = Settings(_env_file=None)
        settings.mcp.servers["threatintel"].enabled = False
        settings.mcp.servers["analysis"].env = {
            emulated_strings.FLOSS_PATH_ENV: "/opt/floss/floss",
            staging.STAGING_DIR_ENV: str(tmp_path / "staging"),
        }
        container = ServiceContainer(settings, mock=True)
        node = make_triage_node(container, stage=container.active_profile().stage("triage_pack"))
        sample = tmp_path / "s.exe"
        sample.write_bytes(_pe())
        try:
            update = asyncio.run(node(_state(sample_path=str(sample), file_type="pe")))
            (call,) = fake.calls
            assert call["environ"][emulated_strings.FLOSS_PATH_ENV] == "/opt/floss/floss"
            job_dir = tmp_path / "staging" / staging.job_directory_name(container.job_key())
            assert Path(call["scratch"]) == job_dir / "floss"
            assert update["evidence_ledger"][-3]["tool"] == "floss"
        finally:
            staging.remove_job_staging(container.job_key())


class TestTheLineSaysWhatItDidToAString:
    def test_a_string_cut_is_said_even_when_every_string_is_shown(self) -> None:
        line = _bounded_line("floss", _answer([_row("A" * 3000, "0xae78", "0x10")]), 1500)
        assert "all 1 shown (1 cut to " in line
        assert "fits its room; the whole string is in the entry" in line

    def test_a_line_with_nothing_cut_says_nothing_about_it(self) -> None:
        assert "cut to" not in _line("floss", _answer(ROWS))

    def test_a_trailing_backslash_does_not_read_as_an_escaped_quote(self) -> None:
        line = _line("floss", _answer([_row("C:\\dir\\", "0xae78", "0x10")]))
        assert '"C:\\dir\\x5c"@0x10' in line

    def test_an_address_with_no_offset_is_marked_virtual(self) -> None:
        row = _row("runnung", "0xae78", "")
        row["called_at_rva"] = None
        line = _line("floss", _answer([row]))
        assert '"runnung"@va 0x1360bc05c02' in line
