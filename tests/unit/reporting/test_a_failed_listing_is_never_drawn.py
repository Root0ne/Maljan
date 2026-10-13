"""A failed decompile or disassembly answer never becomes a code-listing figure.

The ledger report already leaves a failed entry out; the figure builder reads
the captured rows, which now carry the entry's outcome, so a call that failed
is never drawn as "Decompiled ..." whatever the tool or its kind's source.
"""

from __future__ import annotations

from maljan.reporting.figures import build_code_listings
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.schemas.evidence import LedgerEntry, build_entry
from maljan.schemas.tool_evidence import CapturedToolOutput


def _entry(seq: int, *, ok: bool, output: str, tool: str = "decompile_function") -> LedgerEntry:
    return build_entry(
        entry_id=f"ev_{seq:04d}",
        seq=seq,
        agent="reverser",
        tool=tool,
        args={"address": f"0x{0x1000 * seq:08x}"},
        server="any",
        output=output,
        ok=ok,
        error=None if ok else output,
    )


def _report(entries: list[LedgerEntry]) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        technical_evidence={"reverser": [e.to_captured().model_dump() for e in entries]},
    )


def test_a_failed_decompile_draws_no_figure() -> None:
    failed = _entry(1, ok=False, output='{"error": "no function at that address"}')
    answered = _entry(2, ok=True, output="int f(void) { return connect(s, a, n); }")
    figures = build_code_listings(_report([failed, answered]))
    assert len(figures) == 1
    assert "connect" in figures[0].content
    assert "no function" not in figures[0].content


def test_only_failed_answers_draw_nothing() -> None:
    entries = [_entry(i, ok=False, output=f"error {i}") for i in range(1, 6)]
    assert build_code_listings(_report(entries)) == []


def test_an_answered_capture_dumps_as_before() -> None:
    dumped = _entry(1, ok=True, output="int f(void) { return 0; }").to_captured().model_dump()
    assert "ok" not in dumped
    failed = _entry(2, ok=False, output="error").to_captured().model_dump()
    assert failed["ok"] is False


def test_a_stored_capture_without_an_outcome_reads_as_answered() -> None:
    row = {"agent_id": "static", "tool_name": "decompile_function", "output": "int f(void);"}
    assert CapturedToolOutput.model_validate(row).ok is True
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        technical_evidence={"static": [row]},
    )
    assert len(build_code_listings(report)) == 1


def test_the_outcome_survives_a_round_trip() -> None:
    failed = _entry(3, ok=False, output="error")
    back = LedgerEntry.from_captured(failed.to_captured())
    assert back.ok is False
    answered = LedgerEntry.from_captured(_entry(4, ok=True, output="int g(void);").to_captured())
    assert answered.ok is True


def test_many_failed_listings_are_skipped_in_linear_time() -> None:
    entries = [_entry(i, ok=i % 2 == 0, output=f"int f{i}(void);") for i in range(1, 2001)]
    figures = build_code_listings(_report(entries))
    assert figures and all("int f" in f.content for f in figures)
    assert all(int(f.content.split("int f")[1].split("(")[0]) % 2 == 0 for f in figures)
