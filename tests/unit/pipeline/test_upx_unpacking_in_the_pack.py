"""The pack unpacks a PE the packer reader names UPX, once, and states where the program is.

The step comes after every step the pack had, so each earlier id is the id it
was, and only when ``pe_info``'s packer signatures name UPX. The program is
written where the analysis server's ``carve_payloads`` writes for this job and
sample, so the ``carved_path`` the entry gives is read by the server's file
tools; the pack is not run again on it. Its one line takes only the room the
other lines leave. The packed files are synthetic (``synthetic_upx``).
"""

from __future__ import annotations

import importlib.util
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.pipeline import triage_pack
from maljan.pipeline.triage_pack import (
    PIPELINE,
    CapaSettings,
    FlossSettings,
    PackInputs,
    degrades_run,
    failure_reason,
    pack_block,
    pack_entries,
    render_pack,
    run_pack,
)
from maljan.schemas.evidence import EvidenceCounter
from maljan.tools import emulated_strings, rules, staging, upx

from ..tools import synthetic_upx as su
from ..tools.synthetic_pe import SyntheticPE

JOB = "a3d1c0de-0000-4000-8000-000000000001"
SERVER = Path(__file__).resolve().parents[3] / "services" / "analysis-mcp" / "server.py"


@pytest.fixture(autouse=True)
def _no_capa_and_no_floss(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        rules, "capa", lambda path, **_: {"capabilities": [], "function_starts": [], "meta": {}}
    )
    monkeypatch.setattr(emulated_strings, "floss_unavailable", lambda environ=None: "not here")


def _sample(tmp_path: Path, data: bytes, name: str = "packed.exe") -> str:
    folder = tmp_path / "samples"
    folder.mkdir(exist_ok=True)
    target = folder / name
    target.write_bytes(data)
    return str(target)


def _environ(tmp_path: Path) -> dict[str, str]:
    return {staging.STAGING_DIR_ENV: str(tmp_path / "staging")}


def _pack(path: str, tmp_path: Path, job: str = JOB) -> Any:
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    inputs = PackInputs(
        sample_path=path,
        sha256="a" * 64,
        file_type="pe",
        strings_head=10,
        capa=CapaSettings(rules_dir="", signatures_dir="", timeout_s=1),
        floss=FlossSettings(environ=_environ(tmp_path), job_id=job),
    )
    return run_pack(recorder, inputs)


def _entry(result: Any) -> Any:
    return next(e for e in result.entries if e.tool == upx.TOOL)


def _line(result: Any) -> str:
    entry = _entry(result)
    return next(
        line
        for line in pack_block(pack_entries(result.entries), 0).splitlines()
        if line.startswith(f"[{entry.id}]")
    )


def test_the_unpacking_comes_last_and_writes_beside_the_carved_files(tmp_path: Path) -> None:
    path = _sample(tmp_path, su.build().data)
    result = _pack(path, tmp_path)
    assert [e.tool for e in result.entries][-2:] == ["function_index", upx.TOOL]
    entry = _entry(result)
    assert entry.ok and entry.args == {"path": path}
    child = entry.structured["child"]
    written = Path(child["carved_path"])
    digest = triage_pack._file_digest(path)
    tree = staging.job_staging_dir(tmp_path / "staging", JOB) / staging.CARVED_DIRECTORY / digest
    assert written.parent == tree
    assert stat.S_IMODE(written.stat().st_mode) == 0o600
    assert stat.S_IMODE(tree.stat().st_mode) == 0o700
    assert result.failed == []


def test_the_ids_before_it_are_the_ids_a_pack_without_it_gives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _sample(tmp_path, su.build().data)
    with_step = _pack(path, tmp_path)
    monkeypatch.setattr(triage_pack, "_names_upx", lambda facts: False)
    monkeypatch.setattr(triage_pack, "_holds_a_pack_header", lambda path: False)
    without = _pack(path, tmp_path)
    assert [(e.id, e.tool) for e in with_step.entries][:-1] == [
        (e.id, e.tool) for e in without.entries
    ]


def test_the_server_reads_the_program_by_the_carved_path_the_entry_gives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _sample(tmp_path, su.build().data)
    carved = _entry(_pack(path, tmp_path)).structured["child"]["carved_path"]
    monkeypatch.setenv("MALJAN_SAMPLE_ROOTS", str(tmp_path / "samples"))
    monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))
    monkeypatch.setenv(staging.STAGING_JOB_ENV, staging.job_directory_name(JOB))
    spec = importlib.util.spec_from_file_location("analysis_mcp_server_pack_upx", SERVER)
    assert spec and spec.loader
    server = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = server
    spec.loader.exec_module(server)
    info = server.pe_info(path=path, carved_path=carved)
    assert info["read_path"] == carved
    assert ("KERNEL32.DLL", "CreateFileW") in {(r["dll"], r["function"]) for r in info["imports"]}


def test_the_line_states_the_program_and_its_carved_path(tmp_path: Path) -> None:
    path = _sample(tmp_path, su.build().data)
    result = _pack(path, tmp_path)
    line = _line(result)
    child = _entry(result).structured["child"]
    assert "UPX unpacking: UPX NRV2B_LE32 (2), filter 0x26: " in line
    assert f"the unpacked program is file carved_path {child['carved_path']}" in line
    assert "both adler32 checksums matched" in line
    assert f"sha256 {child['sha256']}" in line


def test_the_line_takes_only_the_room_the_other_lines_leave(tmp_path: Path) -> None:
    path = _sample(tmp_path, su.build().data)
    # The function index takes what the rendered pack leaves, passes included,
    # as it does beside every pass, and the other passes share the leftover room:
    # the lines that are not passes are what this one never takes from.
    entries = [
        e
        for e in pack_entries(_pack(path, tmp_path).entries)
        if e.tool not in (triage_pack.INDEX_TOOL, *triage_pack.PASS_TOOLS) or e.tool == upx.TOOL
    ]
    others = [e for e in entries if e.tool != upx.TOOL]
    unpack = next(e for e in entries if e.tool == upx.TOOL)
    whole = render_pack(others, 0)
    child = unpack.structured["child"]["carved_path"]
    # With room for the other lines and the short form only, the short form shows.
    room = (
        len(whole)
        + 1
        + len(f"[{unpack.id}] UPX unpacking: ")
        + len(f"the unpacked program is file carved_path {child}")
    )
    fitted = render_pack(entries, room)
    assert fitted.startswith(whole)
    assert fitted.endswith(f"the unpacked program is file carved_path {child}")
    # With room for the other lines alone, they stay as they are.
    tight = render_pack(entries, len(whole) + 5)
    assert tight.split("\n")[: len(whole.split("\n"))] == whole.split("\n")


def test_no_job_directory_is_one_entry_saying_so(tmp_path: Path) -> None:
    path = _sample(tmp_path, su.build().data)
    result = _pack(path, tmp_path, job="")
    entry = _entry(result)
    assert not entry.ok
    assert _line(result).endswith(f"UPX unpacking: no: {triage_pack.UPX_NO_JOB}")


def _renamed(data: bytes) -> bytes:
    """``data`` with its three section names changed to ones no packer signature lists."""
    out = bytearray(data)
    table = su.PE_OFFSET + 24 + 224
    for index, name in enumerate((b"abc0", b"abc1", b".res")):
        out[table + 40 * index : table + 40 * index + 8] = name.ljust(8, b"\0")
    return bytes(out)


def test_a_true_pack_header_runs_the_unpacking_when_the_sections_are_renamed(
    tmp_path: Path,
) -> None:
    path = _sample(tmp_path, _renamed(su.build().data))
    result = _pack(path, tmp_path)
    pe = next(e for e in result.entries if e.tool == "pe_info")
    assert pe.structured["packer_signatures"] == []
    entry = _entry(result)
    assert entry.ok and entry.structured["unpacked"] == "yes"


def test_a_upx_named_file_with_no_header_gets_its_no_line(tmp_path: Path) -> None:
    packed = su.build()
    data = bytearray(packed.data)
    data[packed.header_offset : packed.header_offset + 4] = b"\0\0\0\0"
    result = _pack(_sample(tmp_path, bytes(data)), tmp_path)
    assert _line(result).endswith(f"UPX unpacking: {upx.NO_HEADER}")


def test_a_sample_the_packer_reader_does_not_name_upx_gets_no_step(tmp_path: Path) -> None:
    path = _sample(tmp_path, SyntheticPE().build(), "plain.exe")
    assert upx.TOOL not in [e.tool for e in _pack(path, tmp_path).entries]


def test_a_damaged_file_is_a_failed_pass_that_does_not_degrade_the_run(tmp_path: Path) -> None:
    packed = su.build()
    data = bytearray(packed.data)
    data[packed.header_offset + 32 + 7] ^= 0x01
    result = _pack(_sample(tmp_path, bytes(data)), tmp_path)
    assert not _entry(result).ok
    assert "UPX unpacking: no: the pass failed: the compressed data's adler32 is" in _line(result)
    assert failure_reason(upx.TOOL) in result.degradation_reasons
    assert not degrades_run(failure_reason(upx.TOOL))
