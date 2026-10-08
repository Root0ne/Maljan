"""The analysis server unpacks a UPX-packed PE beside the carved files, confined as usual.

The packed file is synthetic (``synthetic_upx``): a program the test wrote,
packed by encoders written for the tests. The unpacked program is read back by
the other file tools through the ``carved_path`` the answer gives.
"""

from __future__ import annotations

import importlib.util
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from maljan.tools import binary, upx
from tests.unit.tools import synthetic_upx as su

ROOT = Path(__file__).resolve().parents[3]
SERVER = ROOT / "services" / "analysis-mcp" / "server.py"


@pytest.fixture(scope="module")
def server() -> Any:
    spec = importlib.util.spec_from_file_location("analysis_mcp_server_upx", SERVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _the_test_s_own_directory_is_a_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MALJAN_SAMPLE_ROOTS", str(tmp_path / "samples"))
    monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))


def _sample(tmp_path: Path, data: bytes, name: str = "packed.exe") -> str:
    folder = tmp_path / "samples"
    folder.mkdir(exist_ok=True)
    target = folder / name
    target.write_bytes(data)
    return str(target)


def test_the_unpacked_program_lands_beside_the_carved_files(server: Any, tmp_path: Path) -> None:
    packed = su.build()
    path = _sample(tmp_path, packed.data)
    answer = server.unpack_upx(path=path)
    child = answer["child"]
    written = Path(child["carved_path"])
    digest = server._digest_of(Path(path))
    assert written.parent == server._carved_tree(digest)
    assert written.name == binary.carved_file_name(upx.UNPACKED_LABEL, child["sha256"])
    assert written.name.startswith("upx-unpacked_")
    assert stat.S_IMODE(written.stat().st_mode) == 0o600
    assert stat.S_IMODE(written.parent.stat().st_mode) == 0o700
    assert answer["checksums"]["unpacked"]["matched"] is True


def test_every_file_tool_reads_the_unpacked_program_by_its_carved_path(
    server: Any, tmp_path: Path
) -> None:
    packed = su.build()
    path = _sample(tmp_path, packed.data)
    carved = server.unpack_upx(path=path)["child"]["carved_path"]
    info = server.pe_info(path=path, carved_path=carved)
    assert info["read_path"] == carved
    assert [s["name"] for s in info["sections"]][:3] == [".text", ".rdata", ".data"]
    names = {(row["dll"], row["function"]) for row in info["imports"]}
    assert ("KERNEL32.DLL", "CreateFileW") in names and ("WS2_32.dll", "send") in names
    assert server.hashes(path=path, carved_path=carved)["read_path"] == carved
    assert "error" not in server.strings(path=path, carved_path=carved)
    # The label alone names it too, as it names a carved payload.
    assert server.hashes(path=path, carved_path=upx.UNPACKED_LABEL)["read_path"] == carved


def test_a_file_that_is_not_upx_packed_answers_no(server: Any, tmp_path: Path) -> None:
    from tests.unit.tools.synthetic_pe import SyntheticPE

    path = _sample(tmp_path, SyntheticPE().build(), "plain.exe")
    assert server.unpack_upx(path=path) == {"unpacked": upx.NO_HEADER}


def test_a_damaged_file_is_an_error_with_the_tool_s_remedy(server: Any, tmp_path: Path) -> None:
    packed = su.build()
    data = bytearray(packed.data)
    data[packed.header_offset + 40] ^= 0x10
    answer = server.unpack_upx(path=_sample(tmp_path, bytes(data)))
    assert answer["error"]["code"] == "tool_failed"
    assert answer["error"]["remediation"] == upx.REMEDIATION
    assert answer["tool"] == upx.TOOL


def test_a_path_outside_the_roots_is_refused(server: Any, tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere.exe"
    outside.write_bytes(su.build().data)
    assert server.unpack_upx(path=str(outside))["error"]["code"] == "path_outside_roots"


def test_a_carved_path_outside_this_sample_s_tree_is_refused(server: Any, tmp_path: Path) -> None:
    path = _sample(tmp_path, su.build().data)
    answer = server.unpack_upx(path=path, carved_path="/etc/passwd")
    assert answer["error"]["code"] == "path_outside_roots"
    assert answer["error"]["remediation"] == server.CARVED_REMEDIATION


def test_the_capabilities_answer_states_what_is_read(server: Any) -> None:
    cell = next(c for c in server.capabilities()["tools"] if c["name"] == upx.TOOL)
    assert cell["available"] is True
    assert cell["facts"] == upx.CAPABILITY_FACTS
    for name, _kind, _width in upx.METHODS.values():
        assert name in cell["facts"]
    doc = " ".join((server.unpack_upx.__doc__ or "").split())
    assert server.CARVED_NOTE.split()[0] in doc
    assert "upload cap" in doc
