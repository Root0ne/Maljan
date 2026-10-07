"""The analysis server runs the byte transforms a model names, confined like every file tool.

The sample is synthetic: a PE written by the test (``synthetic_pe``) holding a
text the test encrypted with a key the test chose.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

from maljan.tools import transforms
from tests.unit.tools.synthetic_pe import SyntheticPE
from tests.unit.tools.test_byte_transforms import PLAIN, _rc4_reference

ROOT = Path(__file__).resolve().parents[3]
SERVER = ROOT / "services" / "analysis-mcp" / "server.py"
KEY = b"server-key"


@pytest.fixture(scope="module")
def server() -> Any:
    spec = importlib.util.spec_from_file_location("analysis_mcp_server_transforms", SERVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _the_test_s_own_directory_is_a_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MALJAN_SAMPLE_ROOTS", str(tmp_path / "samples"))
    monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))


def _sample(tmp_path: Path) -> tuple[str, int]:
    image = SyntheticPE()
    image.put("rdata", 0x20, KEY)
    at = image.put("data", 0x80, _rc4_reference(KEY, PLAIN))
    folder = tmp_path / "samples"
    folder.mkdir(exist_ok=True)
    target = folder / "s.exe"
    target.write_bytes(image.build())
    return str(target), at


def test_a_range_by_address_with_a_key_in_the_file(server: Any, tmp_path: Path) -> None:
    path, at = _sample(tmp_path)
    answer = server.transform_bytes(
        path=path,
        rva=hex(at),
        length=len(PLAIN),
        steps=[{"op": "rc4", "key": {"rva": "0x2020", "length": len(KEY)}}],
    )
    assert answer["output"]["sha256"] == hashlib.sha256(PLAIN).hexdigest()
    assert answer["input"]["section"] == ".data"
    assert answer["steps"][0]["key"]["read"] == KEY.hex()


def test_the_absence_words_read_as_absent(server: Any, tmp_path: Path) -> None:
    path, at = _sample(tmp_path)
    answer = server.transform_bytes(path=path, offset="null", rva=hex(at), va="None", length=4)
    assert answer["input"]["rva"] == hex(at)


def test_a_path_outside_the_roots_is_refused(server: Any, tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere.bin"
    outside.write_bytes(PLAIN)
    answer = server.transform_bytes(path=str(outside), offset=0)
    assert answer["error"]["code"] == "path_outside_roots"


def test_a_carved_path_outside_this_sample_s_tree_is_refused(server: Any, tmp_path: Path) -> None:
    path, _at = _sample(tmp_path)
    answer = server.transform_bytes(path=path, carved_path="/etc/passwd", offset=0)
    assert answer["error"]["code"] == "path_outside_roots"
    assert answer["error"]["remediation"] == server.CARVED_REMEDIATION


def test_an_error_names_the_step(server: Any, tmp_path: Path) -> None:
    path, at = _sample(tmp_path)
    answer = server.transform_bytes(path=path, rva=hex(at), steps=[{"op": "rot13"}])
    assert answer["error"]["code"] == "bad_argument"
    assert answer["error"]["message"].startswith("step 1: unknown op")
    assert answer["error"]["remediation"] == transforms.REMEDIATION


def test_the_capabilities_answer_states_the_operations(server: Any) -> None:
    cell = next(c for c in server.capabilities()["tools"] if c["name"] == transforms.TOOL)
    assert cell["available"] is True
    assert cell["facts"] == transforms.CAPABILITY_FACTS
    for op in transforms.OPERATIONS:
        assert op in cell["facts"]
    for op in transforms.OPERATIONS:
        assert f"``{op}``" in (server.transform_bytes.__doc__ or "")
