"""The capture script freezes what the live code builds, and gzips a golden too large for text.

The two prompt fixtures under ``tests/fixtures/prompts`` were written by the
capture script and read by nothing, so they drifted from the prompts the
analysts are really sent. They are compared here with the script's own
builder: a prompt change now comes with its recapture.
"""

from __future__ import annotations

import gzip
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from tests.golden_fixtures import golden_stems, read_golden

ROOT = Path(__file__).resolve().parents[2]
PROMPTS = ROOT / "tests" / "fixtures" / "prompts"


@pytest.fixture(scope="module")
def capture() -> ModuleType:
    path = ROOT / "scripts" / "goldens" / "capture_provider_goldens.py"
    spec = importlib.util.spec_from_file_location("capture_provider_goldens", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_prompt_fixtures_are_the_prompts_the_builder_makes(capture: ModuleType) -> None:
    static, dynamic = capture.build_prompts()
    frozen = {
        "static_isr_system_ghidra.txt": static,
        "dynamic_system_cape2.txt": dynamic,
    }
    for name, built in frozen.items():
        stored = (PROMPTS / name).read_text(encoding="utf-8")
        assert stored == built.rstrip("\n") + "\n", (
            f"{name} differs from the live prompt; "
            "re-run scripts/goldens/capture_provider_goldens.py"
        )


def test_a_golden_under_the_limit_is_plain_text(capture: ModuleType, tmp_path: Path) -> None:
    written = capture.write_golden(tmp_path, "small", {"rows": [1, 2]})

    assert written.name == "small.json"
    assert golden_stems(tmp_path) == ["small"]
    assert read_golden(tmp_path, "small") == {"rows": [1, 2]}


def test_a_golden_over_the_limit_is_gzipped_and_reads_the_same(
    capture: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(capture, "COMPRESS_ABOVE_BYTES", 64)
    payload = {"rows": ["HKEY_CURRENT_USER\\Software\\Example"] * 20}
    (tmp_path / "large.json").write_text("{}", encoding="utf-8")

    written = capture.write_golden(tmp_path, "large", payload)

    assert written.name == "large.json.gz"
    assert not (tmp_path / "large.json").exists()
    assert golden_stems(tmp_path) == ["large"]
    assert read_golden(tmp_path, "large") == payload
    first = written.read_bytes()
    assert json.loads(gzip.decompress(first).decode("utf-8")) == payload
    assert capture.write_golden(tmp_path, "large", payload).read_bytes() == first


def test_a_golden_back_under_the_limit_leaves_no_gzip_behind(
    capture: ModuleType, tmp_path: Path
) -> None:
    (tmp_path / "shrunk.json.gz").write_bytes(gzip.compress(b"{}"))

    capture.write_golden(tmp_path, "shrunk", {"rows": []})

    assert sorted(p.name for p in tmp_path.iterdir()) == ["shrunk.json"]


def test_every_committed_sandbox_golden_is_under_the_limit_or_gzipped(
    capture: ModuleType,
) -> None:
    directory = ROOT / "tests" / "fixtures" / "golden" / "sandbox_tools"
    too_large = [
        p.name for p in directory.glob("*.json") if p.stat().st_size > capture.COMPRESS_ABOVE_BYTES
    ]
    assert too_large == []
