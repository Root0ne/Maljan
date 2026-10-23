"""A file of the job's artefact store reaches a server with a ``sample_mount`` as the sample does.

The worker copies it under the server's ``work_dir`` of the samples
directory, named by its digest, the job and its name's suffix, holds the copy
for the job and releases it with the job's other mirrors; the server is handed
the copy under its mount. A server that declares no mount is handed nothing
here.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from app.worker import analysis_worker, sample_files
from maljan.core.config import MCPServerConfig
from maljan.core.settings_overrides import build_settings

JOB = "8d7f1c1e-0000-4000-8000-000000000001"
BLOB = b"\x00carved payload"
SHA = hashlib.sha256(BLOB).hexdigest()


def _server(mount: str = "", work_dir: str = "") -> dict[str, Any]:
    return MCPServerConfig(
        transport="http",
        enabled=True,
        url="http://scanner.invalid:9000/mcp",
        sample_mount=mount,
        work_dir=work_dir,
    ).model_dump(mode="json")


class _Container:
    def __init__(self, settings: Any) -> None:
        self.config = settings


@pytest.fixture
def samples(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path / "samples"))
    monkeypatch.setattr(sample_files.settings, "upload_temp_dir", str(tmp_path / "uploads"))
    return tmp_path / "samples"


def test_the_copy_is_held_by_the_job_and_released_with_its_mirrors(
    samples: Path, tmp_path: Path
) -> None:
    settings = build_settings(
        {"mcp.servers": {"mounted": _server(mount="/srv/in", work_dir="scan-work")}}
    )
    source = tmp_path / "store" / "inner.js"
    source.parent.mkdir()
    source.write_bytes(BLOB)
    held: list[Path] = []
    path = analysis_worker.place_server_file(
        _Container(settings), "mounted", source, SHA, "inner.js", job_id=JOB, held=held
    )
    name = sample_files.copy_name(SHA, ".js", analysis_worker.canonical_job_id(JOB))
    assert path == f"/srv/in/scan-work/{name}"
    (copy,) = held
    assert copy.name == name and copy.read_bytes() == BLOB
    assert copy.parent.resolve() == (samples / "scan-work").resolve()
    for each in held:
        sample_files.release_copy(each, job_id=analysis_worker.canonical_job_id(JOB))
    assert not copy.exists()


def test_a_server_with_no_mount_is_handed_nothing_here(samples: Path, tmp_path: Path) -> None:
    settings = build_settings({"mcp.servers": {"plain": _server()}})
    source = tmp_path / "x.bin"
    source.write_bytes(BLOB)
    held: list[Path] = []
    assert (
        analysis_worker.place_server_file(
            _Container(settings), "plain", source, SHA, "x.bin", job_id=JOB, held=held
        )
        is None
    )
    assert (
        analysis_worker.place_server_file(
            _Container(settings), "missing", source, SHA, "x.bin", job_id=JOB, held=held
        )
        is None
    )
    assert held == []
