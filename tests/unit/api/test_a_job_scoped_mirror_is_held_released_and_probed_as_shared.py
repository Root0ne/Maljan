"""Job-scoped mirror copies are written, held and released per job; a probe says when shared."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from app.services import settings_probes
from app.worker import analysis_worker, sample_files
from maljan.core.config import MCPServerConfig
from maljan.core.settings_overrides import build_settings
from maljan.providers import server_probe
from maljan.providers.registry import static_provider_class

SHA = "d" * 64
JOB_A = "11111111-1111-4111-8111-111111111111"
JOB_B = "22222222-2222-4222-8222-222222222222"


class _Container:
    def __init__(self, settings: Any) -> None:
        self.config = settings

    def get_static_provider(self, provider_id: str) -> Any:
        return static_provider_class(provider_id).from_settings(self.config)

    def analyst_keys(self) -> list[str]:
        return ["static"]


@pytest.fixture
def samples(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path / "samples"))
    monkeypatch.setattr(sample_files.settings, "upload_temp_dir", str(tmp_path / "uploads"))
    monkeypatch.setattr("maljan.tools.roots.add_sample_root", lambda _p: None)
    return tmp_path / "samples"


def _source(tmp: Path) -> Path:
    source = tmp / "download.exe"
    source.write_bytes(b"MZ")
    return source


def _static(settings: Any, tmp: Path, job: str, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr(analysis_worker, "profile_static_providers", lambda _c: ["ghidra"])
    return analysis_worker.mirror_static_samples(
        _Container(settings),
        temp_path=str(_source(tmp)),
        sha256=SHA,
        extension=".exe",
        copy_fn=lambda src, dest: sample_files.held_copy(src, dest, job_id=job),
        job_id=job,
    )


def _server(**over: Any) -> dict[str, Any]:
    return MCPServerConfig(
        transport="http",
        enabled=True,
        url="http://analyser.invalid:9000/mcp",
        sample_mount="/srv/in",
        work_dir="bound-work",
        agents=["static"],
        **over,
    ).model_dump(mode="json")


def test_static_copies_are_named_by_the_job_and_released_one_at_a_time(
    samples: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = build_settings({})
    hosts_a, paths_a = _static(settings, tmp_path, JOB_A, monkeypatch)
    hosts_b, paths_b = _static(settings, tmp_path, JOB_B, monkeypatch)

    assert hosts_a[0].name == f"{SHA}.{JOB_A}.exe" and hosts_b[0].name == f"{SHA}.{JOB_B}.exe"
    assert paths_a["ghidra"].endswith(f"/{SHA}.{JOB_A}.exe")
    assert paths_b["ghidra"].endswith(f"/{SHA}.{JOB_B}.exe")
    assert hosts_a[0].read_bytes() == b"MZ"
    # Each job holds and releases its own copy: one job ending leaves the other's.
    assert sample_files.release_copy(hosts_a[0], job_id=JOB_A) is True
    assert not hosts_a[0].exists() and hosts_b[0].exists()
    assert sample_files.release_copy(hosts_b[0], job_id=JOB_B) is True
    assert not hosts_b[0].exists()


def test_server_copies_are_job_scoped_and_not_written_twice(samples: Path, tmp_path: Path) -> None:
    settings = build_settings({"mcp.servers": {"bound": _server()}})

    def mirror(job: str, already: tuple[Path, ...] = ()) -> Any:
        return analysis_worker.mirror_server_samples(
            _Container(settings),
            temp_path=str(_source(tmp_path)),
            sha256=SHA,
            extension=".exe",
            copy_fn=lambda src, dest: sample_files.held_copy(src, dest, job_id=job),
            job_id=job,
            already=already,
        )

    hosts_a, paths_a = mirror(JOB_A)
    hosts_b, paths_b = mirror(JOB_B)

    assert paths_a == {"bound": f"/srv/in/bound-work/{SHA}.{JOB_A}.exe"}
    assert paths_b == {"bound": f"/srv/in/bound-work/{SHA}.{JOB_B}.exe"}
    assert hosts_a != hosts_b
    # A copy already written for the same job (by a static provider) is not written again.
    again, paths = mirror(JOB_A, already=tuple(hosts_a))
    assert again == [] and paths == paths_a
    assert sample_files.release_copy(hosts_a[0], job_id=JOB_A) is True
    assert hosts_b[0].exists()


@pytest.mark.parametrize(
    ("transport", "url", "remote"),
    [
        ("http", "http://analyser.invalid/mcp", True),
        ("sse", "http://analyser.invalid/sse", True),
        ("streamable-http", "http://analyser.invalid/mcp", True),
        ("stdio", "", False),
    ],
)
def test_a_probe_passes_remote_for_a_server_at_an_address(
    transport: str, url: str, remote: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[bool] = []

    async def inspect(*_a: Any, **_k: Any) -> Any:
        return server_probe.Inspection(names=["t"], capabilities=None, definitions=[{"name": "t"}])

    def proposals(*_a: Any, **kwargs: Any) -> None:
        seen.append(kwargs["remote"])

    monkeypatch.setattr(settings_probes, "_inspect", inspect)
    monkeypatch.setattr(settings_probes, "_proposals", proposals)
    entry: dict[str, Any] = {"transport": transport, "agents": ["static"]}
    if transport == "stdio":
        entry["command"] = "analyser"
    else:
        entry["url"] = url

    result = asyncio.run(settings_probes.probe_mcp({"name": "probed", "entry": entry}))

    assert result.ok
    assert seen == [remote]
