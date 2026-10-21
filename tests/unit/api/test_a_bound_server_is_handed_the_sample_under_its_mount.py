"""A tool server that declares a ``sample_mount`` is handed the sample under it, whoever binds it.

A static provider's server was copied the sample and handed the copy under
its declared mount; a server an agent is bound to, with the same declaration,
was handed the worker's own path, which it cannot open. The worker now copies
the sample for every enabled server that declares a mount, the agent bound to
it is held to that path, and a server the sample was staged to keeps the path
its own staging answered. A server that declares no mount gets nothing new.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.worker import analysis_worker, sample_files
from maljan.agents.composition import _mounted
from maljan.core.config import MCPServerConfig
from maljan.core.settings_overrides import build_settings
from maljan.providers.registry import mirror_work_dirs

SHA = "b" * 64


def _server(mount: str = "", work_dir: str = "", enabled: bool = True) -> dict[str, Any]:
    return MCPServerConfig(
        transport="http",
        enabled=enabled,
        url="http://analyser.invalid:9000/mcp",
        sample_mount=mount,
        work_dir=work_dir,
        agents=["static"],
    ).model_dump(mode="json")


class _Container:
    def __init__(self, settings: Any, analysts: tuple[str, ...] = ("static",)) -> None:
        self.config = settings
        self._analysts = list(analysts)

    def analyst_keys(self) -> list[str]:
        return list(self._analysts)


@pytest.fixture
def samples(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path / "samples"))
    monkeypatch.setattr(sample_files.settings, "upload_temp_dir", str(tmp_path / "uploads"))
    monkeypatch.setattr("maljan.tools.roots.add_sample_root", lambda _p: None)
    return tmp_path / "samples"


def _mirror(
    settings: Any,
    tmp: Path,
    already: tuple[Path, ...] = (),
    analysts: tuple[str, ...] = ("static",),
) -> Any:
    source = tmp / "download.bin"
    source.write_bytes(b"\x00demo")
    return analysis_worker.mirror_server_samples(
        _Container(settings, analysts),
        temp_path=str(source),
        sha256=SHA,
        extension=".bin",
        copy_fn=sample_files.private_copy,
        already=already,
    )


def test_a_server_that_declares_a_mount_is_copied_the_sample_under_it(
    samples: Path, tmp_path: Path
) -> None:
    settings = build_settings(
        {
            "mcp.servers": {
                "bound": _server(mount="/srv/in", work_dir="bound-work"),
                "plain": _server(),
                "off": _server(mount="/srv/off", enabled=False),
            }
        }
    )
    hosts, paths = _mirror(settings, tmp_path)
    assert paths == {"bound": f"/srv/in/bound-work/{SHA}.bin"}
    assert hosts == [(samples / "bound-work" / f"{SHA}.bin").resolve()]
    assert hosts[0].read_bytes() == b"\x00demo"


def test_a_copy_already_written_for_a_provider_is_not_written_twice(
    samples: Path, tmp_path: Path
) -> None:
    settings = build_settings({"mcp.servers": {"bound": _server(mount="/srv/in")}})
    first, _ = _mirror(settings, tmp_path)
    again, paths = _mirror(settings, tmp_path, already=tuple(first))
    assert again == []
    assert paths == {"bound": f"/srv/in/.work/{SHA}.bin"}


def test_its_directory_is_one_the_worker_sweeps() -> None:
    settings = build_settings({"mcp.servers": {"bound": _server(mount="/in", work_dir="bw")}})
    assert "bw" in mirror_work_dirs(settings)
    off = build_settings(
        {"mcp.servers": {"bound": _server(mount="/in", work_dir="bw", enabled=False)}}
    )
    assert "bw" not in mirror_work_dirs(off)
    assert "bw" in mirror_work_dirs(off, selected_only=False)


class _Tool:
    def __init__(self, server: str) -> None:
        self.name = f"t_{server}"
        self.metadata = {"maljan_server": server}


def test_the_bound_agent_is_held_to_the_mounted_path_and_staging_wins() -> None:
    container = type(
        "C", (), {"server_sample_paths": {"bound": "/srv/in/.work/x", "other": "/o"}}
    )()
    tools = [_Tool("bound"), _Tool("staged"), _Tool("plain")]
    out = _mounted(container, tools, {"staged": "/staging/x"})
    assert out == {"staged": "/staging/x", "bound": "/srv/in/.work/x"}
    # A server the sample was staged to keeps its staging's path.
    out = _mounted(container, [_Tool("bound")], {"bound": "/staging/y"})
    assert out == {"bound": "/staging/y"}


def test_with_no_mounted_server_nothing_changes() -> None:
    container = type("C", (), {"server_sample_paths": {}})()
    staged = {"s": "/p"}
    assert _mounted(container, [_Tool("s")], staged) is staged


def test_a_server_no_agent_of_the_job_binds_is_not_copied(samples: Path, tmp_path: Path) -> None:
    # A team whose only analyst is ``dynamic``: nothing it runs binds the server.
    settings = build_settings(
        {
            "mcp.servers": {"bound": _server(mount="/srv/in")},
            "agents.profiles": {
                "dyn": {
                    "label": "Dyn",
                    "stages": [
                        {"key": "a", "kind": "analysis", "agents": ["dynamic"]},
                        {"key": "verdict", "kind": "verdict", "agents": ["judge"]},
                        {"key": "report", "kind": "report", "agents": ["reporter"]},
                    ],
                }
            },
            "agents.profile": "dyn",
        }
    )
    hosts, paths = _mirror(settings, tmp_path, analysts=("dynamic",))
    assert (hosts, paths) == ([], {})


def test_the_saved_ledger_is_held_to_the_budget_the_run_ran_with() -> None:
    summary = {"settings_snapshot": {"reporting.evidence_budget_bytes": 4096}}
    assert analysis_worker.evidence_budget_of(summary) == 4096
    job = build_settings({"reporting.evidence_budget_bytes": 2048})
    assert analysis_worker.evidence_budget_of({"settings_snapshot": {}}, job) == 2048
    assert analysis_worker.evidence_budget_of(None) == 0
