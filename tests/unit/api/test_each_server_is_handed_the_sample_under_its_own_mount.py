"""Each server is handed the job's sample under its own declared mount.

The worker built every containerised server's sample path from one setting
named for one tool, so a second containerised server mounted elsewhere was
handed a path under the first one's mount and every open answered "file not
found". The path now comes from each server's declared ``sample_mount``
(empty: the server reads the worker's own filesystem), through
``providers.base.path_in_server``, and the directories the worker sweeps,
removes from and exports come from the configured providers and servers.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import pytest

from app.worker import analysis_worker, sample_files
from maljan.core.config import MCPServerConfig
from maljan.core.settings_overrides import build_settings
from maljan.providers.base import DEFAULT_WORK_DIR, MirrorSpec, path_in_server
from maljan.providers.registry import mirror_work_dirs, static_provider_class

SHA = "a" * 64


def _settings(**overrides: Any) -> Any:
    return build_settings(overrides)


def _remote(
    mount: str = "", work_dir: str = "", transport: str = "http", enabled: bool = True
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "transport": transport,
        "enabled": enabled,
        "url": "http://analyser.invalid:9000/mcp" if transport != "stdio" else None,
        "command": "analyser" if transport == "stdio" else "",
        "sample_mount": mount,
        "work_dir": work_dir,
    }
    return MCPServerConfig.model_validate(
        {k: v for k, v in entry.items() if v is not None}
    ).model_dump(mode="json")


class _Container:
    def __init__(self, settings: Any) -> None:
        self.config = settings

    def get_static_provider(self, provider_id: str) -> Any:
        return static_provider_class(provider_id).from_settings(self.config)


@pytest.fixture
def samples(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path / "samples"))
    monkeypatch.setattr(sample_files.settings, "upload_temp_dir", str(tmp_path / "uploads"))
    return tmp_path / "samples"


def _mirror(settings: Any, ids: list[str], monkeypatch: pytest.MonkeyPatch, tmp: Path) -> Any:
    monkeypatch.setattr(analysis_worker, "profile_static_providers", lambda _c: ids)
    source = tmp / "download.exe"
    source.write_bytes(b"MZ")
    return analysis_worker.mirror_static_samples(
        _Container(settings),
        temp_path=str(source),
        sha256=SHA,
        extension=".exe",
        copy_fn=sample_files.private_copy,
    )


class TestTwoContainerisedServersWithDifferentMounts:
    def test_each_receives_its_own_path(
        self, samples: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = _settings(
            **{
                "static.ghidra.sample_mount": "/mnt/ghidra",
                "static.generic.server": "mine",
                "mcp.servers": {"mine": _remote(mount="/srv/in", work_dir="mine-work")},
            }
        )
        _hosts, paths = _mirror(settings, ["ghidra", "generic_mcp"], monkeypatch, tmp_path)
        assert paths == {
            "ghidra": f"/mnt/ghidra/.work/{SHA}.exe",
            "generic_mcp": f"/srv/in/mine-work/{SHA}.exe",
        }

    def test_two_servers_sharing_a_directory_still_see_it_at_their_own_mounts(
        self, samples: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = _settings(
            **{
                "static.generic.server": "mine",
                "mcp.servers": {"mine": _remote(mount="/srv/in")},
            }
        )
        hosts, paths = _mirror(settings, ["ghidra", "generic_mcp"], monkeypatch, tmp_path)
        assert len(hosts) == 1, "one host copy for one directory"
        assert paths["ghidra"] == f"/data/samples/.work/{SHA}.exe"
        assert paths["generic_mcp"] == f"/srv/in/.work/{SHA}.exe"

    def test_the_copy_lands_where_the_path_says(
        self, samples: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = _settings(
            **{
                "static.generic.server": "mine",
                "mcp.servers": {"mine": _remote(mount="/srv/in", work_dir="mine-work")},
            }
        )
        hosts, _paths = _mirror(settings, ["generic_mcp"], monkeypatch, tmp_path)
        assert hosts == [(samples / "mine-work" / f"{SHA}.exe").resolve()]
        assert hosts[0].read_bytes() == b"MZ"


class TestTheMountAServerDeclares:
    def test_a_remote_server_with_no_mount_keeps_the_compose_mount(self) -> None:
        settings = _settings(
            **{"static.generic.server": "mine", "mcp.servers": {"mine": _remote()}}
        )
        spec = static_provider_class("generic_mcp").from_settings(settings).mirror_spec()
        assert spec == MirrorSpec(work_subdir=DEFAULT_WORK_DIR, container_prefix="/data/samples")

    def test_a_stdio_server_with_no_mount_reads_the_worker_s_filesystem(self) -> None:
        settings = _settings(
            **{
                "static.generic.server": "mine",
                "mcp.servers": {"mine": _remote(transport="stdio")},
            }
        )
        spec = static_provider_class("generic_mcp").from_settings(settings).mirror_spec()
        assert spec.container_prefix == ""

    def test_a_stdio_server_that_declares_a_mount_is_handed_the_path_under_it(self) -> None:
        settings = _settings(
            **{
                "static.generic.server": "mine",
                "mcp.servers": {"mine": _remote(mount="/in", transport="stdio")},
            }
        )
        spec = static_provider_class("generic_mcp").from_settings(settings).mirror_spec()
        assert spec.container_prefix == "/in"

    def test_ghidra_s_shipped_mount_is_the_compose_mount(self) -> None:
        spec = static_provider_class("ghidra").from_settings(_settings()).mirror_spec()
        assert spec == MirrorSpec(work_subdir=".work", container_prefix="/data/samples")

    def test_ghidra_with_its_mount_emptied_is_handed_the_host_path(self) -> None:
        settings = _settings(**{"static.ghidra.sample_mount": ""})
        spec = static_provider_class("ghidra").from_settings(settings).mirror_spec()
        assert spec.container_prefix == ""

    def test_r2_with_a_declared_mount_is_handed_the_path_under_it(self) -> None:
        settings = _settings(**{"static.r2.sample_mount": "/r2"})
        spec = static_provider_class("r2").from_settings(settings).mirror_spec()
        assert spec == MirrorSpec(work_subdir="r2-work", container_prefix="/r2")


class TestThePathInAServer:
    def test_an_empty_mount_is_the_host_path(self) -> None:
        spec = MirrorSpec(work_subdir="w", container_prefix="")
        assert path_in_server(spec, "/host/samples/w/x.exe") == "/host/samples/w/x.exe"

    def test_a_mount_takes_the_copy_s_directory_and_name(self) -> None:
        spec = MirrorSpec(work_subdir="w", container_prefix="/in/")
        assert path_in_server(spec, Path("/host/samples/w/x.exe")) == "/in/w/x.exe"

    def test_the_root_as_a_mount_is_written_once(self) -> None:
        spec = MirrorSpec(work_subdir="w", container_prefix="/")
        assert path_in_server(spec, "/host/samples/w/x.exe") == "/w/x.exe"


def _generic(server: dict[str, Any], **more: Any) -> Any:
    return _settings(
        **{
            "static.provider": "generic_mcp",
            "static.generic.server": "mine",
            "mcp.servers": {"mine": server},
            **more,
        }
    )


class TestTheDirectoriesComeFromTheConfiguration:
    def test_every_provider_s_shipped_directory_is_the_worker_s_own(self) -> None:
        assert set(sample_files.shipped_mirror_dirs()) == {".work", "r2-work"}

    def test_the_selected_switched_on_provider_s_directory_counts(self) -> None:
        settings = _generic(_remote(work_dir="mine-work"))
        assert mirror_work_dirs(settings) == ("mine-work",)

    def test_r2_s_own_mirror_directory_counts_when_r2_is_selected_and_on(self) -> None:
        settings = _settings(
            **{
                "static.provider": "r2",
                "static.r2.enabled": True,
                "static.r2.work_dir": "r2-elsewhere",
            }
        )
        assert mirror_work_dirs(settings) == ("r2-elsewhere",)

    def test_a_switched_off_provider_counts_for_nothing(self) -> None:
        assert mirror_work_dirs(_settings()) == ()  # Ghidra, shipped switched off
        assert mirror_work_dirs(_generic(_remote(work_dir="mine-work", enabled=False))) == ()

    def test_a_server_no_provider_copies_into_counts_for_nothing(self) -> None:
        settings = _settings(**{"mcp.servers": {"mine": _remote(work_dir="mine-work")}})
        assert "mine-work" not in mirror_work_dirs(settings)
        assert "mine-work" not in mirror_work_dirs(settings, selected_only=False)

    def test_a_provider_that_fails_to_build_hides_none_of_the_others(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cls = static_provider_class("generic_mcp")

        def broken(_cfg: Any) -> Any:
            raise RuntimeError("no")

        monkeypatch.setattr(cls, "from_settings", classmethod(lambda c, cfg: broken(cfg)))
        assert {".work", "r2-work"} <= set(mirror_work_dirs(_settings(), selected_only=False))

    def test_the_sweep_reaches_the_selected_provider_s_directory(self, samples: Path) -> None:
        settings = _generic(_remote(work_dir="mine-work"))
        stale = sample_files.work_dir("mine-work") / f"{SHA}.exe"
        stale.write_bytes(b"MZ")
        old = time.time() - 100_000
        os.utime(stale, (old, old))
        assert sample_files.sweep(max_age_s=86_400.0, subdirs=mirror_work_dirs(settings)) == 1
        assert not stale.exists()

    def test_a_delete_reaches_the_selected_provider_s_directory(self, samples: Path) -> None:
        settings = _generic(_remote(work_dir="mine-work"))
        copy = sample_files.work_dir("mine-work") / f"{SHA}.exe"
        copy.write_bytes(b"MZ")
        assert sample_files.remove_for_sha(SHA, subdirs=mirror_work_dirs(settings)) == [copy]

    def test_the_selected_provider_s_directory_is_a_sample_root(
        self, samples: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        added: list[Path] = []
        monkeypatch.setattr("maljan.tools.roots.add_sample_root", added.append)
        sample_files.export_sample_roots(mirror_work_dirs(_generic(_remote(work_dir="mine-work"))))
        assert (samples / "mine-work").resolve() in added

    def test_with_no_settings_given_the_shipped_directories_are_swept(self, samples: Path) -> None:
        assert {p.name for p in sample_files.work_dirs()} == {".work", "r2-work"}

    def test_a_name_that_is_no_child_directory_is_skipped_not_fatal(self, samples: Path) -> None:
        roots = {p.name for p in sample_files.work_dirs(["..", "", ".", "ok"])}
        assert roots == {".work", "r2-work", "ok"}

    def test_a_created_directory_is_marked_private(self, samples: Path) -> None:
        made = sample_files.work_dir("mine-work")
        assert (made / sample_files.MIRROR_MARKER).is_file()
        assert oct(os.stat(made).st_mode & 0o777) == "0o700"

    def test_many_repeated_names_take_linear_time(self, samples: Path) -> None:
        def timed(n: int) -> float:
            names = [f"d{i % 3}" for i in range(n)]
            start = time.perf_counter()
            sample_files.work_dirs(names)
            return time.perf_counter() - start

        timed(1_000)
        small = min(timed(10_000) for _ in range(3))
        large = min(timed(100_000) for _ in range(3))
        assert large < small * 30 + 0.05


class TestTheOperatorsOwnDirectoriesAreNeverTouched:
    """Two disabled servers name corpus folders, one of them a link out of the samples directory."""

    @pytest.fixture
    def corpus(self, samples: Path, tmp_path: Path) -> dict[str, Path]:
        samples.mkdir(parents=True)
        static = samples / "static"
        static.mkdir(mode=0o755)
        (static / f"{SHA}.exe").write_bytes(b"corpus")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir(mode=0o755)
        (elsewhere / f"{SHA}.exe").write_bytes(b"outside")
        (samples / "linked").symlink_to(elsewhere, target_is_directory=True)
        old = time.time() - 100_000
        for path in (static / f"{SHA}.exe", elsewhere / f"{SHA}.exe"):
            os.utime(path, (old, old))
        return {"static": static, "elsewhere": elsewhere}

    def _settings(self) -> Any:
        return _settings(
            **{
                "mcp.servers": {
                    "one": _remote(work_dir="static", transport="stdio", enabled=False),
                    "two": _remote(work_dir="linked", transport="stdio", enabled=False),
                }
            }
        )

    def test_disabled_servers_name_no_directory(self, corpus: dict[str, Path]) -> None:
        assert mirror_work_dirs(self._settings()) == ()

    def _assert_untouched(self, corpus: dict[str, Path]) -> None:
        assert (corpus["static"] / f"{SHA}.exe").read_bytes() == b"corpus"
        assert (corpus["elsewhere"] / f"{SHA}.exe").read_bytes() == b"outside"
        assert oct(os.stat(corpus["static"]).st_mode & 0o777) == "0o755"
        assert oct(os.stat(corpus["elsewhere"]).st_mode & 0o777) == "0o755"
        assert not (corpus["static"] / sample_files.MIRROR_MARKER).exists()
        assert not (corpus["elsewhere"] / sample_files.MIRROR_MARKER).exists()

    def test_even_when_named_directly_nothing_is_deleted_chmodded_or_marked(
        self, corpus: dict[str, Path]
    ) -> None:
        names = ["static", "linked"]
        assert sample_files.remove_for_sha(SHA, subdirs=names) == []
        assert sample_files.sweep(max_age_s=86_400.0, subdirs=names) == 0
        self._assert_untouched(corpus)

    def test_nor_exported_as_a_sample_root(
        self, corpus: dict[str, Path], samples: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        added: list[Path] = []
        monkeypatch.setattr("maljan.tools.roots.add_sample_root", added.append)
        sample_files.export_sample_roots(["static", "linked"])
        assert {p.name for p in added} >= {".work", "r2-work"}
        assert not {p.name for p in added} & {"static", "linked", "elsewhere"}
        self._assert_untouched(corpus)

    def test_a_job_mirror_into_an_operator_directory_is_refused(
        self, corpus: dict[str, Path]
    ) -> None:
        for name in ("static", "linked"):
            with pytest.raises(sample_files.NotAMirrorDirectory):
                sample_files.work_dir(name)
        self._assert_untouched(corpus)

    def test_a_selected_provider_naming_an_operator_directory_mirrors_nothing_there(
        self, corpus: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = _generic(_remote(mount="/in", work_dir="static"))
        hosts, paths = _mirror(settings, ["generic_mcp"], monkeypatch, tmp_path)
        assert hosts == [] and paths == {}
        self._assert_untouched(corpus)

    def test_a_link_to_a_shipped_name_is_refused(self, samples: Path, tmp_path: Path) -> None:
        samples.mkdir(parents=True)
        outside = tmp_path / "out"
        outside.mkdir()
        (samples / ".work").symlink_to(outside, target_is_directory=True)
        with pytest.raises(sample_files.NotAMirrorDirectory):
            sample_files.work_dir(".work")
        assert not (outside / sample_files.MIRROR_MARKER).exists()

    def test_a_link_inside_a_mirror_directory_is_never_followed(self, samples: Path) -> None:
        target = samples.parent / "precious.exe"
        target.write_bytes(b"keep")
        made = sample_files.work_dir()
        (made / f"{SHA}.exe").symlink_to(target)
        old = time.time() - 100_000
        os.utime(made / f"{SHA}.exe", (old, old), follow_symlinks=False)
        assert sample_files.remove_for_sha(SHA) == []
        assert sample_files.sweep(max_age_s=86_400.0) == 0
        assert target.read_bytes() == b"keep"
