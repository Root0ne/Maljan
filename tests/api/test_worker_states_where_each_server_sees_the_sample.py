"""The worker says, at start, where each selected static provider's sample copy goes.

A server handed a path under a mount it does not have answers "File not found"
to every load. The worker states, for each static provider the settings select
and that mirrors, the host directory its copy goes to and the path its server
is handed under its declared ``sample_mount``, and it says when a retired
environment variable is still set and which setting holds its value now.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.worker import analysis_worker
from maljan.core.settings_overrides import build_settings


class _Stop(Exception):
    """Ends ``startup`` right after the retired-variable lines, before any database."""


def test_the_shipped_settings_name_the_selected_provider_s_mount() -> None:
    lines = analysis_worker.mirror_lines(build_settings({}))
    assert len(lines) == 1
    (line,) = lines
    assert line.startswith("Static provider 'ghidra' mirrors a sample to ")
    assert line.endswith("and is handed it as /data/samples/.work/<sha256>.")


def test_a_saved_mount_is_the_one_stated() -> None:
    core = build_settings({"static.ghidra.sample_mount": "/mnt/ghidra-in"})
    (line,) = analysis_worker.mirror_lines(core)
    assert line.endswith("and is handed it as /mnt/ghidra-in/.work/<sha256>.")


def test_a_provider_on_the_worker_s_filesystem_is_handed_the_host_path() -> None:
    core = build_settings({"static.provider": "r2"})
    (line,) = analysis_worker.mirror_lines(core)
    host = line.split(" mirrors a sample to ", 1)[1].split(" and is handed it as ", 1)[0]
    assert line.endswith(f"and is handed it as {host}.")
    assert "r2-work" in host


def test_a_provider_that_reads_in_place_states_nothing() -> None:
    assert analysis_worker.mirror_lines(build_settings({"static.provider": "capa_yara"})) == []


def test_no_line_names_a_samples_path_variable() -> None:
    for line in analysis_worker.mirror_lines(build_settings({})):
        assert "SAMPLES_PATH" not in line


def test_a_retired_variable_still_set_is_named_with_the_setting_that_holds_it() -> None:
    lines = analysis_worker.retired_environment_lines(
        {"GHIDRA_CONTAINER_SAMPLES_PATH": "/srv/maljan/data/samples"}
    )
    assert lines == [
        "GHIDRA_CONTAINER_SAMPLES_PATH is set and no longer read; the setting "
        "core.static.ghidra.sample_mount holds the value now (the migration that retired it "
        "copied the variable there once, only if the setting accepts its value, it differs "
        "from the shipped one and the store held none)."
    ]
    assert "/srv/maljan" not in lines[0]


def test_the_retired_attck_age_variable_names_the_refresh_setting() -> None:
    (line,) = analysis_worker.retired_environment_lines({"MALJAN_ATTCK_MAX_AGE_DAYS": "30"})
    assert line.startswith(
        "MALJAN_ATTCK_MAX_AGE_DAYS is set and no longer read; the setting "
        "core.validation.attck_refresh_days holds the value now"
    )
    assert "30" not in line


def test_an_unset_or_empty_retired_variable_says_nothing() -> None:
    assert analysis_worker.retired_environment_lines({}) == []
    assert analysis_worker.retired_environment_lines({"GHIDRA_CONTAINER_SAMPLES_PATH": " "}) == []


def test_startup_warns_once_for_a_retired_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    log = MagicMock()
    monkeypatch.setattr(analysis_worker, "logger", log)
    monkeypatch.setattr(analysis_worker, "setup_logging", lambda: None)
    monkeypatch.setattr("app.bootstrap.require_bootstrap", lambda _settings: None)
    monkeypatch.setenv("GHIDRA_CONTAINER_SAMPLES_PATH", "/data/samples")

    def stop(_overrides: object) -> None:
        raise _Stop

    monkeypatch.setattr(analysis_worker, "build_settings", stop)

    with pytest.raises(_Stop):
        asyncio.run(analysis_worker.startup({}))

    said = [call.args[0] for call in log.warning.call_args_list]
    assert sum(1 for text in said if text.startswith("GHIDRA_CONTAINER_SAMPLES_PATH is set")) == 1


def test_the_statement_reads_the_stored_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    log = MagicMock()
    monkeypatch.setattr(analysis_worker, "logger", log)
    stored = build_settings(
        {"static.ghidra.sample_mount": "/srv/stored", "static.ghidra.enabled": True}
    )

    async def effective(_db: Any) -> Any:
        return stored

    monkeypatch.setattr("app.services.settings_service.effective_core_settings", effective)
    exported: list[Any] = []
    monkeypatch.setattr(
        "app.worker.sample_files.export_sample_roots", lambda subdirs=None: exported.append(subdirs)
    )
    swept: list[Any] = []
    monkeypatch.setattr(
        "app.worker.sample_files.sweep", lambda **kw: swept.append(kw.get("subdirs")) or 0
    )

    @asynccontextmanager
    async def session() -> Any:
        yield object()

    asyncio.run(analysis_worker.state_the_mirrors(session))

    said = [call.args[0] for call in log.info.call_args_list]
    assert any(text.endswith("handed it as /srv/stored/.work/<sha256>.") for text in said)
    assert exported and ".work" in exported[0]
    assert swept == exported, "the stored directories are swept as well as exported"


def test_an_unreadable_store_falls_back_to_the_shipped_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log = MagicMock()
    monkeypatch.setattr(analysis_worker, "logger", log)
    monkeypatch.setattr("app.worker.sample_files.export_sample_roots", lambda subdirs=None: [])
    monkeypatch.setattr("app.worker.sample_files.sweep", lambda **_kw: 0)

    @asynccontextmanager
    async def session() -> Any:
        raise ConnectionError("no database")
        yield  # pragma: no cover

    asyncio.run(analysis_worker.state_the_mirrors(session))

    warned = [call.args[0] for call in log.warning.call_args_list]
    assert any("were not read for the mirror statement" in text for text in warned)
    said = [call.args[0] for call in log.info.call_args_list]
    assert any(text.endswith("handed it as /data/samples/.work/<sha256>.") for text in said)
