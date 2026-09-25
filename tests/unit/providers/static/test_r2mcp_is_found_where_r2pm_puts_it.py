"""r2mcp is looked for where radare2 installs it, and a miss says where it looked.

``static.r2.binary_path`` defaults to the bare name ``r2mcp``. ``r2pm -ci
r2mcp`` installs under radare2's own prefix in the user's data directory and
does not touch PATH, so a worker whose PATH does not hold that directory could
not start the server it had installed. The provider resolves the name at start
through PATH and the places r2pm installs into, and a name that is nowhere is a
degradation that says where it looked.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from maljan.providers.static.r2 import (
    R2_NOT_FOUND_REMEDIATION,
    R2BinaryNotFound,
    R2StaticProvider,
    resolve_r2_binary,
)


def _executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


def test_a_name_on_path_is_found_there(tmp_path: Path) -> None:
    binary = _executable(tmp_path / "bin" / "r2mcp")
    found = resolve_r2_binary("r2mcp", {"PATH": str(tmp_path / "bin"), "HOME": str(tmp_path)})
    assert found.path == str(binary)


def test_a_name_r2pm_installed_is_found_under_the_user_s_data_directory(tmp_path: Path) -> None:
    home = tmp_path / "home"
    binary = _executable(home / ".local" / "share" / "radare2" / "prefix" / "bin" / "r2mcp")
    found = resolve_r2_binary("r2mcp", {"PATH": str(tmp_path / "empty"), "HOME": str(home)})
    assert found.path == str(binary)


def test_xdg_data_home_moves_the_prefix(tmp_path: Path) -> None:
    data = tmp_path / "data"
    binary = _executable(data / "radare2" / "prefix" / "bin" / "r2mcp")
    found = resolve_r2_binary(
        "r2mcp", {"PATH": "", "HOME": str(tmp_path / "home"), "XDG_DATA_HOME": str(data)}
    )
    assert found.path == str(binary)


@pytest.mark.parametrize("variable", ["R2PM_BINDIR", "R2PM_PREFIX"])
def test_r2pm_s_own_variables_are_read_first(tmp_path: Path, variable: str) -> None:
    where = tmp_path / "custom"
    binary = _executable(where / "bin" / "r2mcp" if variable == "R2PM_PREFIX" else where / "r2mcp")
    home = tmp_path / "home"
    _executable(home / ".local" / "share" / "radare2" / "prefix" / "bin" / "r2mcp")
    found = resolve_r2_binary("r2mcp", {"PATH": "", "HOME": str(home), variable: str(where)})
    assert found.path == str(binary)


def test_a_path_is_the_operator_s_and_is_used_as_it_is(tmp_path: Path) -> None:
    binary = _executable(tmp_path / "opt" / "r2mcp")
    assert resolve_r2_binary(str(binary), {"PATH": ""}).path == str(binary)
    missing = resolve_r2_binary(str(tmp_path / "nowhere" / "r2mcp"), {"PATH": ""})
    assert missing.path is None
    assert missing.looked == (str(tmp_path / "nowhere" / "r2mcp"),)


def test_a_file_that_cannot_run_is_not_found(tmp_path: Path) -> None:
    plain = tmp_path / "bin" / "r2mcp"
    plain.parent.mkdir()
    plain.write_text("")
    plain.chmod(0o644)
    assert (
        resolve_r2_binary("r2mcp", {"PATH": str(plain.parent), "HOME": str(tmp_path)}).path is None
    )


def test_a_miss_names_every_place_looked_and_guesses_nothing(tmp_path: Path) -> None:
    home = tmp_path / "home"
    found = resolve_r2_binary("r2mcp", {"PATH": "/nonexistent-bin", "HOME": str(home)})
    assert found.path is None
    described = found.described()
    assert "PATH (/nonexistent-bin)" in described
    assert os.path.join(str(home), ".local", "share", "radare2", "prefix", "bin", "r2mcp") in (
        described
    )


def _nowhere(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """An environment in which no r2mcp can be found."""
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for variable in ("XDG_DATA_HOME", "R2PM_BINDIR", "R2PM_PREFIX"):
        monkeypatch.delenv(variable, raising=False)


def _enabled() -> Any:
    """Settings with the r2 provider switched on; it ships switched off."""
    from maljan.core.config import Settings

    return Settings(_env_file=None, static={"r2": {"enabled": True}})


def test_a_switched_off_r2_looks_for_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Switched off, the handle attaches nothing, so there is no binary to miss."""
    from maljan.core.config import Settings
    from maljan.providers.base import StaticJobContext
    from maljan.providers.static import r2

    _nowhere(monkeypatch, tmp_path)
    looked: list[str] = []
    monkeypatch.setattr(
        r2, "resolve_r2_binary", lambda configured, env=None: looked.append(configured)
    )
    provider = R2StaticProvider.from_settings(Settings(_env_file=None))

    provider.open(StaticJobContext())

    assert looked == []
    assert provider.get_tools() == []


def test_opening_with_no_r2mcp_anywhere_fails_with_the_places_and_the_remedy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from maljan.providers.base import StaticJobContext

    _nowhere(monkeypatch, tmp_path)
    provider = R2StaticProvider.from_settings(_enabled())

    with pytest.raises(R2BinaryNotFound) as caught:
        provider.open(StaticJobContext())

    assert "looked in: PATH" in str(caught.value)
    assert caught.value.remediation == R2_NOT_FOUND_REMEDIATION
    assert provider.capabilities.degrade_on_failure is True


def test_the_analyst_records_the_miss_as_the_run_s_reason(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A degrading provider that did not attach is in the run summary, with its
    remedy and without the directories, which name the worker's home."""
    import logging

    from maljan.agents.static_analyst import StaticAnalyst
    from maljan.providers.base import StaticJobContext

    _nowhere(monkeypatch, tmp_path)
    provider = R2StaticProvider.from_settings(_enabled())

    class _Registry:
        degradation_reasons: list[str] = []

    registry = _Registry()
    analyst = StaticAnalyst.__new__(StaticAnalyst)
    analyst.logger = logging.getLogger("test.r2")
    analyst.degradation_reasons = []
    analyst.name = "static_r2"
    monkeypatch.setattr(analyst, "_provider", lambda: provider)
    monkeypatch.setattr(analyst, "_job_context", StaticJobContext)
    monkeypatch.setattr(analyst, "_server_registry", lambda: registry)
    monkeypatch.setattr(analyst, "_static_capabilities", lambda: provider.capabilities)

    assert analyst._try_initialize_mcp() is False

    assert len(registry.degradation_reasons) == 1
    reason = registry.degradation_reasons[0]
    assert reason.startswith("static provider 'r2' unavailable: ")
    assert "r2pm -ci r2mcp" in reason
    assert str(tmp_path) not in reason
    assert analyst.degradation_reasons == [reason]
