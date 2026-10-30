"""A console trust grant holds for the files its launch resolves to, not only for how it is written.

``granted_launch`` digests a block's launch as written and as it resolves here
(``tool_declarations._resolved_launch``): the real file its command runs, its
real working directory, and the real path of each argument written as a path
that exists. A grant recorded for one launch therefore does not survive the
block being repointed through a link, a relative path or ``PATH`` while what
the block writes stays the same; a launch whose command or working directory
does not resolve holds no grant at all. A file replaced in place, and a new
release, keep it. Every server here is one no catalog has seen.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import maljan.core.tool_declarations as td
from maljan.core.tool_declarations import granted_launch, trusts_served

SOURCE = "mcp:zq-never-seen-server"


def _program(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


def _block(**launch: Any) -> SimpleNamespace:
    fields = {
        "transport": "stdio",
        "command": None,
        "args": [],
        "cwd": None,
        "url": None,
        "env": {},
        "env_allow": [],
    }
    return SimpleNamespace(**{**fields, **launch})


def _trusted(block: SimpleNamespace, grant: str) -> bool:
    held = SimpleNamespace(**vars(block), trusts_served_declaration=True, trust_granted_for=grant)
    return trusts_served(SOURCE, held)


def test_a_command_link_pointed_elsewhere_withdraws_the_grant(tmp_path: Path) -> None:
    first = _program(tmp_path / "a" / "zq-server")
    second = _program(tmp_path / "b" / "zq-server")
    link = tmp_path / "bin" / "zq-server"
    link.parent.mkdir()
    link.symlink_to(first)
    block = _block(command=str(link))
    grant = granted_launch(block)
    assert grant
    assert _trusted(block, grant)
    link.unlink()
    link.symlink_to(second)
    assert granted_launch(block) != grant
    assert not _trusted(block, grant)


def test_a_relative_command_is_read_from_the_working_directory_it_runs_in(
    tmp_path: Path,
) -> None:
    for where in ("one", "two"):
        _program(tmp_path / where / "bin" / "zq-server")
    block = _block(command="bin/zq-server", cwd=str(tmp_path / "one"))
    grant = granted_launch(block)
    assert grant and _trusted(block, grant)
    moved = _block(command="bin/zq-server", cwd=str(tmp_path / "two"))
    assert not _trusted(moved, grant)


def test_a_working_directory_link_pointed_elsewhere_withdraws_the_grant(tmp_path: Path) -> None:
    for where in ("one", "two"):
        _program(tmp_path / where / "zq-server")
    here = tmp_path / "here"
    here.symlink_to(tmp_path / "one")
    block = _block(command="./zq-server", cwd=str(here))
    grant = granted_launch(block)
    assert grant and _trusted(block, grant)
    here.unlink()
    here.symlink_to(tmp_path / "two")
    assert not _trusted(block, grant)


def test_an_interpreter_s_script_is_read_as_the_file_it_names(tmp_path: Path) -> None:
    for where in ("one", "two"):
        (tmp_path / where).mkdir()
        (tmp_path / where / "server.py").write_text("print('zq')\n")
    script = tmp_path / "server.py"
    script.symlink_to(tmp_path / "one" / "server.py")
    block = _block(command=sys.executable, args=["-u", str(script)], cwd=str(tmp_path))
    grant = granted_launch(block)
    assert grant and _trusted(block, grant)
    script.unlink()
    script.symlink_to(tmp_path / "two" / "server.py")
    assert not _trusted(block, grant)


def test_a_bare_command_is_read_as_the_file_path_finds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for where in ("one", "two"):
        _program(tmp_path / where / "zq-server")
    monkeypatch.setenv("PATH", str(tmp_path / "one"))
    block = _block(command="zq-server")
    grant = granted_launch(block)
    assert grant and _trusted(block, grant)
    monkeypatch.setenv("PATH", str(tmp_path / "two"))
    assert not _trusted(block, grant)


@pytest.mark.parametrize(
    "launch",
    [
        {"command": "/nonexistent/zq-server"},
        {"command": "zq-server-on-no-path"},
        {"command": "bin/zq-server", "cwd": "/nonexistent/zq-dir"},
    ],
    ids=["missing-file", "not-on-path", "missing-cwd"],
)
def test_a_launch_that_does_not_resolve_holds_no_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, launch: dict[str, Any]
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    block = _block(**launch)
    assert granted_launch(block) == ""
    # Nor does one recorded before: the grant of the launch as it last resolved.
    _program(tmp_path / "zq-server")
    resolved = _block(command=str(tmp_path / "zq-server"))
    assert not _trusted(block, granted_launch(resolved))


def test_a_file_replaced_in_place_and_a_new_release_keep_the_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    program = _program(tmp_path / "zq-server")
    block = _block(command=str(program), args=["--config", str(tmp_path / "missing.toml")])
    grant = granted_launch(block)
    program.write_text("#!/bin/sh\necho upgraded\n")
    monkeypatch.setattr(td, "KEPT_DECLARATIONS_RELEASE", "a-later-release+99")
    assert granted_launch(block) == grant
    assert _trusted(block, grant)


def test_an_address_is_read_as_written() -> None:
    block = _block(transport="streamable-http", url="http://zq-host.invalid:9000/mcp")
    grant = granted_launch(block)
    assert grant
    assert granted_launch(block) == grant
    assert (
        granted_launch(_block(transport="streamable-http", url="http://zq-host.invalid:9001/mcp"))
        != grant
    )


@pytest.mark.parametrize(
    "env",
    [
        {"LD_PRELOAD": "/tmp/zq-hook.so"},
        {"PYTHONPATH": "/tmp/zq-lib"},
        {"NODE_OPTIONS": "--require /tmp/zq-hook.js"},
        {"PATH": "/usr/bin"},
    ],
    ids=["ld-preload", "pythonpath", "node-options", "path"],
)
def test_a_changed_environment_withdraws_the_grant(tmp_path: Path, env: dict[str, str]) -> None:
    program = _program(tmp_path / "zq-server")
    block = _block(command=str(program), env={})
    grant = granted_launch(block)
    assert grant and _trusted(block, grant)
    assert not _trusted(_block(command=str(program), env=env), grant)
    assert not _trusted(_block(command=str(program), env_allow=["LD_PRELOAD"]), grant)


def test_no_environment_value_is_held_in_the_clear(tmp_path: Path) -> None:
    program = _program(tmp_path / "zq-server")
    block = _block(command=str(program), env={"ZQ_TOKEN": "zq-secret-value"})
    seen: list[str] = []
    real_dumps = td.json.dumps

    def _dumps(value: Any, **kwargs: Any) -> str:
        text = real_dumps(value, **kwargs)
        seen.append(text)
        return text

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(td.json, "dumps", _dumps)
        assert granted_launch(block)
    assert seen and all("zq-secret-value" not in text for text in seen)


def test_a_bare_command_is_found_on_the_path_the_child_is_given(tmp_path: Path) -> None:
    for where in ("good", "evil"):
        _program(tmp_path / where / "zq-server")
    block = _block(command="zq-server", env={"PATH": str(tmp_path / "good")})
    grant = granted_launch(block)
    assert grant and _trusted(block, grant)
    moved = _block(command="zq-server", env={"PATH": str(tmp_path / "evil")})
    assert not _trusted(moved, grant)


def test_an_option_s_path_value_is_read_as_the_file_it_names(tmp_path: Path) -> None:
    program = _program(tmp_path / "zq-server")
    for name in ("one.py", "two.py"):
        (tmp_path / name).write_text("")
    link = tmp_path / "current.py"
    link.symlink_to(tmp_path / "one.py")
    block = _block(command=str(program), args=[f"--script={link}"])
    grant = granted_launch(block)
    assert grant and _trusted(block, grant)
    link.unlink()
    link.symlink_to(tmp_path / "two.py")
    assert not _trusted(block, grant)


def test_the_grant_reads_the_launch_as_the_server_is_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.agents.subprocess_env import stdio_launch
    from maljan.core.config import MCPServerConfig

    # A relative working directory and a relative argument are rooted at the
    # project, as the launch roots them, whatever directory this process is in.
    root = tmp_path / "project"
    (root / "srv").mkdir(parents=True)
    (root / "scripts").mkdir()
    for name in ("one.py", "two.py"):
        (root / "scripts" / name).write_text("")
    script = root / "scripts" / "server.py"
    script.symlink_to(root / "scripts" / "one.py")
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "scripts").mkdir(parents=True)
    (elsewhere / "scripts" / "server.py").write_text("")
    monkeypatch.setattr("maljan.core.paths.get_project_root", lambda *a, **k: root)
    monkeypatch.chdir(elsewhere)
    config = MCPServerConfig(
        enabled=True, command=sys.executable, args=["scripts/server.py"], cwd="srv"
    )
    launch = stdio_launch(config)
    assert launch.cwd == str((root / "srv").resolve())
    assert launch.args == [str(root / "scripts" / "server.py")]
    resolved = td._resolved_launch(config)
    assert resolved is not None
    assert resolved["cwd"] == os.path.realpath(root / "srv")
    assert resolved["args"] == {"0": os.path.realpath(root / "scripts" / "one.py")}
    grant = granted_launch(config)
    script.unlink()
    script.symlink_to(root / "scripts" / "two.py")
    assert granted_launch(config) != grant


def test_a_server_started_away_from_its_grant_does_not_trust_its_declaration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.core.config import MCPServerConfig
    from maljan.providers.servers import ServerHandle

    class _Toolkit:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _Toolkit)
    for where in ("one", "two"):
        _program(tmp_path / where / "zq-server")
    link = tmp_path / "zq-server"
    link.symlink_to(tmp_path / "one" / "zq-server")
    config = MCPServerConfig(enabled=True, command=str(link), trusts_served_declaration=True)
    config = config.model_copy(update={"trust_granted_for": granted_launch(config)})
    held = ServerHandle("zq-never-seen-server", config)
    held._build_toolkit(None, 0, None)
    assert held.config.trusts_served_declaration is True
    link.unlink()
    link.symlink_to(tmp_path / "two" / "zq-server")
    moved = ServerHandle("zq-never-seen-server", config)
    moved._build_toolkit(None, 0, None)
    assert moved.config.trusts_served_declaration is False
    assert moved.config.trust_granted_for is None
