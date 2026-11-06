"""A stdio server's argument is rooted at the project only when it is a path into it.

``resolve_mcp_args`` lets a stored argument name a project file portably
(``scripts/dev/ghidra_manager.py``). Anything else that merely contains a ``/``
— an npm ``@scope/pkg``, a URL, a ``git+https`` spec, an image reference, an
``owner/repo`` — reaches the child exactly as written. So does a relative path
that leaves the project (``../x``): an argument is rooted by the rule a command
is (``resolve_mcp_command``), never to a file outside the project.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from malspark.core.paths import (
    get_project_root,
    mcp_paths_leaving_project,
    resolve_mcp_args,
    resolve_mcp_command,
)

AS_WRITTEN = [
    "@modelcontextprotocol/server-filesystem",
    "https://example.org/mcp/sse",
    "git+https://example.org/owner/repo.git",
    "ghcr.io/owner/image:1.2",
    "ghcr.io/owner/image",
    "owner/repo",
    "KEY=scripts/x",
    "--root=scripts",
    "-v",
    "stdio",
    "/opt/abs/path.py",
    "C:\\tools\\x.exe",
    "~/x.py",
    "./missing-zq/x.py",
]

LEAVING = ["../x.py", "./../x.py", "scripts/../../x.py", ".././scripts/x.py"]


@pytest.mark.parametrize("arg", AS_WRITTEN)
def test_what_is_not_a_project_path_reaches_the_child_as_written(arg: str) -> None:
    assert resolve_mcp_args([arg]) == [arg]
    assert mcp_paths_leaving_project([arg]) == []


@pytest.mark.parametrize(
    "arg", ["scripts/dev/x.py", "./scripts/x.py", "data/an/output/not/made/yet.json"]
)
def test_a_relative_path_into_the_project_is_rooted(arg: str) -> None:
    root = get_project_root()
    (resolved,) = resolve_mcp_args([arg])
    assert resolved.startswith(str(root))
    assert resolved == str(root / arg)


@pytest.mark.parametrize("arg", LEAVING)
def test_a_relative_path_that_leaves_the_project_is_left_as_written(arg: str) -> None:
    assert resolve_mcp_args([arg]) == [arg]
    assert mcp_paths_leaving_project([arg]) == [arg]


def test_a_path_that_steps_back_inside_the_project_is_rooted_where_it_lands() -> None:
    root = get_project_root()
    assert resolve_mcp_args(["scripts/../src/x.py"]) == [str(root / "src" / "x.py")]
    assert mcp_paths_leaving_project(["scripts/../src/x.py"]) == []


@pytest.mark.parametrize("arg", ["scripts/dev/x.py", "./scripts/x.py", *AS_WRITTEN, *LEAVING])
def test_an_argument_is_rooted_by_the_rule_a_command_is(arg: str) -> None:
    assert resolve_mcp_args([arg]) == [resolve_mcp_command(arg)]


def test_a_backslash_separates_only_where_the_platform_s_separator_is_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = get_project_root()
    assert resolve_mcp_args(["src\\x"]) == ["src\\x"]
    monkeypatch.setattr("malspark.core.paths.os.sep", "\\")
    assert resolve_mcp_args(["src\\x"]) == [str(Path(root / "src" / "x"))]
    assert resolve_mcp_args(["..\\x"]) == ["..\\x"]
    assert mcp_paths_leaving_project(["..\\x"]) == ["..\\x"]


def test_the_order_and_count_of_the_arguments_are_kept() -> None:
    root = get_project_root()
    args = ["-y", "@scope/pkg", "scripts/x.py", "../x.py", "stdio"]
    assert resolve_mcp_args(args) == [
        "-y",
        "@scope/pkg",
        str(root / "scripts/x.py"),
        "../x.py",
        "stdio",
    ]
