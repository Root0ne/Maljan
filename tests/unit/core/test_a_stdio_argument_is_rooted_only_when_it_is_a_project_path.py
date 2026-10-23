"""A stdio server's argument is rooted at the project only when it is a path into it.

``resolve_mcp_args`` lets a stored argument name a project file portably
(``scripts/dev/ghidra_manager.py``). Anything else that merely contains a ``/``
— an npm ``@scope/pkg``, a URL, a ``git+https`` spec, an image reference, an
``owner/repo`` — reaches the child exactly as written.
"""

from __future__ import annotations

import pytest

from maljan.core.paths import get_project_root, resolve_mcp_args

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
]


@pytest.mark.parametrize("arg", AS_WRITTEN)
def test_what_is_not_a_project_path_reaches_the_child_as_written(arg: str) -> None:
    assert resolve_mcp_args([arg]) == [arg]


@pytest.mark.parametrize(
    "arg", ["scripts/dev/x.py", "./scripts/x.py", "data/an/output/not/made/yet.json", "src\\x"]
)
def test_a_relative_path_into_the_project_is_rooted(arg: str) -> None:
    root = get_project_root()
    (resolved,) = resolve_mcp_args([arg])
    assert resolved.startswith(str(root))
    assert resolved == str(root / arg)


def test_the_order_and_count_of_the_arguments_are_kept() -> None:
    root = get_project_root()
    args = ["-y", "@scope/pkg", "scripts/x.py", "stdio"]
    assert resolve_mcp_args(args) == ["-y", "@scope/pkg", str(root / "scripts/x.py"), "stdio"]
