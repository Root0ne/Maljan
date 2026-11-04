"""Project path resolution utilities.

Provides a central, robust helper for discovering the project root directory
at runtime.  This eliminates the brittle ``os.path.dirname(...)`` chains that
break whenever a module is moved, and guarantees that relative paths in
configuration files are resolved against the actual project root — never
against the current working directory.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from maljan.core.exceptions import ProjectRootNotFoundError

# Markers that identify the project root directory
_ROOT_MARKERS: tuple[str, ...] = ("pyproject.toml", ".git")


def get_project_root(max_up: int = 8) -> Path:
    """Resolve the project root by walking up from this file.

    The search starts at the directory containing *this* module and walks
    upward until one of the :data:`_ROOT_MARKERS` files is found.  This is
    deterministic regardless of where the application is launched from.

    Args:
        max_up: Maximum number of parent directories to traverse.

    Returns:
        Absolute :class:`~pathlib.Path` to the project root.

    Raises:
        RuntimeError: If no root marker is found within ``max_up`` levels.
    """
    current = Path(__file__).resolve().parent
    for _ in range(max_up):
        if any((current / marker).exists() for marker in _ROOT_MARKERS):
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    raise ProjectRootNotFoundError(f"Could not locate project root (looked for {_ROOT_MARKERS})")


def resolve_data(path_like: str | Path) -> Path:
    """Resolve a relative ``data/...`` path against the project root.

    Returns absolute paths untouched (operator opt-out). Relative paths
    are joined onto :func:`get_project_root` so an arq worker started from
    ``apps/api/`` still finds ``data/sigma_rules`` at the repo root.

    Args:
        path_like: A string or :class:`~pathlib.Path` (e.g. from config).

    Returns:
        Absolute :class:`~pathlib.Path`.
    """
    p = Path(path_like)
    return p if p.is_absolute() else get_project_root() / p


def resolve_mcp_args(args: list[str]) -> list[str]:
    """Resolve relative paths inside MCP ``args`` against the project root.

    An argument is rooted at the project directory by the rule
    :func:`resolve_mcp_command` roots a command by, only when it is a relative
    path into it: it contains ``/`` (or ``\\`` where that is the platform's
    separator), is not absolute, carries no scheme or other colon
    (``https://…``, ``git+https://…``, an image reference's ``:tag``), does not
    start with ``-``, ``@`` (an npm ``@scope/pkg``) or ``~`` and holds no
    ``=``, its first component past any leading ``.`` exists under the project
    root, and the rooted path stays inside it (``scripts/dev/ghidra_manager.py``,
    ``./tools/x``, ``data/out/new.json``). Anything else — a package or image
    name, a URL, ``owner/repo``, a CLI flag, ``../x`` or ``scripts/../../x`` —
    reaches the child exactly as written; :func:`mcp_paths_leaving_project`
    names the last kind, so the launch can say it left them.

    This allows ``.env`` files to store portable relative paths such as
    ``scripts/dev/ghidra_manager.py`` instead of hard-coding host-specific
    absolute paths like ``/mnt/d/MyCodes/Maljan/scripts/dev/ghidra_manager.py``.

    Args:
        args: Raw argument list from :class:`~maljan.core.config.MCPServerConfig`.

    Returns:
        A new list with relative project paths resolved to absolute paths.
    """
    project_root = get_project_root()
    return [_rooted(arg, project_root)[0] for arg in args]


def mcp_paths_leaving_project(values: list[str]) -> list[str]:
    """The ``values`` written as a relative path that leaves the project, which are not rooted.

    ``../x``, ``./../x``, ``scripts/../../x``, or a path through a link that
    points outside the project: :func:`resolve_mcp_args` and
    :func:`resolve_mcp_command` leave each as written, read from the child's
    own working directory, rather than root it at the project as they root a
    relative path into it.
    """
    project_root = get_project_root()
    return [value for value in values if _rooted(value, project_root)[1]]


def resolve_mcp_command(command: str) -> str:
    """An MCP ``command`` rooted at the project root when it is a relative path into it.

    The rule :func:`resolve_mcp_args` roots an argument by: a value with no
    path separator (a bare program name such as ``npx`` or ``uvx``, looked up
    on the child's ``PATH``), an absolute path, ``~``, a scheme or option is
    left as written; ``\\`` is a separator only where the platform's is. A
    relative path is rooted only when its first component past any leading
    ``.`` exists under the project root and the rooted path stays inside it,
    so ``../x``, ``./../x`` and ``./missing/x`` are left as written, as the
    child reads them.
    """
    return _rooted(command)[0]


def _rooted(value: str, project_root: Path | None = None) -> tuple[str, bool]:
    """``value`` rooted at the project root when it is a relative path into it, else as written.

    With whether ``value`` was left as written because it is a relative path
    that leaves the project: by its ``..`` components, or through a link, as
    its real path is read (``link/passwd`` where ``link`` points outside),
    the containment ``launch_cwd`` reads a working directory by. A value whose
    path cannot be read here (too long, say) is left as written.
    ``project_root`` defaults to :func:`get_project_root`, read only for a
    value written as a path.
    """
    if not value or value.startswith(("-", "@", "~")) or ":" in value or "=" in value:
        return value, False
    written = value.replace("\\", "/") if os.sep == "\\" else value
    if "/" not in written or Path(written).is_absolute():
        return value, False
    parts = [part for part in written.split("/") if part]
    while parts and parts[0] == ".":
        parts.pop(0)
    if not parts:
        return value, False
    if parts[0] == "..":
        return value, True
    root = get_project_root() if project_root is None else project_root
    rooted = Path(os.path.normpath(root / written))
    if not rooted.is_relative_to(root):
        return value, True
    try:
        if not (root / parts[0]).exists():
            return value, False
        if not Path(os.path.realpath(rooted)).is_relative_to(root.resolve()):
            return value, True
    except (OSError, ValueError):
        return value, False
    return str(rooted), False


# An absolute POSIX path in free text: a ``file://`` URL, or a slash not after
# a word character, a colon, a dot or another slash (a URL's ``//`` and a
# relative ``a/b`` are not one), then path characters.
_ABSOLUTE_PATH = re.compile(
    r"file://(?:localhost)?(?P<url>/[^\s'\"<>()]*)"
    r"|(?<![\w:./])(?P<path>/[\w.@%+~-]+(?:/[\w.@%+~-]+)*/?)"
)

# The directories a host keeps its own files under. A path that starts with one
# of them, or that exists on this host, is the host's layout; anything else
# that reads as one (an HTTP route, ``/api/v1/jobs``) is left as written.
HOST_ROOTS = ("/home", "/tmp", "/opt", "/var", "/root", "/srv", "/mnt", "/media", "/usr", "/etc")

# What a path off the project is shown as: the host's layout is not the reader's.
OUTSIDE_PROJECT = "a path outside the project"


def host_paths_masked(text: str, project_root: Path | None = None) -> str:
    """``text`` with each host path shown from the project root, or masked outside it.

    For words a report or an answer to any signed-in user carries: a path in
    the project reads as the operator wrote it relative to the root
    (``data/sigma_rules``), and a host path outside it as
    :data:`OUTSIDE_PROJECT`, never as the host's own layout. A host path is
    one under :data:`HOST_ROOTS` or one of the project's parents, or one that
    exists here; a ``file://`` URL is read as its path. Anything else that
    starts with a slash (an HTTP route) is kept.
    """
    root = get_project_root() if project_root is None else project_root
    parents = tuple(str(parent) for parent in root.parents if parent != Path(parent.anchor))

    def shown(match: re.Match[str]) -> str:
        written = match.group("url") or match.group("path")
        path = Path(os.path.normpath(written))
        if path.is_relative_to(root) and path != root:
            return path.relative_to(root).as_posix()
        text = str(path)
        held = any(text == top or text.startswith(top + "/") for top in (*HOST_ROOTS, *parents))
        if held or match.group("url") or _exists(path):
            return OUTSIDE_PROJECT
        return match.group(0)

    return _ABSOLUTE_PATH.sub(shown, str(text or ""))


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except (OSError, ValueError):
        return False
