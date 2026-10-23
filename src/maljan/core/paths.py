"""Project path resolution utilities.

Provides a central, robust helper for discovering the project root directory
at runtime.  This eliminates the brittle ``os.path.dirname(...)`` chains that
break whenever a module is moved, and guarantees that relative paths in
configuration files are resolved against the actual project root — never
against the current working directory.
"""

from __future__ import annotations

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

    An argument is rooted at the project directory only when it is a relative
    path into it: it contains ``/`` or ``\\``, is not absolute, carries no
    scheme or other colon (``https://…``, ``git+https://…``, an image
    reference's ``:tag``), does not start with ``@`` (an npm ``@scope/pkg``)
    and holds no ``=``, and its first component exists under the project root
    (``scripts/dev/ghidra_manager.py``, ``./tools/x``, ``data/out/new.json``).
    Anything else — a package or image name, a URL, ``owner/repo``, a CLI
    flag — reaches the child exactly as written.

    This allows ``.env`` files to store portable relative paths such as
    ``scripts/dev/ghidra_manager.py`` instead of hard-coding host-specific
    absolute paths like ``/mnt/d/MyCodes/Maljan/scripts/dev/ghidra_manager.py``.

    Args:
        args: Raw argument list from :class:`~maljan.core.config.MCPServerConfig`.

    Returns:
        A new list with relative project paths resolved to absolute paths.
    """
    project_root = get_project_root()
    return [_rooted(arg, project_root) for arg in args]


def _rooted(arg: str, project_root: Path) -> str:
    """``arg`` rooted at ``project_root`` when it is a relative path into it, else as written."""
    if arg.startswith(("-", "@")) or ":" in arg or "=" in arg:
        return arg
    if "/" not in arg and "\\" not in arg:
        # Plain value (e.g. "stdio", "root", "Ubuntu").
        return arg
    p = Path(arg)
    if p.is_absolute():
        return arg
    first = arg.replace("\\", "/").split("/", 1)[0]
    if not first or not (project_root / first).exists():
        return arg
    return str(project_root / p)
