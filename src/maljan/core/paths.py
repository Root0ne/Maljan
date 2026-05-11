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


def resolve_mcp_args(args: list[str]) -> list[str]:
    """Resolve relative paths inside MCP ``args`` against the project root.

    Any argument that looks like a relative file or directory path (contains
    ``/`` or ``\\`` but does *not* start with a drive letter on Windows or
    a leading ``/`` on Unix) is expanded to an absolute path rooted at the
    project directory.  CLI flags and already-absolute paths are left untouched.

    This allows ``.env`` files to store portable relative paths such as
    ``scripts/cape_mcp_wrapper.py`` instead of hard-coding host-specific
    absolute paths like ``/mnt/d/MyCodes/Maljan/scripts/cape_mcp_wrapper.py``.

    Args:
        args: Raw argument list from :class:`~maljan.core.config.MCPServerConfig`.

    Returns:
        A new list with relative paths resolved to absolute paths.
    """
    project_root = get_project_root()
    resolved: list[str] = []
    for arg in args:
        # Skip CLI flags
        if arg.startswith("-"):
            resolved.append(arg)
            continue

        p = Path(arg)
        # Already absolute -> keep as-is
        if p.is_absolute():
            resolved.append(arg)
            continue

        # Contains a separator -> treat as a relative path to resolve
        if "/" in arg or "\\" in arg:
            resolved.append(str(project_root / p))
            continue

        # Plain value (e.g. "stdio", "root", "Ubuntu")
        resolved.append(arg)

    return resolved
