"""Static-analysis provider adapters.

The built-in adapters register themselves when imported; the registry imports
them here (``import_built_ins``), so no module outside this package names one.
"""

from __future__ import annotations

import importlib

# The built-in adapters' modules, each registering its provider on import.
BUILT_IN_MODULES: tuple[str, ...] = ("capa_yara", "generic_mcp", "ghidra", "null", "r2")


def import_built_ins() -> None:
    """Import every built-in static adapter once, which registers it."""
    for name in BUILT_IN_MODULES:
        importlib.import_module(f"{__name__}.{name}")
