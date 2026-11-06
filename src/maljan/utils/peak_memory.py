"""Peak resident memory from ``resource.getrusage``, in bytes on every platform."""

from __future__ import annotations

import sys
from typing import Any


def rss_to_bytes(units: int) -> int:
    """``ru_maxrss`` units as bytes: Linux counts kibibytes, macOS counts bytes."""
    return units if sys.platform == "darwin" else units * 1024


def maxrss_bytes(usage: Any) -> int:
    """The peak resident bytes a ``getrusage`` result (or ``wait4`` usage) reports."""
    return rss_to_bytes(getattr(usage, "ru_maxrss", 0))
