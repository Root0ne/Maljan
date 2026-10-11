"""Name the sandbox format behind a report payload, and the sample in front of one.

``sniff_format`` is used by the upload route and the upload provider to name
an attached report's format from the declared formats
(``maljan.core.report_formats``). Kept a pure function over a plain ``dict``
— no I/O, no provider imports — so both call sites can use it without a
dependency on each other.

``detect_sample_format`` and ``option_for_format`` are the submit-side pair:
what a sample on disk is, and which of the operator's per-format settings that
answers to. Every sandbox provider resolves its own package, profile or guest
through them, so one file type means the same thing to all of them.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from maljan.core.report_formats import UNKNOWN_FORMAT, ReportFormat, sniff

# The key an operator writes for "every format I did not name".
FALLBACK_FORMAT_KEY = "*"

# Our platform vocabulary in the names CAPE knows its guests by. A platform
# CAPE has no word for is left unset rather than guessed at, so CAPE picks the
# guest itself instead of being sent to one that cannot run the sample.
CAPE_PLATFORMS: dict[str, str] = {
    "windows": "windows",
    "linux": "linux",
    "android": "android",
}


def detect_sample_format(sample_path: str | Path) -> tuple[str, str]:
    """``(file_type, platform)`` for a sample on disk, ``("unknown", "unknown")`` when unreadable.

    The same detector the pipeline routes on, so the package a sandbox is asked
    for and the analysis the report is read as agree by construction.
    """
    from maljan.extractors.sample_identity import detect_file_type, infer_platform

    path = Path(sample_path)
    try:
        blob = path.read_bytes()
    except OSError:
        return "unknown", "unknown"
    file_type = detect_file_type(path, blob)
    return file_type, infer_platform(file_type)


def option_for_format(options: dict[str, str], file_type: str, fallback: str = "") -> str:
    """The operator's setting for ``file_type``, else the ``"*"`` entry, else ``fallback``."""
    if not options:
        return fallback
    exact = options.get((file_type or "").strip().lower())
    if exact:
        return exact
    return options.get(FALLBACK_FORMAT_KEY) or fallback


def cape_platform(platform: str) -> str:
    """The CAPE guest platform name for one of ours, or an empty string."""
    return CAPE_PLATFORMS.get((platform or "").strip().lower(), "")


def sniff_format(payload: dict[str, Any], formats: Iterable[ReportFormat] | None = None) -> str:
    """Name the format that produced ``payload``: the first declared format that recognises it.

    ``formats`` are the effective declarations (``report_formats.effective_formats``
    over ``sandbox.upload.formats``); ``None`` reads the built-ins alone. The
    built-ins try Triage first (``analysis`` plus a non-empty ``tasks``), then
    CAPE (a ``CAPE`` block or a version string naming it), then Cuckoo (the
    generic ``info`` + ``behavior`` shape CAPE inherited). ``"unknown"`` where
    none recognises it.
    """
    found = sniff(payload, formats)
    return found.name if found is not None else UNKNOWN_FORMAT
