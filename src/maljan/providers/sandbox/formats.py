"""Name the sandbox format behind a report payload, and the sample in front of one.

``sniff_format`` is used by the upload provider to decide which normaliser
handles an attached report, and by the Triage adapter to confirm what it just
fetched. Kept a pure function over a plain ``dict`` — no I/O, no provider
imports — so both call sites can use it without a dependency on each other.

``detect_sample_format`` and ``option_for_format`` are the submit-side pair:
what a sample on disk is, and which of the operator's per-format settings that
answers to. Every sandbox provider resolves its own package, profile or guest
through them, so one file type means the same thing to all of them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

Format = Literal["cape2", "cuckoo", "triage", "unknown"]

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
    from maljan.extractors.sample_identity import _detect_file_type, _infer_platform

    path = Path(sample_path)
    try:
        blob = path.read_bytes()
    except OSError:
        return "unknown", "unknown"
    file_type = _detect_file_type(path, blob)
    return file_type, _infer_platform(file_type, None, None)


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


def sniff_format(payload: dict[str, Any]) -> Format:
    """Name the sandbox that produced ``payload``, most specific first.

    Triage first: its overview carries ``analysis`` plus a non-empty
    ``tasks``, which no CAPE report has. ``tasks`` comes as a list in Triage's
    own documentation and as a dict keyed by task id from the live API, so
    both shapes count. CAPE next: ``CAPE`` as a top-level key, or a version string
    naming it. Cuckoo last, as the generic ``info`` + ``behavior`` shape CAPE
    inherited from it — so it can only be reached once CAPE has been ruled out.
    """
    if not isinstance(payload, dict) or not payload:
        return "unknown"
    analysis = payload.get("analysis")
    tasks = payload.get("tasks")
    if isinstance(analysis, dict) and isinstance(tasks, (list, dict)) and tasks:
        return "triage"
    if isinstance(payload.get("CAPE"), (dict, list)):
        return "cape2"
    info_field = payload.get("info")
    info = info_field if isinstance(info_field, dict) else {}
    version = str(info.get("version") or "")
    if "cape" in version.lower():
        return "cape2"
    if isinstance(payload.get("behavior"), dict) and info:
        return "cuckoo"
    return "unknown"
