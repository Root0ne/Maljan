"""No tracked file or path names the product's previous name, but the few that must.

The product was renamed to Malspark (T-576). The previous name is spelt once,
in ``malspark.core.previous_name``, where data an earlier release wrote is still
read; this test reads it from there, so the test itself does not spell it. Every
other tracked file, its path included, is held to the new name, case-insensitively,
over its bytes (a binary file too).

The list of places allowed to keep it is explicit, and each entry says why. An
entry either allows a whole file or allows the name only on lines that hold a
given fragment, so the constant's own line is allowed and nothing else in its
file is.

The file list comes from ``git ls-files``, so a file added later is covered the
moment it is tracked.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from malspark.core.previous_name import PREVIOUS_NAME

ROOT = Path(__file__).resolve().parents[2]
NEEDLE = PREVIOUS_NAME.lower().encode("ascii")

# path -> (the fragment a line must hold to keep the name, or None for the whole
# file; why it may keep it).
ALLOWED: dict[str, tuple[str | None, str]] = {
    "src/malspark/core/previous_name.py": (
        'PREVIOUS_NAME = "',
        "The one constant every value bound to earlier data is built from: hash-chain "
        "domain tags and HKDF labels, the earlier package key label, the legacy capture "
        "directory, every earlier format and schema label, and stored STIX property names.",
    ),
    "apps/web/src/lib/previousName.ts": (
        "export const PREVIOUS_NAME_FORMAT_PREFIX = ",
        "The console checks a stored or imported document's format before the API sees "
        "it, so it mirrors the constant to read an earlier settings export or evidence "
        "bundle as the same version.",
    ),
    "scripts/upgrade/rename-volumes-and-env.sh": (
        None,
        "Finds and copies the volumes, env keys, database, collections and bucket an "
        "earlier deployment created under the previous name.",
    ),
    "docs/upgrade-from-previous-name.md": (
        None,
        "Tells an operator which of their existing names to look for and how to carry each across.",
    ),
}


def _tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def _offending_lines(path: str, data: bytes) -> list[int]:
    fragment, _reason = ALLOWED.get(path, (None, ""))
    if path in ALLOWED and fragment is None:
        return []
    allowed = fragment.encode("utf-8") if fragment is not None else None
    return [
        number
        for number, line in enumerate(data.split(b"\n"), start=1)
        if NEEDLE in line.lower() and (allowed is None or allowed not in line)
    ]


def test_the_needle_is_the_previous_name_and_the_list_is_real() -> None:
    """A guard on the guard: an empty needle or a stale entry would hide a leftover."""
    assert len(NEEDLE) >= 5
    tracked = set(_tracked())
    assert len(tracked) > 1000
    assert set(ALLOWED) <= tracked, sorted(set(ALLOWED) - tracked)
    for path, (_fragment, reason) in ALLOWED.items():
        assert reason.strip(), path


def test_no_tracked_path_names_the_previous_name() -> None:
    assert [p for p in _tracked() if NEEDLE.decode("ascii") in p.lower()] == []


def test_no_tracked_file_names_the_previous_name_outside_the_allowed_places() -> None:
    found: dict[str, list[int]] = {}
    for path in _tracked():
        full = ROOT / path
        if not full.is_file():
            continue
        data = full.read_bytes()
        if NEEDLE not in data.lower():
            continue
        lines = _offending_lines(path, data)
        if lines:
            found[path] = lines[:10]
    assert found == {}, found


def test_every_allowed_fragment_still_holds_the_name() -> None:
    """An allowed line that no longer holds the name is an entry to delete."""
    for path, (fragment, _reason) in ALLOWED.items():
        data = (ROOT / path).read_bytes()
        assert NEEDLE in data.lower(), path
        if fragment is not None:
            assert any(
                fragment.encode("utf-8") in line and NEEDLE in line.lower()
                for line in data.split(b"\n")
            ), path
