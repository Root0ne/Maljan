#!/usr/bin/env python3
"""Measure a platform's API behaviour block against real binaries on this host.

Offline, operator-run, never imported by the pipeline and never run by a test:
it reads whatever ELF files are under the directories it is given, and a test
that read a host's binaries would answer differently on every machine.

Why it exists. The Linux block's tiers and technique rules are not judged, they
are measured: a behaviour group whose bare presence labels an ordinary program,
or a technique rule that fires on one, is not evidence of anything and does not
ship. That rule can only be kept if the measurement can be repeated — after an
ATT&CK refresh, after a new group, on a distribution whose software is not the
one the block was written against.

What it prints: per group how many binaries it appears on and how many it
labels, per technique rule how many it fires on, and the names of the binaries
carrying a label or a technique row so a reader can judge whether the
population is the one the technique describes. With ``--fail-over`` it exits
non-zero when any rule or any labelled group is above that percentage, which is
the form to put in a refresh checklist.

Usage::

    uv run python scripts/knowledge/measure_api_behaviour_block.py /usr/bin /usr/sbin
    uv run python scripts/knowledge/measure_api_behaviour_block.py --fail-over 1 /usr/bin
"""

from __future__ import annotations

import argparse
import io
import sys
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from maljan.analysis.api_capability_db import load_api_behaviour_db  # noqa: E402
from maljan.tools.knowledge import (  # noqa: E402
    DEFAULT_API_ATTCK_MAP,
    DEFAULT_API_BEHAVIOUR_MAP,
    api_capability,
)


def elf_imports(path: Path) -> list[str] | None:
    """The undefined ``.dynsym`` names of one ELF, or ``None`` when it is not one.

    Undefined is what makes a symbol an import: a defined one is the binary's
    own code, and counting it would credit a library with using itself.
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except ImportError:  # pragma: no cover - the analysis extra is not installed
        raise SystemExit("this needs pyelftools; run it with the tools extra") from None
    try:
        blob = path.read_bytes()
    except OSError:
        return None
    if blob[:4] != b"\x7fELF":
        return None
    try:
        elf = ELFFile(io.BytesIO(blob))
        names: set[str] = set()
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection) or section.name != ".dynsym":
                continue
            for symbol in section.iter_symbols():
                if symbol.entry["st_shndx"] == "SHN_UNDEF" and symbol.name:
                    names.add(str(symbol.name).split("@")[0])
        return sorted(names)
    except Exception:  # noqa: BLE001 — a file this parser cannot read is not a measurement
        return None


def walk(roots: list[str]) -> Iterator[tuple[str, list[str]]]:
    """``(name, imports)`` for every ELF under the given directories.

    Symlinks are skipped so a multicall binary behind twenty names is counted
    once rather than twenty times, which is what the percentages are of.
    """
    for root in roots:
        base = Path(root)
        if not base.is_dir():
            print(f"  (skipped {root}: not a directory)", file=sys.stderr)
            continue
        for entry in sorted(base.rglob("*")):
            if not entry.is_file() or entry.is_symlink():
                continue
            names = elf_imports(entry)
            if names:
                yield entry.name, names


def measure(roots: list[str], platform: str, behaviour_map: str, attck_map: str) -> dict:
    """Ask the catalogue about every binary and count what it answered."""
    group_seen: Counter[str] = Counter()
    group_labelled: Counter[str] = Counter()
    rule_fired: Counter[str] = Counter()
    labelled_names: dict[str, list[str]] = {}
    ruled_names: dict[str, list[str]] = {}
    total = 0
    labelled_binaries = 0
    ruled_binaries = 0

    for name, imports in walk(roots):
        total += 1
        answer = api_capability(
            imports, behaviour_map=behaviour_map, attck_map=attck_map, platform=platform
        )
        rows = answer.get("capabilities") or []
        for group in {r["category"] for r in rows if r.get("category")}:
            group_seen[group] += 1
        labelled = {r["category"] for r in rows if r.get("catalog_flags")}
        if labelled:
            labelled_binaries += 1
        for group in labelled:
            group_labelled[group] += 1
            labelled_names.setdefault(group, []).append(name)
        cleared = {hit["technique_id"] for r in rows for hit in r.get("techniques") or []}
        if cleared:
            ruled_binaries += 1
        for technique_id in cleared:
            rule_fired[technique_id] += 1
            ruled_names.setdefault(technique_id, []).append(name)

    behaviours = load_api_behaviour_db(behaviour_map, platform)
    return {
        "total": total,
        "labelled_binaries": labelled_binaries,
        "ruled_binaries": ruled_binaries,
        "group_seen": group_seen,
        "group_labelled": group_labelled,
        "rule_fired": rule_fired,
        "labelled_names": labelled_names,
        "ruled_names": ruled_names,
        "tiers": behaviours.tiers if behaviours else {},
    }


def report(result: dict, fail_over: float | None) -> int:
    """Print the counts and return the exit status."""
    total = result["total"]
    if not total:
        print("no ELF binary with a dynamic symbol table was found")
        return 1

    def share(count: int) -> str:
        return f"{count:>5} ({100 * count / total:5.2f}%)"

    print(f"binaries with a dynamic symbol table: {total}")
    print(f"carrying at least one labelled row:   {share(result['labelled_binaries'])}")
    print(f"carrying at least one technique row:  {share(result['ruled_binaries'])}")

    print("\nper behaviour group: appears on / labelled on")
    for group in sorted(result["group_seen"], key=lambda g: -result["group_seen"][g]):
        tier = result["tiers"].get(group, "?")
        print(
            f"  {group:<20} tier={tier:<14} appears {share(result['group_seen'][group])}"
            f"  labelled {share(result['group_labelled'][group])}"
        )

    print("\nper technique rule: fires on")
    if not result["rule_fired"]:
        print("  (none)")
    for technique_id in sorted(result["rule_fired"], key=lambda t: -result["rule_fired"][t]):
        print(f"  {technique_id:<14} {share(result['rule_fired'][technique_id])}")

    for heading, names in (
        ("labelled", result["labelled_names"]),
        ("clearing a technique rule", result["ruled_names"]),
    ):
        print(f"\nthe binaries {heading}")
        if not names:
            print("  (none)")
        for key in sorted(names):
            listed = ", ".join(sorted(set(names[key])))
            print(f"  {key}: {listed}")

    if fail_over is None:
        return 0
    over = [
        (key, count)
        for counts in (result["rule_fired"], result["group_labelled"])
        for key, count in counts.items()
        if 100 * count / total > fail_over
    ]
    if over:
        print(f"\nabove {fail_over}% of an ordinary system's own binaries:", file=sys.stderr)
        for key, count in sorted(over, key=lambda row: -row[1]):
            print(f"  {key}: {count} ({100 * count / total:.2f}%)", file=sys.stderr)
        return 1
    print(f"\nnothing fires above {fail_over}% of the binaries read")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure an API behaviour block against the ELF binaries on this host.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("roots", nargs="+", help="Directories to read ELF binaries from.")
    parser.add_argument("--platform", default="linux", help="Which block of the catalogue to ask.")
    parser.add_argument(
        "--behaviour-map", default=DEFAULT_API_BEHAVIOUR_MAP, help="The behaviour catalogue."
    )
    parser.add_argument("--attck-map", default=DEFAULT_API_ATTCK_MAP, help="The technique rules.")
    parser.add_argument(
        "--fail-over",
        type=float,
        default=None,
        metavar="PERCENT",
        help="Exit non-zero when a rule or a labelled group fires above this share.",
    )
    args = parser.parse_args()
    result = measure(args.roots, args.platform, args.behaviour_map, args.attck_map)
    return report(result, args.fail_over)


if __name__ == "__main__":
    raise SystemExit(main())
