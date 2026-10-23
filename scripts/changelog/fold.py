"""Fold the fragments in ``changelog.d/`` into the Unreleased section of CHANGELOG.md.

Every pull request adds its own fragment file instead of editing
``CHANGELOG.md``, so two open pull requests never touch the same lines. A
fragment holds one or more ``### <Section>`` blocks whose text is written as it
should read in the changelog. Folding puts each block at the top of the first
matching section under Unreleased (the section is created at the end of
Unreleased when it is missing), ordered by section and then by file name, and
deletes the folded fragments. Running it again with no fragments left changes
nothing. Run from the repository root:

    python scripts/changelog/fold.py          # fold and delete the fragments
    python scripts/changelog/fold.py --check  # validate only; exit 1 on a problem
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
CHANGELOG = ROOT / "CHANGELOG.md"
FRAGMENTS = ROOT / "changelog.d"

# Output order of the sections of one fold; also the set a fragment may use.
SECTIONS = (
    "Added",
    "Changed",
    "Deprecated",
    "Removed",
    "Fixed",
    "Security",
    "Documentation",
    "Upgrading",
)

_HEADING = re.compile(r"^### (.+?)\s*$")
_CONFLICT = re.compile(r"^(<{7}|={7}|>{7})(\s|$)")
_UNRELEASED = "## Unreleased"


class Entry(NamedTuple):
    section: str
    source: str
    text: str


def _fragment_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.glob("*.md") if p.name.lower() != "readme.md")


def parse_fragment(path: Path) -> tuple[list[Entry], list[str]]:
    """Return the entries of one fragment and the problems found in it."""
    entries: list[Entry] = []
    problems: list[str] = []
    name = path.name
    lines = path.read_text(encoding="utf-8").splitlines()
    current: str | None = None
    body: list[str] = []
    seen: set[str] = set()

    def close() -> None:
        if current is None:
            return
        text = "\n".join(body).strip()
        if not text:
            problems.append(f"{name}: section '{current}' is empty")
        else:
            entries.append(Entry(current, name, text))

    for number, line in enumerate(lines, 1):
        if _CONFLICT.match(line):
            problems.append(f"{name}:{number}: conflict marker")
            continue
        heading = _HEADING.match(line)
        if heading:
            close()
            current = heading.group(1)
            body = []
            if current not in SECTIONS:
                problems.append(f"{name}:{number}: unknown section '{current}'")
                current = None
            elif current in seen:
                problems.append(f"{name}:{number}: section '{current}' repeated")
                current = None
            else:
                seen.add(current)
            continue
        if current is None:
            if line.strip():
                problems.append(f"{name}:{number}: text outside a known '### <Section>' block")
            continue
        body.append(line)
    close()
    if not any(line.strip() for line in lines):
        problems.append(f"{name}: empty")
    return entries, problems


def collect(directory: Path) -> tuple[list[Entry], list[str], list[Path]]:
    files = _fragment_files(directory)
    entries: list[Entry] = []
    problems: list[str] = []
    for path in files:
        found, bad = parse_fragment(path)
        entries.extend(found)
        problems.extend(bad)
    entries.sort(key=lambda e: (SECTIONS.index(e.section), e.source))
    return entries, problems, files


def fold_text(changelog: str, entries: list[Entry]) -> str:
    """Return the changelog with the entries folded under Unreleased."""
    if not entries:
        return changelog
    lines = changelog.split("\n")
    try:
        start = lines.index(_UNRELEASED)
    except ValueError:
        raise ValueError(f"CHANGELOG.md has no '{_UNRELEASED}' section") from None
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].startswith("## "):
            end = i
            break
    by_section: dict[str, list[str]] = {}
    for entry in entries:
        by_section.setdefault(entry.section, []).append(entry.text)
    for section, texts in by_section.items():
        block = "\n\n".join(texts).split("\n")
        heading = f"### {section}"
        at = next((i for i in range(start + 1, end) if lines[i] == heading), None)
        if at is None:
            tail = end
            while tail > start + 1 and not lines[tail - 1].strip():
                tail -= 1
            new = ["", heading, "", *block]
            lines[tail:tail] = new
        else:
            new = [*block, ""]
            lines[at + 2 : at + 2] = new
        end += len(new)
    text = "\n".join(lines)
    return text if text.endswith("\n") else text + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--check", action="store_true", help="validate fragments, write nothing")
    parser.add_argument("--changelog", type=Path, default=CHANGELOG)
    parser.add_argument("--fragments", type=Path, default=FRAGMENTS)
    args = parser.parse_args(argv)

    entries, problems, files = collect(args.fragments)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    if args.check:
        print(f"{len(files)} fragment(s) valid")
        return 0
    if not files:
        print("no fragments to fold")
        return 0
    original = args.changelog.read_text(encoding="utf-8")
    try:
        folded = fold_text(original, entries)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    args.changelog.write_text(folded, encoding="utf-8")
    for path in files:
        path.unlink()
    print(f"folded {len(files)} fragment(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
