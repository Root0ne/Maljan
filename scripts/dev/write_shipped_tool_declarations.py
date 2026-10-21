"""Write the frozen record of the tool declarations every release shipped.

``apps/api/alembic/versions/20261012000000_shipped_tool_declarations.json`` is
read by the revision beside it to tell which release wrote a stored map of a
built-in block's tool declarations. It is frozen: it holds what each of the
releases below shipped, so it never changes. This script rebuilds it from the
git history instead of by hand: for each release it exports the commit's
``src`` and ``data`` trees, builds that release's settings from no override
in a fresh interpreter, and dumps each block's shipped ``tool_facts``. Entries
leave out the fields at their default; each block keeps its distinct shipped
states in release order, with the releases that shipped each.

It needs the full history (every commit named in ``RELEASES``) and the
interpreter's packages for the application's dependencies. Run from the
repository root:

    python scripts/dev/write_shipped_tool_declarations.py          # rewrite the record
    python scripts/dev/write_shipped_tool_declarations.py --check  # exit 1 if it differs
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
RECORD = ROOT / "apps/api/alembic/versions/20261012000000_shipped_tool_declarations.json"

# The first-parent commits of dev from the one that introduced declared tool
# facts (#257) to the last one before the revision, in release order.
RELEASES: tuple[str, ...] = (
    "7c988f65",
    "a8d98e4c",
    "f96cb89f",
    "5e1f1792",
    "bc6fd6be",
    "1f415b17",
    "a0ee72ba",
    "2c2522b2",
    "3770a52c",
    "871ebf23",
    "e2c0bfc2",
    "767bd97a",
    "174bd387",
    "ba27771a",
    "5520f868",
    "5596cb4e",
    "83469e98",
)

ABOUT = (
    "The tool declarations each built-in block shipped in every release that could have "
    "stored a block's tool declarations whole, one entry per tool and version with the "
    "fields at their default left out, and per block the distinct shipped states in "
    "release order (each a tool -> version index, with the releases that shipped it). "
    "Frozen: read only by the revision beside it."
)

# What the exported tree's interpreter prints: the default declaration and, per
# block that ships declarations, its declarations.
_DUMP = r"""
import json
from maljan.core.settings_overrides import build_settings
from maljan.core.tool_declarations import ToolFacts



def defaults():
    # ``kind`` has no default (a declaration of no kind says so with ``""``).
    out = {}
    for name, field in ToolFacts.model_fields.items():
        out[name] = "" if field.is_required() else field.get_default(call_default_factory=True)
    return json.loads(json.dumps(out))


dump = build_settings({}).model_dump(mode="json")
blocks = {}


def walk(node, path):
    if isinstance(node, dict):
        held = node.get("tool_facts")
        if isinstance(held, dict) and held:
            blocks[path] = held
        for key, value in node.items():
            if key != "tool_facts":
                walk(value, f"{path}.{key}" if path else key)


walk(dump, "")
print(json.dumps({"defaults": defaults(), "blocks": blocks}))
"""


def _export(commit: str, into: Path) -> None:
    """The commit's ``src``, ``data`` and ``pyproject.toml``, extracted under ``into``."""
    archive = subprocess.run(
        ["git", "-C", str(ROOT), "archive", commit, "src", "data", "pyproject.toml"],
        check=True,
        capture_output=True,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(into, filter="data")


def shipped_at(commit: str) -> dict[str, Any]:
    """The default declaration and each block's declarations as ``commit`` shipped them."""
    with tempfile.TemporaryDirectory(prefix="shipped-declarations-") as tmp:
        tree = Path(tmp)
        _export(commit, tree)
        # No setting of the machine reaches the dump: only the interpreter's way
        # to its packages and the tree's own sources.
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(tree / "src")}
        done = subprocess.run(
            [sys.executable, "-c", _DUMP],
            check=False,
            capture_output=True,
            text=True,
            cwd=tree,
            env=env,
        )
    if done.returncode:
        raise SystemExit(f"{commit}: the settings did not build\n{done.stderr}")
    last = done.stdout.strip().splitlines()[-1]
    shipped: dict[str, Any] = json.loads(last)
    return shipped


def compose(dumps: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    """The record from each release's dump, in release order."""
    defaults = dumps[-1][1]["defaults"]
    for commit, dump in dumps:
        # An earlier release may lack a field a later one added (it then held
        # that field's default); a field both have must default alike.
        if any(defaults[k] != v for k, v in dump["defaults"].items()):
            raise SystemExit(f"{commit} declares other defaults than the last release")
    names = sorted({block for _, dump in dumps for block in dump["blocks"]})
    blocks: dict[str, Any] = {}
    for name in names:
        versions: dict[str, list[dict[str, Any]]] = {}
        states: list[dict[str, int]] = []
        releases: list[list[str]] = []
        for commit, dump in dumps:
            held = dump["blocks"].get(name)
            if held is None:
                raise SystemExit(f"{commit} ships no declarations for {name}")
            state: dict[str, int] = {}
            for tool, declaration in held.items():
                entry = {k: v for k, v in declaration.items() if defaults.get(k) != v}
                seen = versions.setdefault(tool, [])
                if entry not in seen:
                    seen.append(entry)
                state[tool] = seen.index(entry)
            if state in states:
                releases[states.index(state)].append(commit)
            else:
                states.append(state)
                releases.append([commit])
        blocks[name] = {
            "releases": releases,
            "states": [dict(sorted(s.items())) for s in states],
            "versions": dict(sorted(versions.items())),
        }
    return {"_about": ABOUT, "blocks": blocks, "defaults": defaults}


def rendered() -> str:
    """The record as it is committed: sorted keys, one space of indent, a final newline."""
    dumps = [(commit, shipped_at(commit)) for commit in RELEASES]
    return json.dumps(compose(dumps), indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when the record differs")
    args = parser.parse_args()
    text = rendered()
    if args.check:
        if RECORD.read_text(encoding="utf-8") != text:
            print(f"{RECORD} differs from the generated record", file=sys.stderr)
            return 1
        return 0
    RECORD.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
