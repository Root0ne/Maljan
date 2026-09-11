"""Retired: drafted ANNOTATIONS for settings_annotations.py from .env.example.

This harvested a description for each ``core.*`` leaf from the comment block
above its ``KEY=`` line in the root ``.env.example`` (``LLM__OPENAI__BASE_URL``
-> ``llm.openai.base_url``). That file was deleted when application settings
moved into the settings store (2026-09-11; see
``git log -- docs/specs docs/plans docs/superpowers`` for the design record) and
replaced by ``bootstrap.env.example``, which documents only the bootstrap
contract (``DATABASE_URL``, ``JWT_SECRET_KEY``, ...) and carries none of the
``core.*`` comment blocks this script needs — pointing it there would silently
produce an empty description for every leaf.

Kept only for the historical record of how the entries already in
``settings_annotations.py`` were drafted. A new leaf needs its title and
description written by hand there directly; running this script now raises
rather than pretending to still work.
"""

from __future__ import annotations

import re
from pathlib import Path

from maljan.core.settings_catalog import core_leaves

ENV = Path(__file__).resolve().parents[2] / ".env.example"
KEY = re.compile(r"^#?\s*([A-Z][A-Z0-9_]*)=")


def harvest() -> dict[str, str]:
    if not ENV.exists():
        raise SystemExit(
            f"{ENV} no longer exists: it was deleted when application settings moved "
            "into the settings store. This script is retired — write new "
            "ANNOTATIONS entries by hand in src/maljan/core/settings_annotations.py."
        )
    docs: dict[str, str] = {}
    block: list[str] = []
    for raw in ENV.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        m = KEY.match(line)
        if m:
            path = m.group(1).lower().replace("__", ".")
            text = " ".join(b for b in block if b)
            docs.setdefault(path, text)
            block = []
            continue
        if line.startswith("#") and not set(line) <= {"#", "=", " ", "-"}:
            block.append(line.lstrip("# ").strip())
        elif not line.strip():
            block = []
    return docs


def main() -> None:
    docs = harvest()
    print("ANNOTATIONS: dict[str, Annotation] = {")
    for leaf in core_leaves():
        title = leaf.path.rsplit(".", 1)[-1].replace("_", " ").capitalize()
        desc = docs.get(leaf.path, "").replace('"', "'")
        print(f'    "{leaf.path}": {{"title": "{title}", "description": "{desc}"}},')
    print("}")


if __name__ == "__main__":
    main()
