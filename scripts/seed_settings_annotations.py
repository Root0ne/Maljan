"""Draft ANNOTATIONS for settings_annotations.py from .env.example comments.

For each ``KEY=`` line (commented or not) the comment block immediately above
it becomes the description; the key maps to the dotted path
(``LLM__OPENAI__BASE_URL`` -> ``llm.openai.base_url``). Leaves with no key in
.env.example get an empty description, which the catalog test rejects until a
person writes one. Prints Python to paste.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from maljan.core.settings_catalog import core_leaves  # noqa: E402

ENV = Path(__file__).resolve().parents[1] / ".env.example"
KEY = re.compile(r"^#?\s*([A-Z][A-Z0-9_]*)=")


def harvest() -> dict[str, str]:
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
