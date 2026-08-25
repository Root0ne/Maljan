"""Assemble what Editorial Manager asks for, from what the build already made.

Elsevier's guide is explicit that a PDF is not an acceptable source file, so the
manuscript goes up as LaTeX: main.tex, everything it \\input{}s, the bibliography
style's output, and the six figures that are actually included. The rendered PDF
rides along as the proof, not as the source.

Highlights go up as a separate editable file with the word "highlights" in its
name, which is the guide's wording. docs/academic-article/paper/highlights.md is
a working document: it carries the provenance table and the reasoning behind the
fourth bullet, and neither belongs in a submission. This writes the bullets
alone, and re-derives them from that file so the two cannot drift.

Run:  .venv/bin/python docs/academic-article/paper/make_submission.py
Output is gitignored; it is a rebuildable view of files already in the tree.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from pathlib import Path

_PAPER = Path(__file__).resolve().parent
_TEX = _PAPER / "tex"
_FIGS = _PAPER / "figures"
_OUT = _PAPER / "submission"

# Everything main.tex needs to compile from a clean directory. main.bbl is here
# rather than refs.bib alone because Editorial Manager does not run bibtex.
_SOURCES = [
    "main.tex",
    "abstract.tex",
    "related-work.tex",
    "facts.sty",
    "facts.tex",
    "refs.bib",
    "main.bbl",
    "tables/fallback-rows.tex",
]
_MAX_HIGHLIGHT_CHARS = 85


def _inputs_from_main() -> list[str]:
    """The \\input{} list, read from main.tex rather than kept in step by hand."""
    body = (_TEX / "main.tex").read_text(encoding="utf-8")
    body = re.sub(r"(?m)^\s*%.*$", "", body)
    return [f"{name}.tex" for name in re.findall(r"\\input\{([^}]+)\}", body)]


def _figures_from_tex() -> list[str]:
    """The figures actually included, so an unused variant cannot ride along."""
    found: set[str] = set()
    for tex in sorted(_TEX.glob("*.tex")):
        for match in re.findall(
            r"\\includegraphics\[[^\]]*\]\{figures/([^}]+)\}", tex.read_text(encoding="utf-8")
        ):
            found.add(match)
    return sorted(found)


def _highlight_bullets() -> list[str]:
    """The bullets under the title heading of highlights.md, minus the [n] counts."""
    md = (_PAPER / "highlights.md").read_text(encoding="utf-8")
    bullets: list[str] = []
    for line in md.splitlines():
        if not line.startswith("- "):
            continue
        text = re.sub(r"\s*\[\d+\]\s*$", "", line[2:].strip())
        if text.endswith("."):
            bullets.append(text)
        if len(bullets) == 5:
            break
    if not 3 <= len(bullets) <= 5:
        raise SystemExit(f"highlights.md yielded {len(bullets)} bullets, expected 3-5")
    for text in bullets:
        if len(text) > _MAX_HIGHLIGHT_CHARS:
            raise SystemExit(f"highlight over {_MAX_HIGHLIGHT_CHARS} chars: {text!r}")
    return bullets


def main() -> None:
    if _OUT.exists():
        shutil.rmtree(_OUT)
    (_OUT / "manuscript" / "figures").mkdir(parents=True)
    (_OUT / "manuscript" / "tables").mkdir(parents=True)

    wanted = dict.fromkeys(_SOURCES + _inputs_from_main())
    for name in wanted:
        src = _TEX / name
        if not src.exists():
            raise SystemExit(f"missing source: {src}")
        shutil.copy2(src, _OUT / "manuscript" / name)
    for fig in _figures_from_tex():
        shutil.copy2(_FIGS / fig, _OUT / "manuscript" / "figures" / fig)

    bundle = _OUT / "manuscript-latex.zip"
    root = _OUT / "manuscript"
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(root))

    shutil.copy2(_TEX / "main.pdf", _OUT / "manuscript.pdf")

    bullets = _highlight_bullets()
    md = _OUT / "highlights.md"
    md.write_text("\n".join(f"- {b}" for b in bullets) + "\n", encoding="utf-8")
    docx = _OUT / "highlights.docx"
    subprocess.run(["pandoc", str(md), "-o", str(docx)], check=True, capture_output=True)

    files = sorted(p for p in _OUT.rglob("*") if p.is_file() and root not in p.parents)
    print(f"submission bundle in {_OUT}")
    for path in files:
        print(f"  {path.relative_to(_OUT)}  ({path.stat().st_size:,} bytes)")
    print(f"  manuscript/  ({len(wanted)} source files, {len(_figures_from_tex())} figures)")
    for bullet in bullets:
        print(f"  highlight [{len(bullet)}]  {bullet}")


if __name__ == "__main__":
    main()
