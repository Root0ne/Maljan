"""Compile the paper, and refuse to compile a paper that is wrong in a checkable way.

The sources are LaTeX. They used to be Markdown converted at build time, which
meant the document a reader sees never existed as a file anyone edited: the
tables had no captions and no labels because pandoc cannot invent them, and the
derived numbers were substituted as text rather than defined as macros. Both are
fixed by the sources being what is compiled.

What is left here is the part that is not typesetting. Four gates, each of which
exists because the thing it checks went wrong:

**Facts must be current.** ``facts.tex`` is generated from the committed
per-sample records. If any artifact under ``tests/evaluation/`` changed after the
facts were derived, the paper would quote a number computed before the last run
finished. The gate compares content hashes rather than modification times,
because a checkout rewrites every mtime and ``touch`` clears an mtime gate
without recomputing anything.

**No unresolved macro.** ``\\fact{name}`` raises a LaTeX error when the name is
undefined, so a number the paper asks for and cannot get takes the build down
rather than going stale in it. That is enforced in ``facts.sty``; this script
also reads the log afterwards, because a LaTeX error under ``nonstopmode`` still
produces a PDF, and a build that "succeeded" with a hole in it is the failure the
whole mechanism exists to prevent.

**No stray symbol.** A Unicode minus is a dash-shaped glyph at text metrics, and
this paper reports several hundred signed numbers.

**Anonymity, over the assembled document.** The check this replaces ran section
by section and never saw the title or the preamble.

Run: .venv/bin/python docs/academic-article/paper/build_paper.py
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEX = HERE / "tex"
REPO = HERE.parent.parent.parent
EVAL = REPO / "tests" / "evaluation"

# The name that must never reach the paper, in any casing.
FORBIDDEN = re.compile(r"maljan", re.IGNORECASE)

# Mathematical symbols must already be maths by the time they reach the source.
SYMBOLS = "−×≥≤≫≪≈≠±→Δρασβμ…"

# Characters that break compilation or survive a copy-paste invisibly.
FORBIDDEN_CHARS = {
    "\u00a0": "non-breaking space",
    "\u00ad": "soft hyphen",
    "\u200b": "zero-width space",
    "\ufeff": "byte-order mark",
}

# Verbatim regions, where a symbol is a literal that must survive: an elided
# hash reads `d0de70ef…c4ea`, and turning that ellipsis into maths would put a
# dollar sign inside a monospace token.
VERBATIM = re.compile(
    r"\\texttt\{(?:[^{}]|\{[^{}]*\})*\}"
    r"|\\begin\{verbatim\}.*?\\end\{verbatim\}"
    r"|\\begin\{Shaded\}.*?\\end\{Shaded\}"
    r"|\\begin\{Highlighting\}.*?\\end\{Highlighting\}",
    re.S,
)

FACTS_JSON = EVAL / "paper_facts.json"
FACTS_TEX = TEX / "facts.tex"
STAMP = TEX / ".facts-inputs.sha256"


def source_files() -> list[Path]:
    """Every hand-authored source. ``facts.tex`` is generated and excluded."""
    return sorted(p for p in TEX.glob("*.tex") if p.name != "facts.tex")


def check_facts_current() -> list[str]:
    """The facts must have been derived from the artifacts now on disk.

    The digest is computed by ``paper_facts.py`` — the deriver is what knows what
    it derived from, and a builder that stamped its own inputs would be
    certifying itself.
    """
    if not FACTS_TEX.exists() or not FACTS_JSON.exists():
        return ["facts have not been derived — run: make facts"]
    sys.path.insert(0, str(REPO))
    from tests.evaluation.paper_facts import artifact_digest

    if not STAMP.exists() or STAMP.read_text().strip() != artifact_digest():
        return ["the results changed after the facts were derived — run: make facts"]
    return []


def check_symbols(name: str, tex: str) -> list[str]:
    found: list[str] = []
    for char, why in FORBIDDEN_CHARS.items():
        if char in tex:
            found.append(f"{name}: {why} (U+{ord(char):04X})")
    stripped = VERBATIM.sub(" ", tex)
    for char in SYMBOLS:
        if char in stripped:
            found.append(f"{name}: {char!r} outside verbatim — write it as maths")
    return found


def check_anonymity(name: str, tex: str) -> list[str]:
    return [f"{name}: {m.group(0)!r} at offset {m.start()}" for m in FORBIDDEN.finditer(tex)]


def check_facts_referenced() -> list[str]:
    """Every ``\\fact`` the sources ask for is defined.

    LaTeX catches this too, but a hundred lines into a log rather than as the
    first thing on the terminal.
    """
    if not FACTS_JSON.exists():
        return []
    known = {k.replace("_", "-") for k in json.loads(FACTS_JSON.read_text())}
    missing: list[str] = []
    for path in source_files():
        for m in re.finditer(r"\\fact\{([^}]*)\}", path.read_text()):
            if m.group(1) not in known:
                missing.append(f"{path.name}: no such fact — {m.group(1)}")
    return missing


def main() -> int:
    if not shutil.which("latexmk"):
        print("latexmk is required", file=sys.stderr)
        return 1

    violations: list[str] = []
    violations += check_facts_current()
    for path in source_files():
        text = path.read_text()
        violations += check_symbols(path.name, text)
        violations += check_anonymity(path.name, text)
    if FACTS_TEX.exists():
        violations += check_anonymity("facts.tex", FACTS_TEX.read_text())
    violations += check_facts_referenced()

    if violations:
        print("BUILD REFUSED:", file=sys.stderr)
        for v in violations[:25]:
            print(f"  {v}", file=sys.stderr)
        if len(violations) > 25:
            print(f"  ... and {len(violations) - 25} more", file=sys.stderr)
        return 2

    proc = subprocess.run(
        ["latexmk", "-xelatex", "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
        cwd=TEX,
        capture_output=True,
        text=True,
    )
    pdf = TEX / "main.pdf"
    log = (TEX / "main.log").read_text() if (TEX / "main.log").exists() else ""
    if proc.returncode != 0 or not pdf.exists():
        errs = [ln for ln in log.splitlines() if ln.startswith("!")][:12]
        print("latexmk failed:", file=sys.stderr)
        for e in errs or proc.stdout.splitlines()[-15:]:
            print(f"  {e}", file=sys.stderr)
        return 3

    hard = [ln for ln in log.splitlines() if ln.startswith("!") or "multiply defined" in ln]
    if hard:
        print("BUILD REFUSED — LaTeX reported errors and produced a PDF anyway:", file=sys.stderr)
        for h in hard[:10]:
            print(f"  {h}", file=sys.stderr)
        return 4

    pages = ""
    if shutil.which("pdfinfo"):
        info = subprocess.run(["pdfinfo", str(pdf)], capture_output=True, text=True).stdout
        m = re.search(r"Pages:\s+(\d+)", info)
        pages = f", {m.group(1)} pages" if m else ""
    print(f"built {pdf.relative_to(REPO)}{pages}")
    print("facts current, symbols clean, anonymity clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
