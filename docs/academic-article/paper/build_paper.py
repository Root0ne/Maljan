"""Assemble the paper: Markdown sections in, a single PDF out.

The sections stay authored in Markdown because that is where they have been
reviewed and revised. This script converts them and assembles the document, so
there is never a LaTeX copy of a paragraph drifting away from the Markdown one.

Three things it does beyond calling pandoc:

**Figure captions.** Sections write a figure as an image followed by a bold
paragraph starting `**Figure N:`. That reads correctly in Markdown, where the
caption must be visible text, but pandoc would emit an uncaptioned graphic and
a stray paragraph. The pattern is rewritten into a captioned figure before
conversion, so one caption serves both outputs.

**The anonymity check.** The system's name must not appear anywhere in the
built paper. This is enforced here rather than trusted to review: the build
fails, loudly, if the name survives into any converted section. A rule that is
only in someone's head is not a rule.

**A deferred title.** The title is written last, once the paper is finished, so
the document carries an explicit placeholder rather than a working title that
might quietly become permanent.

Run: .venv/bin/python docs/academic-article/paper/build_paper.py
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILD = HERE / "build"

# The name that must never reach the paper, in any casing.
FORBIDDEN = re.compile(r"maljan", re.IGNORECASE)

TITLE_PLACEHOLDER = r"\textbf{[TITLE DEFERRED --- written once the paper is complete]}"

# Ordered: (source markdown, LaTeX section command, section title)
SECTIONS: list[tuple[str, str]] = [
    ("E4-outline.md", "intro"),  # abstract + introduction are extracted from this
    ("../related-work.md", "Background and Related Work"),
    ("E3-system.md", "The System, Briefly"),
    ("E7-methodology.md", "Measurement Methodology"),
    ("E1-results.md", "Results"),
    ("E6-instrument-failures.md", "Instrument Failures"),
    ("E2-threats-to-validity.md", "Threats to Validity"),
    ("E8-conclusion.md", "Conclusion"),
]

APPENDIX = ("E5-reproducibility.md", "Reproducibility")

PREAMBLE = r"""
% Single column deliberately, for now. The paper carries many wide tables of
% measurements and pandoc renders them as longtable, which cannot live in a
% two-column body. Venue formatting is a last step anyway, and a draft whose
% tables are readable is worth more than one that looks like a proceedings.
\documentclass[11pt]{article}

% XeLaTeX, not pdfLaTeX: the text carries Δ, ×, ≥, — and Turkish-set quotation
% marks throughout, and escaping each one would put a rendering concern into
% every sentence that reports a paired difference.
\usepackage{fontspec}
\setmainfont{TeX Gyre Termes}
\setmonofont[Scale=0.85]{DejaVu Sans Mono}
\usepackage[margin=0.75in]{geometry}
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{array}
\usepackage{caption}
\usepackage{microtype}
\usepackage{xcolor}
\usepackage[hidelinks]{hyperref}
\usepackage{fancyvrb}
\usepackage{amsmath}
% pandoc computes table column widths as `\columnwidth * \real{0.23}`, which is
% calc's arithmetic, not a stub's.
\usepackage{calc}

\captionsetup{font=small,labelfont=bf,skip=6pt}
\setlength{\parskip}{2pt}
\graphicspath{{../}{./}}

% pandoc emits these for its own constructs
\providecommand{\tightlist}{%
  \setlength{\itemsep}{0pt}\setlength{\parskip}{0pt}}
\providecommand{\pandocbounded}[1]{#1}

\title{TITLEPLACEHOLDER}
\author{}
\date{}

\begin{document}
\maketitle
\begin{abstract}
ABSTRACTPLACEHOLDER
\end{abstract}
\vspace{0.6em}
"""


def rewrite_figures(md: str) -> str:
    """Fold a `**Figure N:` paragraph into the caption of the image above it."""
    pattern = re.compile(
        r"!\[[^\]]*\]\((?P<path>[^)]+)\)\s*\n\s*\n(?P<cap>\*\*Figure[^\n]*(?:\n(?!\n)[^\n]*)*)",
    )

    def repl(m: re.Match[str]) -> str:
        caption = " ".join(m.group("cap").split())
        return f"![{caption}]({m.group('path')})"

    return pattern.sub(repl, md)


def strip_draft_notes(md: str) -> str:
    """Drop the italic editorial note some sections open with."""
    lines = md.splitlines()
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("*Draft for the paper") or line.startswith("*Framing locked"):
            while i < len(lines) and lines[i].strip() != "":
                i += 1
            continue
        out.append(line)
        i += 1
    return "\n".join(out)


def extract_abstract(md: str) -> str:
    """Pull the block-quoted abstract out of the outline file."""
    block = re.search(r"## Abstract.*?\n(?P<body>(?:>.*\n|\n(?=>))+)", md)
    if not block:
        return "ABSTRACT NOT FOUND"
    text = "\n".join(line.lstrip("> ").rstrip() for line in block.group("body").splitlines())
    return "\n".join(p for p in text.split("\n"))


def extract_introduction(md: str) -> str:
    m = re.search(r"## Introduction \(draft\)\n(?P<body>.*)", md, re.S)
    return m.group("body") if m else ""


def pandoc(md_text: str, label: str) -> str:
    proc = subprocess.run(
        ["pandoc", "--from", "markdown+pipe_tables", "--to", "latex", "--wrap=preserve"],
        input=md_text,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(f"  pandoc failed on {label}:\n{proc.stderr[:400]}", file=sys.stderr)
        raise SystemExit(1)
    return proc.stdout


def demote_headings(tex: str) -> str:
    """The file's own `##` becomes a subsection under the paper's section."""
    tex = re.sub(r"\\subsubsection\{", r"\\paragraph{", tex)
    tex = re.sub(r"\\subsection\{", r"\\subsubsection{", tex)
    tex = re.sub(r"\\section\{", r"\\subsection{", tex)
    return tex


def check_anonymity(name: str, text: str) -> list[str]:
    return [f"{name}: {m.group(0)!r} at offset {m.start()}" for m in FORBIDDEN.finditer(text)]


def main() -> int:
    if not shutil.which("pandoc"):
        print("pandoc is required", file=sys.stderr)
        return 1
    BUILD.mkdir(exist_ok=True)

    outline = (HERE / "E4-outline.md").read_text()
    abstract_md = extract_abstract(outline)
    intro_md = extract_introduction(outline)

    violations: list[str] = []
    body: list[str] = []

    violations += check_anonymity("abstract", abstract_md)
    violations += check_anonymity("introduction", intro_md)

    body.append("\\section{Introduction}\n")
    body.append(demote_headings(pandoc(strip_draft_notes(intro_md), "introduction")))

    for filename, title in SECTIONS[1:]:
        src = (HERE / filename).resolve()
        if not src.exists():
            print(f"  skipping missing {filename}")
            continue
        md = strip_draft_notes(rewrite_figures(src.read_text()))
        violations += check_anonymity(filename, md)
        body.append(f"\n\\section{{{title}}}\n")
        body.append(demote_headings(pandoc(md, filename)))
        print(f"  converted {filename}")

    app_src = HERE / APPENDIX[0]
    if app_src.exists():
        md = strip_draft_notes(rewrite_figures(app_src.read_text()))
        violations += check_anonymity(APPENDIX[0], md)
        body.append("\n\\appendix\n")
        body.append(f"\n\\section{{{APPENDIX[1]}}}\n")
        body.append(demote_headings(pandoc(md, APPENDIX[0])))
        print(f"  converted {APPENDIX[0]} (appendix)")

    if violations:
        print("\nBUILD FAILED — the system name reached the paper:", file=sys.stderr)
        for v in violations[:20]:
            print(f"  {v}", file=sys.stderr)
        return 2

    abstract_tex = pandoc(abstract_md, "abstract")
    doc = (
        PREAMBLE.replace("TITLEPLACEHOLDER", TITLE_PLACEHOLDER).replace(
            "ABSTRACTPLACEHOLDER", abstract_tex
        )
        + "\n".join(body)
        + "\n\\end{document}\n"
    )
    tex_path = BUILD / "paper.tex"
    tex_path.write_text(doc)
    print(f"\nwrote {tex_path.relative_to(HERE.parent.parent.parent)}")

    proc = subprocess.run(
        ["latexmk", "-xelatex", "-interaction=nonstopmode", "-halt-on-error", "paper.tex"],
        cwd=BUILD,
        capture_output=True,
        text=True,
    )
    pdf = BUILD / "paper.pdf"
    if proc.returncode != 0 or not pdf.exists():
        log = (BUILD / "paper.log").read_text() if (BUILD / "paper.log").exists() else ""
        errs = [ln for ln in log.splitlines() if ln.startswith("!")][:12]
        print("latexmk failed:", file=sys.stderr)
        for e in errs or proc.stdout.splitlines()[-15:]:
            print(f"  {e}", file=sys.stderr)
        return 3

    pages = ""
    if shutil.which("pdfinfo"):
        info = subprocess.run(["pdfinfo", str(pdf)], capture_output=True, text=True).stdout
        m = re.search(r"Pages:\s+(\d+)", info)
        pages = f", {m.group(1)} pages" if m else ""
    print(f"built {pdf.relative_to(HERE.parent.parent.parent)}{pages}")
    print("anonymity check: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
