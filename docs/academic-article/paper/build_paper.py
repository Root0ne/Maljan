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

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILD = HERE / "build"

# The name that must never reach the paper, in any casing.
FORBIDDEN = re.compile(r"maljan", re.IGNORECASE)

# Set 2026-08-15, applying the choice recorded in E4-outline.md's "Working title"
# section rather than making a new one: the contribution is the discipline, and
# the negatives are evidence for it rather than the subject. Deferred until the
# paper was complete, which was the standing instruction.
TITLE = (
    "What It Takes to Trust a Measurement:\\\\ "
    "Instrument Failures in an LLM Malware-Analysis Pipeline"
)

# Ordered: (source markdown, LaTeX section command, section title)
SECTIONS: list[tuple[str, str]] = [
    ("E4-outline.md", "intro"),  # abstract + introduction are extracted from this
    ("../related-work.md", "Background and Related Work"),
    ("E3-system.md", "The System, Briefly"),
    ("E7-methodology.md", "Measurement Methodology"),
    ("E1-results.md", "Results"),
    ("E6-instrument-failures.md", "Instrument Failures"),
    ("E0-discussion.md", "Discussion"),
    ("E2-threats-to-validity.md", "Threats to Validity"),
    ("E8-conclusion.md", "Conclusion"),
    # Many venues want these before the bibliography; both are unnumbered, which
    # is why they are emitted with \section* rather than joining the count.
    ("E9-declarations.md", "Declarations"),
    ("EA-references.md", "References"),
]

# Sections that carry no number: declarations and the bibliography are apparatus,
# not argument, and numbering them makes the paper look like it has ten results
# chapters.
UNNUMBERED = {"Declarations", "References"}

APPENDIX = ("E5-reproducibility.md", "Reproducibility")

PREAMBLE = r"""
% Single column deliberately, for now. The paper carries many wide tables of
% measurements and pandoc renders them as longtable, which cannot live in a
% two-column body. Venue formatting is a last step anyway, and a draft whose
% tables are readable is worth more than one that looks like a proceedings.
\documentclass[11pt]{article}

% XeLaTeX, not pdfLaTeX. The sources are UTF-8 throughout and the em dashes,
% quotation marks and accented author names in the bibliography all resolve
% without an encoding package. Mathematical symbols do NOT reach here as
% literals: build_paper translates them to maths after pandoc and fails the
% build on any that survive, because a Unicode minus is a dash-shaped glyph at
% text metrics and this paper reports several hundred signed numbers.
\usepackage{fontspec}
\setmainfont{TeX Gyre Termes}
\setmonofont[Scale=0.85]{DejaVu Sans Mono}
% Maths in the body's own family. Without this, fontspec leaves maths to
% Computer Modern, so the moment the symbol translator emits its first $-$ the
% document embeds CMMI10, CMR10 and CMSY10 alongside Termes — three extra
% families, and a minus sign that does not match the digits either side of it.
% Caught by the conformance check counting font families, not by reading the page.
\usepackage{unicode-math}
\setmathfont{TeX Gyre Termes Math}
\usepackage[margin=0.75in]{geometry}
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{array}
\usepackage{caption}
\usepackage{microtype}
\usepackage{xcolor}
\usepackage[hidelinks]{hyperref}
% A section title containing maths becomes a PDF bookmark, and unicode-math's
% symbols are not expandable in that string — the build died on "Improper
% alphabetic constant" the moment a heading carried a translated multiplication
% sign. This tells hyperref what to write instead.
\pdfstringdefDisableCommands{%
  \def\times{x}\def\Delta{Delta}\def\rho{rho}\def\alpha{alpha}%
  \def\beta{beta}\def\sigma{sigma}\def\mu{mu}%
  \def\ge{>=}\def\le{<=}\def\gg{>>}\def\ll{<<}%
  \def\approx{~}\def\neq{!=}\def\pm{+/-}\def\rightarrow{->}%
}
\usepackage{fancyvrb}
\usepackage{amsmath}
% pandoc computes table column widths as `\columnwidth * \real{0.23}`, which is
% calc's arithmetic, not a stub's.
\usepackage{calc}

% Long code literals in narrow table columns overrun their neighbour: the
% appendix rendered "judge_contribution_{uncapped,cappe}.json the judge stu..."
% and an endpoint name printed on top of the column beside it. Verbatim text has
% no discretionary break points, so a cell wider than its column simply keeps
% going. Allowing breaks inside \texttt fixes the class rather than the instances.
\usepackage[htt]{hyphenat}
% Figures are drawn at 7.2in and the text block is 7.0in, so every one overran by
% a couple of hundredths of an inch — invisible on screen, an overfull box in the
% log, and a figure hanging into the margin on paper. Bound them to the measure
% rather than trusting each figure's own size.
\setkeys{Gin}{width=\linewidth,keepaspectratio}
% And let TeX loosen a line rather than push a word past the margin. Ugly spacing
% is a worse-looking page; an overfull line is an unreadable one.
\sloppy
% \sloppy sets \hfuzz=0.5pt, which stops sub-half-point overruns being reported
% at all. A zero-overfull log bought that way is not the same as a zero-overfull
% document, so the tolerance goes back to nothing and the zero has to be earned.
\hfuzz=0pt
\vfuzz=0pt


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


_EDITORIAL_QUOTE = re.compile(
    r"\*\*Draft|\*\*Revised \d|Organising principle:|research-briefs/|"
    r"must be resolved to their own records|CITATION-AUDIT"
)


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
        # Block-quoted editorial preambles: related-work.md opens with one that
        # names internal files and dates the draft, and it was reaching the PDF as
        # the first paragraph of the Related Work section.
        if line.startswith(">") and _EDITORIAL_QUOTE.search(line):
            while i < len(lines) and (lines[i].startswith(">") or lines[i].strip() == ""):
                if lines[i].strip() == "" and not (
                    i + 1 < len(lines) and lines[i + 1].startswith(">")
                ):
                    break
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
    """The introduction, and nothing the outline keeps after it.

    ``E4-outline.md`` is a working file: after the introduction it carries
    planning sections — "Methodology (to write)", "Conclusion (to write)" — that
    exist to track what still needed writing. Taking everything to end-of-file put
    those in the paper as §1.0.1 and §1.0.2, so the built PDF contained its own
    to-do list as subsections of the introduction, duplicating §4 and §8 which
    were by then fully written. Caught by reading the assembled PDF; invisible in
    the source, where they are obviously notes.
    """
    m = re.search(r"## Introduction \(draft\)\n(?P<body>.*)", md, re.S)
    if not m:
        return ""
    body = m.group("body")
    # Stop at the first heading that announces itself as unwritten.
    cut = re.search(r"^## .*\(to write", body, re.M)
    return body[: cut.start()] if cut else body


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


FACTS_PATH = HERE.parent.parent.parent / "tests" / "evaluation" / "paper_facts.json"
_PLACEHOLDER = re.compile(r"\{\{([a-z0-9_]+)\}\}")


def load_facts() -> dict[str, str]:
    """Numbers derived from the record, for substitution into the prose.

    Written by ``tests/evaluation/paper_facts.py`` from the committed per-sample
    artifacts. Absent, the build fails rather than emitting a paper with holes in
    it — a placeholder rendered literally would be visible, but a build that
    quietly skipped substitution would not.
    """
    if not FACTS_PATH.exists():
        print(
            f"missing {FACTS_PATH.name} — run tests/evaluation/paper_facts.py first",
            file=sys.stderr,
        )
        raise SystemExit(1)

    # Deriving the numbers only helps if the derivation is current. Without this
    # the staleness simply moves one level: the paper would faithfully quote a
    # facts file computed before the last run finished. Any artifact newer than
    # the facts stops the build rather than being averaged into a plausible page.
    facts_mtime = FACTS_PATH.stat().st_mtime
    newer = [
        p.name
        for p in FACTS_PATH.parent.glob("*.json")
        if p != FACTS_PATH and p.stat().st_mtime > facts_mtime + 1
    ]
    if newer:
        print(
            "BUILD FAILED — these results changed after the facts were derived:",
            file=sys.stderr,
        )
        for n in sorted(newer)[:12]:
            print(f"  {n}", file=sys.stderr)
        print("  re-run tests/evaluation/paper_facts.py", file=sys.stderr)
        raise SystemExit(1)

    return json.loads(FACTS_PATH.read_text())


def substitute_facts(md: str, facts: dict[str, str], label: str) -> tuple[str, list[str]]:
    """Replace ``{{name}}`` with the derived value; report every name that is not one.

    Unresolved placeholders are returned rather than raised so the build can list
    all of them at once. They are fatal: a number the paper asks for and cannot
    get is the failure this whole mechanism exists to make loud, and the four
    drifts that motivated it were all silent.
    """
    missing: list[str] = []

    def repl(m: re.Match[str]) -> str:
        name = m.group(1)
        if name not in facts:
            missing.append(f"{label}: {{{{{name}}}}}")
            return m.group(0)
        return facts[name]

    return _PLACEHOLDER.sub(repl, md), missing


def strip_own_title(md: str) -> str:
    """Drop the file's leading H1 — the build already emitted a section title.

    Every source file opens with its own `# Results` / `# Conclusion`. Demoting
    that to a subsection produced "5 Results" immediately followed by
    "5.1 Results" in the PDF, on every section. The build owns the section title;
    the file's copy of it is redundant by construction.
    """
    return re.sub(r"\A\s*#(?!#)[^\n]*\n", "", md, count=1)


# Mathematical symbols that reach the source as literal UTF-8. XeLaTeX renders
# them, which is why they were left alone — but rendering is not the whole
# question. A Unicode minus pasted into text is a dash-shaped glyph at
# text-metrics, not a true minus at maths metrics, so "−0.016" and "$-0.016$"
# print differently and inconsistently across a paper that reports several
# hundred signed numbers. The same argument applies to the multiplication sign
# and to Greek letters used as variables. Translated once, here, rather than
# left to whoever types the next paired difference.
_SYMBOLS = {
    "−": "$-$",  # MINUS SIGN
    "×": "$\\times$",
    "≥": "$\\ge$",
    "≤": "$\\le$",
    "≫": "$\\gg$",
    "≪": "$\\ll$",
    "≈": "$\\approx$",
    "≠": "$\\neq$",
    "±": "$\\pm$",
    "→": "$\\rightarrow$",
    "Δ": "$\\Delta$",
    "ρ": "$\\rho$",
    "α": "$\\alpha$",
    "β": "$\\beta$",
    "σ": "$\\sigma$",
    "μ": "$\\mu$",
    "…": "\\ldots{}",
}

# Characters that must never reach the .tex at all: they either break
# compilation or survive a copy-paste invisibly.
_FORBIDDEN_CHARS = {
    " ": "non-breaking space",
    "­": "soft hyphen",
    "​": "zero-width space",
    "﻿": "byte-order mark",
    "‘": "left single quote",
    "’": "right single quote",
    "“": "left double quote",
    "”": "right double quote",
}

# Verbatim regions of pandoc's LaTeX output, where a symbol is a literal that
# must survive: an elided hash reads `d0de70ef…c4ea` and turning that ellipsis
# into maths would put a dollar sign inside a monospace token.
_TEX_VERBATIM = re.compile(
    r"\\texttt\{(?:[^{}]|\{[^{}]*\})*\}"
    r"|\\begin\{verbatim\}.*?\\end\{verbatim\}"
    r"|\\begin\{Shaded\}.*?\\end\{Shaded\}"
    r"|\\begin\{Highlighting\}.*?\\end\{Highlighting\}",
    re.S,
)


def translate_symbols(tex: str) -> str:
    """Rewrite mathematical Unicode as maths in pandoc's output.

    Applied **after** pandoc rather than before it. Doing it in the markdown
    looked simpler and produced a broken document: pandoc only reads ``$...$`` as
    maths when the closing dollar is not followed by a digit, so ``$\approx$22k``
    came through as two literal dollar signs and LaTeX then failed with
    "Missing $ inserted". Operating on the LaTeX has no such rule.
    """

    def convert(text: str) -> str:
        for char, latex in _SYMBOLS.items():
            text = text.replace(char, latex)
        return text

    out: list[str] = []
    last = 0
    for m in _TEX_VERBATIM.finditer(tex):
        out.append(convert(tex[last : m.start()]))
        out.append(m.group(0))
        last = m.end()
    out.append(convert(tex[last:]))
    return "".join(out)


def check_symbols(name: str, tex: str) -> list[str]:
    """Report any hazard character that survived translation."""
    found: list[str] = []
    for char, why in _FORBIDDEN_CHARS.items():
        if char in tex:
            found.append(f"{name}: {why} (U+{ord(char):04X})")
    stripped = _TEX_VERBATIM.sub(" ", tex)
    for char in _SYMBOLS:
        if char in stripped:
            found.append(f"{name}: untranslated U+{ord(char):04X} outside verbatim")
    return found


_MANUAL_NUMBER = re.compile(r"^(#{2,6})\s+\d+(?:\.\d+)*\.?\s+", re.M)


def strip_manual_numbers(md: str) -> str:
    """Remove hand-written section numbers from headings; LaTeX numbers them.

    `## 4.1 Equal budgets` rendered as "4.1.1 4.1 Equal budgets" — the author's
    number colliding with the counter. The numbers are useful in the source files,
    which are read on their own, so they are stripped at build time rather than
    deleted.
    """
    return _MANUAL_NUMBER.sub(r"\1 ", md)


_TABLE_WIDTH = re.compile(r"\(\\linewidth - (\d+)\\tabcolsep\)")


def fit_table_widths(tex: str) -> str:
    r"""Shave two points off every pandoc longtable's measure.

    pandoc writes each column as a fraction of the line, and six equal columns
    come out as ``\real{0.1667}`` six times — which sums to 1.0002. The excess is
    a hundredth of a point, invisible on the page and three overfull boxes in the
    log, and it only became visible once ``\hfuzz`` was set back to zero. Reducing
    the intercolumn padding does not help, because pandoc has already subtracted
    it. Taking two points off the measure absorbs any rounding of this kind for
    any column count, and two points across a seven-inch line is not a layout a
    reader can see.
    """
    return _TABLE_WIDTH.sub(r"(\\linewidth - \1\\tabcolsep - 2pt)", tex)


def demote_headings(tex: str) -> str:
    """Guard against a stray top-level heading; the levels already line up.

    With the file's leading H1 removed by ``strip_own_title``, pandoc's natural
    mapping is already correct: the build emits ``\\section``, the file's ``##``
    becomes ``\\subsection``, its ``###`` a ``\\subsubsection``. The previous
    version demoted everything one further step to make room for the duplicated
    title, which is what produced "4.1.1 4.1 Equal budgets" in the PDF.

    Only a *second* H1 in a source file would still reach here as ``\\section``
    and break out of the numbering. Every file has exactly one today, so this
    rewrites that case rather than trusting it to stay true.
    """
    return re.sub(r"\\section\{", r"\\subsection{", tex)


def check_anonymity(name: str, text: str) -> list[str]:
    return [f"{name}: {m.group(0)!r} at offset {m.start()}" for m in FORBIDDEN.finditer(text)]


def main() -> int:
    if not shutil.which("pandoc"):
        print("pandoc is required", file=sys.stderr)
        return 1
    BUILD.mkdir(exist_ok=True)

    facts = load_facts()
    unresolved: list[str] = []

    outline = (HERE / "E4-outline.md").read_text()
    abstract_md = extract_abstract(outline)
    intro_md = extract_introduction(outline)

    violations: list[str] = []
    body: list[str] = []

    violations += check_anonymity("abstract", abstract_md)
    violations += check_anonymity("introduction", intro_md)

    body.append("\\section{Introduction}\n")
    abstract_md, miss = substitute_facts(abstract_md, facts, "abstract")
    unresolved += miss
    intro_md, miss = substitute_facts(intro_md, facts, "introduction")
    unresolved += miss
    intro_clean = strip_manual_numbers(strip_draft_notes(intro_md))
    intro_tex = translate_symbols(pandoc(intro_clean, "introduction"))
    violations += check_symbols("introduction", intro_tex)
    body.append(fit_table_widths(demote_headings(intro_tex)))

    for filename, title in SECTIONS[1:]:
        src = (HERE / filename).resolve()
        if not src.exists():
            print(f"  skipping missing {filename}")
            continue
        md = strip_draft_notes(rewrite_figures(src.read_text()))
        md = strip_manual_numbers(strip_own_title(md))
        md, miss = substitute_facts(md, facts, filename)
        unresolved += miss
        violations += check_anonymity(filename, md)
        star = "*" if title in UNNUMBERED else ""
        section_tex = translate_symbols(pandoc(md, filename))
        violations += check_symbols(filename, section_tex)
        body.append(f"\n\\section{star}{{{title}}}\n")
        body.append(fit_table_widths(demote_headings(section_tex)))
        print(f"  converted {filename}")

    app_src = HERE / APPENDIX[0]
    if app_src.exists():
        md = strip_draft_notes(rewrite_figures(app_src.read_text()))
        md = strip_manual_numbers(strip_own_title(md))
        md, miss = substitute_facts(md, facts, APPENDIX[0])
        unresolved += miss
        violations += check_anonymity(APPENDIX[0], md)
        appendix_tex = translate_symbols(pandoc(md, APPENDIX[0]))
        violations += check_symbols(APPENDIX[0], appendix_tex)
        body.append("\n\\appendix\n")
        body.append(f"\n\\section{{{APPENDIX[1]}}}\n")
        body.append(fit_table_widths(demote_headings(appendix_tex)))
        print(f"  converted {APPENDIX[0]} (appendix)")

    if unresolved:
        print("\nBUILD FAILED — the paper asked for numbers that do not exist:", file=sys.stderr)
        for u in unresolved:
            print(f"  {u}", file=sys.stderr)
        return 1

    if violations:
        print("\nBUILD FAILED — characters that must not reach the .tex:", file=sys.stderr)
        for v in violations[:20]:
            print(f"  {v}", file=sys.stderr)
        return 2

    abstract_tex = translate_symbols(pandoc(abstract_md, "abstract"))
    violations += check_symbols("abstract", abstract_tex)
    if violations:
        print("\nBUILD FAILED — characters that must not reach the .tex:", file=sys.stderr)
        for v in violations[:20]:
            print(f"  {v}", file=sys.stderr)
        return 2
    doc = (
        PREAMBLE.replace("TITLEPLACEHOLDER", TITLE).replace("ABSTRACTPLACEHOLDER", abstract_tex)
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
