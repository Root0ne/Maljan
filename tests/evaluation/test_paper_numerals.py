"""No measurement in the paper's prose may be a hand-typed numeral.

Every number the paper states about its own results has to come from a
``{{placeholder}}`` resolved out of ``paper_facts.json``, so that re-running the
analysis updates the paper and drift becomes impossible. That was the intent;
the mechanism covered about a tenth of the numbers and nothing checked the rest.
The gate that existed, ``strip_manual_numbers``, is a heading-cosmetics function
whose name promises this and does something else — it removes author-written
section numbers from headings.

This is the missing half. It reads the section markdown, strips everything a
numeral is legitimately allowed to appear in, and fails on what is left.

What is legitimately allowed, and why each exemption is safe:

* **``related-work.md``** — its numbers are quoted from cited literature. A fact
  builder cannot derive someone else's result, and pretending it could would be
  worse than typing it.
* **code spans and fenced blocks** — a numeral inside ``T1055`` or
  ``max_tokens=8192`` is an identifier or a literal, not a measurement.
* **citation brackets, section references, dates, figure and table numbers** —
  structural, not empirical.
* **the provenance registry's numbers** — quarantined deliberately in
  ``narrative_provenance.json`` and reachable as placeholders; the registry is
  the record that they are observations rather than derivations.

The failure message names the file, the line and the numeral, because the fix is
always the same and always local: derive it, or say why it cannot be.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent
_PAPER = _REPO_ROOT / "docs" / "academic-article" / "paper" / "tex"
_FACTS = _HERE / "paper_facts.json"

# Sections whose numbers are the paper's own measurements. `related-work.tex` is
# not here: its numbers are quoted from cited literature, which no derivation can
# produce.
_SECTIONS = (
    "abstract.tex",
    "E0-discussion.tex",
    "E1-results.tex",
    "E2-threats-to-validity.tex",
    "E3-system.tex",
    "E4-outline.tex",
    "E5-reproducibility.tex",
    "E6-instrument-failures.tex",
    "E7-methodology.tex",
    "E8-conclusion.tex",
    "E9-declarations.tex",
)

_FENCED = re.compile(
    r"\\begin\{verbatim\}.*?\\end\{verbatim\}"
    r"|\\begin\{Shaded\}.*?\\end\{Shaded\}"
    r"|\\begin\{Highlighting\}.*?\\end\{Highlighting\}",
    re.S,
)
_INLINE_CODE = re.compile(r"\\texttt\{(?:[^{}]|\{[^{}]*\})*\}")
_PLACEHOLDER = re.compile(r"\\fact\{[a-z0-9-]+\}")
_CITATION = re.compile(r"\{\[\}\d+(?:\s*,\s*\d+)*\{\]\}|\[\d+(?:\s*,\s*\d+)*\]")
_SECTION_REF = re.compile(r"§+\s?[\dA-Za-z.]+|\\ref\{[^}]*\}|\\label\{[^}]*\}")
_HEADING_NUMBER = re.compile(r"^\\(?:sub)*section\*?\{[\d.]+\s", re.M)
_MD_LINK = re.compile(r"\\includegraphics(?:\[[^\]]*\])?\{[^}]*\}|\\href\{[^}]*\}")
_DATE = re.compile(r"\b(?:19|20)\d{2}(?:-\d{2}-\d{2})?\b")
_FIGURE_TABLE = re.compile(r"\b(?:Figure|Table|Fig\.|§)~?\s*\d+[A-Za-z]?\b", re.I)
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_ARXIV = re.compile(r"arXiv:\d+\.\d+")
# LaTeX's own dimensions and column arithmetic are not measurements.
_LATEX_DIMS = re.compile(
    r"\\real\{[\d.]+\}|\d+\\tabcolsep|[\d.]+(?:pt|em|ex|in|cm|mm)\b"
    r"|\\(?:multicolumn|arraystretch|columnwidth|linewidth)\{?\d*"
)

# Forms that contain a numeral without stating a result. Each is a name, a
# protocol constant, or a design parameter the paper chose rather than measured.
_NOT_A_MEASUREMENT = (
    # The confidence level and the power an interval was computed at. These are
    # settings, and pinning them to a fact would let a re-run silently move the
    # meaning of every interval in the paper.
    re.compile(r"\b\d{2}%\s+(?:bootstrap\s+)?(?:CI|confidence|cluster\s+CI)", re.I),
    re.compile(r"\b\d{2}%\s+power\b", re.I),
    re.compile(r"\balpha\s*=\s*0?\.\d+|α\s*=\s*0?\.\d+"),
    # Model and hardware names: 120B, 35B-A3B, 3-bit, IQ3_K_R4, RTX 5060.
    re.compile(r"\b\d+(?:\.\d+)?\s?B(?:-A\d+B)?\b"),
    re.compile(r"\b\d+-bit\b"),
    re.compile(r"\bIQ\d\w*"),
    # Protocol and status constants.
    re.compile(r"\bHTTP\s+\d{3}\b"),
    re.compile(r"\bport\s+\d+\b", re.I),
    # Versions, named rather than pattern-matched: a bare `\d+\.\d+` rule would
    # exempt every decimal in the paper, which is most of what this checks.
    re.compile(
        r"\b(?:CAPE|Ghidra|Python|ATT&CK|Sigma|MABEL|CUDA|version)\s+v?\d+(?:\.\d+)+",
        re.I,
    ),
)

# What is left after all of that and still looks like a measurement.
_NUMERAL = re.compile(r"(?<![\w.])[+-]?\d[\d,]*(?:\.\d+)?%?")

# Numerals that survive the strippers but are not measurements. Kept small and
# explicit: a growing allowlist is how a rule stops being one.
_STRUCTURAL = {
    # Ordinals and small counts that are prose, not results.
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
}


def _strip(text: str) -> str:
    for pattern in (
        _FENCED,
        _INLINE_CODE,
        _LATEX_DIMS,
        _PLACEHOLDER,
        _CITATION,
        _MD_LINK,
        _ARXIV,
        _TECHNIQUE,
        _FIGURE_TABLE,
        _SECTION_REF,
        _HEADING_NUMBER,
        _DATE,
        *_NOT_A_MEASUREMENT,
    ):
        text = pattern.sub(" ", text)
    return text


def _offenders(path: Path) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        cleaned = _strip(raw)
        for match in _NUMERAL.finditer(cleaned):
            token = match.group(0)
            if token.lower() in _STRUCTURAL:
                continue
            out.append((lineno, token))
    return out


def _fenced_line_numbers(path: Path) -> set[int]:
    """Line numbers inside fenced blocks, which ``_strip`` cannot see line by line."""
    inside: set[int] = set()
    open_block = False
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if raw.lstrip().startswith("```"):
            open_block = not open_block
            inside.add(lineno)
            continue
        if open_block:
            inside.add(lineno)
    return inside


@pytest.mark.parametrize("filename", _SECTIONS)
def test_no_measurement_is_a_hand_typed_numeral(filename: str) -> None:
    path = _PAPER / filename
    if not path.exists():
        pytest.skip(f"{filename} not present")
    fenced = _fenced_line_numbers(path)
    found = [(n, tok) for n, tok in _offenders(path) if n not in fenced]
    if found:
        listing = "\n".join(f"  {filename}:{n}  {tok}" for n, tok in found[:40])
        more = f"\n  ... and {len(found) - 40} more" if len(found) > 40 else ""
        pytest.fail(
            f"{len(found)} hand-typed numerals in {filename}. Derive each into "
            f"paper_facts.py and reference it as a placeholder, or register it in "
            f"narrative_provenance.json with the record it comes from:\n{listing}{more}"
        )


def test_related_work_is_exempt_and_says_so() -> None:
    """The exemption is asserted so it cannot silently widen to other files."""
    related = _PAPER / "related-work.tex"
    assert related.exists()
    assert related.name not in _SECTIONS


def test_every_placeholder_the_paper_uses_resolves() -> None:
    """The build enforces this too; here it fails fast and names every one."""
    if not _FACTS.exists():
        pytest.skip("paper_facts.json not derived yet")
    facts = json.loads(_FACTS.read_text())
    missing: list[str] = []
    for filename in (*_SECTIONS, "related-work.tex"):
        path = _PAPER / filename
        if not path.exists():
            continue
        for name in re.findall(r"\\fact\{([a-z0-9-]+)\}", path.read_text(encoding="utf-8")):
            if name.replace("-", "_") not in facts:
                missing.append(f"{filename}: {{{{{name}}}}}")
    assert not missing, "unresolved placeholders: " + "; ".join(sorted(set(missing)))


def test_no_markdown_placeholder_survived_the_latex_migration() -> None:
    """A ``{{name}}`` left in a .tex source is printed literally into the PDF.

    The substitution mechanism it belonged to is gone; LaTeX has no opinion about
    double braces and will happily typeset them.
    """
    survivors: list[str] = []
    # Both the bare form and pandoc's escaped one. The escaped form is the one
    # that actually happened: the migration substituted `{{name}}` after pandoc
    # had already rewritten it to `\{\{name\_x\}\}`, so 275 placeholders were
    # typeset into the PDF as literal text and this test, written to look for the
    # bare form, said nothing.
    for path in sorted(_PAPER.glob("*.tex")):
        text = path.read_text(encoding="utf-8")
        for pattern in (r"\{\{([^}]*)\}\}", r"\\\{\\\{([^\\]*)\\\}\\\}"):
            for raw in re.findall(pattern, text):
                survivors.append(f"{path.name}: {raw}")
    assert not survivors, "Markdown placeholders in LaTeX sources: " + "; ".join(survivors[:20])


def test_the_markdown_sources_are_gone() -> None:
    """One source per paragraph.

    The sections were authored in Markdown and converted at build time. They are
    LaTeX now, and leaving the Markdown beside it would be two copies of every
    paragraph with nothing keeping them equal — which is the drift this whole
    directory exists to prevent, in the largest possible form.
    """
    stale = sorted(p.name for p in (_PAPER.parent).glob("E*.md"))
    assert not stale, "Markdown sources survive beside the LaTeX: " + ", ".join(stale)
