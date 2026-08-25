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
_QUOTED = _PAPER.parent / "quoted-numbers.json"
# What the text must carry beside a quoted figure whose source is unverified.
_UNRESOLVED_MARKER = "\\unresolvedcite"

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
    "E4b-contributions.tex",
    "E6-instrument-failures.tex",
    "E7-methodology.tex",
    "E8-conclusion.tex",
    "E9-declarations.tex",
)

# Regions where a digit is not a measurement. Verbatim is a transcript. A
# display equation is a definition: the 2s in `p = 2/2^k` are the arithmetic of
# the sign-flip test, not a result of it, and the same is true of an exponent or
# a bound written into a formula. The constants such an equation *quotes* are a
# different matter and are not exempted here -- they come in through \fact{},
# derived from the module that defines them, so an equation cannot state a
# weight the code no longer uses.
_FENCED = re.compile(
    r"\\begin\{verbatim\}.*?\\end\{verbatim\}"
    r"|\\begin\{Shaded\}.*?\\end\{Shaded\}"
    r"|\\begin\{Highlighting\}.*?\\end\{Highlighting\}"
    r"|\\begin\{equation\*?\}.*?\\end\{equation\*?\}",
    re.S,
)
_INLINE_CODE = re.compile(r"\\texttt\{(?:[^{}]|\{[^{}]*\})*\}")
_PLACEHOLDER = re.compile(r"\\fact\{[a-z0-9-]+\}|\\setting\{[^}]*\}")
_CITATION = re.compile(r"\{\[\}\d+(?:\s*,\s*\d+)*\{\]\}|\[\d+(?:\s*,\s*\d+)*\]")
# House style spells a cross-reference "Section~4.5"; the section sign is gone
# from the document. Both forms are stripped, because the old one still appears
# in this repository's history and a checker that only knew the new spelling
# would report forty-five cross-references as hand-typed measurements. It did.
_SECTION_REF = re.compile(
    r"§+\s?[\dA-Za-z.]+|\bSections?~?\s?[\dA-Za-z.]+|\\ref\{[^}]*\}|\\label\{[^}]*\}"
)
_HEADING_NUMBER = re.compile(r"^\\(?:sub)*section\*?\{[\d.]+\s", re.M)
_MD_LINK = re.compile(r"\\includegraphics(?:\[[^\]]*\])?\{[^}]*\}|\\href\{[^}]*\}")
_DATE = re.compile(r"\b(?:19|20)\d{2}(?:-\d{2}-\d{2})?\b")
_FIGURE_TABLE = re.compile(r"\b(?:Figure|Table|Fig\.|§)~?\s*\d+[A-Za-z]?\b", re.I)
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_ARXIV = re.compile(r"arXiv:\d+\.\d+")
# LaTeX's own dimensions and column arithmetic are not measurements.
_LATEX_DIMS = re.compile(
    r"\\real\{[\d.]+\}|\d+\\tabcolsep|[\d.]+(?:pt|em|ex|in|cm|mm)\b"
    # A fraction written directly onto a length, `0.68\linewidth`, is the plain
    # LaTeX spelling of what pandoc writes the long way round as
    # `(\linewidth - 2\tabcolsep) * \real{0.68}`. The long form was already
    # exempt and the short one was not, so re-specifying a table's columns by
    # hand made a column width read as an unregistered measurement.
    r"|[\d.]+\\(?:linewidth|columnwidth|textwidth|hsize)\b"
    r"|\\(?:multicolumn|arraystretch|columnwidth|linewidth)\{?\d*"
    # `\cmidrule(lr){2-4}` names the columns a rule spans. The digits are
    # column indices in a table's own coordinate system, not a result, and a
    # table with a spanning header cannot be written without them.
    r"|\\cmidrule(?:\([lr]+\))?\{\d+-\d+\}"
)

# Forms that contain a numeral without stating a result. Each is a name, a
# protocol constant, or a design parameter the paper chose rather than measured.
_NOT_A_MEASUREMENT = (
    # The confidence level and the power an interval was computed at. These are
    # settings, and pinning them to a fact would let a re-run silently move the
    # meaning of every interval in the paper.
    re.compile(r"\b\d{2}\\?%\s+(?:bootstrap\s+)?(?:cluster\s+)?(?:CI|confidence|interval)", re.I),
    re.compile(r"\b\d{2}\\?%\s+power\b", re.I),
    re.compile(r"(?:\\alpha|alpha|α)\s*\$?\s*=\s*\$?\s*0?\.\d+"),
    # Model and hardware names: 120B, 35B-A3B, 3-bit, IQ3_K_R4, RTX 5060.
    re.compile(r"\b\d+(?:\.\d+)?\s?B(?:-A\d+B)?\b"),
    re.compile(r"\b\d+-bit\b"),
    re.compile(r"\bIQ\d\w*"),
    # Algorithm and hardware names that carry a digit.
    re.compile(r"\bSHA-?\d+\b|\bRTX\s*\d+\b|\bIQ\d\w*\b|\bq\d_\d\b"),
    # Protocol and status constants. The separator may be a tie: `HTTP~200` is
    # the correct spelling, since a status code orphaned at a line start reads
    # as a bare number both to a reader and to this check, and writing the tie
    # is what stops the reflow that produced two false positives here.
    re.compile(r"\bHTTP[~\s]+\d{3}\b"),
    re.compile(r"\bport\s+\d+\b", re.I),
    # Inline maths carrying a symbolic exponent is a formula, not a
    # measurement: $2/2^k$ is the sign-flip floor as an expression, and the 2s
    # in it are the arithmetic rather than a result. Narrow on purpose — the
    # exponent must be a letter, so $2^{10}$ and $0.85$ still count.
    re.compile(r"\$[^$]*\^\{?[a-zA-Z][^$]*\$"),
    # A digit bound into the tail of a hyphenated name is part of the name:
    # Layer-0, Track-2. The lookbehind in _NUMERAL only refuses a digit after a
    # word character, and a hyphen is not one, so "Layer-0" was being read as
    # the measurement 0. Deliberately narrow — the digit must follow a letter
    # and a hyphen with no space, which "a 28.4-point gap" does not.
    re.compile(r"\b[A-Za-z][A-Za-z]+-\d+\b"),
    # Versions, named rather than pattern-matched: a bare `\d+\.\d+` rule would
    # exempt every decimal in the paper, which is most of what this checks.
    re.compile(
        r"\b(?:CAPE|Ghidra|Python|ATT&CK|Sigma|MABEL|CUDA|STIX|version)[~\s]+v?\d+(?:\.\d+)+",
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


# Sentence splitting, kept deliberately dumb. A period ends a sentence when
# whitespace and then something that starts one follow it -- a capital, a control
# sequence, an opening quote or bracket. The abbreviations below are the ones this
# paper actually contains that would otherwise split mid-sentence; "et al. Their
# Finding 4" is the live example. Decimals need no guard: the character after the
# point is a digit, not a space.
_ABBREV = ("al.", "e.g.", "i.e.", "cf.", "vs.", "Fig.", "Eq.", "No.", "Sec.", "approx.")
_SENTENCE_END = re.compile(r"(?<=[.!?])[ \t\n]+(?=[A-Z\\`\"'(\[])")


def _sentences(text: str) -> list[str]:
    """Paragraph-aware sentence split over LaTeX source.

    Paragraphs first, because a blank line ends a sentence whatever punctuation
    precedes it, and joining across one would bind a number to a citation in an
    unrelated block.
    """
    out: list[str] = []
    for para in re.split(r"\n\s*\n", text):
        flat = " ".join(para.split())
        start = 0
        for m in _SENTENCE_END.finditer(flat):
            head = flat[start : m.start()]
            if any(head.endswith(a) for a in _ABBREV):
                continue
            out.append(head)
            start = m.end()
        out.append(flat[start:])
    return [s for s in out if s.strip()]


def _quoted_index() -> dict[str, set[str]]:
    """value -> the citation keys it may be quoted under.

    A number from someone else's paper cannot be derived, so it is exempt — but
    only where the citation is on the same line. A quoted figure separated from
    its source is indistinguishable from one of ours, which is the exact
    confusion three of this paper's own citations turned out to contain.
    """
    if not _QUOTED.exists():
        return {}
    blob = json.loads(_QUOTED.read_text())
    out: dict[str, set[str]] = {}
    for rec in blob.get("quoted", []):
        # cite=null is a figure whose source was not recovered when the
        # bibliography was rebuilt. It is exempt only beside the unresolved
        # marker, so an unverified citation stays visible in the source
        # instead of becoming a number with a plausible reference next to it.
        key = str(rec["cite"]) if rec.get("cite") else _UNRESOLVED_MARKER
        out.setdefault(str(rec["value"]), set()).add(key)
    return out


def _offenders(path: Path) -> list[tuple[int, str]]:
    quoted = _quoted_index()
    out: list[tuple[int, str]] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        cleaned = _strip(raw)
        # Citations are \cite{key} or \cite{key1,key2} since the bibliography
        # became BibTeX. Keying the exemption on the bib key rather than on a
        # number is the point of the move: the numbers are BibTeX's now and it
        # renumbers them, which a hand-maintained registry cannot follow.
        on_line: set[str] = set()
        # \preprintcite is \cite plus a visible marker; both carry the source.
        for group in re.findall(r"\\(?:cite|preprintcite)\{([^}]*)\}", raw):
            on_line.update(k.strip() for k in group.split(",") if k.strip())
        if _UNRESOLVED_MARKER in raw:
            on_line.add(_UNRESOLVED_MARKER)
        for match in _NUMERAL.finditer(cleaned):
            token = match.group(0)
            if token.lower() in _STRUCTURAL:
                continue
            if quoted.get(token.strip("%+")) and quoted[token.strip("%+")] & on_line:
                continue
            out.append((lineno, token))
    return out


_VERBATIM_OPEN = re.compile(r"\\begin\{(verbatim|Shaded|Highlighting|lstlisting|equation\*?)\}")
_VERBATIM_CLOSE = re.compile(r"\\end\{(verbatim|Shaded|Highlighting|lstlisting|equation\*?)\}")


def _fenced_line_numbers(path: Path) -> set[int]:
    """Line numbers inside a verbatim environment, which ``_strip`` cannot see line by line.

    This looked for Markdown fences until the sources became LaTeX, so a command
    line in the reproducibility appendix — the one place a bare number is
    unambiguously not a measurement — was being reported as a hand-typed result.
    """
    inside: set[int] = set()
    depth = 0
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        opened = bool(_VERBATIM_OPEN.search(raw))
        closed = bool(_VERBATIM_CLOSE.search(raw))
        if opened:
            depth += 1
        if depth:
            inside.add(lineno)
        if closed:
            depth = max(0, depth - 1)
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


def test_setting_is_not_a_way_to_launder_a_measurement() -> None:
    """``\\setting{x}`` may not hold a value the analysis derives.

    The marker exists so a number that cannot drift — a port, a thread count, a
    GPU model — does not need a derivation it would never benefit from. It would
    also be a perfectly good way to silence the checker on a real measurement,
    which is why this test exists: if the value inside a ``\\setting`` is one a
    fact already produces, the number belongs to that fact.
    """
    if not _FACTS.exists():
        pytest.skip("paper_facts.json not derived yet")
    derived = {str(v).strip() for v in json.loads(_FACTS.read_text()).values()}
    # Small integers coincide with something derived by chance; the marker is
    # only suspicious when the value is distinctive enough for the match to mean
    # something, which is the same threshold the substitution sweeps used.
    laundered: list[str] = []
    for path in sorted(_PAPER.glob("*.tex")):
        for m in re.finditer(r"\\setting\{([^}]*)\}", path.read_text(encoding="utf-8")):
            value = m.group(1).strip()
            core = value.strip("%+").replace(",", "")
            distinctive = len(core.split(".")[1]) >= 2 if "." in core else len(core) >= 4
            if distinctive and value in derived:
                laundered.append(f"{path.name}: \\setting{{{value}}} is a derived quantity")
    assert not laundered, "; ".join(laundered)


def test_related_work_is_exempt_and_says_so() -> None:
    """The exemption is asserted so it cannot silently widen to other files."""
    related = _PAPER / "related-work.tex"
    assert related.exists()
    assert related.name not in _SECTIONS


def test_every_registered_quote_sits_beside_the_source_it_is_declared_to_come_from() -> None:
    r"""The registry read backwards, which is the direction that catches a bad binding.

    ``_offenders`` asks of a numeral: is this registered? That question passed
    both of the misattributions this paper's citation audit found. Neither number
    was invented --- rho=0.85 and the 77.5% candidate-space reduction are real
    figures from real papers --- and both were listed in the registry. What was
    wrong was the *binding*: the value was recorded against a key that never
    reported it. A forward-only check cannot see that, because the entry it looks
    up is present and well-formed.

    So the registry is also checked from the other end. If a value is declared to
    come from key K, some line of the paper must show that value next to a
    citation of K. That fails on the two shapes the audit actually met:

    * the number is in the text but its declared key is cited nowhere near it ---
      the 77.5% case, where the body said only ``its hierarchical successor'' and
      the nearest citation was to a different paper;
    * the declared key is cited but no longer carries that number --- what a
      later edit leaves behind when a figure is dropped and the record is not.

    This runs over every source, ``related-work.tex`` included. That file is
    exempt from the forward rule because its numbers are quoted rather than
    derived; it is emphatically not exempt from the rule that a quotation names
    the right source, and it is where both misattributions lived.

    The unit is the **sentence**, not the line. The forward rule can demand the
    same line because whoever writes a derived number puts it where it belongs;
    a reverse rule cannot, because it reads prose that was hard-wrapped for the
    editor. Five figures fail a same-line reading here purely because the
    citation wrapped onto the line above, and rewrapping the source to satisfy a
    checker would be the checker choosing how the paper is written. The sentence
    is also the honest unit: it is what "the paper presents this number as coming
    from that source" actually means. It still catches the 77.5% case, whose
    sentence cited nobody at all.
    """
    quoted = _QUOTED
    if not quoted.exists():
        pytest.skip("quoted-numbers.json not present")
    records = json.loads(quoted.read_text())["quoted"]

    sentences: list[str] = []
    for path in sorted(_PAPER.glob("*.tex")):
        sentences.extend(_sentences(path.read_text(encoding="utf-8")))

    unbound: list[str] = []
    for rec in records:
        value = str(rec["value"])
        key = str(rec["cite"]) if rec.get("cite") else _UNRESOLVED_MARKER
        # Bounded, so "85" does not match inside "85.5" or "185" and report a
        # binding the paper never made.
        pattern = re.compile(r"(?<![\d.,])" + re.escape(value) + r"(?![\d,]|\.\d)")
        found = False
        for sentence in sentences:
            if not pattern.search(sentence):
                continue
            if key == _UNRESOLVED_MARKER:
                if _UNRESOLVED_MARKER in sentence:
                    found = True
                    break
                continue
            cited: set[str] = set()
            for group in re.findall(r"\\(?:cite|preprintcite)\{([^}]*)\}", sentence):
                cited.update(k.strip() for k in group.split(",") if k.strip())
            if key in cited:
                found = True
                break
        if not found:
            unbound.append(f"{value} declared from {key}")

    assert not unbound, (
        f"{len(unbound)} quoted figure(s) never appear beside the source they are declared to "
        "come from — the registry and the text disagree about who reported the number: "
        + "; ".join(unbound)
    )


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
