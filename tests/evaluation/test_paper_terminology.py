"""One name per concept, enforced.

Synonym variation is a virtue in prose and a defect in technical writing, and
this paper had eight concepts carrying between three and six names each. Two of
them were doing real damage rather than merely reading loosely:

* the component the paper's headline claim turns on — the step that restores the
  cascade's techniques regardless of what the judge produced — was "a
  post-processing step" in the abstract, "the reconciliation step" in the
  results, and "reconciliation" in the conclusion. A reader has to work out that
  these are one thing before the claim about it means anything;
* the model that returns a verdict was "the verdict model" in the abstract and
  conclusion and "the judge" throughout the results, so the two sections that
  frame the finding used a name the section that measures it never uses.

The rest are recorded here as retired rather than fixed by hand-waving, so that
a later edit reintroducing one fails rather than being noticed by whoever reads
that paragraph next — which is to say, possibly nobody.

Terms that look like duplicates and are not are listed too, with the distinction,
because the risk of a rule like this is that someone collapses a real difference
to satisfy it. ``sample`` and ``fixture`` are the important pair: they name two
populations that the paper spends a figure and a section keeping apart.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_PAPER = _HERE.parent.parent / "other" / "docs" / "academic-article" / "paper" / "tex"

# The manuscript lives outside this repository. These three modules read it, so
# on a clone that does not carry it they have nothing to check and skip rather
# than fail: a red suite that means "the paper is elsewhere" tells a reader
# nothing about the code.
if not _PAPER.exists():  # pragma: no cover - depends on the checkout
    pytest.skip("the manuscript is not in this checkout", allow_module_level=True)

# Files that are prose. `related-work.tex` is included: it describes other
# people's systems, but it describes ours too and the names have to match.
_GENERATED = {"main.tex", "facts.tex"}


def _sources() -> list[Path]:
    return sorted(p for p in _PAPER.glob("*.tex") if p.name not in _GENERATED)


# retired term -> (canonical term, why the canonical one won)
_RETIRED = {
    r"post-processing step": (
        "the reconciliation step",
        "the paper's headline claim turns on this component; it had three names",
    ),
    r"verdict model": (
        "the judge",
        "the abstract and conclusion used a name the results section never does",
    ),
    r"eleventh check": (
        "the output-cardinality check",
        "a numbering that appears nowhere else in the paper",
    ),
    r"\bartifacts?\b": (
        "artefact",
        "one spelling; the paper is British elsewhere",
    ),
}

# Named components and file paths that legitimately contain a retired string.
_EXEMPT = (
    "tool-artifact layer",  # the component's name, not the noun
    "\\texttt{",  # anything inside a code span is an identifier
)


def _strip_exempt(line: str) -> str:
    out = re.sub(r"\\texttt\{(?:[^{}]|\{[^{}]*\})*\}", " ", line)
    return out.replace("tool-artifact layer", " ")


@pytest.mark.parametrize("retired", sorted(_RETIRED))
def test_a_retired_term_stays_retired(retired: str) -> None:
    canonical, why = _RETIRED[retired]
    hits: list[str] = []
    for path in _sources():
        for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(retired, _strip_exempt(raw), re.I):
                hits.append(f"{path.name}:{lineno}")
    assert not hits, (
        f"{len(hits)} use(s) of a retired term. Use {canonical!r} — {why}. "
        f"At: {', '.join(hits[:8])}"
    )


def test_the_pairs_that_look_like_duplicates_are_still_distinct() -> None:
    """Guard against collapsing a real distinction to satisfy the rule above.

    ``sample`` and ``fixture`` name two populations: 97 real binaries scored
    against family-level ground truth, and five synthesised inputs whose evidence
    is generated from their own technique lists. A figure had to be split in two
    because they were drawn on one axis. If one of these words disappears, the
    distinction has been lost rather than tidied.
    """
    text = "".join(p.read_text(encoding="utf-8") for p in _sources())
    for term in ("sample", "fixture", "bundle", "verdict"):
        assert re.search(rf"\b{term}s?\b", text, re.I), (
            f"{term!r} has vanished from the paper — it names something the paper "
            "distinguishes, and losing the word loses the distinction"
        )


def test_the_vocabulary_is_defined_where_a_reader_meets_it() -> None:
    """The terms a reader must keep apart are defined, not left to context."""
    method = (_PAPER / "E7-methodology.tex").read_text(encoding="utf-8")
    for term in ("arm", "fixture", "sample", "reconciliation step"):
        assert term in method, f"{term!r} is not defined in the methodology section"
