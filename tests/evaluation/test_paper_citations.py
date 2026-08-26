"""The bibliography, checked for the things a reviewer checks first.

Two properties, both learned the hard way by this paper.

**Every citation resolves.** The bibliography became BibTeX with the Elsevier
template, so a key that does not exist now renders as ``[?]`` instead of failing
loudly — the same hole ``\\fact{}`` was built to keep out of the numbers.

**Every preprint is declared.** Journals discount arXiv-only citations because
they carry no review. Twelve of this paper's fifty-three entries have no
peer-reviewed venue — nine preprints, two issue trackers and one tool — and four
of them are load-bearing: the paper quotes a number from them. That is a real
submission risk and it is easy to forget, because a preprint citation looks
exactly like any other in the rendered PDF. So each one is declared with a
resolution, and a new one added without a status fails here.

The registry may not name a venue that has not been verified. Guessing one is
the failure this paper's own citation audit has now caught five times: three
sources cited for something they do not say, and two figures attributed to
papers that never reported them.

Those last two are the reason ``test_paper_numerals.py`` also reads the quoted-
number registry backwards. Both figures were registered, both were real, and
both were bound to the wrong key --- a state no forward "is this number
declared?" check can distinguish from a correct one.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_PAPER = _HERE.parent.parent / "other" / "docs" / "academic-article" / "paper"

# The manuscript lives outside this repository. These three modules read it, so
# on a clone that does not carry it they have nothing to check and skip rather
# than fail: a red suite that means "the paper is elsewhere" tells a reader
# nothing about the code.
if not _PAPER.exists():  # pragma: no cover - depends on the checkout
    pytest.skip("the manuscript is not in this checkout", allow_module_level=True)
_TEX = _PAPER / "tex"
_BIB = _TEX / "refs.bib"
_STATUS = _PAPER / "preprint-status.json"

_ENTRY = re.compile(r"@(\w+)\s*\{\s*([^,\s]+)\s*,(.*?)\n\}", re.S)
_VENUE = re.compile(r"\b(?:booktitle|journal)\s*=\s*\{", re.I)


def _entries() -> dict[str, str]:
    """key -> entry body."""
    return {m.group(2): m.group(3) for m in _ENTRY.finditer(_BIB.read_text(encoding="utf-8"))}


# ``citep``/``citet`` as well as ``cite``: the journal asks for author-year
# citations, so the sources moved to natbib's parenthetical and textual forms
# and a pattern anchored on ``cite{`` stopped seeing any of them.
_ANY_CITE = re.compile(r"\\(preprintcite|cite[pt]?|citealp)\{([^}]*)\}")


def _cites() -> list[tuple[str, str, str]]:
    r"""(file, macro, key) for every citation in the paper.

    Both macros count. `\preprintcite` is `\cite` plus a visible [preprint]
    marker, and a checker that only knew the plain form reported every marked
    citation as an uncited orphan — which is the same shape of mistake as
    matching on something other than what you meant to check.
    """
    out: list[tuple[str, str, str]] = []
    for path in sorted(_TEX.glob("*.tex")):
        for m in _ANY_CITE.finditer(path.read_text(encoding="utf-8")):
            for key in (k.strip() for k in m.group(2).split(",")):
                if key:
                    out.append((path.name, m.group(1), key))
    return out


def _cited_keys() -> set[str]:
    return {key for _, _, key in _cites()}


def test_every_citation_resolves_to_an_entry() -> None:
    missing = sorted(_cited_keys() - set(_entries()))
    assert not missing, (
        f"{len(missing)} citation key(s) with no bibliography entry — these render as [?]: "
        + ", ".join(missing)
    )


def test_every_entry_is_cited() -> None:
    """An uncited entry is decoration, and the paper says it drops those.

    Four were found when the bibliography was converted: they had been listed
    since an early draft and never referenced. They are cited now, in one
    sentence that says what they establish.
    """
    orphans = sorted(set(_entries()) - _cited_keys())
    assert not orphans, f"{len(orphans)} entry(ies) listed but never cited: " + ", ".join(orphans)


def _unreviewed(status: dict) -> set[str]:
    r"""Entries whose citations must carry the visible marker.

    ``entries`` are preprints. ``not_papers`` are non-papers cited *as
    evidence* — an issue tracker offered as proof that a defect is known — and
    they carry the marker for the same reason a preprint does: the reader is
    being asked to believe something on unreviewed authority.

    ``artefacts`` are excluded. A tool, a corpus or a released model cited as
    the object it is asserts nothing a reader could decline, and stamping
    software with ``[preprint]`` would be a false label rather than a cautious
    one. TRAM is the case that forced the distinction: it has no venue and
    never will, and marking it unreviewed would have said something untrue in
    the body of a paper about saying only checked things.
    """
    return set(status["entries"]) | set(status["not_papers"])


def _declared(status: dict) -> set[str]:
    """Everything the registry accounts for, marker or no marker."""
    return _unreviewed(status) | set(status.get("artefacts", {}))


def test_every_preprint_is_declared_with_a_resolution() -> None:
    status = json.loads(_STATUS.read_text(encoding="utf-8"))
    declared = _declared(status)
    preprints = {k for k, body in _entries().items() if not _VENUE.search(body)}

    undeclared = sorted(preprints - declared)
    assert not undeclared, (
        f"{len(undeclared)} bibliography entry(ies) have no peer-reviewed venue and no "
        f"declared status: {', '.join(undeclared)}. Add each to preprint-status.json with "
        "what would resolve it, or give the entry its published venue."
    )

    stale = sorted(k for k in status["entries"] if k not in preprints)
    assert not stale, (
        f"{len(stale)} entry(ies) are declared as preprints but now name a venue — remove "
        f"them from preprint-status.json: {', '.join(stale)}"
    )


def test_a_load_bearing_preprint_declares_what_it_is_load_bearing_for() -> None:
    """A quoted number is a heavier debt than a background citation.

    A reader who declines an unreviewed source loses a figure the paper states,
    not just a pointer, so those entries have to name the figures.
    """
    status = json.loads(_STATUS.read_text(encoding="utf-8"))
    quoted = json.loads((_PAPER / "quoted-numbers.json").read_text(encoding="utf-8"))
    quotes_by_key: dict[str, set[str]] = {}
    for rec in quoted["quoted"]:
        if rec.get("cite"):
            quotes_by_key.setdefault(str(rec["cite"]), set()).add(str(rec["value"]))

    for key, rec in status["entries"].items():
        expected = quotes_by_key.get(key, set())
        assert set(rec["quotes"]) == expected, (
            f"{key}: preprint-status.json lists quotes {sorted(rec['quotes'])} but the paper "
            f"quotes {sorted(expected)} from it"
        )
        assert rec["load_bearing"] is bool(expected), (
            f"{key}: load_bearing is {rec['load_bearing']} but it "
            f"{'does' if expected else 'does not'} carry a quoted figure"
        )
        assert rec["action"].strip(), f"{key}: declared with no action"


def test_the_registry_claims_no_venue_it_has_not_verified() -> None:
    """The guard against fixing this by inventing publication details.

    Every previous citation defect in this paper was a plausible-looking
    attribution that nobody had checked. A registry that let someone write
    "published at X" from memory would be the same mistake with a schema.
    """
    status = json.loads(_STATUS.read_text(encoding="utf-8"))
    assert status["verified_offline"] is False, (
        "verified_offline may only be true when the venues were checked against a "
        "publisher, which needs the network this registry was written without"
    )
    allowed = {"unresolved", "likely-published-unverified", "droppable", "published"}
    for key, rec in status["entries"].items():
        assert rec["status"] in allowed, f"{key}: unknown status {rec['status']!r}"
        if rec["status"] == "published":
            body = _entries().get(key, "")
            assert _VENUE.search(body), (
                f"{key} is marked published but its entry names no venue — the status and "
                "the bibliography disagree, and the bibliography is what a reader sees"
            )


@pytest.mark.parametrize("field", ["title", "year"])
def test_every_entry_has_the_fields_a_reader_needs(field: str) -> None:
    thin = sorted(k for k, body in _entries().items() if f"{field}" not in body)
    assert not thin, f"{len(thin)} entry(ies) with no {field}: " + ", ".join(thin)


_DOI_STATUS = _PAPER / "doi-status.json"
_DOI = re.compile(r"^\s*doi\s*=\s*\{([^}]*)\}", re.M)


def test_every_entry_either_carries_a_doi_or_says_why_not() -> None:
    """An empty ``doi`` field is two different states and looks like one.

    Elsevier asks for a DOI wherever one exists, and eighteen of these entries
    genuinely have none: USENIX, ICLR and COLM register no DOI for their
    proceedings, and a GitHub issue is not a registered work. The remaining
    forty do. A bibliography with a mixture of the two, and nothing recording
    which is which, cannot tell a reader — or a later pass — whether an absence
    was established or merely never looked into.

    So the registry is required to account for every entry, and this test is the
    thing that stops it drifting out of step with the bibliography it describes.
    Both directions fail: an entry with no DOI and no reason, and a reason
    written for an entry that has since acquired one.
    """
    status = json.loads(_DOI_STATUS.read_text(encoding="utf-8"))["entries"]
    entries = _entries()

    unlisted = sorted(set(entries) - set(status))
    assert not unlisted, f"{len(unlisted)} entry(ies) absent from doi-status.json: " + ", ".join(
        unlisted
    )
    stale = sorted(set(status) - set(entries))
    assert not stale, (
        f"{len(stale)} entry(ies) in doi-status.json that the bibliography no longer has: "
        + ", ".join(stale)
    )

    disagree: list[str] = []
    for key, body in entries.items():
        m = _DOI.search(body)
        recorded = status[key].get("doi")
        if m and not recorded:
            disagree.append(f"{key}: refs.bib has {m.group(1)}, the registry says none")
        elif not m and recorded:
            disagree.append(f"{key}: the registry claims {recorded}, refs.bib has no doi field")
        elif m and recorded and m.group(1).strip() != recorded.strip():
            disagree.append(f"{key}: {m.group(1)} in refs.bib against {recorded} recorded")
        elif not m and not str(status[key].get("reason", "")).strip():
            disagree.append(f"{key}: no doi and no reason for its absence")
    assert not disagree, (
        f"{len(disagree)} entry(ies) where the bibliography and the DOI registry disagree: "
        + "; ".join(disagree[:8])
    )


def test_an_unreviewed_source_is_never_cited_without_saying_so() -> None:
    r"""Every citation to a preprint carries the visible marker.

    Seven sources here have no reviewed venue. They were kept deliberately —
    each one concedes ground rather than claims it, and dropping them for want
    of a venue would have made the paper look more original than it is. The
    price of keeping them is that a reader must be able to see which sentences
    rest on unreviewed evidence without cross-referencing the bibliography.

    So the marker is not decoration and not optional: plain `\cite` to an
    unreviewed entry fails here.
    """
    status = json.loads(_STATUS.read_text(encoding="utf-8"))
    unreviewed = _unreviewed(status)
    bare = [(fname, key) for fname, macro, key in _cites() if key in unreviewed and macro == "cite"]
    assert not bare, (
        f"{len(bare)} citation(s) to an unreviewed source without \\preprintcite: "
        + ", ".join(f"{f}:{k}" for f, k in bare[:8])
    )


def test_a_reviewed_source_is_not_marked_as_a_preprint() -> None:
    """The marker must not spread to work that was reviewed.

    A marker on everything says nothing. Five entries turned out to be
    published after all when the venues were checked, and their citations must
    lose the marker with them.
    """
    status = json.loads(_STATUS.read_text(encoding="utf-8"))
    unreviewed = _unreviewed(status)
    wrong = [
        (fname, key)
        for fname, macro, key in _cites()
        if macro == "preprintcite" and key not in unreviewed
    ]
    assert not wrong, f"{len(wrong)} peer-reviewed source(s) marked as preprints: " + ", ".join(
        f"{f}:{k}" for f, k in wrong[:8]
    )
