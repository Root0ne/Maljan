"""Corroboration counts what the analysts said independently, not how many said it.

A local run printed a contradicted technique "corroborated (named by 6
analyst layers)": four analysts had written the same sentence word for word,
one of them twice, and a fifth layer was counted for its summary title, which
it listed under five techniques. Statements with the same normalised text now
count once, the report says how many were identical, and a finding's title is
not a statement.
"""

from __future__ import annotations

from maljan.extractors.capability_matrix import (
    REPEATED_WORDS_SHARE,
    build_capability_matrix,
    independent_statements,
)
from maljan.reporting.renderers.markdown import _corroborated_words
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, Finding

COPIED = "The sample persists by writing a shortcut into the Startup folder."


def _claim(text: str, tid: str = "T1547.001") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref="[ev_0001]", confidence=0.9, technique_id=tid)


def _isr(domain: str, *claims: ClaimEvidence, findings: list[Finding] | None = None) -> AgentISR:
    return AgentISR(agent_id=domain, domain=domain, claims=list(claims), findings=findings or [])


def _mapping(isrs: dict[str, AgentISR], tid: str = "T1547.001"):
    cells, mappings = build_capability_matrix(stix_output=None, isr_reports=isrs)
    cell = next(c for c in cells if c.technique_id == tid)
    mapping = next((m for m in mappings if m.technique_id == tid), None)
    return cell, mapping


def test_the_same_sentence_from_three_layers_is_one_independent_statement() -> None:
    isrs = {
        "static": _isr("static", _claim(COPIED)),
        "dynamic": _isr("dynamic", _claim(COPIED.upper())),
        "network": _isr("network", _claim(f"  {COPIED}  "), _claim(COPIED)),
    }

    cell, mapping = _mapping(isrs)

    assert mapping is not None
    # The same text from several layers credits the first of them by name.
    assert mapping.independent_layers == ["dynamic"]
    assert mapping.identical_statements == 3
    assert mapping.is_corroborated is False
    assert cell.identical_statements == 3


def test_two_layers_in_their_own_words_corroborate() -> None:
    isrs = {
        "static": _isr("static", _claim(COPIED)),
        "dynamic": _isr("dynamic", _claim("A .lnk file is written under the Startup folder.")),
        "network": _isr("network", _claim(COPIED)),
    }

    _cell, mapping = _mapping(isrs)

    assert mapping is not None
    assert mapping.independent_layers == ["dynamic", "network"]
    assert mapping.identical_statements == 1
    assert mapping.is_corroborated is True


def test_a_findings_title_is_not_a_statement() -> None:
    title = "Example Loader with Reconnaissance and Exfiltration"
    isrs = {
        "static": _isr("static", _claim(COPIED)),
        "network": _isr(
            "network", findings=[Finding(title=title, technique_ids=["T1547.001"], confidence=0.9)]
        ),
    }

    cell, mapping = _mapping(isrs)

    assert not any(title in statement for statement in cell.statements)
    assert mapping is not None
    assert mapping.independent_layers == ["static"]
    assert mapping.is_corroborated is False


def test_a_findings_detail_is_a_statement() -> None:
    isrs = {
        "static": _isr("static", _claim(COPIED)),
        "network": _isr(
            "network",
            findings=[
                Finding(
                    title="Persistence",
                    detail="It adds a shortcut to the user's Startup folder at install.",
                    technique_ids=["T1547.001"],
                )
            ],
        ),
    }

    cell, mapping = _mapping(isrs)

    assert mapping is not None
    assert mapping.independent_layers == ["static", "network"]
    assert any("It adds a shortcut" in statement for statement in cell.statements)


def test_the_row_says_how_many_statements_were_identical() -> None:
    isrs = {
        "static": _isr("static", _claim(COPIED)),
        "dynamic": _isr("dynamic", _claim("A .lnk file is written under the Startup folder.")),
        "network": _isr("network", _claim(COPIED)),
    }
    _cell, mapping = _mapping(isrs)

    said = _corroborated_words(mapping, [])

    assert said.startswith(", corroborated")
    assert "named by 2 analyst layers, each in a statement of its own" in said
    assert "1 statement identical or near-identical to another, counted once" in said


def test_a_copied_row_says_it_is_not_corroborated_and_why() -> None:
    isrs = {
        "static": _isr("static", _claim(COPIED)),
        "dynamic": _isr("dynamic", _claim(COPIED)),
    }
    _cell, mapping = _mapping(isrs)

    said = _corroborated_words(mapping, [])

    assert not said.startswith(", corroborated")
    assert "not corroborated" in said
    assert "2 analyst layers name it; 1 of them in a statement of its own" in said
    assert "1 statement identical or near-identical to another, counted once" in said


# Near-copies: a statement one layer cut short, one with a word put in, and one
# written in the analyst's own words.
LONG = (
    "The sample establishes persistence by creating shortcuts in the Startup and Desktop "
    "directories and potentially installing an Updater component."
)
TRUNCATED = "The sample establishes persistence by creating shortcuts in the Startup directories."
INSERTED = (
    "The sample establishes persistence by creating lnk shortcuts in the Startup and Desktop "
    "directories and potentially installing an Updater component."
)
REORDERED = (
    "The sample establishes persistence by creating shortcuts in the Desktop and Startup "
    "directories and potentially installing an Updater component."
)
PARAPHRASE = "A .lnk file placed under the user's Startup folder relaunches it at logon."


def test_a_truncated_copy_counts_once() -> None:
    credited, repeated = independent_statements([("static", LONG), ("network", TRUNCATED)])

    assert (credited, repeated) == (["static"], 1)


def test_a_copy_with_a_word_put_in_counts_once() -> None:
    credited, repeated = independent_statements([("static", LONG), ("dynamic", INSERTED)])

    # The copy with the word put in is the longer one, and the group is its.
    assert (credited, repeated) == (["dynamic"], 1)


def test_a_word_reordered_copy_counts_once() -> None:
    credited, repeated = independent_statements([("static", LONG), ("dynamic", REORDERED)])

    # Of two statements of one length the group is the one whose text sorts first.
    assert (credited, repeated) == (["dynamic"], 1)


def test_an_honest_paraphrase_is_its_own_statement() -> None:
    credited, repeated = independent_statements([("static", LONG), ("dynamic", PARAPHRASE)])

    assert (credited, repeated) == (["static", "dynamic"], 0)


def test_the_share_is_of_the_shorter_statements_words() -> None:
    assert REPEATED_WORDS_SHARE == 0.9


def test_a_word_inside_another_word_is_not_a_substring_copy() -> None:
    credited, _repeated = independent_statements(
        [("static", "It hides its imports"), ("dynamic", "hides")]
    )

    assert credited == ["static"]
    credited, _repeated = independent_statements(
        [("static", "It unhides the window"), ("dynamic", "It hides")]
    )
    assert credited == ["static", "dynamic"]


def test_three_sentences_of_one_layer_are_not_called_one_statement() -> None:
    isrs = {
        "static": _isr(
            "static",
            _claim(COPIED),
            _claim("A registry value under Run launches the dropped copy at boot."),
            _claim("The installer writes its payload beside the shortcut it creates."),
        ),
        "network": _isr(
            "network", _claim("persists by writing a shortcut into the Startup folder")
        ),
    }
    _cell, mapping = _mapping(isrs)

    said = _corroborated_words(mapping, [])

    assert "not corroborated" in said
    assert "2 analyst layers name it; 1 of them in a statement of its own" in said
    assert "independent statement" not in said


def test_a_corroborated_row_with_no_repeats_still_says_its_count() -> None:
    isrs = {
        "static": _isr("static", _claim(COPIED)),
        "dynamic": _isr("dynamic", _claim(PARAPHRASE)),
    }
    _cell, mapping = _mapping(isrs)

    assert _corroborated_words(mapping, []) == (
        ", corroborated (named by 2 analyst layers, each in a statement of its own)"
    )


def test_a_findings_title_is_not_its_procedure() -> None:
    title = "Example Persistence Heading"
    isrs = {
        "static": _isr(
            "static", findings=[Finding(title=title, technique_ids=["T1547.001"], confidence=0.9)]
        ),
        "network": _isr("network", _claim(COPIED)),
    }

    cell, mapping = _mapping(isrs)

    assert title not in cell.evidence
    assert mapping is not None and title not in mapping.evidence_quotes


def test_the_narrative_is_told_which_layers_said_something_of_their_own() -> None:
    from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
    from maljan.reporting.narrative_agent import build_prompt_text

    isrs = {
        "static": _isr("static", _claim(COPIED)),
        "dynamic": _isr("dynamic", _claim(COPIED)),
        "network": _isr("network", _claim(PARAPHRASE)),
    }
    _cell, mapping = _mapping(isrs)
    assert mapping is not None
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), ttp_mappings=[mapping]
    )

    text = build_prompt_text(report)

    assert "layers=static,dynamic,network, independent=dynamic,network" in text


# A short statement and two long ones that each hold its words and nothing of
# each other's: the long ones are two voices, whatever order they were read in.
HUB = "Writes a Run key."
HUB_DYNAMIC = (
    "The sample writes a Run key under HKCU for persistence, observed in the sandbox registry log."
)
HUB_REVERSER = "Decompiled code shows it writes a Run key via RegSetValueExW at startup."


def test_a_short_statement_read_first_does_not_absorb_two_longer_ones() -> None:
    first = independent_statements(
        [("triage", HUB), ("dynamic", HUB_DYNAMIC), ("reverser", HUB_REVERSER)]
    )
    last = independent_statements(
        [("dynamic", HUB_DYNAMIC), ("reverser", HUB_REVERSER), ("triage", HUB)]
    )

    assert sorted(first[0]) == sorted(last[0]) == ["dynamic", "reverser"]
    assert first[1] == last[1] == 1


def test_the_group_is_credited_to_its_longest_statement() -> None:
    credited, repeated = independent_statements([("triage", TRUNCATED), ("static", LONG)])

    assert (credited, repeated) == (["static"], 1)


def test_the_count_does_not_depend_on_the_order_statements_are_read() -> None:
    from itertools import permutations

    statements = [
        ("triage", HUB),
        ("dynamic", HUB_DYNAMIC),
        ("reverser", HUB_REVERSER),
        ("static", LONG),
        ("network", TRUNCATED),
        ("qu1cksc0pe", PARAPHRASE),
    ]
    answers = {
        (frozenset(credited), repeated)
        for order in permutations(statements)
        for credited, repeated in [independent_statements(list(order))]
    }

    assert answers == {(frozenset({"dynamic", "reverser", "static", "qu1cksc0pe"}), 2)}


# Three statements of one length, each edited a word from the last: the first
# and the second repeat each other, the second and the third too, the first
# and the third do not.
CHAIN_A = "alpha bravo charlie delta echo foxtrot golf hotel india juliet"
CHAIN_B = "alpha bravo charlie delta echo foxtrot golf hotel india kilo"
CHAIN_C = "alpha bravo charlie delta echo foxtrot golf hotel kilo lima"


def test_a_chain_of_equal_length_statements_counts_alike_in_every_order() -> None:
    from itertools import permutations

    statements = [("static", CHAIN_A), ("dynamic", CHAIN_B), ("network", CHAIN_C)]
    answers = {
        (frozenset(credited), repeated)
        for order in permutations(statements)
        for credited, repeated in [independent_statements(list(order))]
    }

    assert len(answers) == 1


def test_the_same_text_from_two_layers_is_credited_alike_in_either_order() -> None:
    one = independent_statements([("static", COPIED), ("dynamic", COPIED)])
    two = independent_statements([("dynamic", COPIED), ("static", COPIED)])

    assert set(one[0]) == set(two[0]) and one[1] == two[1] == 1
