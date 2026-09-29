"""One reasoning card per technique, as data beside the vendored table, held to that table.

Every id a card names, its own and each sibling's, is one the vendored table
carries; the card's name is the table's; the fields it cites are fields the
table has; it renders to a few lines; and the techniques the catalogue check
already handles, with every technique the analysts named in the recorded runs,
each have one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maljan.memory.attck_loader import TECHNIQUES_FILE, technique_entry
from maljan.memory.technique_cards import (
    BEHAVIOUR_KIND,
    CARDS_FILE,
    INTENT_KIND,
    MAX_CARD_LINES,
    SOURCE_FIELDS,
    card_lines,
    holds_behaviour,
    load_cards,
    mentions,
    read_card,
    read_cards,
    technique_card,
)
from maljan.pipeline.validation import CAPABILITY_TERMS

CARDS = load_cards()
TABLE = json.loads(Path(TECHNIQUES_FILE).read_text(encoding="utf-8"))

# The techniques the analysts named on a claim or a finding, or the report
# published, in the recorded local and hosted runs of the benchmark sample,
# less the ids the current catalogue no longer carries (those are asked the
# retired-id question instead and have no card).
NAMED_IN_RECORDED_RUNS: tuple[str, ...] = (
    "T1003", "T1005", "T1006", "T1012", "T1016", "T1018", "T1027", "T1027.002", "T1027.005",
    "T1027.007", "T1033", "T1036.005", "T1036.008", "T1041", "T1047", "T1048", "T1053.005",
    "T1055", "T1057", "T1059", "T1059.003", "T1069.002", "T1070.004", "T1071.001", "T1082",
    "T1083", "T1102", "T1105", "T1106", "T1132.001", "T1134", "T1140", "T1204", "T1204.002",
    "T1218.011", "T1482", "T1497.001", "T1497.002", "T1518.001", "T1547.001", "T1547.004",
    "T1547.014", "T1555", "T1564", "T1564.001", "T1564.012", "T1568", "T1571", "T1572",
    "T1573.001", "T1574.001", "T1574.007", "T1599", "T1620", "T1622",
)  # fmt: skip


def _catalogue_check_ids() -> set[str]:
    return {tid for _label, _p, techniques, _keys in CAPABILITY_TERMS for tid in techniques}


class TestTheCardsAreHeldToTheTable:
    def test_the_file_carries_cards(self) -> None:
        assert CARDS_FILE.name == "attck_technique_cards.json"
        assert len(CARDS) >= 90

    @pytest.mark.parametrize("tid", sorted(CARDS))
    def test_every_id_a_card_names_is_in_the_vendored_table(self, tid: str) -> None:
        card = CARDS[tid]
        assert tid in TABLE, tid
        assert card.name == TABLE[tid]["name"]
        for sibling in card.siblings:
            assert sibling.technique_id in TABLE, (tid, sibling.technique_id)
            assert sibling.technique_id != tid

    @pytest.mark.parametrize("tid", sorted(CARDS))
    def test_every_card_cites_fields_the_table_row_has(self, tid: str) -> None:
        card = CARDS[tid]
        assert card.source and set(card.source) <= SOURCE_FIELDS
        assert all(TABLE[tid].get(field) for field in card.source)

    @pytest.mark.parametrize("tid", sorted(CARDS))
    def test_every_card_is_short_and_whole(self, tid: str) -> None:
        card = CARDS[tid]
        assert card.kind in (BEHAVIOUR_KIND, INTENT_KIND)
        assert card.requires and all(r.what and r.terms for r in card.requires)
        assert card.indicators and card.siblings
        assert all(s.criterion and s.terms for s in card.siblings)
        lines = card_lines(card)
        assert len(lines) <= MAX_CARD_LINES
        # Every sibling is shown: a cut card would drop a criterion silently.
        assert len(lines) == 1 + 1 + 1 + len(card.siblings)

    @pytest.mark.parametrize("tid", sorted(CARDS))
    def test_an_intent_critical_card_asks_for_a_stated_purpose(self, tid: str) -> None:
        card = CARDS[tid]
        claim_only = [r for r in card.requires if r.claim_only]
        assert bool(claim_only) == (card.kind == INTENT_KIND), tid


class TestCoverage:
    def test_every_technique_the_catalogue_check_handles_has_a_card(self) -> None:
        in_table = {tid for tid in _catalogue_check_ids() if technique_entry(tid) is not None}

        assert in_table - set(CARDS) == set()

    def test_every_technique_named_in_the_recorded_runs_has_a_card(self) -> None:
        assert set(NAMED_IN_RECORDED_RUNS) - set(CARDS) == set()

    def test_a_sub_technique_without_a_card_is_read_by_its_parent_s(self) -> None:
        card = technique_card("T1055.012")

        assert card is not None and card.technique_id == "T1055"
        assert (
            "the parent's card; T1055.012 has none of its own" in card_lines(card, "T1055.012")[0]
        )

    def test_an_id_with_no_card_and_no_parent_card_has_none(self) -> None:
        assert technique_card("T1112") is None
        assert technique_card("") is None


class TestTheSiblingCriteria:
    def test_unhooking_is_told_apart_from_indicator_removal(self) -> None:
        card = CARDS["T1070"]
        siblings = {s.technique_id for s in card.siblings}

        # The current id of what ATT&CK 19 retired as T1562.
        assert "T1685" in siblings
        reading = read_card(
            card, ["The sample removes the hooks security tools placed in ntdll"], []
        )
        assert [s.technique_id for s in reading.siblings] == ["T1685"]

    def test_run_time_api_resolution_is_told_apart_from_a_legitimate_name(self) -> None:
        card = CARDS["T1036.005"]
        sentence = (
            "The sample uses API hashing (CRC32) to dynamically resolve Windows API calls at "
            "runtime, evading static signature detection."
        )

        reading = read_card(card, [sentence], ["export table walk"])

        assert [s.technique_id for s in reading.siblings] == ["T1027.007"]
        assert {r.what for r in reading.unmet} == {r.what for r in card.requires}

    def test_a_sentence_in_the_card_s_own_words_fits_no_sibling(self) -> None:
        card = CARDS["T1036.005"]
        sentence = "The sample copies itself as svchost.exe to masquerade as a legitimate file"

        assert not read_card(card, [sentence], [None])

    def test_a_sibling_fits_only_when_every_sentence_fits_it(self) -> None:
        card = CARDS["T1036.005"]

        reading = read_card(
            card,
            ["resolves API addresses by hash", "copies itself under System32 as a system file"],
            [None],
        )

        assert not reading.siblings


class TestTheRequirements:
    def test_a_component_a_cited_entry_shows_is_met(self) -> None:
        card = CARDS["T1055"]

        reading = read_card(
            card,
            ["The sample places code in explorer"],
            ["kernel32!WriteProcessMemory kernel32!CreateRemoteThread"],
        )

        assert not reading.unmet

    def test_a_component_nothing_shows_is_unmet_when_every_cited_entry_is_known(self) -> None:
        card = CARDS["T1055"]

        reading = read_card(card, ["The sample does something"], ["an unrelated entry"])

        assert [r.what for r in reading.unmet] == [r.what for r in card.requires]

    def test_a_component_is_not_decided_while_a_cited_entry_is_unknown(self) -> None:
        card = CARDS["T1055"]

        assert not read_card(card, ["The sample does something"], [None]).unmet

    def test_a_stated_purpose_is_read_from_the_sentences_alone(self) -> None:
        card = CARDS["T1622"]
        purpose = next(r for r in card.requires if r.claim_only)

        reading = read_card(
            card, ["The sample calls IsDebuggerPresent"], ["the sample exits when debugged"]
        )

        assert reading.unmet == (purpose,)


class TestTheMatchWords:
    def test_a_term_is_read_from_a_word_start_without_case(self) -> None:
        assert mentions(["inject"], "Process Injection into explorer")
        assert not mentions(["inject"], "reinjected")
        assert mentions(["\\run"], "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")

    def test_an_entry_holds_the_behaviour_by_the_card_s_words(self) -> None:
        card = CARDS["T1055"]

        assert holds_behaviour(card, "kernel32!VirtualAllocEx", None)
        assert not holds_behaviour(card, "PE: 5 imports from 2 libraries", None)
        assert not holds_behaviour(card, "", None)


def test_an_unreadable_file_reads_as_no_cards(tmp_path: Path) -> None:
    broken = tmp_path / "cards.json"
    broken.write_text("{", encoding="utf-8")

    assert read_cards(broken) == {}
    assert read_cards(tmp_path / "absent.json") == {}
