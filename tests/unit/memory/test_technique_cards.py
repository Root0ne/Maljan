"""One reasoning card per technique, as data beside the vendored table, held to that table.

Every id a card names, its own and each sibling's, is one the vendored table
carries; the card's name is the table's; the fields it cites are fields the
table has; it renders whole to a few lines; its kind agrees with what it
requires; and the techniques the catalogue check already handles, with every
technique the analysts named in the recorded runs, each have one.
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
    SOURCE_FIELDS,
    card_lines,
    load_cards,
    read_cards,
    technique_card,
    technique_card_lines,
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

# The words a requirement uses to ask for a stated purpose.
_STATED = "the claim states"


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
        assert card.requires and card.indicators
        assert all(s.criterion for s in card.siblings)
        lines = card_lines(card)
        # Nothing is cut: every sibling is shown, and the data keeps cards short.
        assert len(lines) == 3 + len(card.siblings)
        assert len(lines) <= 8

    @pytest.mark.parametrize("tid", sorted(CARDS))
    def test_only_an_intent_critical_card_asks_for_a_stated_purpose(self, tid: str) -> None:
        card = CARDS[tid]
        stated = [r for r in card.requires if r.startswith(_STATED)]
        assert bool(stated) == (card.kind == INTENT_KIND), tid


class TestTheKinds:
    @pytest.mark.parametrize("tid", ["T1497", "T1497.001", "T1497.002", "T1622", "T1564.012"])
    def test_a_check_or_an_exclusion_alone_is_the_technique(self, tid: str) -> None:
        # The environment and debugging checks sit under Discovery as well as
        # Stealth: the check alone is the technique. An exclusion's purpose is
        # its own.
        assert CARDS[tid].kind == BEHAVIOUR_KIND


class TestCoverage:
    def test_every_technique_the_catalogue_check_handles_has_a_card(self) -> None:
        in_table = {tid for tid in _catalogue_check_ids() if technique_entry(tid) is not None}

        assert in_table - set(CARDS) == set()

    def test_every_technique_named_in_the_recorded_runs_has_a_card(self) -> None:
        assert set(NAMED_IN_RECORDED_RUNS) - set(CARDS) == set()

    def test_a_sub_technique_without_a_card_of_its_own_is_shown_none(self) -> None:
        # Its parent's kind and requirements need not be its own.
        assert "T1055" in CARDS
        assert technique_card("T1055.012") is None
        assert technique_card_lines("T1055.012") == []

    def test_an_id_with_no_card_has_none(self) -> None:
        assert technique_card("T1112") is None
        assert technique_card("") is None
        assert technique_card_lines("T1112") == []


class TestTheSiblings:
    def test_unhooking_is_told_apart_from_indicator_removal(self) -> None:
        # T1685 is the current id of what ATT&CK 19 retired as T1562.
        assert "T1685" in {s.technique_id for s in CARDS["T1070"].siblings}

    @pytest.mark.parametrize(
        ("tid", "kept_out"),
        [
            ("T1036", "T1027.007"),
            ("T1036.005", "T1027.007"),
            ("T1003", "T1497"),
            ("T1564", "T1518.001"),
            ("T1564", "T1497"),
            ("T1012", "T1010"),
        ],
    )
    def test_no_sibling_pairs_techniques_ATT_CK_does_not_relate(
        self, tid: str, kept_out: str
    ) -> None:
        assert kept_out not in {s.technique_id for s in CARDS[tid].siblings}

    @pytest.mark.parametrize(
        ("tid", "sibling"),
        [("T1003", "T1555"), ("T1564", "T1564.001"), ("T1012", "T1518"), ("T1204", "T1218")],
    )
    def test_a_general_confusable_is_named(self, tid: str, sibling: str) -> None:
        assert sibling in {s.technique_id for s in CARDS[tid].siblings}


class TestTheLines:
    def test_a_card_reads_as_kind_requirements_indicators_and_siblings(self) -> None:
        card = CARDS["T1003"]

        lines = card_lines(card)

        assert lines[0] == "card: behaviour-focused, the action alone is the technique"
        assert lines[1] == "requires: " + "; ".join(card.requires)
        assert lines[2] == "indicators: " + "; ".join(card.indicators)
        assert lines[3].startswith("not T1555 Credentials from Password Stores when ")

    def test_the_technique_itself_and_the_card_s_provenance_are_not_written(self) -> None:
        text = "\n".join(card_lines(CARDS["T1003"]))

        assert "OS Credential Dumping" not in text
        assert "written from" not in text


def test_an_unreadable_file_reads_as_no_cards(tmp_path: Path) -> None:
    broken = tmp_path / "cards.json"
    broken.write_text("{", encoding="utf-8")

    assert read_cards(broken) == {}
    assert read_cards(tmp_path / "absent.json") == {}
