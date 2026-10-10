"""A row that writes a field name before its value is held by the entry that pairs the two.

A run's configuration table stated a decoder's seed and first key as
``seed <value>`` and ``first_key <value>``, both citing the decoder's entry
whose JSON held ``"seed": "<value>"`` and ``"first_key": "<value>"``. The
whole-value check looked for each row as written, found no ``seed <value>``
in the entry, and printed both correct rows as unresolved. The entry holds
the value when it pairs that field name with that whole value; the two parts
apart never count, so a value the entry gives another field, a prefix and the
same digits in another radix stay unheld.

Every name and number here is made up for the test.
"""

from __future__ import annotations

import gc
import json
import time
from typing import Any

import pytest

from maljan.pipeline.validation import (
    CITATION_WRONG_ENTRY_CODE,
    STATED_VALUE_UNHELD_CODE,
    EntryTexts,
    field_value_spellings,
    held_spellings,
    stated_value_violations,
    wrong_entry_citations,
)
from maljan.schemas.evidence import LedgerEntry

DECODER = {
    "tool": "example_decoder",
    "blobs": [
        {
            "scheme": "example_scheme",
            "parameters": {"seed": "0x5a17c0de", "first_key": "0x2b", "step": 1},
            "text": "example text",
        }
    ],
}
OTHER = {"tool": "example_decoder", "blobs": [{"parameters": {"seed": "0x0badf00d"}}]}


def _entry(entry_id: str, output: str) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id, agent="pipeline", server="pipeline", tool="example_decoder", output=output
    )


def _texts(*, compact: bool = False) -> EntryTexts:
    separators = (",", ":") if compact else None
    return EntryTexts.from_ledger(
        [
            _entry("ev_0021", json.dumps(DECODER, separators=separators)),
            _entry("ev_0030", json.dumps(OTHER)),
            _entry("ev_0031", "decoder state: seed=0x0c0ffee1 rounds: 7"),
        ]
    )


def _items(*values: str, ref: str = "ev_0021") -> dict[str, Any]:
    return {
        "items": [
            {"key": "Decoding", "value": value, "how_obtained": "decrypted", "evidence_refs": [ref]}
            for value in values
        ]
    }


def _codes(payload: dict[str, Any], texts: EntryTexts | None = None) -> list[str]:
    return [v.code for v in stated_value_violations(payload, texts or _texts())]


class TestAFieldNameAndItsValueAreHeld:
    def test_the_decoder_s_seed_and_first_key_stand(self) -> None:
        assert _codes(_items("seed 0x5a17c0de", "first_key 0x2b")) == []

    def test_the_value_alone_still_stands(self) -> None:
        assert _codes(_items("0x5a17c0de", "example_scheme")) == []

    def test_an_equals_sign_or_a_colon_between_them_stands(self) -> None:
        assert _codes(_items("seed=0x5a17c0de", "first_key: 0x2b", "SEED 0x5A17C0DE")) == []

    def test_a_compact_json_entry_holds_the_pair(self) -> None:
        assert _codes(_items("seed 0x5a17c0de"), _texts(compact=True)) == []

    def test_a_bare_number_member_holds_the_pair(self) -> None:
        assert _codes(_items("step 1")) == []

    def test_a_plain_text_entry_holds_name_equals_value(self) -> None:
        assert _codes(_items("seed 0x0c0ffee1", "rounds 7", ref="ev_0031")) == []

    def test_an_escaped_json_copy_holds_the_pair(self) -> None:
        nested = EntryTexts.from_ledger(
            [_entry("ev_0040", json.dumps({"raw": json.dumps(DECODER)}))]
        )
        assert _codes(_items("seed 0x5a17c0de", ref="ev_0040"), nested) == []


class TestOnlyThePairTheEntryHoldsCounts:
    def test_a_value_only_another_entry_holds_is_offered_that_entry(self) -> None:
        # The table's question leaves it to the citation check, which offers the holder.
        assert _codes(_items("seed 0x0badf00d")) == []
        violations = wrong_entry_citations(_items("seed 0x0badf00d"), _texts())
        assert [v.code for v in violations] == [CITATION_WRONG_ENTRY_CODE]
        assert "ev_0030" in violations[0].message

    def test_the_citation_check_shares_the_pair_reading(self) -> None:
        assert wrong_entry_citations(_items("seed 0x5a17c0de"), _texts()) == []

    def test_a_value_the_entry_gives_another_field_is_asked(self) -> None:
        assert _codes(_items("seed 0x2b")) == [STATED_VALUE_UNHELD_CODE]
        assert _codes(_items("first_key 0x5a17c0de")) == [STATED_VALUE_UNHELD_CODE]

    def test_a_prefix_of_the_field_s_value_is_asked(self) -> None:
        assert _codes(_items("seed 0x5a17")) == [STATED_VALUE_UNHELD_CODE]
        assert _codes(_items("seed 0x0c0f", ref="ev_0031")) == [STATED_VALUE_UNHELD_CODE]

    def test_a_longer_value_than_the_field_s_is_asked(self) -> None:
        assert _codes(_items("seed 0x5a17c0de00")) == [STATED_VALUE_UNHELD_CODE]

    def test_the_same_digits_in_another_radix_are_asked(self) -> None:
        assert _codes(_items("first_key 2b")) == [STATED_VALUE_UNHELD_CODE]
        assert _codes(_items("seed 5a17c0de")) == [STATED_VALUE_UNHELD_CODE]

    def test_a_field_name_the_entry_does_not_have_is_asked(self) -> None:
        assert _codes(_items("key 0x5a17c0de")) == [STATED_VALUE_UNHELD_CODE]

    def test_a_field_name_that_ends_another_is_asked(self) -> None:
        assert _codes(_items("key 0x2b")) == [STATED_VALUE_UNHELD_CODE]


# A plain ``name: value`` text whose value or name runs on through a colon, a
# slash or a backslash: each part is bounded on its own.
@pytest.mark.parametrize(
    ("text", "row"),
    [
        ("time: 12:30:00", "time 12"),
        ("seed: 0x5a17:c0de", "seed 0x5a17"),
        ("key: abc/def", "key abc"),
        ("url: http://host.example/x", "url http"),
        ("path: c:\\windows\\x", "path c"),
        ("cmd: ipconfig /all/x", "cmd ipconfig /all"),
        ("cfg:key: 0x2b", "key 0x2b"),
        ("cfg/key: 0x2b", "key 0x2b"),
        ('{"cfg/key": "0x2b"}', "key 0x2b"),
    ],
)
def test_a_part_that_runs_on_is_not_held(text: str, row: str) -> None:
    texts = EntryTexts.from_ledger([_entry("ev_0050", text)])
    assert not texts.holds("ev_0050", row, fields=True)
    assert _codes(_items(row, ref="ev_0050"), texts) == [STATED_VALUE_UNHELD_CODE]


@pytest.mark.parametrize(
    ("text", "row"),
    [
        ("time: 12 and more", "time 12"),
        ("key: abc, next: 1", "key abc"),
        ("url: http://host.example/x", "url http://host.example/x"),
        ("cfg key: 0x2b.", "key 0x2b"),
    ],
)
def test_a_whole_pair_in_plain_text_is_held(text: str, row: str) -> None:
    texts = EntryTexts.from_ledger([_entry("ev_0050", text)])
    assert texts.holds("ev_0050", row, fields=True)


class TestOnlyTheTableAndCitationChecksReadPairs:
    def test_a_sample_string_read_is_never_held_by_a_tool_s_field(self) -> None:
        texts = EntryTexts.from_ledger([_entry("ev_0060", json.dumps({"offset": 4096}))])
        assert texts.holds("ev_0060", "offset 4096", fields=True)
        assert not texts.holds("ev_0060", "offset 4096")
        assert texts.holding("offset 4096") == []


class TestTheSpellings:
    def test_only_a_name_and_a_value_have_pair_spellings(self) -> None:
        assert field_value_spellings("0x5a17c0de") == ()
        assert field_value_spellings("cmd.exe /c") == ()
        assert '"seed": "0x5a17c0de"' in field_value_spellings("Seed 0x5A17C0DE")

    def test_the_value_comes_first(self) -> None:
        assert held_spellings("seed 0x5a17c0de")[0] == "seed 0x5a17c0de"


def _timed(scale: int) -> float:
    """A table of twenty-two rows over an entry ``scale`` times as long, two values as long."""
    blob = json.dumps(
        {
            "parameters": [
                {"seed": f"0x{n:08x}", "first_key": f"0x{n % 256:02x}"} for n in range(scale)
            ]
        }
    )
    texts = EntryTexts.from_ledger([_entry("ev_0021", blob)])
    payload = _items(
        *(f"seed 0x{n:08x}" for n in range(0, scale, scale // 20)),
        "seed " + "0" * scale,
        "seed" + " " * scale + "=" + "x" * scale,
    )
    gc.collect()
    began = time.perf_counter()
    found = stated_value_violations(payload, texts)
    seconds = time.perf_counter() - began
    assert [v.code for v in found] == [STATED_VALUE_UNHELD_CODE]
    return seconds


class TestTheCheckStaysLinear:
    def test_ten_times_the_entry_takes_about_ten_times_as_long(self) -> None:
        _timed(500)
        low = min(_timed(2_000) for _ in range(2))
        high = min(_timed(20_000) for _ in range(2))
        print("field pairs, 2,000 and 20,000:", round(low, 4), round(high, 4))
        assert high < low * 20
