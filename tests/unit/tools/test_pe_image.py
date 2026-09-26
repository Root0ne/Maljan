"""The one reading of a PE both resolving tools use: functions, chains and the table's own bytes.

Every image is built in the test (``synthetic_pe``).
"""

from __future__ import annotations

import struct

from maljan.tools import pe_image
from maljan.tools.rules import capa_function_starts

from .synthetic_pe import PDATA_RVA, RDATA_RVA, TEXT_RVA, SyntheticPE

CHAININFO = 0x4 << 3


def _unwind(flags: int, chained: tuple[int, int, int] | None = None) -> bytes:
    """An UNWIND_INFO with no codes, and the chained entry when the flag says so."""
    record = bytes([1 | flags, 0, 0, 0])
    if chained is not None:
        record += struct.pack("<III", *chained)
    return record


class TestAChainedFragment:
    def test_is_stated_with_the_start_of_the_function_it_belongs_to(self) -> None:
        image = SyntheticPE()
        primary = image.put("rdata", 0x100, _unwind(0))
        fragment = image.put(
            "rdata", 0x110, _unwind(CHAININFO, (TEXT_RVA, TEXT_RVA + 0x80, primary))
        )
        image.functions = [
            (TEXT_RVA, TEXT_RVA + 0x80, primary),
            (TEXT_RVA + 0x200, TEXT_RVA + 0x240, fragment),
        ]
        parsed = pe_image.parse(image.build())
        assert parsed.function_at(TEXT_RVA + 0x10) == TEXT_RVA
        assert parsed.function_at(TEXT_RVA + 0x210) == TEXT_RVA, "not the fragment's own begin"
        assert "1 chained fragments" in parsed.function_table

    def test_a_chain_that_cannot_be_followed_states_no_function(self) -> None:
        image = SyntheticPE()
        # A chain that points back at itself never reaches a primary entry.
        loop = RDATA_RVA + 0x120
        image.put("rdata", 0x120, _unwind(CHAININFO, (TEXT_RVA + 0x300, TEXT_RVA + 0x340, loop)))
        image.functions = [(TEXT_RVA + 0x300, TEXT_RVA + 0x340, loop)]
        parsed = pe_image.parse(image.build())
        assert parsed.function_at(TEXT_RVA + 0x310) is None


class TestAnImageWithoutATable:
    def test_takes_capa_s_function_starts_and_says_what_they_are(self) -> None:
        image = SyntheticPE(is64=False, image_base=0x400000)
        parsed = pe_image.parse(image.build())
        assert parsed.function_at(TEXT_RVA + 0x141) is None
        pe_image.take_function_starts(parsed, ["0x1000", "0x1100", "not a number"], "capa")
        assert parsed.function_at(TEXT_RVA + 0x141) == TEXT_RVA + 0x100
        assert parsed.function_at(TEXT_RVA + 0x20) == TEXT_RVA
        assert parsed.function_table.startswith("capa, 2 function starts")
        assert "not where they end" in parsed.function_table

    def test_an_image_with_its_own_table_keeps_it(self) -> None:
        image = SyntheticPE(functions=[(TEXT_RVA, TEXT_RVA + 0x40)])
        parsed = pe_image.parse(image.build())
        pe_image.take_function_starts(parsed, ["0x1100"], "capa")
        assert parsed.function_at(TEXT_RVA + 0x141) is None
        assert parsed.function_table.startswith("exception directory")

    def test_capa_s_feature_counts_give_the_starts(self) -> None:
        base = 0x400000
        document = {
            "meta": {
                "analysis": {
                    "base_address": {"type": "absolute", "value": base},
                    "feature_counts": {
                        "file": 3,
                        "functions": [
                            {"address": {"type": "absolute", "value": base + 0x1000}, "count": 9},
                            {"address": {"type": "absolute", "value": base + 0x1100}, "count": 4},
                        ],
                    },
                }
            }
        }
        assert capa_function_starts(document) == ["0x1000", "0x1100"]
        del document["meta"]["analysis"]["base_address"]
        assert capa_function_starts(document) == []


def test_the_function_table_is_not_read_as_program_data() -> None:
    image = SyntheticPE(functions=[(TEXT_RVA, TEXT_RVA + 0x40)], pdata_tail=b"\x55" * 16)
    parsed = pe_image.parse(image.build())
    (section,) = [s for s in parsed.data_sections() if s.rva == PDATA_RVA]
    assert b"\x55" in parsed.section_bytes(section)
    assert b"\x55" not in parsed.data_bytes(section)
    assert not any(parsed.data_bytes(section)[:24])
