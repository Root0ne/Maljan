"""A repeated call is known by the address it names, in one direction only.

An argument whose name says it takes an address in the binary
(``undeclared_tools.named_as_address``, read from the name alone, whatever the
tool) is keyed by its value where it is written with a ``0x`` prefix, so
``0x1360BC03868`` and ``0x1360bc03868`` are one call. A bare spelling is read
as that value only for a lookup, and only where it holds at least one decimal
digit and at least one hex letter and the argument's name has no ``name``
word (``name_or_address="add"`` is a symbol as likely as an address): a bare
ask is answered from an entry a ``0x`` call made, and a ``0x`` ask is never
answered from an entry a bare call made, since a tool nobody declared may read
the bare form otherwise. In haiku5 the reverser's round-2 disassembly was bare
(ev_0121) and its round-3 one prefixed (ev_0128): that direction still runs.
"""

from __future__ import annotations

from maljan.agents.evidence_recorder import RepeatGuard, seeded_repeat_guard
from maljan.schemas.evidence import build_entry

LISTING = "0x1360bc03868: PUSH RBX\n..."


def _key(tool: str, **kwargs: object) -> str:
    return RepeatGuard._key(tool, dict(kwargs))


def _guard(address: str, **args: object) -> RepeatGuard:
    earlier = build_entry(
        entry_id="ev_0121",
        seq=121,
        agent="all_tools_reverser_ghidra",
        tool="disassemble_function",
        args={"address": address, **args},
        server="ghidra",
        output=LISTING,
    )
    return seeded_repeat_guard([], earlier_rounds=[earlier])


class TestTheKey:
    def test_a_prefixed_address_is_keyed_by_its_value(self) -> None:
        assert _key("d", address="0x1360bc03868") == _key("d", address="0X1360BC03868")
        assert _key("d", function_address="0x401a00") == _key("d", function_address="0x0401A00")

    def test_a_bare_spelling_is_recorded_as_written(self) -> None:
        assert _key("d", address="1360bc03868") != _key("d", address="0x1360bc03868")

    def test_other_arguments_still_make_another_call(self) -> None:
        assert _key("d", address="0x10", count="0x10") != _key("d", address="0x10", count="0x010")
        assert _key("d", address="0x10", timeout=180) != _key("d", address="0x10")
        assert _key("d", host="0xab") != _key("d", host="0xAB")


class TestOneDirection:
    def test_a_bare_ask_is_answered_from_a_prefixed_entry(self) -> None:
        guard = _guard("0x1360bc03868")
        assert guard.recorded_answer("disassemble_function", {"address": "1360bc03868"}) == (
            "ev_0121",
            LISTING,
        )

    def test_a_prefixed_ask_is_never_answered_from_a_bare_entry(self) -> None:
        guard = _guard("1360bc03868")
        assert guard.recorded_answer("disassemble_function", {"address": "0x1360bc03868"}) is None
        assert guard.answered_by("disassemble_function", {"address": "0x1360bc03868"}) is None

    def test_the_same_bare_spelling_is_still_the_same_call(self) -> None:
        guard = _guard("1360bc03868")
        assert guard.recorded_answer("disassemble_function", {"address": "1360bc03868"}) == (
            "ev_0121",
            LISTING,
        )

    def test_a_bare_value_without_a_digit_or_without_a_letter_is_not_read_as_an_address(
        self,
    ) -> None:
        assert _guard("0xadd").recorded_answer("disassemble_function", {"address": "add"}) is None
        assert _guard("0x4096").recorded_answer("disassemble_function", {"address": "4096"}) is None

    def test_an_argument_named_for_a_name_keeps_its_bare_value_as_written(self) -> None:
        earlier = build_entry(
            entry_id="ev_0007",
            seq=7,
            agent="reverser",
            tool="decompile",
            args={"name_or_address": "0xadd1"},
            server="ghidra",
            output=LISTING,
        )
        guard = seeded_repeat_guard([], earlier_rounds=[earlier])
        assert guard.recorded_answer("decompile", {"name_or_address": "add1"}) is None
        assert guard.recorded_answer("decompile", {"name_or_address": "0xADD1"}) == (
            "ev_0007",
            LISTING,
        )
