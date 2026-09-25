"""The code-reading stage is handed where the static tools found things, by address.

A reverser told "capa matched a rule" and "FLOSS decoded a string" has to find
both again before it can read them. The pack every agent reads carries each
decoded string with the routine that produced it and the call site, and each
capa rule with the places it matched, as offsets from the image base: the
numbers a decompiler that loaded the file goes to directly.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.agents.prompts import REVERSER_PROMPT
from maljan.pipeline.triage_pack import PIPELINE, pack_block, pack_entries
from maljan.schemas.evidence import build_entry, format_entry_id
from maljan.tools.rules import _capa_capabilities

BASE = 0x180000000


def _capa_document() -> dict[str, Any]:
    def at(offset: int) -> dict[str, Any]:
        return {"type": "absolute", "value": BASE + offset}

    return {
        "meta": {
            "version": "9.4.0",
            "analysis": {
                "format": "pe",
                "arch": "amd64",
                "os": "windows",
                "base_address": {"type": "absolute", "value": BASE},
            },
            "sample": {"sha256": "a" * 64},
        },
        "rules": {
            "parse PE header": {
                "meta": {"name": "parse PE header", "namespace": "load-code/pe"},
                "matches": [
                    [at(0x1A20), {}],
                    [at(0x2B40), {}],
                    [at(0x1A20), {}],
                    [at(0x3C00), {}],
                ],
            },
            "contain an embedded PE file": {
                "meta": {"name": "contain an embedded PE file", "namespace": "executable"},
                "matches": [[{"type": "no address", "value": None}, {}]],
            },
            "read a raw offset": {
                "meta": {"name": "read a raw offset", "namespace": "x"},
                "matches": [[{"type": "file", "value": 0x400}, {}]],
            },
        },
    }


class TestCapaSaysWhereARuleMatched:
    def test_an_address_in_the_image_is_its_offset_from_the_base(self) -> None:
        rows = {row["rule"]: row for row in _capa_capabilities(_capa_document())}
        assert rows["parse PE header"]["addresses"] == ["0x1a20", "0x2b40", "0x3c00"], (
            "once each, in order"
        )
        assert rows["parse PE header"]["match_count"] == 4

    def test_a_file_scope_rule_has_no_address(self) -> None:
        rows = {row["rule"]: row for row in _capa_capabilities(_capa_document())}
        assert rows["contain an embedded PE file"]["addresses"] == []

    def test_a_file_offset_is_marked_as_one(self) -> None:
        rows = {row["rule"]: row for row in _capa_capabilities(_capa_document())}
        assert rows["read a raw offset"]["addresses"] == ["file 0x400"]

    def test_with_no_base_named_an_address_is_marked_virtual(self) -> None:
        document = _capa_document()
        del document["meta"]["analysis"]["base_address"]
        rows = {row["rule"]: row for row in _capa_capabilities(document)}
        assert rows["parse PE header"]["addresses"][0] == f"va {hex(BASE + 0x1A20)}"


def _entry(tool: str, payload: dict[str, Any], seq: int) -> Any:
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent=PIPELINE,
        tool=tool,
        args={},
        server=PIPELINE,
        output=json.dumps(payload),
        ok=True,
        stage="triage_pack",
    )


FLOSS = {
    "strings": [
        {
            "kind": "decoded",
            "string": "first recovered text",
            "function": hex(BASE + 0x5000),
            "function_rva": "0x5000",
            "called_at": hex(BASE + 0x6100),
            "called_at_rva": "0x6100",
        },
        {
            "kind": "stack",
            "string": "built on the stack",
            "function": hex(BASE + 0x7000),
            "function_rva": "0x7000",
        },
    ],
    "counts": {"decoded": 1, "stack": 1, "tight": 0},
    "total": 2,
    "meta": {"functions_discovered": 40, "functions_emulated_for_decoding": 12},
}


def _pack(max_chars: int = 0) -> str:
    capa = {"capabilities": _capa_capabilities(_capa_document()), "meta": {}}
    entries = pack_entries([_entry("capa", capa, 1), _entry("floss", FLOSS, 2)])
    return pack_block(entries, max_chars)


class TestThePackEveryAgentReads:
    def test_each_capa_rule_carries_where_it_matched(self) -> None:
        block = _pack()
        assert "parse PE header @ 0x1a20 0x2b40 0x3c00" in block
        assert "offsets from the image base where it matched" in block

    def test_each_decoded_string_carries_its_routine_and_call_site(self) -> None:
        block = _pack()
        assert "routine 0x5000" in block
        assert '"first recovered text"@0x6100' in block
        assert "routine 0x7000" in block

    def test_a_pack_that_must_say_less_names_how_many_addresses_it_left_out(self) -> None:
        from maljan.pipeline.triage_pack import _DETAIL, PackDetail, _capa

        capa = {"capabilities": _capa_capabilities(_capa_document())}
        token = _DETAIL.set(PackDetail.at(2))
        try:
            line = _capa(capa)
        finally:
            _DETAIL.reset(token)
        assert "parse PE header @ 0x1a20 0x2b40 (+1 more)" in line

    def test_the_agent_brief_carries_the_pack(self) -> None:
        from maljan.pipeline.nodes import brief_agent

        class _Agent:
            pass

        class _Container:
            class config:  # noqa: N801
                class reporting:  # noqa: N801
                    upstream_findings_max_chars = 1_000_000

        agent = _Agent()
        capa = {"capabilities": _capa_capabilities(_capa_document()), "meta": {}}
        state = {
            "evidence_ledger": [
                _entry("capa", capa, 1).model_dump(mode="json"),
                _entry("floss", FLOSS, 2).model_dump(mode="json"),
            ]
        }
        brief_agent(agent, state, _Container())  # type: ignore[arg-type]
        assert "parse PE header @ 0x1a20 0x2b40 0x3c00" in agent.facts_block
        assert '"first recovered text"@0x6100' in agent.facts_block


class TestTheReverserIsToldToUseThem:
    def test_it_starts_from_the_addresses(self) -> None:
        assert "offsets from the image base" in REVERSER_PROMPT
        assert "capability rule" in REVERSER_PROMPT

    def test_it_confirms_or_refutes_each_upstream_finding(self) -> None:
        for outcome in ('"Confirmed"', '"Refuted"', '"Unresolved"'):
            assert outcome in REVERSER_PROMPT

    def test_it_looks_for_the_control_flow_the_static_stage_could_not_see(self) -> None:
        for area in (
            "Command dispatch",
            "Environment checks",
            "Persistence and cleanup",
            "Contact with a remote host",
            "Decoding",
        ):
            assert area in REVERSER_PROMPT
