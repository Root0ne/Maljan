"""A capa rule agrees with a stated anti-analysis row only where it states that row's kind.

Two ways the agreement was wrong. capa's ``PEB access`` is a ``lib/`` rule with
no namespace, and it agreed with a TEB/PEB read only because its name has the
word in it. And any capa rule under ``anti-analysis`` agreed with every row in
its function, so ``contain obfuscated stackstrings`` agreed with an SIDT. The
kind each rule states is read off capa's own namespaces and rule names
(``ghidra_passes.CAPA_NAMESPACE_KINDS``, ``CAPA_RULE_KINDS``); a rule that
states no kind agrees as every anti-analysis rule did.
"""

from __future__ import annotations

from typing import Any

from maljan.analysis.ghidra_passes import (
    CAPA_NAMESPACE_KINDS,
    CAPA_RULE_KINDS,
    SCAN_KINDS,
    capa_agrees,
    scan_kind,
)
from maljan.pipeline import triage_pack

DEBUGGER = "anti-analysis/anti-debugging/debugger-detection"
VM = "anti-analysis/anti-vm/vm-detection"
STACKSTRINGS = "anti-analysis/obfuscation/string/stackstring"


def _row(what: str, offset: str, category: str = "suspicious_instruction") -> dict[str, Any]:
    return {"category": category, "what": what, "offset": offset}


def _capa(rule: str, namespace: str, at: str) -> dict[str, Any]:
    return {"rule": rule, "namespace": namespace, "addresses": [at]}


def _marked(rows: list[dict[str, Any]], beside: list[dict[str, Any]], capa: list[Any]) -> Any:
    answer = {"stated": rows, "not_stated": 0, "beside_capa": beside}
    return triage_pack._anti_analysis_with_capa(answer, capa, ["0x1000", "0x2000"])


class TestTheRowsKind:
    def test_each_instruction_the_scan_states(self) -> None:
        kinds = {
            "RDTSC": "rdtsc",
            "CPUID (leaf 0x40000000)": "cpuid",
            "INT3": "int3",
            "INT 0x3": "int3",
            "INT 0x2d": "int 0x2d",
            "SIDT [EBP + -0x8]": "sidt",
            "SGDT [ESP]": "sgdt",
            "SLDT AX": "sldt",
            "STR AX": "str",
        }
        for what, kind in kinds.items():
            assert scan_kind(_row(what, "0x1")) == kind, what

    def test_a_peb_read_and_a_teb_read(self) -> None:
        teb = "peb_teb_access"
        assert scan_kind(_row("MOV EAX,FS:[0x30]", "0x1", teb)) == "peb"
        assert scan_kind(_row("MOV RAX,qword ptr GS:[0x60]", "0x1", teb)) == "peb"
        assert scan_kind(_row("MOV EAX,FS:[0x18]", "0x1", teb)) == "teb"
        assert scan_kind(_row("MOV EAX,FS:[0x0]", "0x1", teb)) is None
        gs_peb = "GS:[0x60] read (65 48 a1 60 00 00 00 00 00 00 00)"
        gs_teb = "GS:[0x30] read (65 48 8b 04 25 30 00 00 00)"
        assert scan_kind(_row(gs_peb, "0x1", teb)) == "peb"
        assert scan_kind(_row(gs_teb, "0x1", teb)) == "teb"

    def test_an_instruction_the_table_does_not_name_has_no_kind(self) -> None:
        assert scan_kind(_row("INT 0x80", "0x1")) is None
        assert scan_kind(_row("", "0x1")) is None


class TestPebAccess:
    """capa's ``PEB access``, a ``lib/`` rule with no namespace."""

    def test_it_agrees_with_an_fs_and_a_gs_peb_read(self) -> None:
        assert capa_agrees("PEB access", "", "peb")
        assert capa_agrees("PEB access", "", "teb")
        assert capa_agrees("access PEB ldr_data", "linking/runtime-linking", "peb")

    def test_a_read_in_its_function_is_stated_with_it(self) -> None:
        read = _row("MOV EAX,FS:[0x30]", "0x1210", "peb_teb_access")

        marked = _marked([], [read], [_capa("PEB access", "", "0x1290")])

        assert marked["stated"] == [{**read, "capa": [{"rule": "PEB access", "at": "0x1290"}]}]
        assert marked["not_stated"] == 0

    def test_it_agrees_with_no_instruction(self) -> None:
        for kind in ("rdtsc", "sidt", "int3", None):
            assert not capa_agrees("PEB access", "", kind), kind

    def test_another_rule_outside_anti_analysis_agrees_with_nothing(self) -> None:
        assert not capa_agrees("get process heap flags", "host-interaction/process", "peb")
        assert not capa_agrees("PEB walk", "linking/runtime-linking", "peb")


class TestTheKindCapaStates:
    """An anti-analysis rule agrees with a row of the kind its namespace states."""

    def test_a_stack_string_rule_does_not_agree_with_an_sidt(self) -> None:
        sidt = _row("SIDT [EBP + -0x8]", "0x1210")

        marked = _marked(
            [sidt], [], [_capa("contain obfuscated stackstrings", STACKSTRINGS, "0x1220")]
        )

        assert marked["stated"] == [sidt]

    def test_a_vm_rule_agrees_with_an_sidt_and_a_debugger_rule_does_not(self) -> None:
        sidt = _row("SIDT [EBP + -0x8]", "0x1210")
        rdtsc = _row("RDTSC", "0x2210")
        capa = [
            _capa("check for unmoving mouse cursor", VM, "0x1220"),
            _capa("check for debugger via API", DEBUGGER, "0x1230"),
            _capa("execute anti-debugging instructions", DEBUGGER, "0x2220"),
        ]

        marked = _marked([sidt, rdtsc], [], capa)

        assert [c["rule"] for c in marked["stated"][0]["capa"]] == [
            "check for unmoving mouse cursor"
        ]
        assert [c["rule"] for c in marked["stated"][1]["capa"]] == [
            "execute anti-debugging instructions"
        ]

    def test_a_peb_read_beside_a_vm_rule_alone_is_counted(self) -> None:
        read = _row("MOV EAX,FS:[0x30]", "0x1210", "peb_teb_access")

        marked = _marked([], [read], [_capa("check for unmoving mouse cursor", VM, "0x1220")])

        assert marked["stated"] == [] and marked["not_stated"] == 1

    def test_a_rule_that_states_no_kind_agrees_as_before(self) -> None:
        for namespace in ("anti-analysis", "anti-analysis/anti-something-new"):
            for kind in (*sorted(SCAN_KINDS), None):
                assert capa_agrees("r", namespace, kind), (namespace, kind)

    def test_a_row_with_no_kind_agrees_with_every_anti_analysis_rule(self) -> None:
        assert capa_agrees("contain obfuscated stackstrings", STACKSTRINGS, None)
        assert capa_agrees("r", VM, None)


class TestTheTable:
    def test_every_kind_is_one_the_scan_states_and_each_is_held_by_a_namespace(self) -> None:
        held = {kind for kinds in CAPA_NAMESPACE_KINDS.values() for kind in kinds}
        named = {kind for kinds in CAPA_RULE_KINDS.values() for kind in kinds}

        assert held == SCAN_KINDS
        assert named <= SCAN_KINDS

    def test_every_namespace_is_capa_s_anti_analysis_one(self) -> None:
        assert all(space.startswith("anti-analysis/") for space in CAPA_NAMESPACE_KINDS)

    def test_a_sub_namespace_is_read_with_its_parent(self) -> None:
        assert not capa_agrees("packed with UPX", "anti-analysis/packer/upx", "rdtsc")
        assert capa_agrees("check for PEB NtGlobalFlag flag", DEBUGGER, "peb")
        assert capa_agrees("r", "anti-analysis/packerish", "rdtsc")
