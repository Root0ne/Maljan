"""Each calibration case holds what its manifest says it holds, and is the same on every build.

The facts are checked against the bytes by means of this test's own (the
import table read with ``pefile``, the code decoded instruction by instruction
from the entry point by a decoder for exactly the forms the generator writes,
a one-byte XOR searched for, ROR-13 values computed here), and the config blob
by the platform's own decoder, so a case's hard facts are known to be within a
deterministic tool's reach. No case is ever written outside a temporary
directory, and none is run.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pefile
import pytest
from scripts.calibration import cases
from scripts.calibration.cases import FORMATS, SPLITS, Entry

from maljan.tools import upx
from maljan.tools.string_blobs import decode_string_blobs
from tests.unit.tools import synthetic_upx as su
from tests.unit.tools.synthetic_pe import DATA_RVA, TEXT_RVA, SyntheticPE

ALL = cases.build_all()
BY_ID = {c.case_id: c for c in ALL}
_WRITE = 0x80000000
_EXECUTE = 0x20000000

# The set as seeds.json builds it today. A change to the generator, the
# catalogue or a seed changes these, and a run scored against the old set no
# longer matches: update them together, on purpose.
DIGESTS = {
    "cal-pe32-2101": "82f13984c621c3d9",
    "cal-pe32-2102": "8a9e5e2a0a8b9339",
    "cal-pe32-2103": "a8cf4fafd314c418",
    "cal-pe32-2104": "2c2b6e7d91bc7f87",
    "cal-pe64-1101": "2cf522b91628a11e",
    "cal-pe64-1102": "a05a90dc7828c7b8",
    "cal-pe64-1103": "074875bd569ed71d",
    "cal-pe64-1104": "37009d730a96d240",
    "cal-upx-3101": "8a8ce3d01283ce45",
    "cal-upx-3102": "fd5305a641105e9c",
    "cal-upx-3103": "248942f2b5df9d5a",
    "cal-upx-3104": "d00a905ad7590b96",
}


def _plain_text(case: cases.Case) -> list[str]:
    return [t[0] for f in case.manifest()["facts"] for t in f["terms"]]


def _liblzma() -> str:
    """Which LZMA encoder built the packed cases, as far as this process can tell."""
    import ctypes
    import ctypes.util
    import sys

    found = []
    for label, name in (("in this Python", None), ("system", ctypes.util.find_library("lzma"))):
        try:
            version = ctypes.CDLL(name).lzma_version_string
            version.restype = ctypes.c_char_p
            found.append(f"{label}: liblzma {version().decode()}")
        except (OSError, AttributeError, TypeError):
            found.append(f"{label}: liblzma version not exposed")
    return f"Python {sys.version.split()[0]}; " + "; ".join(found)


def test_the_set_is_the_one_its_seeds_build() -> None:
    built = {c.case_id: hashlib.sha256(c.data).hexdigest()[:16] for c in ALL}
    moved = sorted(k for k in DIGESTS if built.get(k) != DIGESTS[k])
    # The packed cases are LZMA streams, whose bytes xz does not promise to keep
    # across encoder versions: a packed case alone moving points there first.
    note = f" (packed with {_liblzma()})" if any("-upx-" in k for k in moved) else ""
    assert built == DIGESTS, f"cases changed: {moved}{note}"


def test_two_builds_give_the_same_bytes_and_manifests() -> None:
    again = cases.build_all()
    assert [c.data for c in again] == [c.data for c in ALL]
    assert [json.dumps(c.manifest()) for c in again] == [json.dumps(c.manifest()) for c in ALL]


def test_no_case_is_written_as_a_program() -> None:
    for case in ALL:
        assert cases.file_name(case.case_id).endswith(".bin")


class TestTheSplit:
    def test_each_format_is_split_in_half_and_the_manifest_says_which(self) -> None:
        for fmt in FORMATS:
            rows = [c for c in ALL if c.format == fmt]
            tuning = [c for c in rows if c.split == SPLITS[0]]
            assert len(tuning) == len(rows) // 2
            for case in rows:
                assert case.manifest()["split"] == case.split
                assert case.manifest()["split_seed"] == case.split_seed

    def test_the_split_seed_fixes_the_split(self) -> None:
        by_format = {"pe64": [1, 2, 3, 4, 5, 6]}
        first = cases.split(11, by_format)
        assert cases.split(11, by_format) == first
        others = [cases.split(seed, by_format) for seed in range(12, 40)]
        assert any(o != first for o in others)
        assert all(sum(e.split == "tuning" for e in o) == 3 for o in [first, *others])

    def test_an_odd_count_holds_the_extra_case_out(self) -> None:
        rows = cases.split(5, {"upx": [1, 2, 3]})
        assert [e.split for e in rows].count("heldout") == 2

    def test_a_seed_listed_twice_or_a_format_unknown_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "seeds.json"
        path.write_text(json.dumps({"split_seed": 1, "cases": [{"seed": 1, "format": "pe64"}] * 2}))
        with pytest.raises(cases.CaseError, match="listed twice"):
            cases.read_seeds(path)
        path.write_text(json.dumps({"split_seed": 1, "cases": [{"seed": 1, "format": "elf"}]}))
        with pytest.raises(cases.CaseError, match="format"):
            cases.read_seeds(path)

    def test_a_half_left_out_is_not_built(self, monkeypatch: pytest.MonkeyPatch) -> None:
        built: list[Entry] = []
        real = cases.build
        monkeypatch.setattr(cases, "build", lambda e, s: built.append(e) or real(e, s))
        cases.build_all(splits=("heldout",))
        assert built and all(e.split == "heldout" for e in built)


def _imports(pe: pefile.PE) -> dict[str, int]:
    return {
        imp.name.decode(): imp.address - pe.OPTIONAL_HEADER.ImageBase
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        for imp in entry.imports
        if imp.name
    }


class Decoded:
    """What the code does: the RVAs it takes, the slots it calls, the functions it reaches."""

    def __init__(self) -> None:
        self.refs: set[int] = set()
        self.slots: set[int] = set()
        self.functions: set[int] = set()


def _decode(text: bytes, start: int, is64: bool, base: int, into: Decoded) -> None:
    """Decode from ``start`` (an offset into ``.text``) to ``ret``, following calls.

    Only the forms the generator writes are known (``call rel32``, ``lea rcx,
    [rip+disp32]``, ``push imm32``, ``call [slot]``, ``ret``); any other byte on
    the path fails, so a reference swallowed by a neighbour cannot pass.
    """
    if start in into.functions:
        return
    into.functions.add(start)
    at = start
    while True:
        op = text[at]
        if op == 0xC3:
            return
        if op == 0xE8:
            target = at + 5 + struct.unpack("<i", text[at + 1 : at + 5])[0]
            _decode(text, target, is64, base, into)
            at += 5
        elif is64 and text[at : at + 3] == b"\x48\x8d\x0d":
            into.refs.add(TEXT_RVA + at + 7 + struct.unpack("<i", text[at + 3 : at + 7])[0])
            at += 7
        elif not is64 and op == 0x68:
            into.refs.add(struct.unpack("<I", text[at + 1 : at + 5])[0] - base)
            at += 5
        elif text[at : at + 2] == b"\xff\x15":
            operand = text[at + 2 : at + 6]
            if is64:
                into.slots.add(TEXT_RVA + at + 6 + struct.unpack("<i", operand)[0])
            else:
                into.slots.add(struct.unpack("<I", operand)[0] - base)
            at += 6
        else:
            raise AssertionError(f"byte {op:#04x} at .text+{at:#x} is no instruction written")


def _trace(pe: pefile.PE) -> tuple[set[int], set[int]]:
    """The slots called and the offsets reached, following control flow from the entry.

    For the packed program, whose filler the strict decoder does not know: it
    follows ``call``/``jmp rel32`` into ``.text``, walks ``nop`` and
    ``call [slot]``, ends a path at ``ret`` or at a byte it does not know, and
    visits each offset once, so a loop ends the walk instead of running on.
    """
    text = pe.sections[0].get_data()
    is64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    base = pe.OPTIONAL_HEADER.ImageBase
    slots: set[int] = set()
    seen: set[int] = set()
    work = [pe.OPTIONAL_HEADER.AddressOfEntryPoint - TEXT_RVA]
    while work:
        at = work.pop()
        while 0 <= at < len(text) - 6 and at not in seen:
            seen.add(at)
            op = text[at]
            if op in (0xE8, 0xE9):
                work.append(at + 5 + struct.unpack("<i", text[at + 1 : at + 5])[0])
                if op == 0xE9:
                    break
                at += 5
            elif op == 0x90:
                at += 1
            elif text[at : at + 2] == b"\xff\x15":
                operand = text[at + 2 : at + 6]
                if is64:
                    slots.add(TEXT_RVA + at + 6 + struct.unpack("<i", operand)[0])
                else:
                    slots.add(struct.unpack("<I", operand)[0] - base)
                at += 6
            else:
                break
    return slots, seen


def _code(pe: pefile.PE, start_rva: int | None = None) -> Decoded:
    text = pe.sections[0].get_data()
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint if start_rva is None else start_rva
    decoded = Decoded()
    _decode(
        text, entry - TEXT_RVA, pe.OPTIONAL_HEADER.Magic == 0x20B, pe.OPTIONAL_HEADER.ImageBase,
        decoded,
    )  # fmt: skip
    return decoded


@pytest.mark.parametrize("case_id", sorted(c.case_id for c in ALL if c.format != "upx"))
def test_a_plain_case_holds_its_facts_and_its_traps(case_id: str, tmp_path: Path) -> None:
    case = BY_ID[case_id]
    document = case.manifest()
    pe = pefile.PE(data=case.data)
    imports = _imports(pe)
    sections = {s.Name.rstrip(b"\0").decode(): s for s in pe.sections}
    data = sections[".data"].get_data()
    target = tmp_path / document["file"]
    target.write_bytes(case.data)
    blobs = decode_string_blobs(str(target))["results"]
    facts = {f["kind"]: f for f in document["facts"] if f["kind"] != "import"}

    code = _code(pe)
    assert len(code.functions) == 2, "the entry and the function it calls"
    for fact in document["facts"]:
        if fact["kind"] == "import":
            name = fact["terms"][0][0]
            assert imports[name] == fact["rva"] and fact["rva"] in code.slots, name
        elif fact["rva"] is not None:
            assert fact["rva"] in code.refs, fact["id"]
    assert code.refs == {f["rva"] for f in document["facts"] if f["kind"] != "import" and f["rva"]}
    assert facts["string"]["terms"][0][0].encode() + b"\0" in case.data
    anomaly = sections[facts["section_anomaly"]["terms"][0][0]]
    assert anomaly.Characteristics & _WRITE and anomaly.Characteristics & _EXECUTE
    hidden = facts["xor_string"]["terms"][0][0].encode()
    assert hidden not in case.data
    assert any(bytes(b ^ key for b in hidden) in data for key in range(0x100))
    assert facts["xor_string"]["rva"] - DATA_RVA == data.index(
        next(
            bytes(b ^ k for b in hidden)
            for k in range(0x100)
            if bytes(b ^ k for b in hidden) in data
        )
    )
    for (name,) in facts["api_hash"]["terms"]:
        assert struct.pack("<I", cases.ror13(name)) in data
        assert name.encode() not in case.data
    config_id, host, key = facts["config"]["terms"]
    (row,) = [r for r in blobs if r["scheme"] == "xor_keyed_header"]
    assert config_id[0] in row["text"] and host[0] in row["text"]
    assert row["parameters"]["key"] in key

    traps = {t["kind"]: t for t in document["traps"]}
    dead = traps["dead_import"]["subject"]
    assert dead in imports and imports[dead] not in code.slots
    comment_api = traps["comment_api"]["subject"]
    assert comment_api.encode() in case.data and comment_api not in imports
    assert traps["comment_api"]["rva"] not in code.refs
    decoy = traps["decoy_url"]["subject"]
    resources = [
        pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size)
        for kind in pe.DIRECTORY_ENTRY_RESOURCE.entries
        for name in kind.directory.entries
        for lang in name.directory.entries
    ]
    assert resources == [decoy.encode() + b"\0"]


@pytest.mark.parametrize("case_id", sorted(c.case_id for c in ALL if c.format == "upx"))
def test_a_packed_case_holds_its_facts_and_its_traps(case_id: str) -> None:
    case = BY_ID[case_id]
    document = case.manifest()
    assert upx.has_pack_header(case.data)
    unpacked = pefile.PE(data=upx.unpack(case.data).image)
    imports = _imports(unpacked)
    called, reached = _trace(unpacked)
    assert su.CALL_BLOCK - TEXT_RVA in reached, "the call block is reached from the entry"
    exports = {e.name.decode() for e in unpacked.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
    for fact in document["facts"]:
        name = fact["terms"][0][0]
        if fact["kind"] == "import":
            assert imports[name] == fact["rva"] and fact["rva"] in called, name
            assert name.encode() not in case.data, f"{name} is readable in the packed file"
        elif fact["kind"] == "export":
            assert name in exports
    traps = {t["kind"]: t for t in document["traps"]}
    dead = traps["dead_import"]["subject"]
    assert dead in imports and imports[dead] not in called
    decoy = traps["decoy_url"]["subject"]
    assert case.data.endswith(decoy.encode() + b"\0"), "the decoy is the overlay"


def test_no_absent_capability_is_one_a_fact_or_a_trap_names() -> None:
    for case in ALL:
        document = case.manifest()
        named = [t for f in document["facts"] for t in f["techniques"]]
        named += [t for x in document["traps"] for t in x["claims"]["techniques"]]
        for absent in document["absent"]:
            for technique in absent["claims"]["techniques"]:
                assert not any(cases.covers(technique, n) for n in named), (case.case_id, absent)
        assert document["absent"], case.case_id


def test_each_half_draws_its_surface_from_its_own_half_of_every_catalogue() -> None:
    surfaces: dict[str, set[str]] = {split: set() for split in SPLITS}
    for case in ALL:
        document = case.manifest()
        seen = surfaces[case.split]
        seen |= {t[0] for f in document["facts"] if f["kind"] in ("import", "api_hash")
                 for t in f["terms"]}  # fmt: skip
        seen |= {t["subject"] for t in document["traps"] if t["kind"] != "decoy_url"}
        seen |= {p for p in cases.TEMPLATE_PHRASES if p in case.leak_terms}
    assert surfaces["tuning"] and surfaces["heldout"]
    assert not surfaces["tuning"] & surfaces["heldout"]


def test_the_template_phrases_are_leak_terms_and_one_claim_is_one_trap() -> None:
    assert cases.TEMPLATE_PHRASES
    for case in ALL:
        if case.format != "upx":
            assert any(p in case.leak_terms for p in cases.TEMPLATE_PHRASES), case.case_id
        traps = [x["claims"]["techniques"] for x in case.manifest()["traps"]]
        for i, first in enumerate(traps):
            for second in traps[i + 1 :]:
                assert not any(cases.covers(a, b) for a in first for b in second), case.case_id


def test_the_leak_terms_are_the_generated_values() -> None:
    for case in ALL:
        assert len(case.leak_terms) == len(set(case.leak_terms)), case.case_id
        for term in case.leak_terms:
            assert not any(term == name for _, name, *_ in cases.CALLED_IMPORTS)
            assert term not in cases.WORDS


def test_an_image_without_the_new_parts_is_laid_out_as_before() -> None:
    """The digests the generator gave before it learnt extra sections, resources and an overlay."""
    image = SyntheticPE()
    pe = pefile.PE(data=image.build())
    assert [s.Name.rstrip(b"\0") for s in pe.sections] == [b".text", b".rdata", b".data"]
    assert pe.get_overlay() is None
    assert hashlib.sha256(image.build()).hexdigest()[:16] == "22272ecc4912e2e4"
    image = SyntheticPE(functions=[(TEXT_RVA, TEXT_RVA + 0x100)])
    image.imports_at(0x100, {"KERNEL32.dll": ["CreateFileW"]})
    image.lea_to(0x10, DATA_RVA)
    assert hashlib.sha256(image.build()).hexdigest()[:16] == "9f196b91eba4f62a"


def test_the_decoder_fails_on_a_reference_a_gap_would_swallow() -> None:
    case = next(c for c in ALL if c.format == "pe64")
    pe = pefile.PE(data=case.data)
    text = bytearray(pe.sections[0].get_data())
    first = 0x100 + 7  # after the first lea of the function
    text[first + 1 : first + 1] = b"\0"
    with pytest.raises(AssertionError, match="no instruction written"):
        _decode(bytes(text), 0, True, pe.OPTIONAL_HEADER.ImageBase, Decoded())


def test_the_trace_fails_when_the_entry_never_reaches_the_call_block() -> None:
    program = su.Program(calls=[])
    unpacked = pefile.PE(data=upx.unpack(su.build(program).data).image)
    called, reached = _trace(unpacked)
    assert su.CALL_BLOCK - TEXT_RVA not in reached and not called


def test_a_moved_packed_digest_names_the_lzma_encoder() -> None:
    assert _liblzma().startswith("Python ") and "liblzma" in _liblzma()
