"""The calibration cases: synthetic PE files built from a seed, each with its ground truth.

Every case is built by the test suite's own PE writers
(``tests/unit/tools/synthetic_pe.py`` and ``synthetic_upx.py``) from one seed,
so the same seed gives the same bytes and the same manifest on every machine.
The bytes are benign and no case is ever run: the code is a short call
graph laid out back to back (the entry calls one function, which takes the
addresses of the parts it uses and calls the imports it uses, then returns),
so a disassembler finds every reference a fact claims, and none a trap lacks.

Every surface a case shows is drawn from its seed, and the catalogues it draws
from (the APIs, the comment phrasings, the URL shapes, the config's layout and
key names) are split in two: a tuning case draws from one half and a held-out
case from the other, so nothing learnt about the tuning cases' surface carries
over to the held-out ones. The template phrases are leak terms too
(:data:`TEMPLATE_PHRASES`).

A manifest says what is in the file and what is not:

- **facts**, each easy or hard, with the terms a report states it by (an
  import the code calls, a plain string, a section that is writable and
  executable, an XOR-encoded string, a table of API-name hashes, a config blob
  with its key stored in front, a packer layer, an export of a packed file);
- **traps**, which look like a capability and are not (an import no code
  calls, an API name inside a comment string, a URL in a resource or overlay
  nothing refers to), each with the publications that would claim it;
- **absent** capabilities a careless analysis might claim, each with the
  technique ids that would claim it.

The split into a tuning and a held-out half is fixed by ``seeds.json``'s split
seed, stratified by format, and written into every manifest.
"""

from __future__ import annotations

import hashlib
import json
import random
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tests.unit.tools import synthetic_upx as su
from tests.unit.tools.synthetic_pe import SECTION_ALIGNMENT, TEXT_RVA, SyntheticPE

SEEDS = Path(__file__).resolve().parent / "seeds.json"
MANIFEST_SCHEMA = 1
SPLITS: tuple[str, ...] = ("tuning", "heldout")
FORMATS: tuple[str, ...] = ("pe64", "pe32", "upx")

# Invented words the generated values are made of. Each value also carries
# random hex, so no value is a word a report or a prompt uses for anything else.
WORDS: tuple[str, ...] = (
    "amber", "basalt", "cobalt", "dune", "ember", "fjord", "garnet", "heath",
    "indigo", "juniper", "kestrel", "lichen", "marl", "nimbus", "onyx", "pumice",
    "quartz", "rowan", "sorrel", "tundra", "umber", "vesper", "willow", "yarrow",
)  # fmt: skip

# Each catalogue below is split by position: even entries for the tuning half,
# odd ones for the held-out half (:func:`_half`).

# Imports the code calls, with the technique the call is evidence of ("" for none).
CALLED_IMPORTS: tuple[tuple[str, str, str], ...] = (
    ("ADVAPI32.dll", "GetUserNameW", "T1033"),
    ("ADVAPI32.dll", "GetUserNameA", "T1033"),
    ("KERNEL32.dll", "GetComputerNameW", "T1082"),
    ("KERNEL32.dll", "GetSystemInfo", "T1082"),
    ("KERNEL32.dll", "FindFirstFileW", "T1083"),
    ("KERNEL32.dll", "GetLogicalDrives", "T1083"),
    ("KERNEL32.dll", "CreateToolhelp32Snapshot", "T1057"),
    ("KERNEL32.dll", "Process32FirstW", "T1057"),
    ("KERNEL32.dll", "GetSystemTimeAsFileTime", ""),
    ("KERNEL32.dll", "GetLocalTime", ""),
)
# Imports no code calls, with the techniques publishing them as a capability claims.
DEAD_IMPORTS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("ADVAPI32.dll", "RegSetValueExW", ("T1112", "T1547")),
    ("ADVAPI32.dll", "RegCreateKeyExW", ("T1112", "T1547")),
    ("KERNEL32.dll", "WriteProcessMemory", ("T1055",)),
    ("KERNEL32.dll", "VirtualAllocEx", ("T1055",)),
    ("ADVAPI32.dll", "CryptEncrypt", ("T1486",)),
    ("BCRYPT.dll", "BCryptEncrypt", ("T1486",)),
    ("USER32.dll", "SetWindowsHookExW", ("T1056",)),
    ("USER32.dll", "GetAsyncKeyState", ("T1056",)),
)
# API names written only inside a comment string, with the techniques they suggest.
COMMENT_APIS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("CreateRemoteThread", ("T1055",)),
    ("QueueUserAPC", ("T1055",)),
    ("URLDownloadToFileW", ("T1105",)),
    ("InternetOpenUrlW", ("T1105",)),
    ("BitBlt", ("T1113",)),
    ("PrintWindow", ("T1113",)),
    ("CreateServiceW", ("T1543",)),
    ("StartServiceW", ("T1543",)),
)
# The comment strings an API name is written into: (template, its fixed phrase).
COMMENT_TEMPLATES: tuple[tuple[str, str], ...] = (
    ("// {api} is not called in this build", "is not called in this build"),
    ("/* {api}: kept for reference, unused */", "kept for reference, unused"),
    ("# {api} was dropped from the loader long ago", "was dropped from the loader long ago"),
    ("TODO: remove the stale {api} prototype", "remove the stale"),
)
# The shapes of a decoy URL: (template, its fixed phrase or "").
URL_SHAPES: tuple[tuple[str, str], ...] = (
    ("https://{host}/{word}/{token}.html", ""),
    ("http://{host}:{port}/{word}/{token}", ""),
    ("https://{host}/{word}/{word2}?k={hex}", ""),
    ("https://{host}/{token}/{word}.php", ""),
)
# The roles of a config's three fields, each a pool of names.
CONFIG_ID_NAMES: tuple[str, ...] = ("id", "bot", "grp", "node")
CONFIG_HOST_NAMES: tuple[str, ...] = ("host", "srv", "gate", "relay")
CONFIG_PORT_NAMES: tuple[str, ...] = ("port", "tcp", "svc", "p")
CONFIG_SEPARATORS: tuple[str, ...] = (";", "&", "|", ",")
# The config blob's stated-length width: the decoder reads both.
CONFIG_LENGTH_WIDTHS: tuple[str, ...] = ("<H", "<I")
# Capabilities no case has, and the technique ids that would claim each.
ABSENT: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("process injection", ("T1055",)),
    ("persistence through a Run key or the Startup folder", ("T1547",)),
    ("a scheduled task", ("T1053",)),
    ("data encrypted for impact", ("T1486",)),
    ("inhibiting system recovery", ("T1490",)),
    ("input capture", ("T1056",)),
    ("screen capture", ("T1113",)),
    ("a new service", ("T1543",)),
    ("ingress tool transfer", ("T1105",)),
    ("an application-layer command-and-control protocol", ("T1071",)),
    ("registry modification", ("T1112",)),
)
# Names whose ROR-13 hashes a case keeps in a table.
HASHED_APIS: tuple[str, ...] = (
    "VirtualProtect", "Sleep", "CreateMutexA", "GetTickCount64", "LoadLibraryW", "ExitProcess",
    "HeapAlloc", "OpenMutexW", "GetModuleHandleW", "FreeLibrary", "WaitForSingleObject",
    "GetCurrentProcessId",
)  # fmt: skip
# Every fixed phrase the generator writes into a case: a prompt carrying one
# would be tuned to the generator rather than to any sample.
TEMPLATE_PHRASES: tuple[str, ...] = tuple(
    phrase for _, phrase in (*COMMENT_TEMPLATES, *URL_SHAPES) if phrase
)

_INT3 = 0xCC  # the filler between functions: no instruction runs into it
_ENTRY_TO_FUNCTION = 0x100  # where the one function starts, from the entry
_RDATA_MARKER, _RDATA_COMMENT, _RDATA_IMPORTS = 0x010, 0x080, 0x200
_DATA_XOR, _DATA_HASHES, _DATA_CONFIG = 0x040, 0x100, 0x200
_RWX = 0xE0000020  # code, execute, read, write
_RT_RCDATA = 10
# An XOR key byte with the top bit set changes every byte of ASCII text and
# leaves none of it printable, so the encoded text cannot read as text itself.
_KEY_TOP_BIT = 0x80
# A decoy's host is under a delegated top-level domain, so the publish rule may
# publish it (it publishes no reserved name: ``.example``, ``.invalid``,
# ``.test``, ``.localhost``, ``.local``, ``.onion`` are all answered no) and
# claiming it can be counted; a live run looks it up through threat intel like
# any other indicator. A config's host is reserved and never resolves.
# Every host carries random hex as well, so it is unlikely to be a registered name.
DECOY_TLD = "com"
CONFIG_TLD = "invalid"
_PORTS = (1024, 65536)  # the unprivileged ports a config or a URL may name
_KEY_BYTES = 4
_SECTION_BODY = 0x200
_HASH_COUNT = 3
_CALLED = 2
_EXPORTS = 2
# UPX's method number for LZMA (``synthetic_upx.compress``): a range coder
# leaves no name of the compressed import records readable in the packed file.
_LZMA_METHOD = 14


class CaseError(ValueError):
    """A case cannot be built or read; the message names why."""


@dataclass(frozen=True)
class Fact:
    """Something the file holds, and the terms a report states it by.

    Each term is a tuple of spellings; a term is stated when any spelling is.
    """

    id: str
    kind: str
    difficulty: str
    where: str
    terms: tuple[tuple[str, ...], ...]
    techniques: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()
    # The RVA the code takes, for a fact the code refers to (None for others).
    rva: int | None = None


@dataclass(frozen=True)
class Trap:
    """Something that looks like a capability and is not, and what would claim it."""

    id: str
    kind: str
    subject: str
    why: str
    techniques: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()
    # Where the trap's bytes sit (an RVA; None for an import or the overlay).
    rva: int | None = None


@dataclass(frozen=True)
class Absent:
    """A capability the file does not have, and the technique ids that would claim it."""

    id: str
    capability: str
    techniques: tuple[str, ...]


@dataclass
class Case:
    case_id: str
    seed: int
    format: str
    split: str
    split_seed: int
    data: bytes
    facts: list[Fact] = field(default_factory=list)
    traps: list[Trap] = field(default_factory=list)
    absent: list[Absent] = field(default_factory=list)
    # The generated values a prompt must never carry (the leak check's terms).
    leak_terms: list[str] = field(default_factory=list)

    def manifest(self) -> dict[str, Any]:
        return {
            "schema": MANIFEST_SCHEMA,
            "case": self.case_id,
            "seed": self.seed,
            "format": self.format,
            "split": self.split,
            "split_seed": self.split_seed,
            "file": file_name(self.case_id),
            "size": len(self.data),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "facts": [
                {
                    "id": f.id,
                    "kind": f.kind,
                    "difficulty": f.difficulty,
                    "where": f.where,
                    "terms": [list(t) for t in f.terms],
                    "techniques": list(f.techniques),
                    "indicators": list(f.indicators),
                    "rva": f.rva,
                }
                for f in self.facts
            ],
            "traps": [
                {
                    "id": t.id,
                    "kind": t.kind,
                    "subject": t.subject,
                    "why": t.why,
                    "claims": {"techniques": list(t.techniques), "indicators": list(t.indicators)},
                    "rva": t.rva,
                }
                for t in self.traps
            ],
            "absent": [
                {
                    "id": a.id,
                    "capability": a.capability,
                    "claims": {"techniques": list(a.techniques)},
                }
                for a in self.absent
            ],
            "leak_terms": list(self.leak_terms),
        }


@dataclass(frozen=True)
class Entry:
    """One line of ``seeds.json``, with the split it falls in."""

    case_id: str
    seed: int
    format: str
    split: str


def file_name(case_id: str) -> str:
    """The file a case is written to: ``.bin``, so nothing takes it for a program to start."""
    return f"{case_id}.bin"


def read_seeds(path: Path = SEEDS) -> tuple[int, list[Entry]]:
    """The split seed and every case of ``path``, each with its split."""
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    split_seed = document.get("split_seed")
    rows = document.get("cases")
    if not isinstance(split_seed, int) or not isinstance(rows, list) or not rows:
        raise CaseError(f"{path}: needs an integer split_seed and a non-empty cases list")
    seen: set[int] = set()
    by_format: dict[str, list[int]] = {}
    for row in rows:
        seed = row.get("seed") if isinstance(row, dict) else None
        fmt = row.get("format") if isinstance(row, dict) else None
        if not isinstance(seed, int) or fmt not in FORMATS:
            raise CaseError(
                f"{path}: a case needs an integer seed and a format of {FORMATS}: {row}"
            )
        if seed in seen:
            raise CaseError(f"{path}: seed {seed} is listed twice")
        seen.add(seed)
        by_format.setdefault(fmt, []).append(seed)
    return split_seed, split(split_seed, by_format)


def split(split_seed: int, by_format: dict[str, list[int]]) -> list[Entry]:
    """The stratified split: per format, a seeded shuffle; its first half tunes, the rest held out.

    A format with an odd count puts the extra case in the held-out half.
    """
    entries: list[Entry] = []
    for fmt in sorted(by_format):
        seeds = sorted(by_format[fmt])
        order = list(seeds)
        random.Random(f"{split_seed}:{fmt}").shuffle(order)
        tuning = set(order[: len(order) // 2])
        entries += [
            Entry(case_id(fmt, s), s, fmt, SPLITS[0] if s in tuning else SPLITS[1]) for s in seeds
        ]
    return entries


def case_id(fmt: str, seed: int) -> str:
    return f"cal-{fmt}-{seed}"


def _token(rng: random.Random) -> str:
    return f"{rng.choice(WORDS)}{rng.choice(WORDS)}-{rng.getrandbits(24):06x}"


def _phrase(rng: random.Random) -> str:
    """Words and a number: text that reads as text, which a decoder tells from random bytes."""
    return f"{rng.choice(WORDS)} {rng.choice(WORDS)} {rng.choice(WORDS)} {rng.getrandbits(16)}"


def _host(rng: random.Random, tld: str) -> str:
    return f"{rng.choice(WORDS)}-{rng.getrandbits(24):06x}.{tld}"


def ror13(name: str) -> int:
    """The ROR-13 hash of an API name, computed here and not by the platform's tool."""
    value = 0
    for byte in name.encode():
        value = ((value >> 13) | (value << 19)) & 0xFFFFFFFF
        value = (value + byte) & 0xFFFFFFFF
    return value


def _key_byte(rng: random.Random) -> int:
    return _KEY_TOP_BIT | rng.getrandbits(7)


def _xor8(text: bytes, key: int) -> bytes:
    return bytes(byte ^ key for byte in text)


def _repeating(text: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(text))


def _key_spellings(key: bytes) -> tuple[str, ...]:
    """How a report writes a key: hex in one run (``0x`` before it included), or as spaced bytes."""
    plain = key.hex()
    return (plain, " ".join(f"{b:02x}" for b in key))


def _grouped(imports: list[tuple[str, str]]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for dll, name in imports:
        groups.setdefault(dll, []).append(name)
    return groups


def _absent(taken: set[str]) -> list[Absent]:
    """Every catalogue capability none of the case's facts or traps names a technique of."""
    rows = [
        (capability, techniques)
        for capability, techniques in ABSENT
        if not any(covers(t, technique) for t in techniques for technique in taken)
    ]
    return [Absent(f"A{i}", c, t) for i, (c, t) in enumerate(rows, start=1)]


def covers(claimed: str, technique: str) -> bool:
    """Whether two technique ids are one technique or a technique and its sub-technique."""
    a, b = claimed.upper(), technique.upper()
    return a == b or a.startswith(b + ".") or b.startswith(a + ".")


def _half(pool: tuple[Any, ...], split_name: str) -> list[Any]:
    """The half of a catalogue a split draws from: even entries tune, odd ones are held out."""
    return list(pool[SPLITS.index(split_name) :: len(SPLITS)])


def _comment(
    rng: random.Random, split_name: str, dead: tuple[str, ...]
) -> tuple[str, tuple[str, ...]]:
    """A comment API whose techniques the dead import does not share, so one claim is one trap."""
    choices = [
        (api, techniques)
        for api, techniques in _half(COMMENT_APIS, split_name)
        if not any(covers(a, b) for a in techniques for b in dead)
    ]
    return rng.choice(choices)


def _decoy(rng: random.Random, split_name: str) -> tuple[str, str]:
    host = _host(rng, DECOY_TLD)
    shape, _ = rng.choice(_half(URL_SHAPES, split_name))
    url = shape.format(
        host=host,
        port=rng.randrange(*_PORTS),
        word=rng.choice(WORDS),
        word2=rng.choice(WORDS),
        token=_token(rng),
        hex=f"{rng.getrandbits(32):08x}",
    )
    return url, host


class _Code:
    """``.text`` laid out back to back: the entry calls one function, which returns."""

    def __init__(self, image: SyntheticPE) -> None:
        self.image = image
        image.text = bytearray([_INT3]) * len(image.text)
        self.at = _ENTRY_TO_FUNCTION

    def refer(self, rva: int) -> None:
        self.image.refer(self.at, rva)
        self.at += 7 if self.image.is64 else 5

    def call(self, slot: int) -> None:
        self.image.call_slot(self.at, slot)
        self.at += 6

    def finish(self) -> None:
        self.image.put("text", self.at, b"\xc3")
        end = self.at + 1
        entry_call = b"\xe8" + struct.pack("<i", _ENTRY_TO_FUNCTION - 5)
        self.image.put("text", 0, entry_call + b"\xc3")
        if self.image.is64:
            self.image.functions = [
                (TEXT_RVA, TEXT_RVA + len(entry_call) + 1),
                (TEXT_RVA + _ENTRY_TO_FUNCTION, TEXT_RVA + end),
            ]


def _config(rng: random.Random, split_name: str) -> tuple[bytes, Fact, list[str]]:
    """The config blob: key length, key, stated length, text; and its fact and leak terms."""
    prefix = rng.choice(WORDS)[:3]
    names = [
        f"{prefix}_{rng.choice(_half(pool, split_name))}"
        for pool in (CONFIG_ID_NAMES, CONFIG_HOST_NAMES, CONFIG_PORT_NAMES)
    ]
    config_id = _token(rng)
    config_host = _host(rng, CONFIG_TLD)
    values = [config_id, config_host, str(rng.randrange(*_PORTS))]
    pairs = [f"{n}={v}" for n, v in zip(names, values, strict=True)]
    rng.shuffle(pairs)
    text = rng.choice(_half(CONFIG_SEPARATORS, split_name)).join(pairs).encode() + b"\0"
    width = rng.choice(CONFIG_LENGTH_WIDTHS)
    key = bytes(_key_byte(rng) for _ in range(_KEY_BYTES))
    blob = bytes([len(key)]) + key + struct.pack(width, len(text)) + _repeating(text, key)
    fact = Fact(
        "F7",
        "config",
        "hard",
        f"repeating-XOR config: key length, {len(key)}-byte key, a {struct.calcsize(width)}-byte"
        " text length, text",
        ((config_id,), (config_host,), _key_spellings(key)),
        indicators=(config_host,),
    )
    return blob, fact, [*names, config_id, config_host, key.hex()]


def _plain(entry: Entry, split_seed: int) -> Case:
    rng = random.Random(entry.seed)
    half = entry.split
    is64 = entry.format == "pe64"
    image = SyntheticPE(is64=is64, image_base=su.Program(is64=is64).image_base)
    code = _Code(image)
    called = rng.sample(_half(CALLED_IMPORTS, half), _CALLED)
    dead = rng.choice(_half(DEAD_IMPORTS, half))
    slots = image.imports_at(
        _RDATA_IMPORTS, _grouped([(d, n) for d, n, _ in called] + [(dead[0], dead[1])])
    )

    marker = f"{_token(rng)}.cfg"
    marker_rva = image.put("rdata", _RDATA_MARKER, marker.encode() + b"\0")
    code.refer(marker_rva)
    comment_api, comment_techniques = _comment(rng, half, dead[2])
    template, phrase = rng.choice(_half(COMMENT_TEMPLATES, half))
    comment = template.format(api=comment_api)
    comment_rva = image.put("rdata", _RDATA_COMMENT, comment.encode() + b"\0")

    section = f".{rng.choice(WORDS)[:3]}{rng.getrandbits(12):03x}"
    image.extra_sections.append((section.encode(), rng.randbytes(_SECTION_BODY), _RWX))

    hidden = _phrase(rng)
    xor_key = _key_byte(rng)
    xor_rva = image.put("data", _DATA_XOR, _xor8(hidden.encode() + b"\0", xor_key))
    code.refer(xor_rva)

    hashed = rng.sample(_half(HASHED_APIS, half), _HASH_COUNT)
    table = b"".join(struct.pack("<I", ror13(name)) for name in hashed)
    hashes_rva = image.put("data", _DATA_HASHES, table)
    code.refer(hashes_rva)

    blob, config_fact, config_terms = _config(rng, half)
    config_rva = image.put("data", _DATA_CONFIG, blob)
    code.refer(config_rva)
    for _, name, _ in called:
        code.call(slots[name])
    code.finish()

    decoy, decoy_host = _decoy(rng, half)
    image.resources.append((_RT_RCDATA, 1, decoy.encode() + b"\0"))

    for name in ("text", "rdata", "data"):
        if len(getattr(image, name)) > SECTION_ALIGNMENT:
            raise CaseError(f"{entry.case_id}: .{name} outgrew its {SECTION_ALIGNMENT:#x} slot")

    facts = [
        Fact(
            f"F{i}",
            "import",
            "easy",
            f"{dll}!{name}, called from .text",
            ((name,),),
            (technique,) if technique else (),
            rva=slots[name],
        )
        for i, (dll, name, technique) in enumerate(called, start=1)
    ]
    facts += [
        Fact("F3", "string", "easy", f"plain ASCII in .rdata at {marker_rva:#x}, the code takes it",
             ((marker,),), rva=marker_rva),
        Fact("F4", "section_anomaly", "easy",
             f"section {section}: writable and executable, random bytes", ((section,),)),
        Fact("F5", "xor_string", "hard",
             f"XOR key {xor_key:#04x} at {xor_rva:#x}, the code takes it", ((hidden,),),
             rva=xor_rva),
        Fact("F6", "api_hash", "hard", f"ROR-13 table at {hashes_rva:#x}, the code takes it",
             tuple((name,) for name in hashed), rva=hashes_rva),
        Fact(config_fact.id, config_fact.kind, config_fact.difficulty,
             f"{config_fact.where}, at {config_rva:#x}, the code takes it", config_fact.terms,
             indicators=config_fact.indicators, rva=config_rva),
    ]  # fmt: skip
    traps = [
        Trap("T1", "dead_import", dead[1], f"{dead[0]}!{dead[1]} is imported and no code calls it",
             techniques=dead[2], rva=slots[dead[1]]),
        Trap("T2", "comment_api", comment_api, f"it appears only in the string {comment!r}",
             techniques=comment_techniques, rva=comment_rva),
        Trap("T3", "decoy_url", decoy, "a URL in an RCDATA resource nothing refers to",
             indicators=(decoy, decoy_host)),
    ]  # fmt: skip
    taken = {t for f in facts for t in f.techniques} | {t for x in traps for t in x.techniques}
    return Case(
        entry.case_id,
        entry.seed,
        entry.format,
        entry.split,
        split_seed,
        image.build(),
        facts,
        traps,
        _absent(taken),
        [marker, section, hidden, *config_terms, decoy_host, phrase],
    )


def _export_name(rng: random.Random) -> str:
    return (
        f"{rng.choice(WORDS).capitalize()}{rng.choice(WORDS).capitalize()}{rng.getrandbits(16):04x}"
    )


def _packed(entry: Entry, split_seed: int) -> Case:
    rng = random.Random(entry.seed)
    half = entry.split
    is64 = rng.choice((False, True))
    present = rng.sample(_half(CALLED_IMPORTS, half), _CALLED)
    dead = rng.choice(_half(DEAD_IMPORTS, half))
    imports: dict[str, list[str | int]] = {
        dll: list(names)
        for dll, names in _grouped([(d, n) for d, n, _ in present] + [(dead[0], dead[1])]).items()
    }
    defaults = su.Program()
    exports = [(_export_name(rng), address) for _, address in defaults.exports[:_EXPORTS]]
    decoy, decoy_host = _decoy(rng, half)
    program = su.Program(
        is64=is64,
        method=_LZMA_METHOD,
        imports=imports,
        exports=exports,
        forwarders=[],
        overlay=decoy.encode() + b"\0",
        calls=[name for _, name, _ in present],
    )
    packed = su.build(program)
    readable = [n for _, n, _ in present if n.encode() in packed.data]
    if readable:
        raise CaseError(f"{entry.case_id}: the packed file shows {readable} as plain text")
    facts = [
        Fact(
            "F1", "packed", "easy", "UPX: UPX0 and UPX1 sections and the pack header", (("UPX",),)
        ),
    ]
    facts += [
        Fact(f"F{i}", "export", "easy", "an export of the packed file", ((name,),))
        for i, (name, _) in enumerate(exports, start=2)
    ]
    facts += [
        Fact(f"F{i}", "import", "hard",
             f"{dll}!{name}, called from the unpacked code, named only in UPX's compressed records",
             ((name,),), (technique,) if technique else (), rva=su.iat_slot(program, name))
        for i, (dll, name, technique) in enumerate(present, start=2 + len(exports))
    ]  # fmt: skip
    traps = [
        Trap("T1", "dead_import", dead[1], f"{dead[0]}!{dead[1]} is imported and no code calls it",
             techniques=dead[2], rva=su.iat_slot(program, dead[1])),
        Trap("T2", "decoy_url", decoy, "a URL in the overlay nothing refers to",
             indicators=(decoy, decoy_host)),
    ]  # fmt: skip
    taken = {t for f in facts for t in f.techniques} | {t for x in traps for t in x.techniques}
    return Case(
        entry.case_id,
        entry.seed,
        entry.format,
        entry.split,
        split_seed,
        packed.data,
        facts,
        traps,
        _absent(taken),
        [name for name, _ in exports] + [decoy_host],
    )


def build(entry: Entry, split_seed: int) -> Case:
    """The case of one seed: its bytes and its manifest."""
    return (_packed if entry.format == "upx" else _plain)(entry, split_seed)


def build_all(path: Path = SEEDS, splits: tuple[str, ...] = SPLITS) -> list[Case]:
    """Every case of ``path`` in ``splits``; a case outside them is not built at all."""
    split_seed, entries = read_seeds(path)
    return [build(e, split_seed) for e in entries if e.split in splits]
