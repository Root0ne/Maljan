"""Ghidra's anti-analysis scan, made by the triage pack once per job, before any model turn.

A model used to reach Ghidra's ``find_anti_analysis_techniques`` only by
asking for it. The pack now makes it on every run where Ghidra is reachable
over its REST API, the way the sink pre-pass opens the sample
(``providers.static.ghidra.prepare_sample``): load the job's sample, make it
the current program, run auto-analysis, ask for the image base, then scan.

Ghidra's answer is recorded whole, each address also stated as an offset from
the image base Ghidra loaded the program at. What the pack states as a fact is
only the part of it that is exact (``read_findings``):

* an instruction match, when the instruction Ghidra returns is the one its
  list names: the same mnemonic and, where the list gives one, the same
  operand. Ghidra matches mnemonics by prefix, so it files ``INT3`` under
  ``INT 0x2d`` as well. Two instructions ordinary builds carry are read in the
  file's bytes first: an ``INT3`` counts only alone, not in a run of them, not
  as the byte before a function (compilers pad and align with them) and not
  right after a call, jump or return (compilers put one after a call that
  never returns, and pad with one where nothing falls through), and
  a ``CPUID`` only where the code sets the hypervisor leaf (0x40000000 to
  0x400000ff) in ``eax`` just before it, or sets leaf 1 and tests ECX's bit 31
  within 32 bytes after it with nothing writing ECX in between (a runtime's
  feature probe asks other leaves);
* a TEB/PEB read, when the instruction reads through ``FS:[0x30]`` or
  ``FS:[0x18]`` exactly and a capa rule in the same function agrees (the
  triage pack decides that; a read with no such rule is counted, since a
  language runtime's own code reads the PEB as well).

An API call is never stated, only counted. Ghidra matches symbol names by
substring over a broad list and lists every call site, a language runtime's
own included (the MSVC runtime calls ``IsDebuggerPresent`` on its failure
path), while capa leaves the library functions it recognises out and the
catalogue line already reads the imports.

Every other match is counted, once per place and match, not stated. The scan
checks what ``SCAN_CHECKS`` says and nothing else, so an empty result is said
as that list matching nothing, never as the sample having no anti-analysis
code.

A pass that cannot run says why: the pack records that sentence rather than
leaving the pass out. A request Ghidra did not answer, or answered with an
error, stops the pass, and the entry states Ghidra's own words.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from maljan.core.logger import logger

ANTI_ANALYSIS_TOOL = "find_anti_analysis_techniques"

# The formats Ghidra's loader and the scan read.
GHIDRA_FORMATS = frozenset({"pe", "elf", "macho"})

# What Ghidra's scan looks at, said wherever its answer is.
SCAN_CHECKS = (
    "calls to the APIs on Ghidra's list, the x86 instructions RDTSC, CPUID, INT3, INT 0x2d, SIDT, "
    "SGDT, SLDT and STR, and reads through FS:[0x30] or FS:[0x18]"
)

# How the stated part is chosen, said in every answer.
STATED_RULE = (
    "stated: an instruction that is the listed one (the same mnemonic and operand), an INT3 only "
    "alone, not as padding before a function and not right after a call, jump or return, a "
    "CPUID only where the code sets the hypervisor leaf or sets leaf 1 and tests ECX bit 31 "
    "before ECX is written again, and a read through FS:[0x30] or FS:[0x18] exactly where a "
    "capa rule in the same function agrees; API calls, and every other distinct match, are "
    "counted, not stated"
)

GHIDRA_SWITCHED_OFF = "Ghidra is switched off (core.static.ghidra.enabled)"
GHIDRA_NOT_OVER_HTTP = (
    "Ghidra is reached over {transport}, which serves no REST API the pack can call; its scan "
    "runs with core.static.ghidra.transport set to http"
)
GHIDRA_HAS_NO_COPY = (
    "Ghidra is not a static provider of this run's profile, so no copy of the sample stands "
    "where Ghidra reads"
)


class GhidraPassFailed(RuntimeError):
    """A pass that was made and did not complete, with what happened."""


_INSTRUCTION_CATEGORY = "suspicious_instruction"
_TEB_CATEGORY = "peb_teb_access"
_TEB_OPERAND = re.compile(r"\bFS:\[0x(?:30|18)\]", re.IGNORECASE)

# The CPUID leaves a hypervisor answers, and the bytes around a CPUID read.
_HYPERVISOR_LEAVES = range(0x40000000, 0x40000100)
_CLEAR_ECX = (b"\x31\xc9", b"\x33\xc9")
# bt ecx, 31; test ecx, 0x80000000; and ecx, 0x80000000; test ecx, ecx then js.
_ECX_BIT_31 = (
    b"\x0f\xba\xe1\x1f",
    b"\xf7\xc1\x00\x00\x00\x80",
    b"\x81\xe1\x00\x00\x00\x80",
    b"\x85\xc9\x78",
    b"\x85\xc9\x0f\x88",
)
# How far past a CPUID the test of ECX's bit 31 is looked for.
_BIT_TEST_WINDOW = 32
# The first bytes of an instruction that writes ECX: mov ecx, imm32; mov or
# xor or sub ecx with a register; pop rcx. A test after one reads another value.
_WRITES_ECX = (
    b"\xb9",
    b"\x89\xc1",
    b"\x89\xd1",
    b"\x89\xd9",
    b"\x89\xf1",
    b"\x89\xf9",
    b"\x31\xc9",
    b"\x33\xc9",
    b"\x29\xc9",
    b"\x2b\xc9",
    b"\x8b\xc8",
    b"\x8b\xca",
    b"\x8b\xcb",
    b"\x8b\xce",
    b"\x8b\xcf",
    b"\x59",
)


def _operand_value(text: str) -> int | None:
    try:
        return int(text, 0)
    except ValueError:
        return None


def _is_the_listed_instruction(technique: str, instruction: str) -> bool:
    """Whether ``instruction`` (Ghidra's text) is exactly what ``technique`` names."""
    listed = technique.strip().upper().split(None, 1)
    found = instruction.strip().upper().split(None, 1)
    if not listed or not found:
        return False
    listed_operand = _operand_value(listed[1]) if len(listed) > 1 else None
    found_operand = _operand_value(found[1]) if len(found) > 1 else None
    # ``INT3`` is the one-byte form of ``INT 3``.
    if found[0] == "INT3" and len(found) == 1:
        found, found_operand = ["INT"], 3
    if listed[0] != found[0]:
        return False
    if len(listed) > 1:
        return listed_operand is not None and listed_operand == found_operand
    return True


class _Code:
    """The file's bytes around an instruction Ghidra named, when the file is a PE image."""

    def __init__(self, image: Any, function_starts: Iterable[int]) -> None:
        self.image = image
        starts = set(function_starts)
        if image is not None:
            starts.update(int(start) for start in image.function_starts)
        self.starts = starts

    def at(self, offset: str) -> int | None:
        """The file offset of an offset from the image base, or ``None``."""
        if self.image is None:
            return None
        try:
            found = self.image.offset_of_rva(int(offset, 16))
        except (TypeError, ValueError):
            return None
        return int(found) if found is not None else None

    def byte(self, at: int) -> int | None:
        data: bytes = self.image.data
        return data[at] if 0 <= at < len(data) else None


def _modrm_length(modrm: int, sib: int | None) -> int:
    """The length of an ``FF /r`` instruction from its ModRM (and SIB) byte, opcode included."""
    mod, rm = modrm >> 6, modrm & 7
    if mod == 3:
        return 2
    length = 2
    if rm == 4:
        length += 1
        if mod == 0 and sib is not None and sib & 7 == 5:
            length += 4
    elif mod == 0 and rm == 5:
        length += 4
    return length + {0: 0, 1: 1, 2: 4}[mod]


# The ``FF /r`` forms that transfer control: /2 is a near call, /4 a near jump.
_FF_TRANSFERS = frozenset({2, 4})


def _ends_a_transfer(data: bytes, at: int) -> bool:
    """Whether the bytes just before ``at`` are a whole near call, jump or return.

    The encodings: ``E8 rel32`` (call), ``E9 rel32`` and ``EB rel8`` (jump),
    ``C3`` and ``C2 imm16`` (return), and ``FF /2`` or ``FF /4`` in every
    ModRM form (through a register, ``FF D0`` and with a REX prefix
    ``41 FF D0``; through memory, ``FF 15 disp32`` and the rest), the length
    read from the ModRM. A byte sequence that only looks like one makes the
    check say yes, which leaves an ``INT3`` unstated rather than stated wrongly.
    """
    if at >= 5 and data[at - 5] in (0xE8, 0xE9):
        return True
    if at >= 2 and data[at - 2] == 0xEB:
        return True
    if at >= 1 and data[at - 1] == 0xC3:
        return True
    if at >= 3 and data[at - 3] == 0xC2:
        return True
    for length in range(2, 8):
        begin = at - length
        if begin < 0 or data[begin] != 0xFF:
            continue
        modrm = data[begin + 1]
        if (modrm >> 3) & 7 not in _FF_TRANSFERS:
            continue
        sib = data[begin + 2] if begin + 2 < at else None
        if _modrm_length(modrm, sib) == length:
            return True
    return False


def _int3_is_a_trap(code: _Code, offset: str) -> bool:
    """A one-byte ``INT3`` not in a run, not before a function, not right after a transfer.

    Compilers put one ``int 3`` after a call that never returns, and pad with
    one after a function's last return or jump, where nothing falls through.
    """
    at = code.at(offset)
    if at is None or code.byte(at) != 0xCC:
        return False
    if code.byte(at - 1) == 0xCC or code.byte(at + 1) == 0xCC:
        return False
    if _ends_a_transfer(code.image.data, at):
        return False
    return int(offset, 16) + 1 not in code.starts


def _cpuid_leaf_said(code: _Code, offset: str) -> str:
    """What the code around a CPUID shows it asks, when it shows the hypervisor question."""
    at = code.at(offset)
    if at is None:
        return ""
    data = code.image.data
    if data[at : at + 2] != b"\x0f\xa2":
        return ""
    before = at
    if data[before - 2 : before] in _CLEAR_ECX:
        before -= 2
    if before < 5 or data[before - 5] != 0xB8:
        return ""
    # A REX prefix makes ``B8`` a move into r8d, not eax.
    if before >= 6 and 0x40 <= data[before - 6] <= 0x4F:
        return ""
    leaf = int.from_bytes(data[before - 4 : before], "little")
    if leaf in _HYPERVISOR_LEAVES:
        return f"CPUID (leaf {leaf:#x})"
    if leaf == 1 and _tests_ecx_bit_31(data[at + 2 : at + 2 + _BIT_TEST_WINDOW]):
        return "CPUID (leaf 1, then ECX bit 31 tested)"
    return ""


def _tests_ecx_bit_31(after: bytes) -> bool:
    """Whether ``after`` tests ECX's bit 31 before anything listed writes ECX.

    The window is cut at the first place an ECX write's bytes begin, so a test
    that may read another value is not taken. The cut is by byte pattern, and
    errs toward stating nothing.
    """
    tests = [i for p in _ECX_BIT_31 if (i := after.find(p)) >= 0]
    if not tests:
        return False
    writes = [i for p in _WRITES_ECX if (i := after.find(p)) >= 0]
    return min(tests) < min(writes, default=len(after))


def read_findings(
    findings: Iterable[dict[str, Any]],
    image: Any = None,
    function_starts: Iterable[int] = (),
) -> dict[str, Any]:
    """The exact part of Ghidra's findings as facts, and how many distinct others there were.

    ``image`` is the sample as ``tools.pe_image`` maps it, for the two
    instructions whose meaning the bytes around them decide: an ``INT3`` is a
    trap only alone and not as the padding before a function, and a ``CPUID``
    is the hypervisor question only when the code sets the hypervisor leaf, or
    sets leaf 1 and then tests ECX's bit 31. Without the bytes neither is
    stated. ``function_starts`` (offsets from the image base) add to the
    image's own table. Ghidra's rows are read once per place and match.

    An exact TEB/PEB read is not stated here: it goes in ``beside_capa``, for
    the pack to state where a capa rule in the same function agrees and to
    count otherwise (``triage_pack._anti_analysis_with_capa``). A language
    runtime reads the PEB too (the UCRT's exit path reads ``NtGlobalFlag``),
    and capa leaves the library functions it recognises out.
    """
    code = _Code(image, function_starts)
    stated: list[dict[str, Any]] = []
    beside_capa: list[dict[str, Any]] = []
    stated_keys: set[tuple[str, str]] = set()
    unstated_keys: set[tuple[str, str]] = set()
    for row in findings:
        if not isinstance(row, dict):
            continue
        category = str(row.get("category") or "")
        technique = str(row.get("technique") or "")
        instruction = str(row.get("instruction") or "").strip()
        where = str(row.get("offset") or row.get("address") or "")
        key = (where, instruction.upper() if instruction else f"call {technique}")
        what = ""
        if category == _INSTRUCTION_CATEGORY:
            if _is_the_listed_instruction(technique, instruction):
                mnemonic = instruction.upper().split(None, 1)[0]
                if mnemonic == "INT3":
                    what = instruction if _int3_is_a_trap(code, where) else ""
                elif mnemonic == "CPUID":
                    what = _cpuid_leaf_said(code, where)
                else:
                    what = instruction
        elif category == _TEB_CATEGORY:
            if _TEB_OPERAND.search(instruction):
                what = instruction
        if not what:
            unstated_keys.add(key)
            continue
        if key in stated_keys:
            continue
        stated_keys.add(key)
        fact = {"category": category, "what": what, "offset": where}
        if row.get("function"):
            fact["function"] = str(row["function"])
        (beside_capa if category == _TEB_CATEGORY else stated).append(fact)
    return {
        "stated": stated,
        "beside_capa": beside_capa,
        "not_stated": len(unstated_keys - stated_keys),
    }


@dataclass
class GhidraPasses:
    """The Ghidra pass of one job: where Ghidra is, and which copy of the sample it reads.

    ``unavailable`` is the sentence the pack records when there is no Ghidra
    to ask; nothing is called then. ``transport`` stands in for the network in
    tests. The key never appears in the object's repr.
    """

    base_url: str = ""
    token: str = field(default="", repr=False)
    sample_path: str = ""
    call_timeout: float | None = None
    unavailable: str = ""
    transport: Any = field(default=None, repr=False)
    _http: Any = field(default=None, init=False, repr=False)
    _program: str = field(default="", init=False)
    _image_base: int | None = field(default=None, init=False)
    _failure: GhidraPassFailed | None = field(default=None, init=False, repr=False)

    # -- the connection -----------------------------------------------------

    def _client(self) -> Any:
        if self._http is None:
            import httpx

            headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            self._http = httpx.Client(
                base_url=self.base_url.rstrip("/"),
                headers=headers,
                timeout=self.call_timeout if self.call_timeout else None,
                transport=self.transport,
            )
        return self._http

    def close(self) -> None:
        if self._http is not None:
            try:
                self._http.close()
            finally:
                self._http = None

    def _request(self, method: str, path: str, what: str, **kwargs: Any) -> Any:
        """One request, answered as parsed JSON; a Ghidra that did not answer raises."""
        import httpx

        try:
            response = self._client().request(method, path, **kwargs)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise GhidraPassFailed(
                f"Ghidra answered HTTP {exc.response.status_code} to {what}"
            ) from exc
        except httpx.HTTPError as exc:
            raise GhidraPassFailed(f"Ghidra did not answer {what} ({type(exc).__name__})") from exc
        try:
            return json.loads(response.text)
        except ValueError:
            return response.text

    def open(self) -> str:
        """Load, switch to and analyse the job's sample once; the program's name.

        A failure is kept, so a second ask is told the same thing without
        asking Ghidra again.
        """
        if self._failure is not None:
            raise self._failure
        if self._program:
            return self._program
        try:
            self._open()
        except GhidraPassFailed as failure:
            self._failure = failure
            raise
        return self._program

    def _open(self) -> None:
        from maljan.analysis.ghidra_program import SWITCH_PARAM, SWITCH_PATH, program_name_from_load
        from maljan.tools.errors import error_parts

        loaded = self._request(
            "POST", "/load_program", "the load of the job's sample", json={"file": self.sample_path}
        )
        name = program_name_from_load(json.dumps(loaded) if isinstance(loaded, dict) else "")
        if not name:
            parts = error_parts(loaded) if isinstance(loaded, dict) else None
            words = parts[1] if parts else str(loaded)[:200]
            raise GhidraPassFailed(f"Ghidra did not open the job's sample: {words}")
        self._request(
            "POST",
            SWITCH_PATH,
            "the switch to the job's sample",
            params={SWITCH_PARAM: name},
            json={},
        )
        analysed = self._request(
            "POST", "/run_analysis", "the auto-analysis of the job's sample", json={"program": name}
        )
        _raise_on_error(analysed, "the auto-analysis of the job's sample")
        info = self._request(
            "GET",
            "/get_current_program_info",
            "the question of the program's image base",
            params={"program": name},
        )
        _raise_on_error(info, "the question of the program's image base")
        base = info.get("image_base") if isinstance(info, dict) else None
        try:
            self._image_base = int(str(base), 16)
        except (TypeError, ValueError):
            raise GhidraPassFailed(
                f"Ghidra did not state the program's image base (it said {base!r})"
            ) from None
        self._program = name

    # -- the anti-analysis scan -------------------------------------------

    def anti_analysis(
        self,
        host_path: str = "",
        function_starts: Sequence[Any] = (),
    ) -> dict[str, Any]:
        """Ghidra's scan, whole, with the exact part of it stated (``read_findings``).

        ``host_path`` is this process's copy of the sample, read for the bytes
        around an ``INT3`` or a ``CPUID``; ``function_starts`` are capa's.
        """
        program = self.open()
        answer = self._request(
            "GET",
            f"/{ANTI_ANALYSIS_TOOL}",
            "the anti-analysis scan",
            params={"program": program},
        )
        _raise_on_error(answer, "the anti-analysis scan")
        if not isinstance(answer, dict):
            raise GhidraPassFailed(f"Ghidra's anti-analysis scan answered {str(answer)[:200]!r}")
        findings: list[dict[str, Any]] = []
        notes: list[str] = []
        for row in answer.get("findings") or []:
            if not isinstance(row, dict):
                continue
            if set(row) == {"note"}:
                notes.append(str(row["note"]))
                continue
            finding = dict(row)
            offset = self._offset(row.get("address"))
            if offset is not None:
                finding["offset"] = hex(offset)
            findings.append(finding)
        return {
            "tool": ANTI_ANALYSIS_TOOL,
            "server": "ghidra",
            "program": program,
            "image_base": hex(self._image_base or 0),
            "checks": SCAN_CHECKS,
            "how": STATED_RULE,
            "total_findings": int(answer.get("total_findings") or len(findings)),
            "returned": len(findings),
            "notes": notes,
            **read_findings(findings, _image_of(host_path), _starts(function_starts)),
            "findings": findings,
        }

    def _offset(self, address: Any) -> int | None:
        """A Ghidra address as an offset from the image base, or ``None`` outside it."""
        try:
            value = int(str(address), 16)
        except (TypeError, ValueError):
            return None
        base = self._image_base or 0
        return value - base if value >= base else None


def _image_of(path: str) -> Any:
    """The PE image at ``path`` as ``tools.pe_image`` maps it, or ``None``."""
    if not path:
        return None
    from maljan.tools import pe_image

    try:
        return pe_image.load(path)
    except (OSError, ValueError):
        return None


def _starts(values: Sequence[Any]) -> list[int]:
    starts: list[int] = []
    for value in values:
        try:
            starts.append(int(str(value), 16))
        except ValueError:
            continue
    return starts


def _raise_on_error(answer: Any, what: str) -> None:
    if isinstance(answer, dict) and answer.get("error"):
        raise GhidraPassFailed(f"Ghidra refused {what}: {str(answer['error'])[:300]}")


def run_pass(call: Callable[[], dict[str, Any]], what: str) -> dict[str, Any]:
    """``call()``, logging a failure before it is handed on."""
    try:
        return call()
    except GhidraPassFailed as failure:
        logger.warning("Ghidra pass %s did not complete: %s", what, failure)
        raise
