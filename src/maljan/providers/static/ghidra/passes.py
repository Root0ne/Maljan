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
  ``FS:[0x18]`` exactly, or, in an x64 file's code bytes, which Ghidra's scan
  does not look at for GS, a GS-prefixed read of ``GS:[0x60]`` or
  ``GS:[0x30]`` (``gs_reads``), and a capa rule in the same function agrees (the
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
error, stops the pass, and the entry states Ghidra's own words. Every request
is held by the job's guard for Ghidra, the agents' own; one it does not send
while Ghidra rests stops the pass too, and the entry states the guard's.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from maljan.analysis.anti_analysis import (
    INSTRUCTION_CATEGORY,
    TEB_CATEGORY,
    Code,
    PassFailed,
    cpuid_leaf_said,
    gs_reads,
    image_of,
    int3_is_a_trap,
    operand_value,
    starts_of,
)

# Ghidra's own tool, the REST endpoint the scan calls.
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
    "before ECX is written again, and a read through FS:[0x30] or FS:[0x18], or a GS:[0x60] or "
    "GS:[0x30] read the platform finds in an x64 file's code bytes, exactly where a capa rule in "
    "the same function agrees; API calls, and every other distinct match, are counted, not "
    "stated"
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

# What Ghidra's scan looks at, as the pack line says it.
SCAN_CHECKS_SHORT = "listed API calls, listed x86 instructions, FS:[0x30] and FS:[0x18]"


class GhidraPassFailed(PassFailed):
    """A Ghidra pass that was made and did not complete, with what happened."""


_TEB_OPERAND = re.compile(r"\bFS:\[0x(?:30|18)\]", re.IGNORECASE)


def _is_the_listed_instruction(technique: str, instruction: str) -> bool:
    """Whether ``instruction`` (Ghidra's text) is exactly what ``technique`` names."""
    listed = technique.strip().upper().split(None, 1)
    found = instruction.strip().upper().split(None, 1)
    if not listed or not found:
        return False
    listed_operand = operand_value(listed[1]) if len(listed) > 1 else None
    found_operand = operand_value(found[1]) if len(found) > 1 else None
    # ``INT3`` is the one-byte form of ``INT 3``.
    if found[0] == "INT3" and len(found) == 1:
        found, found_operand = ["INT"], 3
    if listed[0] != found[0]:
        return False
    if len(listed) > 1:
        return listed_operand is not None and listed_operand == found_operand
    return True


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
    code = Code(image, function_starts)
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
        if category == INSTRUCTION_CATEGORY:
            if _is_the_listed_instruction(technique, instruction):
                mnemonic = instruction.upper().split(None, 1)[0]
                if mnemonic == "INT3":
                    what = instruction if int3_is_a_trap(code, where) else ""
                elif mnemonic == "CPUID":
                    what = cpuid_leaf_said(code, where)
                else:
                    what = instruction
        elif category == TEB_CATEGORY:
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
        (beside_capa if category == TEB_CATEGORY else stated).append(fact)
    for fact in gs_reads(image):
        key = (fact["offset"], fact["what"])
        if key not in stated_keys:
            stated_keys.add(key)
            beside_capa.append(fact)
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
    # What the Ghidra block declares for opening a sample, and the job's note
    # of the paths it opened (``providers.sample_open``): the pass opens the
    # sample through the same opener as the agents, so a path one of them
    # opened is not imported again.
    sample_open: Any = field(default=None, repr=False)
    sample_notes: Any = field(default=None, repr=False)
    # The server in the job's note (``sample_open.server_note_key``): Ghidra's
    # address, as the agents' and the load before the loop's own opens name it.
    # Given by every caller: a pass noting under a name of its own would miss
    # the job's note.
    note_key: str = field(kw_only=True)
    # The id of the provider that scans (``GhidraStaticProvider.id``), which its
    # answer names as its server, and the formats the scan reads.
    provider: str = field(default="ghidra", kw_only=True)
    formats: frozenset[str] = field(default=GHIDRA_FORMATS, kw_only=True)
    # The job's breaker and call cap for this server (``providers.server_guard``),
    # the one the agents' calls go through; ``None`` sends every request as it is.
    guard: Any = field(default=None, repr=False, kw_only=True)
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
        """One request, answered as parsed JSON; a Ghidra that did not answer raises.

        Held by the job's guard for this server: a request the resting server
        is not sent fails the pass with the guard's sentence.
        """
        import httpx

        from maljan.providers.server_guard import ServerResting, guarded_http

        try:
            response = guarded_http(self._client(), self.guard).request(method, path, **kwargs)
            response.raise_for_status()
        except ServerResting as exc:
            raise GhidraPassFailed(f"{exc}; {what} was not sent") from exc
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

    def _open_sample(self) -> str:
        """The load of the job's sample through the general opener; the load's answer.

        With the tools the Ghidra block declares, the sample is loaded, made
        current and analysed once per job, or answered from the job's note.
        With none declared, it is loaded, made current and analysed here, as
        this pass always did.
        """
        from maljan.providers.sample_open import SampleNotes, SampleOpener, declared
        from maljan.providers.server_guard import ServerResting
        from maljan.providers.static.ghidra.program import (
            SWITCH_PARAM,
            SWITCH_PATH,
            program_name_from_load,
        )

        def call(tool: str, arguments: dict[str, Any]) -> str:
            try:
                answer = self._request(
                    "POST",
                    f"/{tool}",
                    f"the {tool} call",
                    params=dict(arguments),
                    json=dict(arguments),
                    timeout=None,
                )
            except GhidraPassFailed as failure:
                if isinstance(failure.__cause__, ServerResting):
                    # Not a refusal of the open: the guard's sentence ends the pass.
                    raise
                return json.dumps({"tool_error": "request_failed", "detail": str(failure)})
            return json.dumps(answer) if isinstance(answer, (dict, list)) else str(answer)

        if declared(self.sample_open):
            notes = self.sample_notes
            if not isinstance(notes, SampleNotes):
                notes = SampleNotes()
            opener = SampleOpener(self.note_key, self.sample_open, notes)
            answer = opener.open(self.sample_path, call, held=self.sample_path)
            # An open is noted only once the declared analysis answered: an
            # opened program with none noted was not analysed, and this pass
            # reads what the analysis records.
            if (
                self.sample_open.analyse_tool
                and program_name_from_load(answer)
                and opener.name_of(self.sample_path) is None
            ):
                raise GhidraPassFailed(
                    "Ghidra did not confirm the auto-analysis of the job's sample"
                )
            return answer
        loaded = self._request(
            "POST", "/load_program", "the load of the job's sample", json={"file": self.sample_path}
        )
        answer = json.dumps(loaded) if isinstance(loaded, dict) else str(loaded)
        name = program_name_from_load(answer)
        if name:
            self._request(
                "POST",
                SWITCH_PATH,
                "the switch to the job's sample",
                params={SWITCH_PARAM: name},
                json={},
            )
            analysed = self._request(
                "POST",
                "/run_analysis",
                "the auto-analysis of the job's sample",
                json={"program": name},
            )
            _raise_on_error(analysed, "the auto-analysis of the job's sample")
        return answer

    def _open(self) -> None:
        from maljan.providers.static.ghidra.program import program_name_from_load
        from maljan.tools.errors import error_parts

        answer = self._open_sample()
        name = program_name_from_load(answer)
        if not name:
            parts = error_parts(answer)
            words = parts[1] if parts else str(answer)[:200]
            raise GhidraPassFailed(f"Ghidra did not open the job's sample: {words}")
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
            "server": self.provider,
            "program": program,
            "image_base": hex(self._image_base or 0),
            "checks": SCAN_CHECKS,
            "how": STATED_RULE,
            "total_findings": int(answer.get("total_findings") or len(findings)),
            "returned": len(findings),
            "notes": notes,
            **read_findings(findings, image_of(host_path), starts_of(function_starts)),
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


def _raise_on_error(answer: Any, what: str) -> None:
    if isinstance(answer, dict) and answer.get("error"):
        raise GhidraPassFailed(f"Ghidra refused {what}: {str(answer['error'])[:300]}")
