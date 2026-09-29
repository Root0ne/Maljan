"""Ghidra's passes the triage pack runs once per job, before any model turn.

Two passes a model used to reach only by asking for them, made by the platform
on every run where Ghidra is reachable over its REST API, the same way the sink
pre-pass is (``providers.static.ghidra.prepare_sample``): open the job's sample
in Ghidra, make it the current program, run auto-analysis, then call.

* **Anti-analysis scan.** Ghidra's ``find_anti_analysis_techniques``, over the
  whole program. Its answer is recorded as Ghidra gave it, and each finding's
  address is also stated as an offset from the image base Ghidra loaded the
  program at, the number every other fact of the pack uses.
* **The sample's own hashing routines, emulated.** Ghidra's
  ``emulate_function`` runs one routine of the sample's code on one name at a
  time, inside Ghidra's P-code emulator; the sample is never executed. Which
  routines, and how, is stated in every answer (``ROUTINE_RULE``,
  ``CONVENTION_RULE``): the functions capa matched with a rule of its hashing
  or checksum namespaces, each given every Windows function and module name of
  the vendored catalogue ``tools.api_hashes`` reads. A routine's output for a
  name is kept only when the emulation returned to the caller with no error.
  The file's 32-bit values (the same candidate scan ``resolve_api_hashes``
  uses) that equal an output are the hits, with every place each stands.

A pass that cannot run says why: the pack records that sentence rather than
leaving the pass out. A request Ghidra did not answer stops the pass that made
it, and the pass is recorded as failed with what happened; no later request of
it is made.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from maljan.core.logger import logger

ANTI_ANALYSIS_TOOL = "find_anti_analysis_techniques"
EMULATION_TOOL = "emulate_api_hashes"
GHIDRA_EMULATE = "emulate_function"

# The formats Ghidra's loader and the anti-analysis scan read, and the one the
# name catalogue is about.
GHIDRA_FORMATS = frozenset({"pe", "elf", "macho"})
EMULATED_FORMATS = frozenset({"pe"})

# The capa namespaces whose rules say a function computes a hash or a checksum
# over data, and so can take a name and return a number.
ROUTINE_NAMESPACES = ("data-manipulation/hashing", "data-manipulation/checksum")

ROUTINE_RULE = (
    "the functions capa matched with a rule of its data-manipulation/hashing or "
    "data-manipulation/checksum namespaces, each at the function start capa listed at or "
    "before the match; each is emulated by Ghidra on every Windows function name of the "
    "catalogue as ASCII and every module name as ASCII and as UTF-16LE, and an output counts "
    "only when the emulation returned to its caller with no error"
)

CONVENTION_RULE = (
    "the name's address is handed over as the first argument and its length in bytes as the "
    "second, which a routine that reads to the terminator does not read: in rcx and rdx on "
    "x64; on x86 on the stack, else in ecx and edx; a way is taken when two different names "
    "return two different values through it"
)

# Where the emulator is given the name and its stack; the addresses Ghidra's
# own batch endpoint uses, outside any image these samples map.
SCRATCH = 0x7FFE0000
STACK = 0x7FFF0000
RETURN_SENTINEL = 0xDEADBEEF


class GhidraPassFailed(RuntimeError):
    """A pass that was made and did not complete, with what happened."""


@dataclass(frozen=True)
class Routine:
    """One function to emulate, and why: the capa rules that matched in it."""

    start: int
    rules: tuple[str, ...]


@dataclass(frozen=True)
class Convention:
    """One way of handing a routine the name's address and its length.

    ``pointer`` and ``length`` name the registers; with neither, the two go on
    the stack as the first and second arguments.
    """

    name: str
    pointer: str = ""
    length: str = ""

    @property
    def on_the_stack(self) -> bool:
        return not self.pointer


X64_CONVENTIONS = (Convention("rcx, length in rdx", "RCX", "RDX"),)
X86_CONVENTIONS = (
    Convention("stack arguments 1 and 2"),
    Convention("ecx, length in edx", "ECX", "EDX"),
)


def hash_routines(
    capa_rows: Iterable[Any], function_starts: Sequence[Any]
) -> tuple[list[Routine], str]:
    """The routines ``ROUTINE_RULE`` names in capa's answer, or none and why."""
    read = (_int(start) for start in function_starts)
    starts = sorted({start for start in read if start is not None})
    by_start: dict[int, list[str]] = {}
    matched_without_start: list[str] = []
    for row in capa_rows:
        if not isinstance(row, dict):
            continue
        namespace = str(row.get("namespace") or "")
        if not any(namespace == ns or namespace.startswith(f"{ns}/") for ns in ROUTINE_NAMESPACES):
            continue
        rule = str(row.get("rule") or "")
        for address in row.get("addresses") or []:
            where = _int(address)
            start = _start_at_or_before(starts, where) if where is not None else None
            if start is None:
                matched_without_start.append(rule)
                continue
            rules = by_start.setdefault(start, [])
            if rule not in rules:
                rules.append(rule)
    routines = [Routine(start, tuple(rules)) for start, rules in sorted(by_start.items())]
    if routines:
        return routines, ""
    if matched_without_start:
        return [], NO_ROUTINE_START
    return [], NO_ROUTINE_RULE


# Why a pass has nothing to run on, as the pack line says it.
NO_ROUTINE_RULE = (
    "capa matched no rule of its hashing or checksum namespaces in this sample, so no routine "
    "of the sample's own is known to emulate"
)
NO_ROUTINE_START = (
    "capa matched a hashing or checksum rule, but at no address with a function start capa "
    "listed at or before it"
)
NO_CAPA_ANSWER = "capa gave no answer in this run, so no routine is known to emulate"
NO_CONVENTION = "no way of handing over the name returned two different values for two names"
GHIDRA_SWITCHED_OFF = "Ghidra is switched off (core.static.ghidra.enabled)"
GHIDRA_NOT_OVER_HTTP = (
    "Ghidra is reached over {transport}, which serves no REST API the pack can call; its passes "
    "run with core.static.ghidra.transport set to http"
)
GHIDRA_HAS_NO_COPY = (
    "Ghidra is not a static provider of this run's profile, so no copy of the sample stands "
    "where Ghidra reads"
)


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 16) if str(value).lower().startswith("0x") else int(str(value))
    except (TypeError, ValueError):
        return None


def _start_at_or_before(starts: list[int], address: int) -> int | None:
    from bisect import bisect_right

    index = bisect_right(starts, address) - 1
    return starts[index] if index >= 0 else None


@dataclass
class GhidraPasses:
    """The Ghidra passes of one job: where Ghidra is, and which copy of the sample it reads.

    ``unavailable`` is the sentence the pack records for every pass when there
    is no Ghidra to ask; nothing is called then. ``transport`` stands in for
    the network in tests.
    """

    base_url: str = ""
    token: str = ""
    sample_path: str = ""
    call_timeout: float | None = None
    unavailable: str = ""
    transport: Any = None
    # The name catalogue the emulation reads; ``None`` is the vendored one.
    names_path: str | None = None
    _http: Any = field(default=None, init=False, repr=False)
    _program: str = field(default="", init=False)
    _image_base: int | None = field(default=None, init=False)
    _failure: GhidraPassFailed | None = field(default=None, init=False)

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

        A failure is kept, so the second pass is told the same thing without
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

    def anti_analysis(self) -> dict[str, Any]:
        """Ghidra's anti-analysis scan, as it answered, each address also as an offset."""
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
            "total_findings": int(answer.get("total_findings") or len(findings)),
            "summary": answer.get("summary") or {},
            "findings": findings,
            "notes": notes,
        }

    def _offset(self, address: Any) -> int | None:
        """A Ghidra address as an offset from the image base, or ``None`` outside it."""
        try:
            value = int(str(address), 16)
        except (TypeError, ValueError):
            return None
        base = self._image_base or 0
        return value - base if value >= base else None

    # -- the emulation -----------------------------------------------------

    def emulate_api_hashes(
        self,
        host_path: str,
        routines: Sequence[Routine],
        function_starts: Sequence[Any] = (),
        names_path: str | None = None,
    ) -> dict[str, Any]:
        """Each routine emulated on every catalogue name; the file's values that equal an output."""
        from maljan.tools import api_hashes, pe_image

        program = self.open()
        image = pe_image.load(host_path)
        pe_image.take_function_starts(image, function_starts, "capa")
        names = _catalogue_names(names_path or self.names_path or api_hashes.DEFAULT_EXPORT_NAMES)
        candidates = set(api_hashes.candidate_values(image))
        conventions = X64_CONVENTIONS if image.is64 else X86_CONVENTIONS

        readings: dict[int, list[dict[str, Any]]] = {}
        rows: list[dict[str, Any]] = []
        for routine in routines:
            row, outputs = self._emulate_routine(program, routine, conventions, names)
            matched = {value for value in outputs if value in candidates}
            row["values_matched"] = len(matched)
            rows.append(row)
            for value in sorted(matched):
                for name in outputs[value]:
                    readings.setdefault(value, []).append(
                        {"routine": hex(routine.start), **name, "set_size": len(matched)}
                    )

        hit_values = [
            value
            for value, found in readings.items()
            if any(int(reading["set_size"]) > 1 for reading in found)
        ]
        lone_values = [value for value in readings if value not in set(hit_values)]

        def _row(value: int) -> dict[str, Any]:
            said = [{k: v for k, v in r.items() if k != "set_size"} for r in readings[value]]
            places = [image.where(at) for at in image.occurrences(value)]
            return {"value": f"{value:#010x}", "readings": said, "occurrences": places}

        hits = sorted((_row(v) for v in hit_values), key=_first_place)
        lone = sorted((_row(v) for v in lone_values), key=_first_place)
        return {
            "tool": EMULATION_TOOL,
            "emulator": f"Ghidra {GHIDRA_EMULATE}",
            "program": program,
            "how": ROUTINE_RULE,
            "conventions": CONVENTION_RULE,
            "image_base": hex(image.image_base),
            "function_table": image.function_table,
            "names": {"functions": names.functions, "modules": names.modules},
            "routines": rows,
            "candidates": {"scanned": len(candidates), "how": api_hashes.SCAN_HEURISTIC},
            "hits": hits,
            "total": len(hits),
            "lone_hits": lone,
        }

    def _emulate_routine(
        self,
        program: str,
        routine: Routine,
        conventions: Sequence[Convention],
        names: _Names,
    ) -> tuple[dict[str, Any], dict[int, list[dict[str, Any]]]]:
        address = (self._image_base or 0) + routine.start
        row: dict[str, Any] = {
            "start": hex(routine.start),
            "address": hex(address),
            "capa_rules": list(routine.rules),
        }
        probes = names.probes()
        taken: Convention | None = None
        tried: list[str] = []
        for convention in conventions:
            first = self._emulate(program, address, convention, probes[0])
            second = self._emulate(program, address, convention, probes[1])
            tried.append(convention.name)
            if first is not None and second is not None and first != second:
                taken = convention
                break
        row["conventions_tried"] = tried
        if taken is None:
            row["convention"] = None
            row["reason"] = NO_CONVENTION
            return row, {}
        row["convention"] = taken.name
        outputs: dict[int, list[dict[str, Any]]] = {}
        returned = 0
        for name in names.all():
            value = self._emulate(program, address, taken, name)
            if value is None:
                continue
            returned += 1
            outputs.setdefault(value, []).append(name.reading())
        row["names_emulated"] = names.count()
        row["names_returned"] = returned
        return row, outputs

    def _emulate(
        self, program: str, address: int, convention: Convention, name: _Name
    ) -> int | None:
        """The routine's 32-bit result for one name, or ``None`` when it did not return cleanly.

        Addresses go as plain hex, the form Ghidra writes them in; register
        values with ``0x``, which Ghidra reads as hex and a bare number as
        decimal. The stack's return address is written eight bytes wide, so an
        x64 return lands on the sentinel as an x86 one does.
        """
        length = name.length()
        regions = [
            {"address": f"{SCRATCH:x}", "hex": name.encoded().hex()},
            {"address": f"{STACK:x}", "hex": RETURN_SENTINEL.to_bytes(8, "little").hex()},
        ]
        registers: dict[str, str] = {}
        if convention.on_the_stack:
            arguments = SCRATCH.to_bytes(4, "little") + length.to_bytes(4, "little")
            regions.append({"address": f"{STACK + 4:x}", "hex": arguments.hex()})
        else:
            registers = {convention.pointer: hex(SCRATCH), convention.length: hex(length)}
        answer = self._request(
            "POST",
            f"/{GHIDRA_EMULATE}",
            f"the emulation of the routine at {hex(address)}",
            params={"program": program},
            json={
                "address": f"{address:x}",
                "registers": registers,
                "memory": regions,
                "return_registers": "EAX",
            },
        )
        if not isinstance(answer, dict) or answer.get("error"):
            return None
        if answer.get("hit_return") is not True or answer.get("emulation_error"):
            return None
        said = (answer.get("registers") or {}).get("EAX")
        try:
            return int(str(said), 16) & 0xFFFFFFFF
        except (TypeError, ValueError):
            return None


def _raise_on_error(answer: Any, what: str) -> None:
    if isinstance(answer, dict) and answer.get("error"):
        raise GhidraPassFailed(f"Ghidra refused {what}: {str(answer['error'])[:300]}")


def _first_place(row: dict[str, Any]) -> tuple[int, int]:
    places = row.get("occurrences") or []
    if not places:
        return (1, 0)
    return (0, int(str(places[0]["offset"]), 16))


@dataclass(frozen=True)
class _Name:
    """One name the routines are given, and how its bytes are laid out."""

    name: str
    name_set: str
    encoding: str
    dlls: tuple[str, ...] = ()

    def encoded(self) -> bytes:
        """The name's bytes and its terminator."""
        if self.encoding == "utf-16le":
            return self.name.encode("utf-16-le") + b"\0\0"
        return self.name.encode("latin-1", errors="replace") + b"\0"

    def length(self) -> int:
        """The name's length in bytes, without its terminator."""
        return len(self.encoded()) - (2 if self.encoding == "utf-16le" else 1)

    def reading(self) -> dict[str, Any]:
        said: dict[str, Any] = {"set": self.name_set, "name": self.name, "encoding": self.encoding}
        if self.dlls:
            said["dlls"] = list(self.dlls)
        return said


@dataclass(frozen=True)
class _Names:
    exported: tuple[_Name, ...]
    module_names: tuple[_Name, ...]

    @property
    def functions(self) -> int:
        return len(self.exported)

    @property
    def modules(self) -> int:
        return len({name.name for name in self.module_names})

    def all(self) -> Iterable[_Name]:
        yield from self.exported
        yield from self.module_names

    def count(self) -> int:
        return len(self.exported) + len(self.module_names)

    def probes(self) -> tuple[_Name, _Name]:
        return self.exported[0], self.exported[1]


def _catalogue_names(path: str) -> _Names:
    """Every function name of the catalogue once, with its DLLs, then every module name.

    The vendored catalogue comes from ``api_hashes``' own cache; another one is
    read on its own, so it never pushes the vendored one out of that cache.
    """
    from maljan.core.paths import resolve_data
    from maljan.tools import api_hashes

    if path == api_hashes.DEFAULT_EXPORT_NAMES:
        document = api_hashes.load_export_names(path)
    else:
        document = dict(json.loads(resolve_data(path).read_text(encoding="utf-8")))
    by_name: dict[str, list[str]] = {}
    for dll, exported in (document.get("dlls") or {}).items():
        for name in exported:
            by_name.setdefault(str(name), []).append(str(dll))
    exported_names = tuple(
        _Name(name, api_hashes.EXPORTS, "ascii", tuple(dlls)) for name, dlls in by_name.items()
    )
    modules = [str(m) for m in (document.get("modules") or {}).get("names") or []]
    module_names = tuple(
        _Name(module, api_hashes.MODULES, encoding)
        for module in modules
        for encoding in ("ascii", "utf-16le")
    )
    if len(exported_names) < 2:
        raise GhidraPassFailed("the name catalogue holds fewer than two function names")
    return _Names(exported_names, module_names)


def mark_agreement(
    answer: dict[str, Any], resolved: dict[str, Any] | None, entry_id: str
) -> dict[str, Any]:
    """``answer`` with each value the platform's own resolution names the same way marked.

    ``resolved`` is the ``resolve_api_hashes`` answer of the same run and
    ``entry_id`` its ledger id. A value is marked (``also_named_by``) when the
    resolution read it and one of its names is a name the emulation read;
    ``agrees_with`` counts the marked hits. The two are independent readings
    of one value — arithmetic over published algorithms, and the sample's own
    code run on the names — and the pack line says the second agrees with the
    first rather than listing the value twice.
    """
    if not resolved or not entry_id:
        return answer
    named: dict[int, set[str]] = {}
    for key in ("hits", "lone_hits"):
        for hit in resolved.get(key) or []:
            if not isinstance(hit, dict):
                continue
            value = _int(hit.get("value"))
            if value is None:
                continue
            names = {str(r.get("name")) for r in hit.get("readings") or [] if isinstance(r, dict)}
            named.setdefault(value, set()).update(names)
    marked = dict(answer)
    agreeing = 0
    for key in ("hits", "lone_hits"):
        rows = []
        for hit in answer.get(key) or []:
            row = dict(hit)
            value = _int(row.get("value"))
            names = {str(r.get("name")) for r in row.get("readings") or [] if isinstance(r, dict)}
            if value is not None and names & named.get(value, set()):
                row["also_named_by"] = entry_id
                agreeing += key == "hits"
            rows.append(row)
        marked[key] = rows
    marked["agrees_with"] = {"entry": entry_id, "tool": "resolve_api_hashes", "hits": agreeing}
    return marked


def run_pass(call: Callable[[], dict[str, Any]], what: str) -> dict[str, Any]:
    """``call()``, logging a failure before it is handed on."""
    try:
        return call()
    except GhidraPassFailed as failure:
        logger.warning("Ghidra pass %s did not complete: %s", what, failure)
        raise
