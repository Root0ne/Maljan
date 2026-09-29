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
  ``INT 0x2d`` as well;
* a TEB/PEB read, when the instruction reads through ``FS:[0x30]`` or
  ``FS:[0x18]`` exactly;
* an API call, when the API is on the platform's own short list of APIs whose
  documented purpose is the technique (``anti_analysis_apis``: the anti-debug
  APIs the vendored behaviour catalogue treats as corroborating, and the APIs
  its T1497 rule names) and the file imports it. Ghidra matches symbol names
  by substring over a broad list, so it files ``CloseHandle`` under debugger
  detection; the call is stated by the imported name.

Every other match is counted, not stated. The scan checks what
``SCAN_CHECKS`` says and nothing else, so an empty result is said as that list
matching nothing, never as the sample having no anti-analysis code.

A pass that cannot run says why: the pack records that sentence rather than
leaving the pass out. A request Ghidra did not answer, or answered with an
error, stops the pass, and the entry states Ghidra's own words.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
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
    "stated: an instruction that is the listed one (the same mnemonic and operand), a read "
    "through FS:[0x30] or FS:[0x18] exactly, and a call to an API the platform's catalogue lists "
    "for the technique that the file imports; every other match is counted, not stated"
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

_BEHAVIOUR_MAP = "data/api_behaviour_map_v1.json"
_ATTCK_MAP = "data/api_attck_map_v1.json"


class GhidraPassFailed(RuntimeError):
    """A pass that was made and did not complete, with what happened."""


@lru_cache(maxsize=1)
def anti_analysis_apis() -> frozenset[str]:
    """The APIs whose documented purpose is an anti-analysis technique, from the catalogue.

    The vendored behaviour catalogue's anti-debug block lists, beside its broad
    set, the few APIs it treats as corroborating (the ones ordinary software
    rarely calls); its ATT&CK map's T1497 rule names the firmware, device and
    idle-user APIs of sandbox evasion. The union of the two, nothing added.
    """
    from maljan.core.paths import resolve_data

    names: set[str] = set()
    behaviour = json.loads(resolve_data(_BEHAVIOUR_MAP).read_text(encoding="utf-8"))
    block = ((behaviour.get("platforms") or {}).get("windows") or {}).get("anti_debug") or {}
    names.update(str(n) for n in block.get("corroborated_by") or [])
    attck = json.loads(resolve_data(_ATTCK_MAP).read_text(encoding="utf-8"))
    for technique in attck.get("techniques") or []:
        if str(technique.get("technique_id") or "").startswith("T1497"):
            names.update(str(n) for n in technique.get("apis") or [])
    return frozenset(names)


_INSTRUCTION_CATEGORY = "suspicious_instruction"
_TEB_CATEGORY = "peb_teb_access"
_TEB_OPERAND = re.compile(r"\bFS:\[0x(?:30|18)\]", re.IGNORECASE)


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


def read_findings(findings: Iterable[dict[str, Any]], imported: Sequence[str]) -> dict[str, Any]:
    """The exact part of Ghidra's findings as facts, and how many others there were."""
    apis = anti_analysis_apis()
    held = [str(name) for name in imported if str(name)]
    stated: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    not_stated = 0
    for row in findings:
        if not isinstance(row, dict):
            continue
        category = str(row.get("category") or "")
        technique = str(row.get("technique") or "")
        instruction = str(row.get("instruction") or "")
        what = ""
        if category == _INSTRUCTION_CATEGORY:
            if _is_the_listed_instruction(technique, instruction):
                what = instruction.strip()
        elif category == _TEB_CATEGORY:
            if _TEB_OPERAND.search(instruction):
                what = instruction.strip()
        else:
            named = [name for name in held if technique and technique in name and name in apis]
            if len(named) == 1:
                what = f"call to {named[0]}"
        if not what:
            not_stated += 1
            continue
        where = str(row.get("offset") or row.get("address") or "")
        if (where, what) in seen:
            continue
        seen.add((where, what))
        fact = {"category": category, "what": what, "offset": where}
        if row.get("function"):
            fact["function"] = str(row["function"])
        stated.append(fact)
    return {"stated": stated, "not_stated": not_stated}


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

    def anti_analysis(self, imported: Sequence[str] = ()) -> dict[str, Any]:
        """Ghidra's scan, whole, with the exact part of it stated (``read_findings``)."""
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
            **read_findings(findings, imported),
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


def run_pass(call: Callable[[], dict[str, Any]], what: str) -> dict[str, Any]:
    """``call()``, logging a failure before it is handed on."""
    try:
        return call()
    except GhidraPassFailed as failure:
        logger.warning("Ghidra pass %s did not complete: %s", what, failure)
        raise
