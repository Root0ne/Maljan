"""32-bit values in a PE resolved to the Windows function names they are hashes of.

A program that does not want its imports read keeps a 32-bit hash of each
function name instead, walks a loaded module's export table at run time, and
calls the function whose name hashes to the stored value. A reader of the file
sees only numbers. This tool turns the numbers back into names, statically:
it hashes every name in vendored export lists of common Windows DLLs under a
set of published algorithms and looks each value up.

The data, both vendored under ``data/``:

* ``windows_export_names_v1.json`` — the named exports of common Windows DLLs,
  generated from the Wine project's DLL spec files by
  ``scripts/knowledge/build_windows_export_names.py`` (the file records the
  release tag and each spec's URL and sha256, and the license the names are
  held under). No DLL binary is read or shipped. The same file carries the
  module-name set: each DLL's own file name with and without ``.dll``, in lower
  and in upper case, which a resolver that walks the loaded-module list hashes
  to find a module before its exports. Every reading names the set it came
  from (``set``: ``exports`` or ``modules``).
* ``api_hash_algorithms_v1.json`` — the algorithms, each a primitive
  implemented here (``crc32``, ``ror13``, ``djb2``, ``fnv1a32``) with the
  encoding, the case folding, the terminator and, for the forms that add a
  hash of the module name, how that name is hashed.

Which values are looked up. The caller's, when it passes ``hashes``. With none,
the candidates are found by a stated heuristic and nothing else:

* in executable sections, the 32-bit immediate of every byte pattern that
  encodes ``push imm32``, ``mov r32, imm32``, ``mov r/m32, imm32``,
  ``cmp eax, imm32`` or ``cmp r/m32, imm32`` — the instructions a lookup loop
  compares a computed hash with, or a caller passes one to a resolver with;
* in the other sections, every four-byte-aligned 32-bit value — where a table
  of hashes a resolver walks is kept;
* leaving out values below 0x10000 and values that are a virtual address
  inside the image, which are counts and pointers rather than hashes.

A resolution is a fact about arithmetic: the value equals that algorithm's
hash of that name. With some ten thousand names and ten algorithms, an
arbitrary 32-bit value matches one by chance about once in forty thousand, so a
scan of a large file finds a few coincidences. They are not dropped: a value
whose algorithm resolves no other value in the file is reported under
``lone_hits`` instead of ``hits``, because a program that resolves functions
by hash uses one algorithm for many of them. A value the caller named is always
a hit or ``unresolved``.

Every reading is reported. A value that is the hash of two names, under one
algorithm or two, carries both; one is never picked. Each hit lists every place
in the file where the value is stored (little-endian, aligned or not), with the
RVA, the section and, inside code, the start of the function the file's own
function table puts around it (``maljan.tools.pe_image``); no start is guessed.

Nothing is limited by default: ``limit`` pages the answer only when the caller
asks for pages.
"""

from __future__ import annotations

import json
import re
import zlib
from collections.abc import Callable, Sequence
from functools import lru_cache
from typing import Any

import numpy as np

from maljan.core.paths import resolve_data
from maljan.tools import pe_image

DEFAULT_EXPORT_NAMES = "data/windows_export_names_v1.json"
DEFAULT_ALGORITHMS = "data/api_hash_algorithms_v1.json"

TOOL = "resolve_api_hashes"

# Values below this are counts, sizes and flags far more often than hashes.
_SMALLEST_CANDIDATE = 0x10000

# The sentence the answer carries about how the candidates were chosen.
SCAN_HEURISTIC = (
    "32-bit immediates of push, mov and cmp byte patterns in executable sections, and every "
    "four-byte-aligned 32-bit value in the other sections, leaving out values below 0x10000 "
    "and virtual addresses inside the image"
)


# ---------------------------------------------------------------------------
# The primitives
# ---------------------------------------------------------------------------


def _crc32(data: bytes, start: int = 0) -> int:
    return zlib.crc32(data, start) & 0xFFFFFFFF


def _ror13(data: bytes, start: int = 0) -> int:
    value = start
    for byte in data:
        value = ((value >> 13) | (value << 19)) & 0xFFFFFFFF
        value = (value + byte) & 0xFFFFFFFF
    return value


def _djb2(data: bytes, start: int = 5381) -> int:
    value = start
    for byte in data:
        value = (value * 33 + byte) & 0xFFFFFFFF
    return value


def _fnv1a32(data: bytes, start: int = 0x811C9DC5) -> int:
    value = start
    for byte in data:
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    return value


PRIMITIVES: dict[str, Callable[[bytes], int]] = {
    "crc32": _crc32,
    "ror13": _ror13,
    "djb2": _djb2,
    "fnv1a32": _fnv1a32,
}


def _encoded(name: str, encoding: str, case: str, terminator: bool) -> bytes:
    text = name.lower() if case == "lower" else name.upper() if case == "upper" else name
    if terminator:
        text += "\0"
    return text.encode("utf-16-le" if encoding == "utf16le" else "latin-1", errors="replace")


def hash_name(algorithm: dict[str, Any], name: str, module: str = "") -> int:
    """``name``'s hash under one algorithm entry of the data file."""
    primitive = PRIMITIVES[str(algorithm["primitive"])]
    value = primitive(
        _encoded(
            name,
            str(algorithm.get("encoding", "ascii")),
            str(algorithm.get("case", "as-is")),
            bool(algorithm.get("terminator", False)),
        )
    )
    spec = algorithm.get("module")
    if isinstance(spec, dict):
        module_hash = primitive(
            _encoded(
                module,
                str(spec.get("encoding", "ascii")),
                str(spec.get("case", "as-is")),
                bool(spec.get("terminator", False)),
            )
        )
        value = (value + module_hash) & 0xFFFFFFFF
    return value


# ---------------------------------------------------------------------------
# The vendored data
# ---------------------------------------------------------------------------


@lru_cache(maxsize=4)
def load_export_names(path: str = DEFAULT_EXPORT_NAMES) -> dict[str, Any]:
    return dict(json.loads(resolve_data(path).read_text(encoding="utf-8")))


@lru_cache(maxsize=4)
def load_algorithms(path: str = DEFAULT_ALGORITHMS) -> tuple[dict[str, Any], ...]:
    document = json.loads(resolve_data(path).read_text(encoding="utf-8"))
    return tuple(dict(entry) for entry in document.get("algorithms") or [])


# The two name sets a value is looked up in, as each reading names its own.
EXPORTS = "exports"
MODULES = "modules"


@lru_cache(maxsize=16)
def _table(algorithm_ids: tuple[str, ...], names_path: str, algorithms_path: str) -> dict[int, Any]:
    """Every (algorithm, name set, name, dll) reading of every hash value, keyed by the value.

    The exported function names of each DLL, and the module names — the DLLs'
    own file names in the spellings the data lists — which a resolver that
    walks the loaded-module list hashes to find the module before its exports.
    The algorithms that add a module hash to a function hash already take the
    module name in; module names alone are hashed under every other one.
    """
    document = load_export_names(names_path)
    names = document.get("dlls") or {}
    modules = (document.get("modules") or {}).get("names") or []
    table: dict[int, dict[tuple[str, str, str], list[str]]] = {}
    for algorithm in load_algorithms(algorithms_path):
        if algorithm["id"] not in algorithm_ids:
            continue
        per_module = isinstance(algorithm.get("module"), dict)
        plain: dict[str, int] = {}
        for dll, exported in names.items():
            for name in exported:
                if per_module:
                    value = hash_name(algorithm, name, dll)
                elif name in plain:
                    value = plain[name]
                else:
                    value = plain[name] = hash_name(algorithm, name)
                readings = table.setdefault(value, {})
                readings.setdefault((algorithm["id"], EXPORTS, name), []).append(dll)
        if per_module:
            continue
        for module in modules:
            readings = table.setdefault(hash_name(algorithm, str(module)), {})
            readings.setdefault((algorithm["id"], MODULES, str(module)), [])
    return table


def _readings(table: dict[int, Any], value: int) -> list[dict[str, Any]]:
    """Each reading: the algorithm, the name set, the name and, for an export, its DLLs."""
    found = table.get(value) or {}
    return [
        {"algorithm": algorithm, "set": name_set, "name": name, "dlls": list(dlls)}
        for (algorithm, name_set, name), dlls in found.items()
    ]


# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------

# The one-byte opcodes followed directly by a 32-bit immediate:
# push imm32, mov r32 imm32 (B8..BF) and cmp eax imm32.
_DIRECT_IMMEDIATE = re.compile(rb"[\x68\xb8-\xbf\x3d]", re.DOTALL)
# The opcodes whose immediate follows a ModRM operand: cmp r/m32 imm32 (81 /7)
# and mov r/m32 imm32 (C7 /0).
_MODRM_IMMEDIATE = re.compile(rb"[\x81\xc7]", re.DOTALL)


def _operand_length(code: bytes, at: int, is64: bool) -> int | None:
    """Bytes the ModRM at ``at`` and what follows it take before an immediate."""
    if at >= len(code):
        return None
    modrm = code[at]
    mod, rm = modrm >> 6, modrm & 7
    length = 1
    if mod == 3:
        return length
    if rm == 4:
        if at + 1 >= len(code):
            return None
        sib = code[at + 1]
        length += 1
        if mod == 0 and (sib & 7) == 5:
            length += 4
    elif mod == 0 and rm == 5:
        return length + 4
    if mod == 1:
        length += 1
    elif mod == 2:
        length += 4
    return length


def _code_immediates(code: bytes, is64: bool) -> set[int]:
    values: set[int] = set()
    for match in _DIRECT_IMMEDIATE.finditer(code):
        at = match.start() + 1
        if at + 4 <= len(code):
            values.add(int.from_bytes(code[at : at + 4], "little"))
    for match in _MODRM_IMMEDIATE.finditer(code):
        opcode = code[match.start()]
        at = match.start() + 1
        if at >= len(code):
            continue
        reg = (code[at] >> 3) & 7
        if (opcode == 0x81 and reg != 7) or (opcode == 0xC7 and reg != 0):
            continue
        length = _operand_length(code, at, is64)
        if length is None:
            continue
        start = at + length
        if start + 4 <= len(code):
            values.add(int.from_bytes(code[start : start + 4], "little"))
    return values


def candidate_values(image: pe_image.Image) -> list[int]:
    """The values the scan looks up, in ascending order (see the module docstring)."""
    values: set[int] = set()
    for section in image.code_sections():
        values |= _code_immediates(image.section_bytes(section), image.is64)
    for section in image.data_sections():
        raw = image.data_bytes(section)
        usable = len(raw) // 4 * 4
        if usable:
            values.update(int(v) for v in np.unique(np.frombuffer(raw[:usable], dtype="<u4")))
    low, high = image.image_base, image.image_base + max(image.size_of_image, 1)
    return sorted(v for v in values if v >= _SMALLEST_CANDIDATE and not (low <= v < high))


def _value(raw: Any) -> int | None:
    """One caller-given hash, as an int: a number, or a decimal or ``0x`` string."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw & 0xFFFFFFFF if raw >= 0 else None
    text = str(raw or "").strip().strip("\"'").lower()
    try:
        value = int(text, 16) if text.startswith("0x") else int(text, 10)
    except ValueError:
        try:
            value = int(text, 16)
        except ValueError:
            return None
    return value if 0 <= value <= 0xFFFFFFFF else None


# ---------------------------------------------------------------------------
# The tool
# ---------------------------------------------------------------------------


def _error(message: str) -> dict[str, Any]:
    return {"error": message, "tool": TOOL}


def resolve_api_hashes(
    path: str,
    hashes: Sequence[Any] | None = None,
    algorithms: Sequence[str] | None = None,
    offset: int = 0,
    limit: int | None = None,
    names_path: str = DEFAULT_EXPORT_NAMES,
    algorithms_path: str = DEFAULT_ALGORITHMS,
    function_starts: Sequence[Any] | None = None,
    function_source: str = "capa",
) -> dict[str, Any]:
    """Resolve 32-bit values in a PE to the function names they are hashes of.

    ``hashes`` are the values to resolve; with none the file is scanned for
    candidates. ``algorithms`` keeps some of the data file's algorithm ids;
    with none every one is tried. ``offset``/``limit`` page ``hits`` when the
    caller wants pages; ``limit`` of ``None`` is every hit.
    ``function_starts`` (offsets from the image base, from ``function_source``)
    stand in for a function table the image lacks (``pe_image``).
    """
    try:
        image = pe_image.load(path)
    except FileNotFoundError:
        return _error(f"no such file: {path}")
    except pe_image.NotAPortableExecutable as exc:
        return _error(f"this tool reads Windows PE images only; {exc}")
    pe_image.take_function_starts(image, function_starts, function_source)
    known = [str(entry["id"]) for entry in load_algorithms(algorithms_path)]
    wanted = tuple(known) if not algorithms else tuple(str(a).strip() for a in algorithms)
    unknown = [a for a in wanted if a not in known]
    if unknown:
        return _error(f"unknown algorithms {unknown}; known: {', '.join(known)}")
    table = _table(tuple(sorted(wanted)), names_path, algorithms_path)
    names = load_export_names(names_path)
    dlls = names.get("dlls") or {}

    given = hashes is not None and len(hashes) > 0
    unreadable: list[str] = []
    if given:
        values: list[int] = []
        for raw in hashes or []:
            value = _value(raw)
            if value is None:
                unreadable.append(str(raw))
            elif value not in values:
                values.append(value)
    else:
        values = candidate_values(image)

    resolved = {value: _readings(table, value) for value in values}
    resolved = {value: readings for value, readings in resolved.items() if readings}
    if given:
        hit_values = list(resolved)
        lone_values: list[int] = []
    else:
        # How many distinct values each algorithm resolved in this file.
        per_algorithm: dict[str, int] = {}
        for readings in resolved.values():
            for algorithm in {r["algorithm"] for r in readings}:
                per_algorithm[algorithm] = per_algorithm.get(algorithm, 0) + 1
        hit_values = [
            value
            for value, readings in resolved.items()
            if any(per_algorithm[r["algorithm"]] > 1 for r in readings)
        ]
        lone_values = [value for value in resolved if value not in set(hit_values)]

    def _row(value: int) -> dict[str, Any]:
        places = [image.where(at) for at in image.occurrences(value)]
        return {"value": f"{value:#010x}", "readings": resolved[value], "occurrences": places}

    hits = [_row(value) for value in hit_values]
    hits.sort(key=lambda row: _first_place(row))
    lone = [_row(value) for value in lone_values]
    lone.sort(key=lambda row: _first_place(row))
    start = max(0, int(offset or 0))
    page = hits[start:] if limit is None else hits[start : start + max(0, int(limit))]
    more = start + len(page) < len(hits)
    answer: dict[str, Any] = {
        "tool": TOOL,
        "image_base": hex(image.image_base),
        "function_table": image.function_table,
        "algorithms": list(wanted),
        "names": {
            "dlls": len(dlls),
            "names": sum(len(v) for v in dlls.values()),
            "source": str(names.get("source") or ""),
            "license": str(names.get("license") or ""),
            "modules": len((names.get("modules") or {}).get("names") or []),
            "modules_source": str((names.get("modules") or {}).get("source") or ""),
        },
        "candidates": (
            {"given": len(values) + len(unreadable)}
            if given
            else {"scanned": len(values), "how": SCAN_HEURISTIC}
        ),
        "hits": page,
        "total": len(hits),
        "page_offset": start,
        "next_offset": start + len(page) if more else None,
    }
    if given:
        answer["unresolved"] = [f"{v:#010x}" for v in values if v not in resolved]
        if unreadable:
            answer["unreadable"] = unreadable
    else:
        answer["lone_hits"] = lone
    return answer


def _first_place(row: dict[str, Any]) -> tuple[int, int]:
    places = row.get("occurrences") or []
    if not places:
        return (1, 0)
    return (0, int(str(places[0]["offset"]), 16))
