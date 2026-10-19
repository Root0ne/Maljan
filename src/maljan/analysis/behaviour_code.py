"""Observed behaviour linked to the static places that hold it, by exact match only.

A sandbox observes values: the mutexes the sample created, the registry keys
and values it touched, the files and named pipes it opened, the hosts,
addresses, URLs and user agents it used, the services it made and the command
lines it ran. The pack's static answers hold texts: the printable runs of the
file (``strings``), the strings a decoder recovered at a call site, the texts
the platform decoded from the data sections, and the plain and decoded strings
the function index places in each function. A value the sandbox observed that
one of those texts holds is a link an analyst can follow from the behaviour to
the code: "observed X, held at Y, in function Z".

This module states those links and nothing else.

* **The observed values** are read from the normalised sandbox report through
  its sections (``analysis.sandbox_sections``), whichever provider produced
  it, each with the item ids it came from. A section the report does not
  carry is named with its ``no:`` sentence, and the items of a section that
  held no value under the fields read are counted. A network value is linked
  only where the sandbox attributes it to the sample's process tree
  (``schemas.sandbox_report.SAMPLE_TREE_KEY``); where the row does not say,
  the link is marked "process not attributed"; a value every row of which
  the sandbox attributes to another process is not linked, and is counted.
  An HTTP request's path is joined with the request's own host (and scheme,
  where the row states one); a path with no host is a path, never a URL.
* **The match is exact**, after the platform's own normalisation for the
  value's kind (``reporting.dedupe.indicator_fingerprint``): a registry key
  and a Windows path fold their case and their separators, a host name and an
  address are read by one shared host form on both sides
  (``extractors.network_extractor.host_form``: port, brackets and trailing dot
  off, IDNA, canonical IPv6), defanging is undone, and every other kind (a
  mutex, a URL, a user agent, a service, a command line) keeps its case. A
  text that holds the value inside a longer one is not a match, with two
  structured readings that are still exact and say so: a domain or address
  that is the host of a held URL, and a registry key whose path after its
  hive is held with no hive (``detection_signatures.hiveless_key``).
* **The static texts** are read as their answers decoded them, so a UTF-16LE
  run, an XOR-decoded blob and a base64 layer are compared as the text they
  spell; the holding names the encoding it was read in.
* **The function** of a holding is the one its own answer names by place (a
  decoded blob's references, a recovered string's routine). Where only the
  function index's text names one, it is said as "same text elsewhere in
  function X": the index places that text, not this copy of it. Where no
  function index was made, the answer says so.
* A value held nowhere among the texts compared is listed as **observed
  only**, or as "observed; static side partly read" where a compared answer
  holds a page of its texts, decodings were not compared, a static answer
  could not be read or the pack's time ran out.

Time is linear: every observed value is indexed once by its normalised key,
and every static text is looked up once per kind observed (a fixed handful),
so the join is hash lookups, never one list against another. The step runs
under the pack's time budget and stops with a partial answer.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from maljan.analysis.sandbox_sections import Sections
from maljan.extractors.network_extractor import host_form
from maljan.reporting.dedupe import canonical_path, canonical_value, indicator_fingerprint
from maljan.schemas.sandbox_report import SAMPLE_TREE_KEY

TOOL = "behaviour_code_links"
KIND = "behaviour_code_links"

# The kinds of observed value, each with the kind the platform's normalisation
# (``reporting.dedupe.indicator_fingerprint``) reads it as.
FINGERPRINT_KIND: dict[str, str] = {
    "mutex": "mutex",
    "registry key": "registry",
    "registry value name": "registry_value",
    "registry value data": "registry_value",
    "path": "path",
    "named pipe": "path",
    "url path": "path",
    "domain": "domain",
    "ip": "ip",
    "url": "url",
    "user agent": "user_agent",
    "service": "service",
    "command line": "command",
}
# The normalisation kinds read through the shared host form.
_HOST_KINDS = ("domain", "ip")

# The sources of a holding, as the answer names them.
STRINGS = "strings"
RECOVERED = "recovered string"
BLOB = "decoded blob"
BLOB_LAYER = "decoded blob layer"
INDEXED = "function index"

# How a holding matched its value: the whole text, or one of the two
# structured readings (each still exact after the platform's normalisation).
EXACT = "exact"
URL_HOST = "host of a held URL"
WITHOUT_HIVE = "held without its hive"

# Said where a value is held by none of the texts compared: all of them read,
# or some of the static side not read.
OBSERVED_ONLY = "observed only"
PARTLY_READ = "observed; static side partly read"
# Said of a network value whose rows do not say which process made them.
NOT_ATTRIBUTED = "process not attributed"
# Said of a network value the sandbox attributes to the sample's process tree.
SAMPLE_TREE = "sample's process tree"
# Said of a holding whose answer names no function and that the index does not place.
NO_FUNCTION = "none stated"
# Said of a function the function index gives by the text alone.
SAME_TEXT = "same text elsewhere in function"
# Said where no function index answer is in the pack.
NO_INDEX = "no: the pack holds no function index answer"
# Said where the pack's time budget ran out before every static text was compared.
CUT_BY_BUDGET = (
    "the pack's time budget ran out after {done} static texts; the rest were not compared"
)

# How a named pipe's path begins, as a path the platform normalises (case
# folded, separators written ``/``), its leading separators aside.
_PIPE_PREFIXES = ("./pipe/", "??/pipe/", "device/namedpipe/")

# The fields an observed row names its value under, per section and kind.
_FILE_FIELDS = ("path", "filename", "file", "name")
_REGISTRY_KEY_FIELDS = ("key", "regkey", "path", "name")
_REGISTRY_NAME_FIELDS = ("value", "value_name", "valuename")
_REGISTRY_DATA_FIELDS = ("data", "value_data", "valuedata")
_COMMAND_FIELDS = ("command", "cmdline", "command_line")
_SERVICE_FIELDS = ("name", "service")
_MUTEX_FIELDS = ("name", "mutex")
_URL_FIELDS = ("url", "uri")
_HOST_FIELDS = ("host", "hostname", "domain")
_ADDRESS_FIELDS = ("dst", "ip", "address")
_SNI_FIELDS = ("sni", "server_name")
_USER_AGENT_FIELDS = ("user_agent", "user-agent", "useragent")
_DNS_FIELDS = ("request", "query", "hostname", "domain", "name")
_SCHEME_FIELDS = ("scheme", "protocol")
_PORT_FIELDS = ("port", "dport")
# The ports a URL leaves unwritten for its scheme (RFC 3986's default ports).
_DEFAULT_PORTS = {"http": 80, "https": 443}
# How the answer's ``absent`` names a sandbox section the report does not carry.
SANDBOX_ABSENT_PREFIX = "sandbox "
# The sections read, in the order the answer lists their values.
SECTIONS_READ = ("mutexes", "registry", "files", "commands", "processes", "services", "network")


@dataclass
class Observed:
    """One distinct value the sandbox observed, and the items it was observed in."""

    kind: str
    value: str
    items: list[str] = field(default_factory=list)
    held: list[dict[str, Any]] = field(default_factory=list)
    # The ids in ``items``, so a repeated id is one set lookup, not a scan of the list.
    seen: set[str] = field(default_factory=set, repr=False, compare=False)
    # A network value's attribution over its rows: whether any row the sandbox
    # attributes to the sample's tree, any row that does not say, any row of
    # another process.
    tree: set[bool | None] = field(default_factory=set, repr=False, compare=False)

    def observed_in(self, item_id: str) -> None:
        """Add ``item_id`` to ``items`` once, in the order first seen."""
        if item_id and item_id not in self.seen:
            self.seen.add(item_id)
            self.items.append(item_id)

    @property
    def attribution(self) -> str | None:
        """``SAMPLE_TREE``, ``NOT_ATTRIBUTED``, ``""`` (others only) or ``None`` (no rows)."""
        if not self.tree:
            return None
        if True in self.tree:
            return SAMPLE_TREE
        if None in self.tree:
            return NOT_ATTRIBUTED
        return ""

    def as_row(self) -> dict[str, Any]:
        row: dict[str, Any] = {
            "kind": self.kind,
            "value": self.value,
            "items": self.items,
            "held": self.held,
        }
        if self.attribution:
            row["attribution"] = self.attribution
        return row


@dataclass
class StaticInputs:
    """The pack's static answers the links are read from, each with its entry id and tool.

    ``strings``: answers of printable runs (``rows`` of ``offset``, ``enc``,
    ``text``), with how many runs the answer counted. ``recovered``: rows of
    strings a decoder recovered at a call site; ``recovered_of``, by entry id,
    how many the answer counted where the rows read are a page of them.
    ``blobs``: the static decoder's answer. ``index``: the function index's
    answer. ``sections``: the PE header's sections, for the section a file
    offset is in. ``absent``: each input the pack lacks, with why;
    ``unread``: the static answers among them that were made and could not be
    read (failed, not made, or holding no readable answer).
    """

    strings: list[tuple[str, str, Mapping[str, Any]]] = field(default_factory=list)
    recovered: list[tuple[str, str, Sequence[Mapping[str, Any]]]] = field(default_factory=list)
    recovered_of: dict[str, int] = field(default_factory=dict)
    blobs: tuple[str, str, Mapping[str, Any]] | None = None
    index: tuple[str, str, Mapping[str, Any]] | None = None
    sections: Sequence[Mapping[str, Any]] = ()
    absent: dict[str, str] = field(default_factory=dict)
    unread: list[str] = field(default_factory=list)


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _lowered(fields: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key).lower(): value for key, value in fields.items()}


def _field(lowered: Mapping[str, Any], names: Sequence[str]) -> str:
    """The first non-blank string among ``names`` in fields whose keys are lower-cased."""
    for name in names:
        found = _text(lowered.get(name))
        if found.strip():
            return found
    return ""


def _host_kind(host: str) -> str:
    """``ip`` for an address (port and brackets aside), else ``domain``."""
    import ipaddress

    try:
        ipaddress.ip_address(host_form(host))
    except ValueError:
        return "domain"
    return "ip"


def _file_kind(path: str) -> str:
    folded = canonical_path(path).lower().lstrip("/")
    return "named pipe" if folded.startswith(_PIPE_PREFIXES) else "path"


def _key(kind: str, value: str) -> tuple[str, str]:
    """The normalised key of a value of a normalisation ``kind``; hosts through the host form."""
    return indicator_fingerprint(kind, host_form(value) if kind in _HOST_KINDS else value)


def _values_of(section: str, item: Mapping[str, Any]) -> Iterator[tuple[str, str]]:
    """``(kind, value)`` of each value one sandbox item observed."""
    fields = item.get("fields")
    if not isinstance(fields, Mapping):
        return
    scalar = _text(fields.get("value")) if set(fields) == {"value"} else ""
    lowered = _lowered(fields)
    if section == "mutexes":
        name = scalar or _field(lowered, _MUTEX_FIELDS)
        if name:
            yield "mutex", name
    elif section == "registry":
        if scalar:
            yield "registry key", scalar
            return
        key = _field(lowered, _REGISTRY_KEY_FIELDS)
        if key:
            yield "registry key", key
        name = _field(lowered, _REGISTRY_NAME_FIELDS)
        if name:
            yield "registry value name", name
        data = _field(lowered, _REGISTRY_DATA_FIELDS)
        if data:
            yield "registry value data", data
    elif section == "files":
        path = scalar or _field(lowered, _FILE_FIELDS)
        if path:
            yield _file_kind(path), path
    elif section in ("commands", "processes"):
        command = scalar if section == "commands" else ""
        command = command or _field(lowered, _COMMAND_FIELDS)
        if command:
            yield "command line", command
    elif section == "services":
        name = scalar or _field(lowered, _SERVICE_FIELDS)
        if name:
            yield "service", name
    elif section == "network":
        yield from _network_values(str(item.get("kind") or ""), lowered, scalar)


def _scheme(lowered: Mapping[str, Any]) -> str:
    """The scheme an HTTP row states: its scheme or protocol field, else its ``encrypted``."""
    stated = _field(lowered, _SCHEME_FIELDS).strip().lower().removesuffix("://")
    if stated in _DEFAULT_PORTS:
        return stated
    encrypted = lowered.get("encrypted")
    if isinstance(encrypted, bool):
        return "https" if encrypted else "http"
    return ""


def _joined_url(path: str, host: str, lowered: Mapping[str, Any]) -> str:
    """A request's URL from its own host and path, where the row states the scheme; else ``""``."""
    scheme = _scheme(lowered)
    if not scheme or not host:
        return ""
    port = lowered.get("port")
    written = host if ":" not in host or host.startswith("[") else f"[{host}]"
    if isinstance(port, int) and not isinstance(port, bool) and port != _DEFAULT_PORTS[scheme]:
        written += f":{port}"
    return f"{scheme}://{written}{path if path.startswith('/') else '/' + path}"


def _network_values(
    kind: str, lowered: Mapping[str, Any], scalar: str
) -> Iterator[tuple[str, str]]:
    if kind == "icmp":
        return
    if scalar:
        yield _host_kind(scalar), scalar
        return
    if kind == "dns":
        name = _field(lowered, _DNS_FIELDS)
        if name:
            yield "domain", name.strip()
        return
    host = _field(lowered, _HOST_FIELDS)
    url = _field(lowered, _URL_FIELDS)
    if url and "://" in url:
        yield "url", url
    elif url:
        # A path the request was made for: a URL only with the request's own
        # host and stated scheme; otherwise a path, never compared as a URL.
        joined = _joined_url(url, host, lowered)
        yield ("url", joined) if joined else ("url path", url)
    for named in (host, _field(lowered, _SNI_FIELDS)):
        if named:
            yield _host_kind(named), named
    address = _field(lowered, _ADDRESS_FIELDS)
    if address:
        yield _host_kind(address), address
    agent = _field(lowered, _USER_AGENT_FIELDS)
    if agent:
        yield "user agent", agent


def _sample_tree(item: Mapping[str, Any]) -> bool | None:
    """Whether the sandbox attributes a network row to the sample's tree; ``None``: not said."""
    fields = item.get("fields")
    stated = fields.get(SAMPLE_TREE_KEY) if isinstance(fields, Mapping) else None
    return stated if isinstance(stated, bool) else None


@dataclass
class ObservedValues:
    """Every distinct value the report observed, and what reading it could not use."""

    values: list[Observed]
    # The ``no:`` of each section read that the report does not carry.
    absent: dict[str, str]
    # Per section, the items that held no value under the fields read.
    no_value: dict[str, int]
    # The network values the sandbox attributes only to other processes: not linked.
    other_processes: int


def observed_values(
    report: Mapping[str, Any], normalised_by: Sequence[str] | None = None
) -> ObservedValues:
    """Every distinct value the report observed, with the items it came from.

    Distinct by the platform's normalised key for the value's kind; the first
    spelling is kept, and every item that observed it is listed. A network
    value whose every row the sandbox attributes to a process outside the
    sample's tree is left out and counted.
    """
    sections = Sections(report, normalised_by)
    found: dict[tuple[str, str], Observed] = {}
    absent: dict[str, str] = {}
    no_value: dict[str, int] = {}
    for name in SECTIONS_READ:
        section = sections.sections[name]
        if section.no:
            absent[name] = section.no
            continue
        for item in sections.items(name):
            read = False
            for kind, value in _values_of(name, item):
                read = True
                key = _key(FINGERPRINT_KIND[kind], value)
                held = found.get(key)
                if held is None:
                    held = found[key] = Observed(kind, value)
                held.observed_in(str(item.get("id") or ""))
                if name == "network":
                    held.tree.add(_sample_tree(item))
            if not read:
                no_value[name] = no_value.get(name, 0) + 1
    values = [one for one in found.values() if one.attribution != ""]
    return ObservedValues(values, absent, no_value, len(found) - len(values))


class _SectionOf:
    """The innermost section a file offset is in, from the PE header's raw ranges.

    The smallest raw range holding the offset, read over every section, so
    ranges that overlap (a malformed header) still name one; two of equal
    size holding it are both named. Linear in the sections per offset.
    """

    def __init__(self, sections: Iterable[Mapping[str, Any]]) -> None:
        self._spans: list[tuple[int, int, str]] = []
        for row in sections:
            start, size = row.get("raw_offset"), row.get("raw_size")
            if isinstance(start, int) and isinstance(size, int) and size > 0:
                self._spans.append((start, size, str(row.get("name") or "")))

    def __call__(self, offset: Any) -> str | None:
        at = _int(offset)
        if at is None:
            return None
        best: int | None = None
        names: list[str] = []
        for start, size, name in self._spans:
            if not start <= at < start + size:
                continue
            if best is None or size < best:
                best, names = size, [name]
            elif size == best:
                names.append(name)
        return " / ".join(names) if names else None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _hex(value: Any) -> str | None:
    at = _int(value)
    return hex(at) if at is not None and at >= 0 else None


def _index_functions(index: Mapping[str, Any] | None) -> dict[str, list[str]]:
    """Each text the function index places, to the functions (offsets from the image base)."""
    # Each text's functions as an insertion-ordered dict: a repeat is one lookup.
    out: dict[str, dict[str, None]] = {}
    for row in (index or {}).get("rows") or []:
        if not isinstance(row, Mapping):
            continue
        function = str(row.get("offset") or row.get("function") or "")
        if not function:
            continue
        for key in ("plain_strings", "decoded_strings"):
            for cell in row.get(key) or []:
                text = _text(cell.get("text")) if isinstance(cell, Mapping) else ""
                if text:
                    out.setdefault(text, {})[function] = None
    return {text: list(functions) for text, functions in out.items()}


def _holdings(inputs: StaticInputs) -> Iterator[tuple[str, dict[str, Any]]]:
    """``(text, holding)`` of every static text the inputs hold, each where it stands."""
    section_of = _SectionOf(inputs.sections)
    for entry_id, tool, data in inputs.strings:
        for row in data.get("strings") or []:
            if not isinstance(row, Mapping):
                continue
            text = _text(row.get("text"))
            if text:
                yield (
                    text,
                    {
                        "entry": entry_id,
                        "tool": tool,
                        "source": STRINGS,
                        "offset": _hex(row.get("offset")),
                        "section": section_of(row.get("offset")),
                        "encoding": _text(row.get("enc")) or None,
                    },
                )
    for entry_id, tool, rows in inputs.recovered:
        for row in rows:
            text = _text(row.get("string"))
            if not text:
                continue
            function = _text(row.get("function_rva"))
            virtual = _text(row.get("function"))
            yield (
                text,
                {
                    "entry": entry_id,
                    "tool": tool,
                    "source": RECOVERED,
                    "recovered_as": _text(row.get("kind")) or None,
                    "encoding": _text(row.get("encoding")) or None,
                    "functions": [function] if function else [],
                    **({"function_va": virtual} if virtual and not function else {}),
                },
            )
    if inputs.blobs is not None:
        entry_id, tool, data = inputs.blobs
        for row in data.get("results") or []:
            if not isinstance(row, Mapping):
                continue
            # Distinct, in reference order, through an insertion-ordered dict.
            functions = list(
                dict.fromkeys(
                    function
                    for place in row.get("references") or []
                    if (
                        function := _text(place.get("function"))
                        if isinstance(place, Mapping)
                        else ""
                    )
                )
            )
            place = {
                "entry": entry_id,
                "tool": tool,
                "offset": _text(row.get("offset")) or None,
                "section": _text(row.get("section")) or None,
                "encoding": _text(row.get("encoding")) or None,
                "scheme": _text(row.get("scheme")) or None,
                "functions": functions,
                "references": len(row.get("references") or []),
            }
            text = _text(row.get("text"))
            if text:
                yield text, {**place, "source": BLOB}
            for layer in row.get("layers") or []:
                inner = _text(layer.get("text")) if isinstance(layer, Mapping) else ""
                if inner:
                    scheme = _text(layer.get("scheme")) if isinstance(layer, Mapping) else ""
                    yield inner, {**place, "source": BLOB_LAYER, "layer": scheme or None}


def _url_host(text: str) -> str:
    """The host of a held URL in the shared host form; ``""`` for none."""
    try:
        netloc = urlsplit(canonical_value(text, fold_case=False)).netloc
    except ValueError:
        return ""
    return host_form(netloc.rpartition("@")[2])


def link_behaviour_to_code(
    report: Mapping[str, Any],
    normalised_by: Sequence[str] | None,
    inputs: StaticInputs,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Each value the sandbox observed, with every static place that holds it exactly.

    The answer lists every observed value (``links``), those held first, each
    with its holdings; ``compared`` names each static answer read and how much
    of it; ``functions`` names where the functions came from, or why none
    could be stated; ``absent`` names each input or sandbox section missing;
    ``no_value`` counts the items read with no value; ``not_linked`` counts the
    network values left out as another process's. ``deadline`` is the pack's
    (``clock`` time): past it, no further static text is compared and
    ``partial`` says how far the comparison got.
    """
    read = observed_values(report, normalised_by)
    observed = read.values
    by_key: dict[tuple[str, str], Observed] = {}
    for one in observed:
        by_key[_key(FINGERPRINT_KIND[one.kind], one.value)] = one
    kinds = sorted({FINGERPRINT_KIND[one.kind] for one in observed})
    index_data = inputs.index[2] if inputs.index is not None else None
    placed = _index_functions(index_data)

    hiveless = _hiveless_index(observed)
    hosts = any(kind in kinds for kind in _HOST_KINDS)

    def matches(text: str) -> Iterator[tuple[Observed, str]]:
        """Each observed value ``text`` holds, and how: exact first, then structured."""
        seen: set[int] = set()
        found: list[tuple[Observed | None, str]] = [
            (by_key.get(_key(kind, text)), EXACT) for kind in kinds
        ]
        if hosts and "://" in text:
            host = _url_host(text)
            if host:
                found.extend(
                    (by_key.get(indicator_fingerprint(kind, host)), URL_HOST)
                    for kind in _HOST_KINDS
                )
        if hiveless and _is_hiveless_path(text):
            found.extend(
                (paired, WITHOUT_HIVE)
                for paired in hiveless.get(indicator_fingerprint("registry", text), ())
            )
        for hit, how in found:
            if hit is not None and id(hit) not in seen:
                seen.add(id(hit))
                yield hit, how

    def out_of_time() -> bool:
        return deadline is not None and clock() > deadline

    held_texts: dict[int, set[str]] = {}
    done = 0
    cut = False
    for text, holding in _holdings(inputs):
        if out_of_time():
            cut = True
            break
        done += 1
        for hit, how in matches(text):
            own = list(holding.get("functions") or [])
            row = {key: value for key, value in holding.items() if key != "functions"}
            row["text"] = text
            row["matched"] = how
            row["functions"] = own or list(placed.get(text, []))
            if not own and row["functions"]:
                # The index places this text, not this copy of it.
                row["functions_by_text"] = True
            hit.held.append(row)
            held_texts.setdefault(id(hit), set()).add(text)
    if inputs.index is not None and not cut:
        entry_id, tool, _data = inputs.index
        for text, functions in placed.items():
            if out_of_time():
                cut = True
                break
            done += 1
            for hit, how in matches(text):
                if text in held_texts.get(id(hit), set()):
                    continue
                hit.held.append(
                    {
                        "entry": entry_id,
                        "tool": tool,
                        "source": INDEXED,
                        "text": text,
                        "matched": how,
                        "functions": list(functions),
                    }
                )
    compared = _compared(inputs)
    partly = cut or bool(inputs.unread) or any("of" in c or "not_compared" in c for c in compared)
    ordered = [one for one in observed if one.held] + [one for one in observed if not one.held]
    held = sum(1 for one in observed if one.held)
    answer: dict[str, Any] = {
        "tool": TOOL,
        "observed": len(observed),
        "held": held,
        "observed_only": len(observed) - held,
        "observed_only_label": PARTLY_READ if partly else OBSERVED_ONLY,
        "match": (
            "exact, after the platform's normalisation for each kind; also exact on the "
            f"host of a held URL ({URL_HOST!r}) and on a registry key's path after its hive "
            f"held with none ({WITHOUT_HIVE!r})"
        ),
        "compared": compared,
        "functions": (
            {"entry": inputs.index[0], "tool": inputs.index[1]}
            if inputs.index is not None
            else inputs.absent.get("function_index", NO_INDEX)
        ),
        "absent": {
            **inputs.absent,
            **{f"{SANDBOX_ABSENT_PREFIX}{k}": v for k, v in read.absent.items()},
        },
        "no_value": read.no_value,
        "not_linked": {"other processes": read.other_processes} if read.other_processes else {},
        "links": [one.as_row() for one in ordered],
    }
    if cut:
        answer["partial"] = CUT_BY_BUDGET.format(done=done)
    return answer


def _hiveless_index(observed: Iterable[Observed]) -> dict[tuple[str, str], list[Observed]]:
    """Each observed registry key that names a hive, by its normalised path after the hive.

    Every key that maps to a path is listed under it: two keys that differ
    only by hive are both held by the one text. The hive is read off by the
    platform's own reading (``reporting.detection_signatures.hiveless_key``:
    the short, long and kernel spellings of every hive), with no IOC-table
    suffix taken off (``Vendor App (x86)`` is a key name); a key naming no
    hive is not indexed.
    """
    from maljan.reporting.detection_signatures import hiveless_key

    out: dict[tuple[str, str], list[Observed]] = {}
    for one in observed:
        if one.kind != "registry key":
            continue
        rest = hiveless_key(one.value, value_suffix=False)
        if rest and rest != one.value.strip().strip("\\"):
            out.setdefault(indicator_fingerprint("registry", rest), []).append(one)
    return out


def _is_hiveless_path(text: str) -> bool:
    """Whether a held text is a registry-style path naming no hive: two parts or more."""
    from maljan.reporting.detection_signatures import hiveless_key

    stripped = text.strip().strip("\\")
    return "\\" in stripped and hiveless_key(text, value_suffix=False) == stripped


def _compared(inputs: StaticInputs) -> list[dict[str, Any]]:
    """Each static answer read: its entry, its tool, what it holds and how much was compared."""
    out: list[dict[str, Any]] = []
    for entry_id, tool, data in inputs.strings:
        rows = [row for row in data.get("strings") or [] if isinstance(row, Mapping)]
        total = _int(data.get("total_matched"))
        if total is None:
            total = _int(data.get("total"))
        whole = total is None or total <= len(rows)
        out.append(
            {
                "entry": entry_id,
                "tool": tool,
                "what": STRINGS,
                "texts": len(rows),
                **({} if whole else {"of": total}),
            }
        )
    for entry_id, tool, recovered in inputs.recovered:
        of = inputs.recovered_of.get(entry_id)
        out.append(
            {
                "entry": entry_id,
                "tool": tool,
                "what": RECOVERED,
                "texts": len(recovered),
                **({"of": of} if of is not None and of > len(recovered) else {}),
            }
        )
    if inputs.blobs is not None:
        entry_id, tool, data = inputs.blobs
        rows = [row for row in data.get("results") or [] if isinstance(row, Mapping)]
        unreferenced = _int(data.get("unreferenced")) or 0
        listed = isinstance(data.get("unreferenced_results"), list)
        out.append(
            {
                "entry": entry_id,
                "tool": tool,
                "what": BLOB,
                "texts": len(rows),
                **({"not_compared": unreferenced} if unreferenced and not listed else {}),
            }
        )
    if inputs.index is not None:
        entry_id, tool, data = inputs.index
        out.append(
            {
                "entry": entry_id,
                "tool": tool,
                "what": INDEXED,
                "texts": len(_index_functions(data)),
            }
        )
    return out


def compared_words(row: Mapping[str, Any]) -> str:
    """``[3] strings (150 of 2,400 texts, a page)``: one static answer read, and how much."""
    count = int(row.get("texts") or 0)
    of = row.get("of")
    said = (
        f"{count:,} of {int(of):,} texts, a page"
        if of is not None
        else f"{count:,} {'text' if count == 1 else 'texts'}"
    )
    skipped = int(row.get("not_compared") or 0)
    if skipped:
        said += f"; {skipped:,} decodings no code refers to were not compared"
    return f"[{row.get('entry')}] {row.get('what')} ({said})"


def unread_words(data: Mapping[str, Any]) -> list[str]:
    """What the reading could not use, as sentences: items with no value, values not linked."""
    out: list[str] = []
    no_value = data.get("no_value") or {}
    if no_value:
        listed = ", ".join(f"{name} {count:,}" for name, count in no_value.items())
        out.append(f"items with no value under the fields read: {listed}")
    other = (data.get("not_linked") or {}).get("other processes")
    if other:
        out.append(
            f"{other:,} network values the sandbox attributes only to processes outside the "
            "sample's tree were not linked"
        )
    if data.get("partial"):
        out.append(str(data["partial"]))
    return out


def place_words(holding: Mapping[str, Any]) -> str:
    """Where a holding stands, in words, without its text or its function.

    ``decoded blob file 0x3010 (.data, xor8, utf-16le)``. The section is the
    sample's own name for it and is returned raw: a caller quotes it.
    """
    source = str(holding.get("source") or "")
    words = [source]
    if holding.get("layer"):
        words.append(str(holding["layer"]))
    if holding.get("offset"):
        words.append(f"file {holding['offset']}")
    if holding.get("recovered_as"):
        words.append(f"({holding['recovered_as']})")
    return " ".join(words)


def place_details(holding: Mapping[str, Any]) -> list[str]:
    """The section, scheme and encoding of a holding, each where stated; the section raw."""
    out: list[str] = []
    for key in ("section", "scheme", "encoding"):
        value = holding.get(key)
        if value:
            out.append(str(value))
    return out


def function_words(holding: Mapping[str, Any], functions: Any) -> str:
    """The function a holding is in: its offsets from the image base, or why none is stated.

    A function the index gives by the text alone is said as the same text
    elsewhere in it. ``functions`` is the answer's ``functions`` field: where
    it is a ``no:`` sentence, no function index was made and it is said.
    """
    found = [str(f) for f in holding.get("functions") or []]
    if found and holding.get("functions_by_text"):
        return f"{SAME_TEXT} " + ", ".join(found)
    if found:
        return "function " + ", ".join(found)
    if holding.get("function_va"):
        return f"function va {holding['function_va']}"
    if isinstance(functions, str):
        return f"function {NO_FUNCTION} ({functions})"
    return f"function {NO_FUNCTION}"
