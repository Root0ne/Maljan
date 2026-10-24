"""Check that every finding a job produced appears, whole and consistent, on every surface.

    python -m scripts.audit.surfaces --run <stored-run directory> [--out report.json]
    python -m scripts.audit.surfaces --api http://host:8000 --job <job uuid> [--token-env NAME]

A job's findings are read from its own decisions: the report row's verdict and
confidence, and from its report document the severity, the family, the
published techniques, the IOC table with each value's publication, the report
sections with their items and citations, the key findings, the network
values the judge kept, the sandbox's processes and the generated rules. Each
finding is then looked for on every surface that should carry it, by the
declared mapping table in ``surface_map.json`` (finding kind x surface, each
row with the code it was read from): the job detail, the report
row, the full report JSON, the Markdown and the HTML, the STIX export and the
judge's bundle, ``/mitre``, ``/iocs`` with and without ``include=all``, the
evidence ledger, the event log, the run summary, the usage, the follow-ups,
the ATT&CK layer, the rule downloads and the job package, and the web
console's tabs by the field map in ``web_fields.json``.

A surface that filters on purpose is named in the table with the code that
filters and the rule it follows, and the rule is checked rather than the
surface skipped: the default ``/iocs`` is the ``include=all`` rows that carry
``published: true``; the STIX export carries the published IOCs only; the
Markdown cuts a cell at 160 characters and a list item at 200 with an
ellipsis. A cut that follows its rule is counted under ``filtered``; anything
else is a defect.

``--run`` reads the files the benchmark runner saves (``job.json``,
``report-byjob.json``, ``report.json``, ``report.md``, ``report.html``,
``stix-bundle.json``, ``stix-judge.json``, ``mitre.json``, ``iocs.json``
(``include=all``), ``evidence.json``, ``events.json``, ``run-summary.json``,
``usage.json``, and ``follow-ups.json``, ``iocs-default.json``,
``attack-layer.json`` where present). A surface whose file is absent is listed
under ``not_checked`` with the reason. ``--api`` reads the same surfaces from a
running API with the bearer token in the environment variable ``--token-env``
names (never printed), plus the job package.

The answer is a JSON report (stdout, or ``--out``) and a short text summary on
stderr. Exit status: 0 no defect, 1 at least one defect, 2 a usage or read
error. Each surface is read once, into an index by identifier or into the
text a reader sees, and each finding is looked up in it: the work grows with
the findings and the surfaces, never with pairs of findings. No per-sample
constant and no tool is named.
"""

from __future__ import annotations

import argparse
import html
import io
import json
import os
import re
import sys
import tarfile
import urllib.request
from collections import Counter, deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

WEB_FIELDS = Path(__file__).with_name("web_fields.json")
SURFACE_MAP = Path(__file__).with_name("surface_map.json")

# The surface inventory, the finding kind x surface mapping and the declared
# filters, each row with the code it was read from (``surface_map.json``).
_MAP = json.loads(SURFACE_MAP.read_text(encoding="utf-8"))
SURFACES: dict[str, dict[str, str]] = _MAP["surfaces"]
MAPPING: list[dict[str, str]] = _MAP["mapping"]
FILTERS: list[dict[str, str]] = _MAP["filters"]

ELLIPSIS = "\u2026"
_EV_RE = re.compile(r"\bev_\d{3,}\b")
_TAG_RE = re.compile(r"<[^>]+>")
_MD_ESCAPE_RE = re.compile(r"\\([!-/:-@\[-`{-~])")
_SPACE_RE = re.compile(r"\s+")
_PATTERN_RE = re.compile(r"([a-z0-9-]+):([A-Za-z0-9_.'\-]+)\s*=\s*'((?:[^'\\]|\\.)*)'")
_HASH_PREFIX_RE = re.compile(
    r"^(md5|sha1|sha256|sha512|sha-1|sha-256|sha-512|imphash|ssdeep|tlsh):", re.I
)
# The shortest prefix a cut value must keep to be told apart from a value that
# is simply absent.
_MIN_CUT = 12


@dataclass
class Report:
    """What the checker found, by class."""

    defects: list[dict[str, Any]] = field(default_factory=list)
    filtered: Counter = field(default_factory=Counter)
    not_checked: dict[str, str] = field(default_factory=dict)
    checked: Counter = field(default_factory=Counter)

    def defect(self, cls: str, kind: str, surface: str, finding: Any, detail: str) -> None:
        self.defects.append(
            {"class": cls, "kind": kind, "surface": surface, "finding": finding, "detail": detail}
        )


# ---------------------------------------------------------------------------
# Reading the surfaces
# ---------------------------------------------------------------------------


def _read_json(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    return json.loads(text) if text.strip() else None


def load_run(directory: Path) -> dict[str, Any]:
    """Every surface a stored-run directory holds, by surface name; absent ones are not keys."""
    out: dict[str, Any] = {}
    for name, where in SURFACES.items():
        if name in {"web", "package"}:
            continue
        path = directory / where["file"]
        if not path.is_file():
            continue
        out[name] = (
            path.read_text(encoding="utf-8")
            if path.suffix in {".md", ".html"}
            else _read_json(path)
        )
    package = directory / SURFACES["package"]["file"]
    if package.is_file():
        out["package"] = _read_package(package.read_bytes())
    return out


def _read_package(blob: bytes) -> dict[str, Any]:
    """The run files a job package carries, under the stored-run names."""
    found: dict[str, Any] = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            name = member.name.split("/", 1)[-1] if member.name.startswith("run/") else member.name
            handle = archive.extractfile(member)
            if handle is None:
                continue
            raw = handle.read().decode("utf-8", errors="replace")
            if name.endswith(".json"):
                try:
                    found[name] = json.loads(raw) if raw.strip() else None
                except ValueError:
                    continue
            elif name.endswith(".md"):
                found[name] = raw
    return found


def load_live(api: str, job_id: str, token: str | None) -> dict[str, Any]:
    """The same surfaces from a running API (read-only GETs)."""
    if not api.lower().startswith(("http://", "https://")):
        raise ValueError(f"--api must be an http or https URL, not {api!r}")
    base = api.rstrip("/") + "/api/v1"

    def get(path: str, raw: bool = False) -> Any:
        request = urllib.request.Request(base + path)  # noqa: S310 — scheme checked above
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — the operator's own http(s) API base, scheme checked above  # noqa: E501
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310  # nosec B310
            body = response.read()
        return body if raw else json.loads(body.decode("utf-8"))

    out: dict[str, Any] = {"job": get(f"/jobs/{job_id}")}
    row = get(f"/reports/job/{job_id}")
    out["report_row"] = row
    out["run_summary"] = row.get("run_summary")
    rid = row["id"]
    simple = {
        "report_full": f"/reports/{rid}/full",
        "stix": f"/reports/{rid}/stix",
        "stix_judge": f"/reports/{rid}/stix?source=judge",
        "mitre": f"/reports/{rid}/mitre",
        "iocs_all": f"/reports/{rid}/iocs?include=all",
        "iocs_default": f"/reports/{rid}/iocs",
        "attack_layer": f"/reports/{rid}/attack-layer",
        "usage": f"/jobs/{job_id}/usage",
        "follow_ups": f"/jobs/{job_id}/follow-ups",
    }
    for name, path in simple.items():
        out[name] = get(path)
    out["markdown"] = get(f"/reports/{rid}/markdown", raw=True).decode("utf-8")
    out["html"] = get(f"/reports/{rid}/html", raw=True).decode("utf-8")
    entries: list[Any] = []
    page = 1
    while True:
        chunk = get(f"/jobs/{job_id}/evidence?page={page}&page_size=200")
        items = chunk.get("entries") or chunk.get("items") or []
        entries.extend(items)
        if len(items) < 200:
            break
        page += 1
    out["evidence"] = {"total": len(entries), "items": entries}
    events: list[Any] = []
    since = None
    while True:
        query = "?limit=1000" + (f"&since={since}" if since is not None else "")
        chunk = get(f"/jobs/{job_id}/events{query}").get("events") or []
        events.extend(chunk)
        if len(chunk) < 1000:
            break
        since = max(int(e.get("seq") or 0) for e in chunk)
    out["events"] = events
    out["signatures"] = {
        kind: get(f"/reports/{rid}/signatures/{kind}", raw=True).decode("utf-8")
        for kind in ("yara", "sigma", "suricata", "snort")
    }
    out["package"] = _read_package(get(f"/jobs/{job_id}/package", raw=True))
    return out


# ---------------------------------------------------------------------------
# Small readers
# ---------------------------------------------------------------------------


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _bundle(value: Any) -> dict[str, Any]:
    """A STIX bundle out of the export's or the judge's envelope."""
    data = _dict(value)
    if "objects" in data:
        return data
    return _dict(data.get("bundle"))


def plain(text: str, *, markup: bool = False) -> str:
    """A rendering as a reader sees its words: tags gone, escapes read, indicators refanged.

    A code span keeps its backslashes where the rest of the text has them as
    escapes, so the text is given twice: once with the escapes read and once
    as written, a value counting as shown when either holds it.
    """
    if markup:
        text = html.unescape(_TAG_RE.sub(" ", text))
    return _refanged(_MD_ESCAPE_RE.sub(r"\1", text)) + "\n\x00\n" + _refanged(text)


def _refanged(text: str) -> str:
    text = (
        text.replace("[.]", ".")
        .replace("[:]", ":")
        .replace("[@]", "@")
        .replace("[://]", "://")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("HXXPS://", "HTTPS://")
        .replace("HXXP://", "HTTP://")
        .replace("fxp://", "ftp://")
    )
    return _SPACE_RE.sub(" ", text)


def _norm(value: Any) -> str:
    return _SPACE_RE.sub(" ", _text(value)).strip()


def _ioc_key(value: Any) -> str:
    return _HASH_PREFIX_RE.sub("", _norm(value)).casefold()


def find(text: str, value: str, *, cut_at: int | None = None) -> str:
    """``present``, ``cut`` (a declared prefix then an ellipsis), ``truncated`` or ``missing``.

    ``cut_at`` is the length a surface's rule cuts a value past; a value cut
    there is ``cut``, cut anywhere else ``truncated``.
    """
    needle = _norm(value)
    if not needle or needle in text:
        return "present"
    head = needle[: max(_MIN_CUT, 1)]
    if len(needle) <= _MIN_CUT:
        return "missing"
    start = text.find(head)
    best = 0
    split = False
    while start != -1:
        at = start + len(head)
        kept = len(head)
        while at < len(text) and kept < len(needle) and text[at] == needle[kept]:
            at += 1
            kept += 1
        if at < len(text) and text[at] == ELLIPSIS:
            best = max(best, kept)
        elif text[at : at + 1] == "[" and text[at + 2 : at + 3] == ELLIPSIS:
            # Cut inside a defang mark (``[.`` then the ellipsis): never the declared cut.
            split = True
        start = text.find(head, start + 1)
    if not best:
        return "truncated" if split else "missing"
    if cut_at is not None and _shortest_cut(_text(value), cut_at) <= best <= cut_at - 1:
        return "cut"
    return "truncated"


def _shortest_cut(value: str, cut_at: int) -> int:
    """How much of ``value``, read with its whitespace runs collapsed, a cut keeps at the least.

    The renderer counts what it writes, before a reader's whitespace collapses,
    and writing a value defanged turns each ``.``, ``:`` and ``@`` into three
    characters: a cut can fall that much earlier in the value, never later.
    """
    written = kept = 0
    space = False
    for char in value:
        written += 3 if char in ".:@" else 1
        if char.isspace():
            # A leading run is not read at all, and any other run reads as one space.
            kept += 0 if space or not kept else 1
            space = True
        else:
            kept += 1
            space = False
        if written >= cut_at - 1:
            return max(kept - 2, 0)
    return kept


def _walk(node: Any, path: list[str], recursive: str | None = None) -> Iterator[Any]:
    """Values at a dotted path, ``[]`` walking a list; ``recursive`` descends a child list."""
    if not path:
        yield node
        return
    head, rest = path[0], path[1:]
    many = head.endswith("[]")
    name = head[:-2] if many else head
    value = node.get(name) if isinstance(node, dict) and name else node
    if many:
        stack = deque(_list(value))
        while stack:
            item = stack.popleft()
            yield from _walk(item, rest, recursive)
            if recursive and isinstance(item, dict):
                stack.extend(_list(item.get(recursive)))
    elif value is not None:
        yield from _walk(value, rest, recursive)


# ---------------------------------------------------------------------------
# The canonical findings
# ---------------------------------------------------------------------------


@dataclass
class Findings:
    """The job's canonical findings, each kind keyed by what identifies it."""

    verdict: str | None
    confidence: float | None
    severity: str | None
    family: str | None
    techniques: dict[str, str]
    iocs: dict[str, dict[str, Any]]
    judge_indicators: dict[str, dict[str, Any]]
    sections: list[dict[str, Any]]
    key_findings: list[dict[str, Any]]
    network_facts: dict[str, dict[str, Any]]
    processes: list[dict[str, Any]]
    detection_rules: list[str]
    citations: dict[str, list[str]]


def _published(value: Any) -> bool | None:
    """A consolidated IOC's publication: ``yes: ...`` / ``no: ...``, a bool, or unknown."""
    if isinstance(value, bool):
        return value
    said = _text(value).strip().lower()
    if said.startswith("yes"):
        return True
    if said.startswith("no"):
        return False
    return None


def canonical(surfaces: dict[str, Any]) -> Findings:
    """The job's own decisions, from the report row and its report document."""
    row = _dict(surfaces.get("report_row"))
    mr = _dict(row.get("malware_report"))
    techniques = {
        _norm(t.get("technique_id")).upper(): _norm(t.get("technique_name"))
        for t in _list(mr.get("ttp_mappings"))
        if isinstance(t, dict) and t.get("technique_id")
    }
    iocs: dict[str, dict[str, Any]] = {}
    for ioc in _list(mr.get("consolidated_iocs")):
        if not isinstance(ioc, dict) or not _norm(ioc.get("value")):
            continue
        iocs.setdefault(
            _ioc_key(ioc.get("value")),
            {
                "value": _norm(ioc.get("value")),
                "type": _text(ioc.get("kind") or ioc.get("type")),
                "published": _published(ioc.get("published")),
            },
        )
    judge = {
        _ioc_key(j.get("value")): {"value": _norm(j.get("value")), "type": _text(j.get("kind"))}
        for j in _list(mr.get("judge_indicators"))
        if isinstance(j, dict) and _norm(j.get("value"))
    }
    network: dict[str, dict[str, Any]] = {}
    net = _dict(mr.get("network"))
    for kind, rows, key in (("domain", "domains", "fqdn"), ("ip", "ips", "address")):
        for item in _list(net.get(rows)):
            if isinstance(item, dict) and _list(item.get("kept_by")) and _norm(item.get(key)):
                network[_ioc_key(item.get(key))] = {"value": _norm(item.get(key)), "type": kind}
    processes = [
        {
            "pid": p.get("pid"),
            "name": _norm(p.get("name")),
            "command_line": _norm(p.get("command_line")),
        }
        for p in _walk(mr, ["dynamic", "process_tree[]"], "children")
        if isinstance(p, dict)
    ]
    sections = [s for s in _list(mr.get("sections")) if isinstance(s, dict)]
    findings = [
        k for k in _list(mr.get("key_findings")) if isinstance(k, dict) and _norm(k.get("text"))
    ]
    rules = [
        _norm(r.get("name"))
        for r in _list(mr.get("detection_signatures"))
        if isinstance(r, dict) and r.get("name")
    ]
    severity = _dict(mr.get("severity")).get("rating")
    family = _dict(mr.get("attribution")).get("family")
    confidence = row.get("overall_confidence")
    return Findings(
        verdict=_text(row.get("verdict")) or None,
        confidence=float(confidence) if isinstance(confidence, (int, float)) else None,
        severity=_text(severity) or None,
        family=_text(family) or None,
        techniques=techniques,
        iocs=iocs,
        judge_indicators=judge,
        sections=sections,
        key_findings=findings,
        network_facts=network,
        processes=processes,
        detection_rules=rules,
        citations=_citations(mr),
    )


def _citations(mr: dict[str, Any]) -> dict[str, list[str]]:
    """Every ev_ id the report document cites, with where (first three places)."""
    places: dict[str, list[str]] = {}

    def visit(node: Any, where: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in {"evidence_index", "run_summary"}:
                    continue
                visit(value, f"{where}.{key}" if where else key)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                visit(value, f"{where}[{index}]")
        elif isinstance(node, str):
            for found in _EV_RE.findall(node):
                seen = places.setdefault(found, [])
                if len(seen) < 3:
                    seen.append(where)

    visit(mr, "")
    return places


# ---------------------------------------------------------------------------
# Views of each surface
# ---------------------------------------------------------------------------


def _stix_values(bundle: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Each value an export carries (indicator patterns and observables), by IOC key."""
    found: dict[str, list[dict[str, Any]]] = {}
    for obj in _list(bundle.get("objects")):
        if not isinstance(obj, dict):
            continue
        kind = obj.get("type")
        values: list[str] = []
        if kind == "indicator":
            compared = [
                (m.group(1), m.group(2), m.group(3).replace("\\'", "'").replace("\\\\", "\\"))
                for m in _PATTERN_RE.finditer(_text(obj.get("pattern")))
            ]
            values = _paired_path(compared) or [value for _type, _prop, value in compared]
        elif kind in {"domain-name", "ipv4-addr", "ipv6-addr", "url", "email-addr", "mutex"}:
            values = [_text(obj.get("value") or obj.get("name"))]
        elif kind == "windows-registry-key":
            values = [_text(obj.get("key"))]
        for value in values:
            if value:
                found.setdefault(_ioc_key(value), []).append(obj)
    return found


def _paired_path(compared: list[tuple[str, str, str]]) -> list[str]:
    """The one path a pattern naming a file in its directory compares, else nothing.

    The export writes a path as the file's name and its parent directory's
    path, joined by ``AND``; that pair is the table's one path value.
    """
    if len(compared) != 2:
        return []
    by_prop = {(otype, prop): value for otype, prop, value in compared}
    name = by_prop.get(("file", "name"))
    folder = by_prop.get(("file", "parent_directory_ref.path"))
    if name is None or folder is None:
        return []
    if folder.endswith(("\\", "/")):
        return [folder + name]
    # A backslash for a directory written the Windows way (a backslash, a
    # drive, a ``%VARIABLE%``), else a forward slash.
    windows = "\\" in folder or "%" in folder or re.match(r"^[A-Za-z]:", folder) is not None
    return [folder + ("\\" if windows else "/") + name]


def _stix_techniques(bundle: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for obj in _list(bundle.get("objects")):
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        for ref in _list(obj.get("external_references")):
            if (
                isinstance(ref, dict)
                and ref.get("source_name") == "mitre-attack"
                and ref.get("external_id")
            ):
                out[_norm(ref["external_id"]).upper()] = _norm(obj.get("name"))
    return out


def _row_techniques(rows: Iterable[Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in rows:
        if isinstance(item, dict):
            tid = item.get("technique_id") or item.get("id") or item.get("techniqueID")
            if tid:
                out[_norm(tid).upper()] = _norm(item.get("technique_name") or item.get("name"))
    return out


def _texts(surfaces: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(surfaces.get("markdown"), str):
        out["markdown"] = plain(surfaces["markdown"])
    if isinstance(surfaces.get("html"), str):
        out["html"] = plain(surfaces["html"], markup=True)
    return out


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------


def _scalar_md(text: str, label: str) -> str | None:
    """The word after ``Label:`` (or ``Label``, as the STIX report writes it) in a header line."""
    match = re.search(rf"\b{label}:?\**\s*`?\[?([A-Za-z]+)", text)
    return match.group(1) if match else None


def check_scalars(
    found: Findings, surfaces: dict[str, Any], texts: dict[str, str], out: Report
) -> None:
    row = _dict(surfaces.get("report_row"))
    mr = _dict(row.get("malware_report"))
    full = surfaces.get("report_full")
    for kind, canon in (("verdict", found.verdict), ("severity", found.severity)):
        if canon is None:
            continue
        seen: dict[str, Any] = {}
        if kind == "verdict":
            seen["report_row.malware_report"] = mr.get("verdict")
        if isinstance(full, dict):
            seen["report_full"] = (
                full.get("verdict")
                if kind == "verdict"
                else _dict(full.get("severity")).get("rating")
            )
        for name, text in texts.items():
            seen[name] = _scalar_md(text, kind.capitalize())
        report_obj = next(
            (
                o
                for o in _list(_bundle(surfaces.get("stix")).get("objects"))
                if isinstance(o, dict) and o.get("type") == "report"
            ),
            None,
        )
        if report_obj is not None:
            seen["stix"] = _scalar_md(_text(report_obj.get("description")), kind.capitalize())
        if kind == "verdict":
            seen["run_summary"] = _dict(surfaces.get("run_summary") or row.get("run_summary")).get(
                "final_decision"
            )
            completed = _completed_event(surfaces.get("events"))
            if completed is not None:
                seen["events"] = completed.get("verdict")
        for name, value in seen.items():
            out.checked[kind] += 1
            if value is None or _text(value).casefold() != canon.casefold():
                out.defect("differs", kind, name, canon, f"the surface says {value!r}")
    if found.confidence is not None:
        seen = {"report_row.malware_report": mr.get("overall_confidence")}
        if isinstance(full, dict):
            seen["report_full"] = full.get("overall_confidence")
        completed = _completed_event(surfaces.get("events"))
        if completed is not None:
            seen["events"] = completed.get("confidence")
        for name, value in seen.items():
            out.checked["confidence"] += 1
            if not isinstance(value, (int, float)) or abs(float(value) - found.confidence) > 1e-9:
                out.defect(
                    "differs", "confidence", name, found.confidence, f"the surface says {value!r}"
                )
        written = f"{found.confidence:.2f}"
        for name, text in texts.items():
            out.checked["confidence"] += 1
            line = re.search(r"Verdict:[^\n]{0,200}", text)
            if not line or written not in line.group(0):
                out.defect(
                    "differs",
                    "confidence",
                    name,
                    written,
                    "the header does not state the confidence as stored",
                )
    if found.family:
        seen = {}
        if isinstance(full, dict):
            seen["report_full"] = _dict(full.get("attribution")).get("family")
        malware = [
            o
            for o in _list(_bundle(surfaces.get("stix")).get("objects"))
            if isinstance(o, dict) and o.get("type") == "malware"
        ]
        if "stix" in surfaces:
            seen["stix"] = malware[0].get("name") if malware else None
        for name, value in seen.items():
            out.checked["family"] += 1
            if _norm(value).casefold() != found.family.casefold():
                out.defect("differs", "family", name, found.family, f"the surface says {value!r}")
        for name, text in texts.items():
            out.checked["family"] += 1
            line = re.search(r"Family:[^\n]{0,300}", text)
            if not line or found.family not in line.group(0):
                out.defect(
                    "differs", "family", name, found.family, "the header does not name the family"
                )


def _completed_event(events: Any) -> dict[str, Any] | None:
    for event in reversed(_events(events)):
        if event.get("type") == "completed":
            return _dict(event.get("payload")) or event
    return None


def _events(events: Any) -> list[dict[str, Any]]:
    rows = events.get("events") if isinstance(events, dict) else events
    return [e for e in _list(rows) if isinstance(e, dict)]


def _compare_keyed(
    kind: str,
    surface: str,
    canon: dict[str, str],
    seen: dict[str, str],
    out: Report,
    *,
    reverse: bool = True,
) -> None:
    """Missing, renamed and (``reverse``) extra entries between two id -> name maps."""
    for key, name in canon.items():
        out.checked[kind] += 1
        if key not in seen:
            out.defect("missing", kind, surface, key, f"{name!r} is not on this surface")
        elif name and seen[key] and seen[key] != name:
            out.defect(
                "altered", kind, surface, key, f"named {seen[key]!r} here, {name!r} in the report"
            )
    if reverse:
        for key in seen.keys() - canon.keys():
            out.defect("orphan", kind, surface, key, f"{seen[key]!r} has no published report item")


def check_techniques(
    found: Findings, surfaces: dict[str, Any], texts: dict[str, str], out: Report
) -> None:
    row = _dict(surfaces.get("report_row"))
    mr = _dict(row.get("malware_report"))
    canon = found.techniques
    _compare_keyed(
        "technique",
        "report_row.mitre_techniques",
        canon,
        _row_techniques(_list(row.get("mitre_techniques"))),
        out,
    )
    if isinstance(surfaces.get("report_full"), dict):
        _compare_keyed(
            "technique",
            "report_full",
            canon,
            _row_techniques(_list(surfaces["report_full"].get("ttp_mappings"))),
            out,
        )
    if "mitre" in surfaces:
        _compare_keyed(
            "technique",
            "mitre",
            canon,
            _row_techniques(_list(_dict(surfaces["mitre"]).get("techniques"))),
            out,
        )
    cells = [c for c in _list(mr.get("capability_matrix")) if isinstance(c, dict)]
    if cells:
        published = _row_techniques(c for c in cells if not _norm(c.get("not_published")))
        _compare_keyed("technique", "capability_matrix", canon, published, out)
    if "stix" in surfaces:
        _compare_keyed("technique", "stix", canon, _stix_techniques(_bundle(surfaces["stix"])), out)
    if "stix_judge" in surfaces:
        declined = {
            _norm(c.get("technique_id")).upper() for c in cells if _norm(c.get("not_published"))
        }
        for tid, name in _stix_techniques(_bundle(surfaces["stix_judge"])).items():
            out.checked["technique"] += 1
            if tid not in canon and tid not in declined:
                out.defect(
                    "orphan",
                    "technique",
                    "stix_judge",
                    tid,
                    f"the judge's bundle names {name!r}, which is neither published nor "
                    "declined with a reason",
                )
    if "attack_layer" in surfaces:
        layer = {
            _norm(t.get("techniqueID")).upper(): ""
            for t in _list(_dict(surfaces["attack_layer"]).get("techniques"))
            if isinstance(t, dict) and t.get("techniqueID")
        }
        _compare_keyed("technique", "attack_layer", {k: "" for k in canon}, layer, out)
    for name, text in texts.items():
        for tid, tname in canon.items():
            out.checked["technique"] += 1
            if tid not in text:
                out.defect("missing", "technique", name, tid, f"{tname!r} is not in the rendering")
            elif tname and tname not in text:
                out.defect(
                    "altered", "technique", name, tid, f"its name {tname!r} is not in the rendering"
                )


def check_iocs(
    found: Findings, surfaces: dict[str, Any], texts: dict[str, str], out: Report
) -> None:
    canon = found.iocs
    full = surfaces.get("report_full")
    if isinstance(full, dict):
        keys = {
            _ioc_key(i.get("value"))
            for i in _list(full.get("consolidated_iocs"))
            if isinstance(i, dict)
        }
        for key, ioc in canon.items():
            out.checked["ioc"] += 1
            if key not in keys:
                out.defect(
                    "missing", "ioc", "report_full", ioc["value"], "not in consolidated_iocs"
                )
    rows_all = [
        r for r in _list(_dict(surfaces.get("iocs_all")).get("items")) if isinstance(r, dict)
    ]
    if "iocs_all" in surfaces:
        feed: dict[str, dict[str, Any]] = {}
        for item in rows_all:
            feed.setdefault(_ioc_key(item.get("value")), item)
        for key, ioc in canon.items():
            out.checked["ioc"] += 1
            listed = feed.get(key)
            if listed is None:
                out.defect(
                    "missing",
                    "ioc",
                    "iocs_all",
                    ioc["value"],
                    f"{ioc['type']} value is not in the feed",
                )
                continue
            said = _published(listed.get("published"))
            if ioc["published"] is not None and said is not None and said != ioc["published"]:
                out.defect(
                    "altered",
                    "ioc",
                    "iocs_all",
                    ioc["value"],
                    f"published={said} in the feed, {ioc['published']} in the report's IOC table",
                )
        for key in feed.keys() - canon.keys():
            out.defect(
                "orphan",
                "ioc",
                "iocs_all",
                feed[key].get("value"),
                "a feed row with no row in the report's IOC table",
            )
    if "iocs_default" in surfaces:
        _check_default_filter(rows_all, surfaces, out)
    elif rows_all:
        out.not_checked["iocs_default"] = (
            "not stored; its rule (the include=all rows whose published flag is true) is checked "
            "on the include=all rows: every row must carry the flag"
        )
        for item in rows_all:
            out.checked["ioc_filter"] += 1
            if not isinstance(item.get("published"), bool):
                out.defect(
                    "filter",
                    "ioc",
                    "iocs_default",
                    item.get("value"),
                    "a row without a published flag cannot be filtered",
                )
    if "stix" in surfaces:
        values = _stix_values(_bundle(surfaces["stix"]))
        for key, ioc in canon.items():
            out.checked["ioc"] += 1
            if ioc["published"] is True and key not in values:
                out.defect(
                    "missing",
                    "ioc",
                    "stix",
                    ioc["value"],
                    "published in the report's IOC table, absent from the export",
                )
            elif ioc["published"] is False and key in values:
                out.defect(
                    "filter",
                    "ioc",
                    "stix",
                    ioc["value"],
                    "the export carries a value the report withholds",
                )
            elif ioc["published"] is False:
                out.filtered["stix: withheld IOC"] += 1
        for key in values.keys() - canon.keys():
            obj = values[key][0]
            out.defect(
                "orphan",
                "ioc",
                "stix",
                obj.get("pattern") or obj.get("value"),
                "an export value with no row in the report's IOC table",
            )
    for key, judged in found.judge_indicators.items():
        out.checked["ioc"] += 1
        if key not in canon:
            out.defect(
                "missing",
                "ioc",
                "report_full.consolidated_iocs",
                judged["value"],
                "a judge indicator the IOC table does not list",
            )
    for name, text in texts.items():
        for ioc in canon.values():
            out.checked["ioc"] += 1
            _found_in_text(out, "ioc", name, text, ioc["value"], cut_at=240)
        for fact in found.network_facts.values():
            out.checked["network_fact"] += 1
            _found_in_text(out, "network_fact", name, text, fact["value"], cut_at=240)
    if "iocs_all" in surfaces:
        feed_keys = {_ioc_key(r.get("value")) for r in rows_all}
        for key, fact in found.network_facts.items():
            out.checked["network_fact"] += 1
            if key not in feed_keys:
                out.defect(
                    "missing",
                    "network_fact",
                    "iocs_all",
                    fact["value"],
                    "a value the judge kept is not in the feed",
                )


def _check_default_filter(
    rows_all: list[dict[str, Any]], surfaces: dict[str, Any], out: Report
) -> None:
    want = Counter(_ioc_key(r.get("value")) for r in rows_all if r.get("published") is True)
    got = Counter(
        _ioc_key(r.get("value"))
        for r in _list(_dict(surfaces["iocs_default"]).get("items"))
        if isinstance(r, dict)
    )
    out.checked["ioc_filter"] += 1
    for key in want - got:
        out.defect(
            "filter",
            "ioc",
            "iocs_default",
            key,
            "a published row of include=all is missing from the default feed",
        )
    for key in got - want:
        out.defect(
            "filter",
            "ioc",
            "iocs_default",
            key,
            "the default feed carries a row include=all does not publish",
        )
    out.filtered["iocs_default: unpublished rows"] += sum(
        1 for r in rows_all if r.get("published") is False
    )


def _found_in_text(
    out: Report, kind: str, surface: str, text: str, value: str, *, cut_at: int | None
) -> str:
    state = find(text, value, cut_at=cut_at)
    if state == "cut":
        out.filtered[f"{surface}: value cut at its declared length"] += 1
    elif state in {"truncated", "missing"}:
        out.defect(
            state,
            kind,
            surface,
            _norm(value)[:300],
            f"{len(value)} characters; {state} in the rendering",
        )
    return state


def check_sections(
    found: Findings, surfaces: dict[str, Any], texts: dict[str, str], out: Report
) -> None:
    full = surfaces.get("report_full")
    full_keys = Counter(
        (_text(s.get("key")), len(_list(s.get("rows"))), len(_list(s.get("items"))))
        for s in _list(_dict(full).get("sections"))
        if isinstance(s, dict)
    )
    # The ledger entries whose answer holds a value: a section citing one has
    # data behind it. A list of records a tool answered under a field is drawn
    # as a section of its own, keyed ``<section>_<field>``, so a section whose
    # data sits in such a child is not blank.
    answers = {
        _text(r.get("entry_id") or r.get("id"))
        for r in _ledger_rows(surfaces)
        if r.get("ok", True) and _holds_data(r.get("structured", r.get("output")))
    }
    filled = {
        _text(s.get("key"))
        for s in found.sections
        if _list(s.get("rows")) or _list(s.get("items")) or _text(s.get("text")).strip()
    }
    for section in found.sections:
        key = _text(section.get("key"))
        rows = [r for r in _list(section.get("rows")) if isinstance(r, list)]
        items = [_text(i) for i in _list(section.get("items"))]
        body = _text(section.get("text")).strip()
        kind = _text(section.get("kind") or "text")
        has = bool(rows or items or body)
        if isinstance(full, dict):
            out.checked["section"] += 1
            if full_keys[(key, len(rows), len(items))] <= 0:
                out.defect(
                    "altered",
                    "section",
                    "report_full",
                    key,
                    "no section with this key and these counts",
                )
            else:
                full_keys[(key, len(rows), len(items))] -= 1
        if not has:
            answered = [
                _text(ev) for ev in _list(section.get("evidence_ids")) if _text(ev) in answers
            ]
            if answered and not any(k.startswith(f"{key}_") for k in filled):
                out.defect(
                    "blank_section",
                    "section",
                    "web",
                    key,
                    "no rows, items or text, so no surface draws it, while its cited calls "
                    + ", ".join(answered[:5])
                    + " answered with output",
                )
            continue
        for name, text in texts.items():
            out.checked["section"] += 1
            title = _norm(section.get("title")) or key
            if title not in text:
                out.defect(
                    "missing", "section", name, key, f"its title {title!r} is not in the rendering"
                )
                continue
            # What the Markdown section body draws (markdown.py:5455): a table or
            # kv section's rows up to its columns, a list's items, and the text.
            if kind in {"table", "kv"} and rows:
                width = len(_list(section.get("columns"))) or len(rows[0])
                for cell in _distinct(_text(c) for r in rows for c in r[:width]):
                    out.checked["section_item"] += 1
                    _found_in_text(out, "section_item", f"{name}:{key}", text, cell, cut_at=160)
                wide = sum(1 for r in rows if len(r) > width)
                if wide:
                    out.defect(
                        "dropped",
                        "section",
                        name,
                        key,
                        f"{wide} rows carry more cells than the {width} columns; "
                        "the cells past them are not rendered",
                    )
            elif rows:
                out.defect(
                    "dropped",
                    "section",
                    name,
                    key,
                    f"a {kind} section's {len(rows)} rows are not rendered",
                )
            if kind == "list":
                for item in _distinct(items):
                    out.checked["section_item"] += 1
                    _found_in_text(out, "section_item", f"{name}:{key}", text, item, cut_at=200)
            elif items:
                out.defect(
                    "dropped",
                    "section",
                    name,
                    key,
                    f"a {kind} section's {len(items)} items are not rendered",
                )
            if body:
                out.checked["section_item"] += 1
                _found_in_text(out, "section_item", f"{name}:{key}", text, body, cut_at=None)


def _holds_data(value: Any) -> bool:
    """Whether an answer holds any value: a non-empty string, a number or true, at any depth."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str):
            if item.strip() and item.strip() not in {"{}", "[]"}:
                return True
        elif item is not None and item is not False:
            return True
    return False


def _distinct(values: Iterable[str]) -> list[str]:
    """Each value once by how it reads, as written; values too short to tell apart are left out."""
    seen: dict[str, str] = {}
    for value in values:
        key = _norm(value)
        if len(key) >= 4:
            seen.setdefault(key, value)
    return list(seen.values())


def check_key_findings(found: Findings, texts: dict[str, str], out: Report) -> None:
    for name, text in texts.items():
        for item in found.key_findings:
            out.checked["key_finding"] += 1
            _found_in_text(out, "key_finding", name, text, _norm(item.get("text")), cut_at=None)


def _ledger_rows(surfaces: dict[str, Any]) -> list[dict[str, Any]]:
    ledger = _dict(surfaces.get("evidence"))
    return [r for r in _list(ledger.get("items") or ledger.get("entries")) if isinstance(r, dict)]


def check_citations(found: Findings, surfaces: dict[str, Any], out: Report) -> None:
    mr = _dict(_dict(surfaces.get("report_row")).get("malware_report"))
    index = {_text(r.get("id")) for r in _list(mr.get("evidence_index")) if isinstance(r, dict)}
    ledger = None
    if "evidence" in surfaces:
        ledger = {_text(r.get("entry_id") or r.get("id")) for r in _ledger_rows(surfaces)}
    for ev, where in found.citations.items():
        out.checked["citation"] += 1
        if index and ev not in index:
            out.defect(
                "unresolved_citation",
                "citation",
                "report_full.evidence_index",
                ev,
                f"cited at {', '.join(where)}",
            )
        if ledger is not None and ev not in ledger:
            out.defect(
                "unresolved_citation", "citation", "evidence", ev, f"cited at {', '.join(where)}"
            )
    known = ledger if ledger is not None else index
    if "stix" in surfaces and known:
        for obj in _list(_bundle(surfaces["stix"]).get("objects")):
            for ev in _list(_dict(obj).get("x_maljan_evidence_refs")):
                out.checked["citation"] += 1
                if _text(ev) not in known:
                    out.defect(
                        "unresolved_citation", "citation", "stix", ev, f"on {_dict(obj).get('id')}"
                    )
    if "follow_ups" in surfaces and known:
        for item in _list(_dict(surfaces["follow_ups"]).get("follow_ups")):
            for ev in _list(_dict(_dict(item).get("answer")).get("evidence_ids")):
                out.checked["citation"] += 1
                if _text(ev) not in known:
                    out.defect(
                        "unresolved_citation",
                        "citation",
                        "follow_ups",
                        ev,
                        f"in the answer to {_dict(item).get('id')}",
                    )


def check_processes(
    found: Findings, surfaces: dict[str, Any], texts: dict[str, str], out: Report
) -> None:
    if "stix" in surfaces:
        stix = [
            o
            for o in _list(_bundle(surfaces["stix"]).get("objects"))
            if isinstance(o, dict) and o.get("type") == "process"
        ]
        seen = Counter((o.get("pid"), _norm(o.get("command_line"))) for o in stix)
        want = Counter((p["pid"], p["command_line"]) for p in found.processes)
        for pid, cmd in want - seen:
            out.defect(
                "missing", "process", "stix", f"pid {pid}", f"{cmd[:120]!r} has no process object"
            )
        for pid, cmd in seen - want:
            out.defect(
                "orphan",
                "process",
                "stix",
                f"pid {pid}",
                f"{cmd[:120]!r} is not in the report's process tree",
            )
        out.checked["process"] += len(want)
    for name, text in texts.items():
        for proc in found.processes:
            out.checked["process"] += 1
            if proc["name"] and proc["name"] not in text:
                out.defect(
                    "missing",
                    "process",
                    name,
                    f"pid {proc['pid']}",
                    f"{proc['name']!r} is not in the rendering",
                )


def check_rules(
    found: Findings, surfaces: dict[str, Any], texts: dict[str, str], out: Report
) -> None:
    for name, text in texts.items():
        for rule in found.detection_rules:
            out.checked["detection_rule"] += 1
            if rule not in text:
                out.defect(
                    "missing", "detection_rule", name, rule, "the rule is not in the rendering"
                )
    served = surfaces.get("signatures")
    if isinstance(served, dict):
        joined = "\n".join(_text(v) for v in served.values())
        for rule in found.detection_rules:
            out.checked["detection_rule"] += 1
            if f"// {rule}\n" not in joined:
                out.defect(
                    "missing", "detection_rule", "signatures", rule, "not in its kind's download"
                )
    else:
        out.not_checked["signatures"] = "not stored; the rule bodies are checked in the Markdown"


def check_counts(found: Findings, surfaces: dict[str, Any], out: Report) -> None:
    row = _dict(surfaces.get("report_row"))
    mr = _dict(row.get("malware_report"))
    summary = _dict(surfaces.get("run_summary") or row.get("run_summary"))
    events = _events(surfaces.get("events"))
    types = Counter(_text(e.get("type")) for e in events)
    pairs: list[tuple[str, str, Any, Any]] = []
    entries = _dict(summary.get("evidence")).get("entries")
    if entries is not None:
        pairs.append(
            (
                "evidence entries",
                "report_full.evidence_index",
                entries,
                len(_list(mr.get("evidence_index"))),
            )
        )
        if "evidence" in surfaces:
            ledger = _dict(surfaces["evidence"])
            pairs.append(
                (
                    "evidence entries",
                    "evidence",
                    entries,
                    ledger.get("total", len(_list(ledger.get("items")))),
                )
            )
        if events:
            pairs.append(
                (
                    "evidence entries",
                    "events.tool_call_finished",
                    entries,
                    types["tool_call_finished"],
                )
            )
    if summary.get("stix_object_count") is not None and "stix" in surfaces:
        pairs.append(
            (
                "STIX objects",
                "stix",
                summary["stix_object_count"],
                len(_list(_bundle(surfaces["stix"]).get("objects"))),
            )
        )
    if summary.get("judge_stix_object_count") is not None and "stix_judge" in surfaces:
        pairs.append(
            (
                "judge STIX objects",
                "stix_judge",
                summary["judge_stix_object_count"],
                len(_list(_bundle(surfaces["stix_judge"]).get("objects"))),
            )
        )
    calls = _dict(summary.get("tokens")).get("llm_calls")
    if calls is not None and events and types["model_usage"]:
        pairs.append(("model calls", "events.model_usage", calls, types["model_usage"]))
    if "run_summary" in surfaces and isinstance(row.get("run_summary"), dict):
        out.checked["count"] += 1
        if surfaces["run_summary"] != row["run_summary"]:
            out.defect(
                "differs",
                "count",
                "run_summary",
                "run summary",
                "the stored run summary is not the report row's",
            )
    inner = _dict(mr.get("run_summary"))
    for key in inner.keys() & summary.keys():
        out.checked["count"] += 1
        if inner[key] != summary[key]:
            out.defect(
                "differs",
                "count",
                "report_full.run_summary",
                key,
                "the report document's run summary differs from the row's",
            )
    for what, surface, want, got in pairs:
        out.checked["count"] += 1
        if want != got:
            out.defect("differs", "count", surface, what, f"{got} here, {want} in the run summary")
    usage = surfaces.get("usage")
    if isinstance(usage, dict) and calls is not None:
        said = _dict(usage.get("tokens")).get("llm_calls", usage.get("calls"))
        out.checked["count"] += 1
        if said != calls:
            if _is_stored(surfaces) and isinstance(said, int) and said < calls:
                out.not_checked["usage"] = (
                    f"the stored usage is a snapshot taken during the run "
                    f"({said} of {calls} calls); "
                    "it is compared only when read live"
                )
            else:
                out.defect(
                    "differs",
                    "count",
                    "usage",
                    "model calls",
                    f"{said} here, {calls} in the run summary",
                )


def _is_stored(surfaces: dict[str, Any]) -> bool:
    return bool(surfaces.get("_stored"))


def check_identity(surfaces: dict[str, Any], out: Report) -> None:
    row = _dict(surfaces.get("report_row"))
    mr = _dict(row.get("malware_report"))
    job = surfaces.get("job")
    if isinstance(job, dict):
        out.checked["identity"] += 3
        if row.get("job_id") and job.get("id") != row.get("job_id"):
            out.defect(
                "differs",
                "identity",
                "job",
                "job id",
                f"{job.get('id')} vs report row {row.get('job_id')}",
            )
        sha = _dict(_dict(mr.get("identity")).get("hashes")).get("sha256")
        if sha and job.get("sample_sha256") != sha:
            out.defect(
                "differs",
                "identity",
                "job",
                "sample sha256",
                f"{job.get('sample_sha256')} vs report {sha}",
            )
        if job.get("status") != "completed":
            out.defect(
                "differs", "identity", "job", "status", f"the job says {job.get('status')!r}"
            )
    completed = _completed_event(surfaces.get("events"))
    if completed is not None and row.get("id"):
        out.checked["identity"] += 1
        if completed.get("report_id") != row.get("id"):
            out.defect(
                "differs",
                "identity",
                "events",
                "report id",
                f"{completed.get('report_id')} vs {row.get('id')}",
            )
    package = surfaces.get("package")
    if isinstance(package, dict):
        _check_package(package, surfaces, out)


def _check_package(package: dict[str, Any], surfaces: dict[str, Any], out: Report) -> None:
    """The job package's stored run says what the served surfaces say.

    The served report row and full report carry read-time additions (the
    section tabs, each section's server), so the package's copies are compared
    by the findings read from them, not byte for byte; its Markdown is rendered
    from the same stored report as the served one, and is compared whole.
    """
    row = package.get("report-byjob.json")
    if isinstance(row, dict):
        mine, served = canonical({"report_row": row}), canonical(surfaces)
        for what in ("verdict", "confidence", "severity", "family"):
            out.checked["identity"] += 1
            if getattr(mine, what) != getattr(served, what):
                out.defect(
                    "differs",
                    what,
                    "package",
                    getattr(served, what),
                    f"the package's report row says {getattr(mine, what)!r}",
                )
        for what in ("techniques", "iocs"):
            out.checked["identity"] += 1
            lost = set(getattr(served, what)) ^ set(getattr(mine, what))
            if lost:
                out.defect(
                    "differs",
                    what,
                    "package",
                    sorted(lost)[:20],
                    "the package's report row and the served one list different entries",
                )
    bundle = package.get("stix-bundle.json")
    if bundle is not None and "stix" in surfaces:
        out.checked["identity"] += 1
        mine_ids = set(_stix_techniques(_bundle(bundle))) | set(_stix_values(_bundle(bundle)))
        served_ids = set(_stix_techniques(_bundle(surfaces["stix"]))) | set(
            _stix_values(_bundle(surfaces["stix"]))
        )
        if mine_ids != served_ids:
            out.defect(
                "differs",
                "identity",
                "package",
                sorted(mine_ids ^ served_ids)[:20],
                "the package's STIX bundle and the served one carry different techniques or values",
            )
    md = package.get("report/report.md")
    if isinstance(md, str) and isinstance(surfaces.get("markdown"), str):
        out.checked["identity"] += 1
        if md != surfaces["markdown"]:
            out.defect(
                "differs",
                "identity",
                "package",
                "report.md",
                "the package's Markdown differs from the served one",
            )


# ---------------------------------------------------------------------------
# The web console
# ---------------------------------------------------------------------------


def _route(key: str, placed: dict[str, Any], routing: dict[str, Any]) -> str:
    """The tab a section lands on, as reportSections.ts places it."""
    name = key.strip()
    rendered = set(routing["rendered_tabs"])
    head, dot, _ = name.partition(".")
    if dot and head in rendered:
        return head
    if name in routing["by_key"]:
        return str(routing["by_key"][name])
    tab = placed.get(name)
    if isinstance(tab, str) and tab in rendered:
        return tab
    for suffix, by_suffix in routing["by_suffix"]:
        if name.endswith(suffix):
            return str(by_suffix)
    for prefix, by_prefix in routing["by_prefix"]:
        if name.startswith(prefix):
            return str(by_prefix)
    return "other"


def _section_shows(section: dict[str, Any]) -> list[str]:
    """What ArtifactTable draws of a section, as strings."""
    kind = _text(section.get("kind") or "text")
    rows = [r for r in _list(section.get("rows")) if isinstance(r, list)]
    if kind == "kv":
        rows = [r for r in rows if any(_norm(c) not in {"", "-"} for c in r[1:])]
    if kind == "table" or (kind == "kv" and rows):
        return [_norm(c) for r in rows for c in r]
    if kind == "list":
        return [_norm(i) for i in _list(section.get("items"))]
    return [_norm(section.get("text"))]


def web_view(surfaces: dict[str, Any], spec: dict[str, Any], out: Report) -> str:
    """Everything the tabs draw, joined, after each tab's own cuts and stand-downs."""
    row = _dict(surfaces.get("report_row"))
    mr = _dict(row.get("malware_report"))
    roots = {
        "report": row,
        "job": surfaces.get("job"),
        "stix": _bundle(surfaces.get("stix")) or _dict(row.get("stix_bundle")),
        "evidence": {"entries": _list(_dict(surfaces.get("evidence")).get("items"))},
        "events": {"events": _events(surfaces.get("events"))},
        "follow_ups": surfaces.get("follow_ups"),
    }
    sections = [s for s in _list(mr.get("sections")) if isinstance(s, dict)]
    with_content = {
        _text(s.get("key"))
        for s in sections
        if _list(s.get("rows")) or _list(s.get("items")) or _text(s.get("text")).strip()
    }
    shown: list[str] = []
    for tab in spec["tabs"].values():
        for item in tab["fields"]:
            if set(item.get("hidden_if_section", [])) & with_content:
                continue
            root, _, path = item["path"].partition(":")
            gate = item.get("only_if_empty")
            if gate:
                groot, _, gpath = gate.partition(":")
                if any(_list(v) for v in _walk(roots.get(groot), gpath.split("."))):
                    continue
            values = list(_walk(roots.get(root), path.split("."), item.get("recursive")))
            if item.get("limit"):
                values = values[: int(item["limit"])]
            for value in values:
                if isinstance(value, float) and item.get("format") == "fixed2":
                    shown.append(f"{value:.2f}")
                elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
                    shown.append(_norm(value))
    routing = spec["section_routing"]
    placed = _dict(row.get("section_tabs"))
    detection = routing["detection_draws_only"]
    first: set[str] = set()
    for section in sections:
        key = _text(section.get("key"))
        if key not in with_content:
            continue
        tab = _route(key, placed, routing)
        if tab == "detection":
            ruled = (
                key in detection["keys"] and bool(_list(section.get("rows"))) and key not in first
            )
            first.add(key)
            if not ruled:
                out.defect(
                    "missing",
                    "section",
                    "web",
                    key,
                    "placed on DETECTION, which draws only the first "
                    f"{'/'.join(detection['keys'])} with rows "
                    f"({detection['ref']})",
                )
            else:
                shown.extend(_section_shows(section))
            continue
        lost = _section_lost(section)
        if lost:
            out.defect("dropped", "section", "web", key, f"{lost} ({spec['section_body']['ref']})")
        shown.extend(_section_shows(section))
    return "\n".join(s for s in shown if s)


def _section_lost(section: dict[str, Any]) -> str:
    """What of a section the console's section body does not draw, or nothing.

    A kv row whose values are all empty is a field with no value, which the
    console leaves out on purpose; it is not counted.
    """
    kind = _text(section.get("kind") or "text")
    rows = [r for r in _list(section.get("rows")) if isinstance(r, list)]
    items = _list(section.get("items"))
    body = _text(section.get("text")).strip()
    kept = (
        [r for r in rows if any(_norm(c) not in {"", "-"} for c in r[1:])] if kind == "kv" else rows
    )
    lost: list[str] = []
    draws_rows = kind == "table" or (kind == "kv" and bool(kept))
    if items and kind != "list":
        lost.append(f"{len(items)} items")
    if rows and kind not in {"table", "kv"}:
        lost.append(f"{len(rows)} rows")
    if body and (draws_rows or kind == "list"):
        lost.append(f"its text ({body[:80]!r})")
    if kind == "table" and not rows and (items or body):
        lost.append("drawn as 'The tool returned no rows.'")
    return "; ".join(lost)


def check_web(found: Findings, surfaces: dict[str, Any], spec: dict[str, Any], out: Report) -> None:
    rendered = {item["path"] for tab in spec["tabs"].values() for item in tab["fields"]}
    for kind, path in spec["kinds"].items():
        out.checked["web_kind"] += 1
        if path.endswith("sections[]"):
            continue
        if path not in rendered:
            out.defect(
                "unrendered",
                kind,
                "web",
                path,
                "no tab renders this field (scripts/audit/web_fields.json)",
            )
    view = web_view(surfaces, spec, out)
    if found.verdict and found.verdict not in view:
        out.defect("missing", "verdict", "web", found.verdict, "not drawn")
    if found.severity and found.severity not in view:
        out.defect("missing", "severity", "web", found.severity, "not drawn")
    if found.family and found.family not in view:
        out.defect("missing", "family", "web", found.family, "not drawn")
    if found.confidence is not None and f"{found.confidence:.2f}" not in view:
        out.defect("missing", "confidence", "web", found.confidence, "not drawn")
    checks: list[tuple[str, str]] = [("technique", t) for t in found.techniques]
    checks += [("ioc", i["value"]) for i in found.iocs.values()]
    checks += [("network_fact", n["value"]) for n in found.network_facts.values()]
    checks += [("key_finding", _norm(k.get("text"))) for k in found.key_findings]
    checks += [("detection_rule", r) for r in found.detection_rules]
    checks += [("process", p["name"]) for p in found.processes if p["name"]]
    for kind, value in checks:
        out.checked[f"web_{kind}"] += 1
        state = find(view, value)
        if state != "present":
            out.defect(state, kind, "web", value[:300], "no tab draws this value")


# ---------------------------------------------------------------------------
# Running it
# ---------------------------------------------------------------------------


def audit(surfaces: dict[str, Any], spec: dict[str, Any] | None = None) -> dict[str, Any]:
    """The JSON report for one job's surfaces."""
    out = Report()
    if not isinstance(surfaces.get("report_row"), dict):
        raise ValueError("no report row: the canonical findings cannot be read")
    for name in SURFACES:
        if name not in surfaces and name not in {"web", "iocs_default", "signatures"}:
            out.not_checked.setdefault(name, f"{SURFACES[name]['file']} is not stored")
    found = canonical(surfaces)
    texts = _texts(surfaces)
    check_scalars(found, surfaces, texts, out)
    check_techniques(found, surfaces, texts, out)
    check_iocs(found, surfaces, texts, out)
    check_sections(found, surfaces, texts, out)
    check_key_findings(found, texts, out)
    check_citations(found, surfaces, out)
    check_processes(found, surfaces, texts, out)
    check_rules(found, surfaces, texts, out)
    check_counts(found, surfaces, out)
    check_identity(surfaces, out)
    check_web(found, surfaces, spec or json.loads(WEB_FIELDS.read_text(encoding="utf-8")), out)
    by_class = Counter(d["class"] for d in out.defects)
    return {
        "status": "defects" if out.defects else "clean",
        "canonical": {
            "verdict": found.verdict,
            "confidence": found.confidence,
            "severity": found.severity,
            "family": found.family,
            "techniques": len(found.techniques),
            "iocs": len(found.iocs),
            "sections": len(found.sections),
            "key_findings": len(found.key_findings),
            "citations": len(found.citations),
            "network_facts": len(found.network_facts),
            "processes": len(found.processes),
            "detection_rules": len(found.detection_rules),
        },
        "defect_count": len(out.defects),
        "by_class": dict(sorted(by_class.items())),
        "defects": out.defects,
        "filtered": dict(sorted(out.filtered.items())),
        "not_checked": dict(sorted(out.not_checked.items())),
        "checked": dict(sorted(out.checked.items())),
    }


def summary(result: dict[str, Any]) -> str:
    lines = [f"{result['status']}: {result['defect_count']} defect(s)"]
    for cls, count in result["by_class"].items():
        lines.append(f"  {cls}: {count}")
    grouped = Counter((d["class"], d["kind"], d["surface"]) for d in result["defects"])
    for (cls, kind, surface), count in sorted(grouped.items()):
        lines.append(f"    {cls} {kind} on {surface}: {count}")
    for name, why in result["not_checked"].items():
        lines.append(f"  not checked {name}: {why}")
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.audit.surfaces",
        description=(
            "Check that every finding of a job appears, whole and consistent, on every surface."
        ),
    )
    where = parser.add_mutually_exclusive_group(required=True)
    where.add_argument("--run", type=Path, help="a stored-run directory")
    where.add_argument("--api", help="a running API's base URL, with --job")
    parser.add_argument("--job", help="with --api: the job id")
    parser.add_argument(
        "--token-env",
        default="MALJAN_TOKEN",
        help="with --api: the environment variable holding the bearer token (default MALJAN_TOKEN)",
    )
    parser.add_argument(
        "--web-fields", type=Path, default=WEB_FIELDS, help="the web console's field map"
    )
    parser.add_argument("--out", type=Path, help="write the JSON report here instead of stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        spec = json.loads(args.web_fields.read_text(encoding="utf-8"))
        if args.run is not None:
            if not args.run.is_dir():
                print(f"not a directory: {args.run}", file=sys.stderr)
                return 2
            surfaces = load_run(args.run)
            surfaces["_stored"] = True
        else:
            if not args.job:
                print("--api needs --job", file=sys.stderr)
                return 2
            surfaces = load_live(args.api, args.job, os.environ.get(args.token_env))
        result = audit(surfaces, spec)
    except (OSError, ValueError, KeyError, tarfile.TarError) as exc:
        print(f"could not read the surfaces: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    body = json.dumps(result, indent=1, sort_keys=True, default=str)
    if args.out:
        args.out.write_text(body + "\n", encoding="utf-8")
    else:
        print(body)
    print(summary(result), file=sys.stderr)
    return 1 if result["defects"] else 0


if __name__ == "__main__":
    sys.exit(main())
