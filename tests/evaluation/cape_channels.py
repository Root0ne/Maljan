"""Real evidence channels from an archived CAPE report, for the arms that had none.

The consensus ablation, the frontier probe and the confidence calibration were
all measured on five fixtures whose evidence is **generated from their own answer
key**: ``eval_consensus_ablation.build_channels`` walks a fixture's ground-truth
technique list and emits one hand-written sentence per technique from a static
dictionary. Evidence and truth are in bijection, a regular expression over that
dictionary scores F1 = 1.000 by construction, and the corpus has five clusters —
so the exact cluster permutation test on it floors at p = 0.0625 and no result
measured there can reach α = 0.05.

This module builds the same three channels from what the sandbox actually
observed, over the 97-sample cohort that already has archived reports and
family-level MITRE ground truth. 92 of the 97 populate all three channels. The
cluster count goes from 5 to 24, and — this is the part that matters for the
figure the paper had to withdraw — the arms and the no-LLM CAPE baseline land on
**the same population**, so they may finally share an axis.

Three properties the builder enforces rather than hopes for.

**No technique identifier reaches a channel.** CAPE reports carry a ``ttps``
block, and signature descriptions occasionally name an identifier inline. Either
would turn the measurement back into the copying exercise the fixtures were. The
scrubber runs last and :func:`build_channels` asserts on its own output.

**Truncation is deterministic and counted.** Reports run to 2 MB and a channel
has a character budget, so entries are sorted before they are cut. A run that
silently kept a different subset on a re-run would be unreproducible; a run that
cut without saying so would misreport how much evidence the model saw.

**The sandbox's self-description is removed.** Of the cohort's distinct domains
most appear in every sample — the guest image phoning its own vendor. Passing
those as network evidence is how a network analyst comes to claim command and
control on every sample in a corpus. The caller supplies the ubiquitous set,
computed across the whole cohort by ``eval_dynamic_vs_static.ubiquitous_domains``.

What this does *not* fix: the ground truth is still a family-level ``uses`` set,
so one binary need not exhibit everything its family is catalogued for. That
ceiling is constant across arms, which is exactly why the baseline matters.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

# Matches an ATT&CK technique identifier anywhere in prose. Deliberately loose:
# a false positive costs one scrubbed token, a false negative costs the study.
_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

CHANNELS = ("static", "dynamic", "network")

# Per-channel character budget. Chosen so the three together sit inside the
# production static-evidence ceiling rather than a number picked for this file.
DEFAULT_BUDGET = 6000

# How many entries of any one kind reach a channel. Registry writes run to 12,667
# on one sample; the analyst reads a sample of them either way, and an unstated
# sample is the defect this bounds.
_PER_KIND = 18


@dataclass
class ChannelBuild:
    """The three channels, plus what had to be dropped to fit them."""

    channels: dict[str, str]
    truncated: dict[str, int] = field(default_factory=dict)
    dropped_entries: dict[str, int] = field(default_factory=dict)
    scrubbed_ids: int = 0

    @property
    def populated(self) -> tuple[str, ...]:
        return tuple(c for c in CHANNELS if self.channels.get(c, "").strip())

    def as_json(self) -> dict[str, Any]:
        return {
            "populated": list(self.populated),
            "chars": {c: len(self.channels.get(c, "")) for c in CHANNELS},
            "truncated_chars": self.truncated,
            "dropped_entries": self.dropped_entries,
            "scrubbed_technique_ids": self.scrubbed_ids,
        }


def scrub_technique_ids(text: str) -> tuple[str, int]:
    """Replace every ATT&CK identifier with a marker, and say how many.

    The count is returned rather than logged because it is a measurement: a
    report whose signature prose names twenty identifiers is a report where the
    sandbox has already done the mapping, and the number belongs beside the
    result.
    """
    scrubbed, n = _TID_RE.subn("[technique id withheld]", text)
    return scrubbed, n


def _clean(value: Any) -> str:
    return " ".join(str(value).split())


def _bullets(label: str, items: Iterable[Any], limit: int = _PER_KIND) -> tuple[list[str], int]:
    """A labelled block of at most ``limit`` entries, sorted so the cut is stable."""
    seen: list[str] = []
    for item in items:
        text = _clean(item)
        if text and text not in seen:
            seen.append(text)
    seen.sort()
    kept = seen[:limit]
    if not kept:
        return [], 0
    head = f"{label} ({len(seen)} distinct"
    head += f", {limit} shown)" if len(seen) > limit else ")"
    return [head + ":", *(f"  - {k}" for k in kept)], max(0, len(seen) - limit)


def _pe_imports(pe: dict[str, Any]) -> list[str]:
    """Imported API names, flattened across DLLs.

    CAPE emits ``imports`` as a list of ``{dll, imports: [{name, address}]}`` on
    some versions and as a dict keyed by DLL on others. Both shapes appear in
    this cohort's archive, so both are read.
    """
    out: list[str] = []
    raw = pe.get("imports")
    entries: list[Any] = []
    if isinstance(raw, list):
        entries = raw
    elif isinstance(raw, dict):
        entries = list(raw.values())
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        dll = _clean(entry.get("dll") or entry.get("name") or "?")
        names = entry.get("imports") or []
        if isinstance(names, list):
            for fn in names:
                label = fn.get("name") if isinstance(fn, dict) else fn
                if label:
                    out.append(f"{dll}!{_clean(label)}")
    return out


def static_channel(report: dict[str, Any]) -> list[str]:
    """What is visible without running the sample."""
    target = (report.get("target") or {}).get("file") or {}
    pe = target.get("pe") or {}
    lines: list[str] = []

    kind = _clean(target.get("type") or "")
    size = target.get("size")
    if kind or size:
        lines.append(f"File: {kind or 'unknown type'}, {size or 'unknown'} bytes.")

    machine = _clean(pe.get("machine_type") or "")
    entry = _clean(pe.get("entrypoint") or "")
    imphash = _clean(pe.get("imphash") or "")
    meta = [
        x
        for x in (
            machine and f"machine {machine}",
            entry and f"entrypoint {entry}",
            imphash and f"imphash {imphash}",
        )
        if x
    ]
    if meta:
        lines.append("PE header: " + ", ".join(meta) + ".")

    sections = pe.get("sections") or []
    if isinstance(sections, list) and sections:
        described = []
        for s in sections:
            if not isinstance(s, dict):
                continue
            name = _clean(s.get("name") or "?")
            entropy = s.get("entropy")
            raw = s.get("size_of_data") or s.get("virtual_size")
            bit = name
            if entropy is not None:
                bit += f" entropy {entropy}"
            if raw is not None:
                bit += f" size {raw}"
            described.append(bit)
        block, dropped = _bullets("Sections", described)
        lines += block

    for label, key in (
        ("PEiD signatures", "peid_signatures"),
        ("Digital signers", "digital_signers"),
    ):
        block, _ = _bullets(label, pe.get(key) or [], limit=6)
        lines += block

    block, _ = _bullets("Imported APIs", _pe_imports(pe), limit=_PER_KIND * 2)
    lines += block

    yara = [r.get("name") if isinstance(r, dict) else r for r in (target.get("yara") or [])]
    block, _ = _bullets("YARA rule matches", yara, limit=8)
    lines += block

    return lines


def dynamic_channel(report: dict[str, Any]) -> list[str]:
    """What the sandbox observed while the sample ran."""
    behavior = report.get("behavior") or {}
    summary = behavior.get("summary") or {}
    lines: list[str] = []

    procs = [
        p.get("process_name") for p in (behavior.get("processes") or []) if isinstance(p, dict)
    ]
    block, _ = _bullets("Processes", [p for p in procs if p], limit=12)
    lines += block

    for label, key in (
        ("Executed commands", "executed_commands"),
        ("Registry keys written", "write_keys"),
        ("Registry keys read", "read_keys"),
        ("Files written", "write_files"),
        ("Files deleted", "delete_files"),
        ("Mutexes", "mutexes"),
        ("Services created", "created_services"),
        ("Services started", "started_services"),
        ("APIs resolved at runtime", "resolved_apis"),
    ):
        block, _ = _bullets(label, summary.get(key) or [])
        lines += block

    # The sandbox's own behavioural detections. These are the same signatures the
    # no-LLM baseline maps to technique ids, which is the point: both arms see one
    # body of evidence and the question is whether the model adds anything to the
    # mapping. Their identifiers are scrubbed downstream.
    sigs = []
    for s in report.get("signatures") or []:
        if not isinstance(s, dict):
            continue
        name = _clean(s.get("name") or "")
        desc = _clean(s.get("description") or "")
        severity = s.get("severity")
        if name or desc:
            sigs.append(f"{name}: {desc} (severity {severity})")
    block, _ = _bullets("Sandbox behavioural detections", sigs, limit=_PER_KIND * 2)
    lines += block

    return lines


def network_channel(report: dict[str, Any], ubiquitous: frozenset[str] = frozenset()) -> list[str]:
    """What the sample sent, minus what every sample in the cohort sent."""
    net = report.get("network") or {}
    lines: list[str] = []

    domains = []
    filtered = 0
    for entry in net.get("domains") or []:
        name = entry.get("domain") if isinstance(entry, dict) else entry
        if not name:
            continue
        if str(name) in ubiquitous:
            filtered += 1
            continue
        domains.append(name)
    block, _ = _bullets("Domains resolved", domains)
    lines += block
    if filtered:
        lines.append(
            f"({filtered} further domains appear in every sample of this cohort and are "
            "the guest image describing itself; they are withheld.)"
        )

    hosts = []
    for h in net.get("hosts") or []:
        if not isinstance(h, dict):
            continue
        ip = _clean(h.get("ip") or "")
        country = _clean(h.get("country_name") or "")
        asn = _clean(h.get("asn_name") or "")
        ports = h.get("ports") or []
        if ip:
            hosts.append(f"{ip} ({country or 'unknown'}, {asn or 'unknown ASN'}) ports {ports}")
    block, _ = _bullets("Hosts contacted", hosts)
    lines += block

    http = []
    for r in net.get("http") or []:
        if not isinstance(r, dict):
            continue
        http.append(f"{_clean(r.get('method'))} {_clean(r.get('host'))}{_clean(r.get('path'))}")
    block, _ = _bullets("HTTP requests", http, limit=12)
    lines += block

    for label, key in (("UDP flows", "udp"), ("TCP flows", "tcp")):
        flows = []
        for f in net.get(key) or []:
            if isinstance(f, dict):
                flows.append(f"{_clean(f.get('dst'))}:{f.get('dport')}")
        block, _ = _bullets(label, flows, limit=10)
        lines += block

    return lines


def build_channels(
    report: dict[str, Any],
    *,
    ubiquitous: frozenset[str] = frozenset(),
    budget: int = DEFAULT_BUDGET,
) -> ChannelBuild:
    """The three channels, scrubbed, bounded, and with the losses counted."""
    raw = {
        "static": static_channel(report),
        "dynamic": dynamic_channel(report),
        "network": network_channel(report, ubiquitous),
    }
    channels: dict[str, str] = {}
    truncated: dict[str, int] = {}
    scrubbed_total = 0
    for name, lines in raw.items():
        text = "\n".join(lines).strip()
        text, scrubbed = scrub_technique_ids(text)
        scrubbed_total += scrubbed
        if len(text) > budget:
            # Cut on a line boundary so the analyst never reads half an entry.
            kept: list[str] = []
            used = 0
            for line in text.splitlines():
                if used + len(line) + 1 > budget:
                    break
                kept.append(line)
                used += len(line) + 1
            truncated[name] = len(text) - used
            text = "\n".join(kept)
        channels[name] = text

    build = ChannelBuild(channels=channels, truncated=truncated, scrubbed_ids=scrubbed_total)
    leaked = {c: _TID_RE.findall(t) for c, t in channels.items() if _TID_RE.search(t)}
    if leaked:
        raise AssertionError(f"technique identifiers reached the evidence: {leaked}")
    return build


def leaked_truth(channels: dict[str, str], truth: Sequence[str]) -> set[str]:
    """Ground-truth identifiers visible in the evidence. Must always be empty.

    The fixture corpus this replaces had every one of its answers in its own
    evidence. Checking rather than trusting is the whole difference between the
    two corpora, so the check ships with the builder.
    """
    blob = "\n".join(channels.values()).upper()
    return {t for t in (str(x).upper() for x in truth) if t and t in blob}
