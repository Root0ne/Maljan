"""Render a ``SandboxReport`` into the dict today's nine consumers read.

The short circuit is the design, not an optimisation. A CAPE or mock report
already *is* the dict every extractor, parser and analysis layer was written
against, so returning ``report.raw`` — the same object, ``rendered is raw`` —
makes byte-identity structural: no normalisation function has to be complete
for the default profile to behave exactly as it did. Providers that never saw a
CAPE report (triage, a report uploaded in another shape) take the real render
below, and the golden test proves that render carries every key the consumers
touch.
"""

from __future__ import annotations

from typing import Any

from maljan.schemas.sandbox_report import SandboxReport

_CAPE_SHAPED = {"cape2", "mock"}


def to_cape_shaped_dict(report: SandboxReport) -> dict[str, Any]:
    if report.source_format in _CAPE_SHAPED and report.raw:
        return report.raw

    behavior: dict[str, Any] = {
        "processes": [
            {
                "pid": p.pid,
                "ppid": p.ppid,
                "process_name": p.name,
                "command_line": p.command_line,
                "first_seen": p.first_seen,
                "calls": list(p.calls),
            }
            for p in report.processes
        ],
        "apistats": {pid: dict(stats) for pid, stats in report.apistats.items()},
        "generic": list(report.generic_events),
        "calls": [c for p in report.processes for c in p.calls],
        # "keys" is the registry-path passthrough; the other four are ruled in
        # during the pre-flight scan (beyond the brief's own field list) —
        # persistence_extractor's Linux path rules read all four directly and
        # a missing key reads exactly like a clean sample, so each is always
        # present even when empty.
        "summary": {
            "keys": list(report.registry),
            "files": list(report.summary.get("files", [])),
            "write_files": list(report.summary.get("write_files", [])),
            "modified_files": list(report.summary.get("modified_files", [])),
            "wrote_files": list(report.summary.get("wrote_files", [])),
        },
    }
    rendered: dict[str, Any] = {
        "target": {
            "sha256": report.target.sha256,
            "md5": report.target.md5,
            "name": report.target.name,
            "file": {"type": report.target.mime_type, "size": report.target.size},
        },
        "behavior": behavior,
        "signatures": [
            {
                "name": s.name,
                "description": s.description,
                "severity": s.severity,
                "marks": list(s.marks),
                "ttp_tags": list(s.ttp_tags),
            }
            for s in report.signatures
        ],
        "network": {
            "dns": list(report.network.dns),
            "http": list(report.network.http),
            "tcp": list(report.network.tcp),
            "udp": list(report.network.udp),
            "hosts": list(report.network.hosts),
            "domains": list(report.network.domains),
            "tls": list(report.network.tls),
        },
        "dropped": list(report.dropped_files),
        "screenshots": list(report.screenshots),
        "cti": dict(report.cti),
        "ttp_tags": sorted({t for s in report.signatures for t in s.ttp_tags}),
        # Named here because an empty section from a sandbox that cannot produce
        # it reads exactly like a clean sample; the report renderers say so.
        "unavailable": list(report.unavailable),
        # Top-level file-write arrays some sandboxes emit alongside (or instead
        # of) behavior.summary — ruled in during the pre-flight scan, read by
        # persistence_extractor's Linux path rules.
        "file_writes": list(report.file_writes),
    }
    if report.network.pcap_local_path:
        rendered["network"]["pcap_local_path"] = report.network.pcap_local_path
    return rendered
