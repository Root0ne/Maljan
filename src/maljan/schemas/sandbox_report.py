"""The neutral sandbox report every sandbox adapter produces.

Today ``SubmissionResult.report`` *is* the raw CAPEv2 JSON, and nine
consumers (extractors, parsers, the attribution and persistence layers) read
CAPE-shaped keys directly out of it. ``SandboxReport`` is the vocabulary a
sandbox-agnostic pipeline reads instead; :func:`cape_report_to_sandbox_report`
is the one-way reader that fills it from a CAPE/Cuckoo-shaped dict, and
``maljan.providers.cape_view.to_cape_shaped_dict`` is the renderer that turns
it back into the dict today's consumers already know how to read.

Every model here is deliberately permissive: ``model_config =
ConfigDict(extra="ignore")`` so an unexpected sandbox field never breaks
ingestion, and every collection defaults to empty rather than ``None`` so a
consumer can iterate a fresh ``SandboxReport()`` without a null check.
"""

from __future__ import annotations

from typing import Any, Literal, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidatorFunctionWrapHandler, field_validator


def _int(value: Any) -> int:
    """Best-effort int coercion; malformed sandbox data becomes ``0``, never a crash."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _rows(value: Any) -> list[dict[str, Any]]:
    """Keep only the dict entries of a possibly-mixed sandbox-report array."""
    return [row for row in (value or []) if isinstance(row, dict)]


def _as_str_list(value: Any) -> list[str]:
    """Coerce a sandbox field that is sometimes a list, sometimes a scalar, to ``list[str]``."""
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)] if value else []


def _dict_identity_or_validate(value: Any, handler: ValidatorFunctionWrapHandler) -> dict[str, Any]:
    """Return ``value`` unchanged when it is already a dict; otherwise validate normally.

    This is the narrow fix a bare ``SkipValidation[dict[str, Any]]`` does not
    give: identity (``rendered is raw``) is what ``to_cape_shaped_dict``'s
    short circuit depends on, but ``SkipValidation`` accepts *anything* —
    a string, a list, ``None`` — and would hand it to every consumer as if it
    were the CAPE dict. A dict still passes through untouched (same object,
    no pydantic-core rebuild); anything else still goes through the ordinary
    ``dict[str, Any]`` validator and still raises ``ValidationError``.
    """
    if isinstance(value, dict):
        return value
    return cast("dict[str, Any]", handler(value))


class SandboxTarget(BaseModel):
    """The sample identity a sandbox detonated."""

    model_config = ConfigDict(extra="ignore")

    sha256: str = ""
    md5: str = ""
    name: str = ""
    file_type: str = ""
    mime_type: str = ""
    size: int = 0


class SandboxProcess(BaseModel):
    """One process in the sandbox's flat process list (parent/child ids only)."""

    model_config = ConfigDict(extra="ignore")

    pid: int = 0
    ppid: int = 0
    name: str = ""
    command_line: str = ""
    first_seen: str = ""
    calls: list[dict[str, Any]] = Field(default_factory=list)


class SandboxSignatureRow(BaseModel):
    """One sandbox signature hit, marks carried through unprocessed."""

    model_config = ConfigDict(extra="ignore")

    name: str = ""
    description: str = ""
    severity: int = 0
    marks: list[Any] = Field(default_factory=list)
    ttp_tags: list[str] = Field(default_factory=list)


class SandboxNetwork(BaseModel):
    """Network IOC rows, carried through close to their sandbox shape.

    ``domains`` is ``list[str | dict[str, Any]]`` rather than a strict
    ``list[dict]`` because a CAPE report emits both shapes for that one array
    (a bare hostname string, or a ``{"domain": ...}`` row).
    """

    model_config = ConfigDict(extra="ignore")

    dns: list[dict[str, Any]] = Field(default_factory=list)
    http: list[dict[str, Any]] = Field(default_factory=list)
    tcp: list[dict[str, Any]] = Field(default_factory=list)
    udp: list[dict[str, Any]] = Field(default_factory=list)
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    domains: list[str | dict[str, Any]] = Field(default_factory=list)
    tls: list[dict[str, Any]] = Field(default_factory=list)
    pcap_local_path: str | None = None


class SandboxReport(BaseModel):
    """The sandbox-agnostic report. ``provider``/``source_format`` are the one
    thing every reader needs and nothing can infer, so they are the two
    required fields; everything else defaults to empty."""

    model_config = ConfigDict(extra="ignore")

    provider: str
    source_format: Literal["cape2", "cuckoo", "triage", "mock", "generic"]
    task_id: str = ""
    target: SandboxTarget = Field(default_factory=SandboxTarget)
    processes: list[SandboxProcess] = Field(default_factory=list)
    apistats: dict[str, dict[str, int]] = Field(default_factory=dict)
    generic_events: list[dict[str, Any]] = Field(default_factory=list)
    signatures: list[SandboxSignatureRow] = Field(default_factory=list)
    network: SandboxNetwork = Field(default_factory=SandboxNetwork)
    dropped_files: list[dict[str, Any]] = Field(default_factory=list)
    # list[str], not list[dict]: the real shape is behavior.summary.keys, a
    # flat array of registry-path strings (confirmed against every one of the
    # 97 real reports under data/cape_reports/ — 139,056 string entries, zero
    # dicts). A dict-only filter here would silently drop all of it, the same
    # mistake ``file_writes`` had below.
    registry: list[str] = Field(default_factory=list)
    screenshots: list[dict[str, Any]] = Field(default_factory=list)
    cti: dict[str, Any] = Field(default_factory=dict)
    unavailable: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    _validate_raw = field_validator("raw", mode="wrap")(_dict_identity_or_validate)
    # Ruled in during the pre-flight scan, beyond the brief's own field list:
    # persistence_extractor's Linux path rules read both of these directly
    # (``behavior.summary.{files,write_files,modified_files,wrote_files}`` and
    # the top-level ``file_writes``/``files_written`` arrays) and keep only
    # the string entries of each (its own ``isinstance(p, str)`` guard) — a
    # dict-shaped entry is not richer data, it is a shape the consumer already
    # discards, so both are coerced to ``list[str]`` here rather than filtered
    # to dicts only.
    summary: dict[str, list[str]] = Field(default_factory=dict)
    file_writes: list[str] = Field(default_factory=list)


class SandboxRun(BaseModel):
    """One sandbox job's outcome: the neutral report plus the job's own status.

    ``report`` has no safe empty value — a run without a report is not a run —
    so it is the one field with no default.
    """

    model_config = ConfigDict(extra="ignore")

    task_id: str
    sample_sha256: str = ""
    sample_name: str = ""
    status: str = "reported"
    report: SandboxReport
    # Same wrap-validator identity fix as SandboxReport.raw above, and for the
    # same reason: a sandbox provider's ``fetch()`` sets both
    # ``SandboxRun.raw`` and ``SandboxReport.raw`` to the very same
    # client-returned dict, and ``test_fetch_keeps_the_raw_report_by_identity``
    # depends on ``run.raw is <that dict>`` holding exactly as it does for the
    # report — a plain ``dict[str, Any]`` field does not hold that (confirmed
    # empirically: pydantic-core rebuilds the container even when every value
    # already validates), so this field needs the same protection.
    raw: dict[str, Any]
    _validate_raw = field_validator("raw", mode="wrap")(_dict_identity_or_validate)
    error: str = ""


_SUMMARY_KEYS: tuple[str, ...] = ("files", "write_files", "modified_files", "wrote_files")


def cape_report_to_sandbox_report(
    raw: dict[str, Any],
    *,
    provider: str,
    source_format: Literal["cape2", "cuckoo", "triage", "mock", "generic"] = "cape2",
    task_id: str = "",
) -> SandboxReport:
    """Read a CAPE/Cuckoo-shaped report into the neutral model, keeping ``raw``.

    Deliberately lossless in one direction only: everything the neutral model
    names is copied out, and the original dict is carried whole in ``raw`` so
    ``to_cape_shaped_dict`` can hand today's consumers the very object they
    would have received before the provider layer existed.
    """
    behavior_field, net_field, target_field = (
        raw.get("behavior"),
        raw.get("network"),
        raw.get("target"),
    )
    behavior = behavior_field if isinstance(behavior_field, dict) else {}
    net = net_field if isinstance(net_field, dict) else {}
    target = target_field if isinstance(target_field, dict) else {}
    file_block_field = target.get("file")
    file_block = file_block_field if isinstance(file_block_field, dict) else {}
    summary_field = behavior.get("summary")
    summary_raw = summary_field if isinstance(summary_field, dict) else {}
    cti_field = raw.get("cti")

    processes = [
        SandboxProcess(
            pid=_int(p.get("pid")),
            ppid=_int(p.get("ppid")),
            name=str(p.get("process_name") or p.get("name") or ""),
            command_line=str(p.get("command_line") or p.get("cmd") or ""),
            first_seen=str(p.get("first_seen") or ""),
            calls=[c for c in (p.get("calls") or []) if isinstance(c, dict)],
        )
        for p in (behavior.get("processes") or [])
        if isinstance(p, dict)
    ]
    signatures = [
        SandboxSignatureRow(
            name=str(s.get("name") or ""),
            description=str(s.get("description") or s.get("name") or ""),
            severity=_int(s.get("severity") or s.get("score")),
            marks=list(s.get("marks") or []),
            ttp_tags=_as_str_list(s.get("ttp_tags") or s.get("attck_id")),
        )
        for s in (raw.get("signatures") or [])
        if isinstance(s, dict)
    ]
    return SandboxReport(
        provider=provider,
        source_format=source_format,
        task_id=str(task_id or (raw.get("info") or {}).get("id") or ""),
        target=SandboxTarget(
            # CAPE nests the hashes under target.file.*; a handful of other
            # builds (and the neutral providers upstream of this one) put them
            # directly on target. Both are checked so neither shape loses data.
            sha256=str(target.get("sha256") or file_block.get("sha256") or ""),
            md5=str(target.get("md5") or file_block.get("md5") or ""),
            name=str(target.get("name") or file_block.get("name") or ""),
            file_type=str(file_block.get("type") or ""),
            mime_type=str(file_block.get("type") or ""),
            size=_int(file_block.get("size")),
        ),
        processes=processes,
        apistats={
            str(pid): {str(api): _int(n) for api, n in (stats or {}).items()}
            for pid, stats in (behavior.get("apistats") or {}).items()
            if isinstance(stats, dict)
        },
        generic_events=[g for g in (behavior.get("generic") or []) if isinstance(g, dict)],
        signatures=signatures,
        network=SandboxNetwork(
            dns=_rows(net.get("dns")),
            http=_rows(net.get("http")),
            tcp=_rows(net.get("tcp")),
            udp=_rows(net.get("udp")),
            hosts=_rows(net.get("hosts")),
            domains=list(net.get("domains") or []),
            tls=_rows(net.get("tls")),
            pcap_local_path=net.get("pcap_local_path") or None,
        ),
        dropped_files=_rows(raw.get("dropped")),
        registry=_as_str_list((behavior.get("summary") or {}).get("keys")),
        screenshots=_rows(raw.get("screenshots")),
        cti=cti_field if isinstance(cti_field, dict) else {},
        unavailable=[],
        raw=raw,
        summary={key: _as_str_list(summary_raw.get(key)) for key in _SUMMARY_KEYS},
        file_writes=_as_str_list(raw.get("file_writes") or raw.get("files_written")),
    )


def _split_host_port(value: str) -> tuple[str, int | None]:
    """Split Triage's combined ``"host:port"`` flow endpoint.

    Triage's dynamic-report flows carry the destination as one string rather
    than separate host/port fields (confirmed against the "Dynamic Report"
    docs page on 2026-09-04). A value with no trailing ``:<digits>`` is kept
    whole as the host, port ``None`` — this also covers a bare IPv6 address,
    which is never mistaken for a port suffix since the part after the last
    ``:`` would not be all-digits.
    """
    host, sep, port_str = value.rpartition(":")
    if sep and port_str.isdigit():
        return host, int(port_str)
    return value, None


def triage_overview_to_sandbox_report(
    overview: dict[str, Any],
    *,
    provider: str = "triage",
    task_reports: dict[str, dict[str, Any]] | None = None,
    task_id: str = "",
) -> SandboxReport:
    """Map a Triage overview (plus its behavioural task reports) onto the model.

    Triage reports what it observed, not every API call: there is no per-call
    log, no apistats, no registry timeline, no generic-event stream and (for a
    file sample) no screenshot. Those five sections are listed in
    ``unavailable`` rather than left empty and silent, because an empty
    dynamic section reads exactly like a clean sample — and the report
    renderers say so out loud (Task 17).

    Every other channel a consumer reads is populated straight from the
    fixture shape confirmed against Triage's "Dynamic Report" docs page on
    2026-09-04: each task's ``network.flows`` (tcp/udp, split by ``proto``,
    plus a synthesised ``network.hosts`` row per destination carrying that
    flow's ASN/country) and ``network.requests`` (``domain_req``/
    ``domain_resp`` pairs for DNS, ``web_req``/``web_resp`` pairs for HTTP),
    and each task's ``dumped`` files for ``dropped_files``. Every one of these
    is mapped into the *consumer* shape (``network.dns`` rows as
    ``{request, type, answers: [{data}]}``, ``network.tcp``/``udp`` rows as
    ``{dst, dport}``) rather than passed through in Triage's own shape, so
    ``network_extractor``/``network_parser`` read real domains and IPs
    instead of rendering ``N/A`` for fields they don't recognise.

    ``TriageSandboxProvider`` is imported here, inside the function body rather
    than at module scope, because it is the one caller: the provider module
    imports this function at import time, so a module-level import back would
    be circular. By the time anything actually calls this function, both
    modules have finished loading regardless of which one a caller reached
    first.
    """
    from maljan.providers.sandbox.triage import TriageSandboxProvider

    sample_field, analysis_field = overview.get("sample"), overview.get("analysis")
    sample = sample_field if isinstance(sample_field, dict) else {}
    analysis = analysis_field if isinstance(analysis_field, dict) else {}
    processes: list[SandboxProcess] = []
    dropped_files: list[dict[str, Any]] = []
    network = SandboxNetwork()
    hosts_by_ip: dict[str, dict[str, Any]] = {}
    for task in (task_reports or {}).values():
        for proc in task.get("processes") or []:
            if not isinstance(proc, dict):
                continue
            processes.append(
                SandboxProcess(
                    pid=_int(proc.get("procid") or proc.get("pid")),
                    ppid=_int(proc.get("procid_parent") or proc.get("ppid")),
                    name=str(proc.get("image") or proc.get("name") or ""),
                    command_line=str(proc.get("cmd") or ""),
                    first_seen=str(proc.get("started") or ""),
                    calls=[],
                )
            )
        dumped_field = task.get("dumped")
        dropped_files.extend(_rows(dumped_field))

        net_field = task.get("network")
        net = net_field if isinstance(net_field, dict) else {}

        for flow in _rows(net.get("flows")):
            proto = str(flow.get("proto") or "").lower()
            dst_host, dst_port = _split_host_port(str(flow.get("dst") or ""))
            if not dst_host:
                continue
            row = {"dst": dst_host, "dport": dst_port}
            if proto == "tcp":
                network.tcp.append(row)
            elif proto == "udp":
                network.udp.append(row)
            host_row = hosts_by_ip.setdefault(dst_host, {"ip": dst_host})
            as_num, as_org = flow.get("as_num"), flow.get("as_org")
            if as_num or as_org:
                host_row["asn"] = " ".join(str(x) for x in (as_num, as_org) if x)
            if flow.get("country"):
                host_row["country_name"] = str(flow["country"])

        for req in _rows(net.get("requests")):
            domain_req_field = req.get("domain_req")
            domain_req = domain_req_field if isinstance(domain_req_field, dict) else None
            domain_resp_field = req.get("domain_resp")
            domain_resp = domain_resp_field if isinstance(domain_resp_field, dict) else None
            web_req_field = req.get("web_req")
            web_req = web_req_field if isinstance(web_req_field, dict) else None
            web_resp_field = req.get("web_resp")
            web_resp = web_resp_field if isinstance(web_resp_field, dict) else None

            if domain_req is not None:
                answers = [
                    {"data": str(a["value"])}
                    for a in _rows((domain_resp or {}).get("answers"))
                    if a.get("value")
                ]
                for question in _rows(domain_req.get("questions")):
                    name = str(question.get("name") or "")
                    if not name:
                        continue
                    network.dns.append(
                        {
                            "request": name,
                            "type": str(question.get("type") or ""),
                            "answers": answers,
                        }
                    )
                    network.domains.append(name)

            if web_req is not None:
                parsed_url = urlsplit(str(web_req.get("url") or ""))
                headers_field = web_req.get("headers")
                headers = headers_field if isinstance(headers_field, dict) else {}
                network.http.append(
                    {
                        "host": parsed_url.hostname or "",
                        "uri": parsed_url.path or "/",
                        "method": str(web_req.get("method") or ""),
                        "status": (web_resp or {}).get("status"),
                        "port": parsed_url.port,
                        "encrypted": parsed_url.scheme == "https",
                        "user_agent": str(headers.get("User-Agent") or ""),
                    }
                )
    network.hosts = list(hosts_by_ip.values())

    return SandboxReport(
        provider=provider,
        source_format="triage",
        task_id=str(task_id or sample.get("id") or ""),
        target=SandboxTarget(
            sha256=str(sample.get("sha256") or ""),
            md5=str(sample.get("md5") or ""),
            name=str(sample.get("target") or ""),
            file_type=str(sample.get("kind") or ""),
            mime_type=str(sample.get("kind") or ""),
            size=_int(sample.get("size")),
        ),
        processes=processes,
        apistats={},
        generic_events=[],
        signatures=[
            SandboxSignatureRow(
                name=str(s.get("name") or ""),
                description=str(s.get("desc") or s.get("name") or ""),
                severity=_int(s.get("score")),
                marks=list(s.get("indicators") or []),
                ttp_tags=_as_str_list(s.get("ttp")),
            )
            for s in (overview.get("signatures") or [])
            if isinstance(s, dict)
        ],
        network=network,
        dropped_files=dropped_files,
        registry=[],
        screenshots=[],
        cti={"family": _as_str_list(analysis.get("family")), "score": analysis.get("score")},
        unavailable=list(TriageSandboxProvider.UNAVAILABLE),
        raw=overview,
    )
