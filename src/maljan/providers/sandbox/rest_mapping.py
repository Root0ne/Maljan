"""Turn any sandbox's JSON into a ``SandboxReport``, using settings alone.

Every other sandbox this project speaks to has an adapter written against its
documented shape. This one has no shape: the operator describes where each
channel lives with an RFC 9535 JSONPath, and this module compiles those paths
once and coerces whatever they select into the row shapes the consumers
already read.

Three rules make that safe to run against a report nobody has seen:

* A row that lacks the field its consumer indexes on is dropped, not guessed
  at, and the drop is counted — the preview endpoint shows those counts before
  a job is ever submitted.
* A channel with no path goes into ``SandboxReport.unavailable``. An empty
  ``network.dns`` and a sandbox that publishes no DNS at all look identical in
  a rendered report, and only one of them means the sample was quiet.
* Every channel is capped at ``MAX_ROWS_PER_CHANNEL``. A JSONPath over a
  200 MB report can select a million rows, and a report nobody can render is
  not more evidence than one that stops at five thousand and says so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.providers.errors import ProviderConfigurationError

if TYPE_CHECKING:
    from maljan.core.config import RestMappingConfig
    from maljan.schemas.sandbox_report import SandboxReport

CHANNELS: tuple[str, ...] = (
    "processes",
    "calls",
    "signatures",
    "dns",
    "http",
    "tcp",
    "udp",
    "hosts",
    "domains",
    "dropped_files",
    "registry",
)

MAX_ROWS_PER_CHANNEL = 5000

# The field each channel's consumer indexes on. A row without it is not a
# thinner row, it is a row the consumer will skip or crash on.
_REQUIRED: dict[str, tuple[str, ...]] = {
    "processes": ("pid",),
    "calls": ("pid", "api"),
    "signatures": ("name",),
    "dns": ("request",),
    "http": (),
    "tcp": ("dst",),
    "udp": ("dst",),
    "dropped_files": ("name",),
}

# Channels whose rows are plain strings rather than mappings.
_STRING_CHANNELS = frozenset({"hosts", "domains", "registry"})

# The fields each mapping-shaped channel carries into its consumer row.
_FIELDS: dict[str, tuple[str, ...]] = {
    "processes": ("pid", "ppid", "name", "command_line"),
    "calls": ("pid", "api", "args", "timestamp"),
    "signatures": ("name", "description", "severity", "ttps"),
    "dns": ("request", "type", "answers"),
    "tcp": ("dst", "dport"),
    "udp": ("dst", "dport"),
    "dropped_files": ("name", "sha256", "size"),
}


@dataclass(frozen=True)
class ChannelStats:
    """What one channel's path selected, and what survived coercion."""

    matched: int = 0
    kept: int = 0
    dropped: int = 0
    sample_rows: list[Any] = field(default_factory=list)
    error: str = ""


@dataclass(frozen=True)
class CompiledMapping:
    config: RestMappingConfig
    target_sha256: Any | None
    paths: dict[str, Any]


@dataclass(frozen=True)
class MappingResult:
    report: SandboxReport
    stats: dict[str, ChannelStats]


def _compile_one(expression: str, channel: str) -> Any:
    import jsonpath_rfc9535

    try:
        return jsonpath_rfc9535.compile(expression)
    except Exception as exc:  # noqa: BLE001 — the library raises its own error type
        raise ProviderConfigurationError(
            f"sandbox.rest.mapping.{channel}: {expression!r} is not a valid JSONPath ({exc})"
        ) from exc


def compile_mapping(cfg: RestMappingConfig) -> CompiledMapping:
    """Compile every non-empty path once, naming the channel that fails.

    Called by ``RestSandboxProvider.from_settings`` and by the preview
    endpoint, so a typo is an error an operator sees at save or preview time
    rather than a job that detonates a sample and then produces nothing.
    """
    paths = {
        channel: _compile_one(getattr(cfg, channel), channel)
        for channel in CHANNELS
        if getattr(cfg, channel)
    }
    target = _compile_one(cfg.target_sha256, "target_sha256") if cfg.target_sha256 else None
    return CompiledMapping(config=cfg, target_sha256=target, paths=paths)


def _rename(channel: str, names: dict[str, str], row: dict[str, Any], want: str) -> Any:
    """One consumer field out of ``row``, under this sandbox's own name for it."""
    return row.get(names.get(f"{channel}.{want}", want))


def _coerce(channel: str, names: dict[str, str], raw: Any) -> Any | None:
    """One selected match as its consumer row, or None when it cannot be one."""
    if channel in _STRING_CHANNELS:
        text = raw if isinstance(raw, str) else raw.get("value") if isinstance(raw, dict) else None
        return text if isinstance(text, str) and text else None
    if not isinstance(raw, dict):
        return None
    row = {want: _rename(channel, names, raw, want) for want in _FIELDS.get(channel, ())}
    if channel == "http":
        row = dict(raw)
    for required in _REQUIRED.get(channel, ()):
        if row.get(required) in (None, ""):
            return None
    return row


def _select(compiled: CompiledMapping, channel: str, payload: dict[str, Any]) -> ChannelStats:
    """Run one channel's path and coerce what it selected."""
    path = compiled.paths.get(channel)
    if path is None:
        return ChannelStats()
    try:
        matches = [node.value for node in path.finditer(payload)]
    except Exception as exc:  # noqa: BLE001 — a path valid in isolation can still fail on data
        return ChannelStats(error=f"{type(exc).__name__}: {exc}")
    names = compiled.config.field_names
    kept: list[Any] = []
    dropped = 0
    for raw in matches[:MAX_ROWS_PER_CHANNEL]:
        row = _coerce(channel, names, raw)
        if row is None:
            dropped += 1
        else:
            kept.append(row)
    stats = ChannelStats(
        matched=len(matches),
        kept=len(kept),
        dropped=dropped,
        sample_rows=kept[:3],
    )
    object.__setattr__(stats, "_rows", kept)  # carried to the builder, not part of the wire shape
    return stats


def apply_mapping(
    compiled: CompiledMapping, payload: dict[str, Any], *, provider: str, task_id: str
) -> MappingResult:
    """Map one report payload, and say per channel what happened."""
    from maljan.schemas.sandbox_report import (
        SandboxNetwork,
        SandboxProcess,
        SandboxReport,
        SandboxSignatureRow,
        SandboxTarget,
    )

    stats = {channel: _select(compiled, channel, payload) for channel in CHANNELS}
    rows: dict[str, list[Any]] = {c: list(getattr(s, "_rows", [])) for c, s in stats.items()}

    processes = [
        SandboxProcess(
            pid=int(r.get("pid") or 0),
            ppid=int(r.get("ppid") or 0),
            name=str(r.get("name") or ""),
            command_line=str(r.get("command_line") or ""),
        )
        for r in rows["processes"]
    ]
    by_pid = {p.pid: p for p in processes}
    apistats: dict[str, dict[str, int]] = {}
    orphaned = 0
    for call in rows["calls"]:
        pid = int(call.get("pid") or 0)
        process = by_pid.get(pid)
        if process is None:
            orphaned += 1
            continue
        process.calls.append(call)
        api = str(call.get("api") or "")
        apistats.setdefault(str(pid), {})
        apistats[str(pid)][api] = apistats[str(pid)].get(api, 0) + 1
    if orphaned:
        stats["calls"] = ChannelStats(
            matched=stats["calls"].matched,
            kept=stats["calls"].kept - orphaned,
            dropped=stats["calls"].dropped + orphaned,
            sample_rows=stats["calls"].sample_rows,
        )

    signatures = [
        SandboxSignatureRow(
            name=str(r.get("name") or ""),
            description=str(r.get("description") or ""),
            severity=int(r.get("severity") or 0),
            ttp_tags=[str(t) for t in (r.get("ttps") or []) if t],
        )
        for r in rows["signatures"]
    ]

    network = SandboxNetwork(
        dns=rows["dns"],
        http=rows["http"],
        tcp=rows["tcp"],
        udp=rows["udp"],
        # The consumers read ``hosts`` as rows; a sandbox that publishes bare
        # addresses gets them wrapped rather than a second row shape.
        hosts=[{"ip": h} for h in rows["hosts"]],
        domains=rows["domains"],
    )

    sha256 = ""
    if compiled.target_sha256 is not None:
        found = [node.value for node in compiled.target_sha256.finditer(payload)]
        if found and isinstance(found[0], str):
            sha256 = found[0]

    unavailable = sorted(c for c in CHANNELS if c not in compiled.paths)
    for channel, stat in stats.items():
        if stat.error:
            logger.warning(
                "rest mapping: channel %s failed on this report: %s", channel, stat.error
            )
        elif stat.dropped:
            logger.info(
                "rest mapping: channel %s kept %d of %d rows (%d dropped for missing fields).",
                channel,
                stat.kept,
                stat.matched,
                stat.dropped,
            )

    report = SandboxReport(
        provider=provider,
        source_format="generic",
        task_id=task_id,
        target=SandboxTarget(sha256=sha256),
        processes=processes,
        apistats=apistats,
        signatures=signatures,
        network=network,
        dropped_files=rows["dropped_files"],
        registry=rows["registry"],
        unavailable=unavailable,
        raw=payload,
    )
    return MappingResult(report=report, stats=stats)
