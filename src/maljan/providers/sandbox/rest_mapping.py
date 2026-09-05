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
  not more evidence than one that stops at five thousand and says so; a
  truncated channel says so too (``ChannelStats.truncated``), rather than
  quietly looking like a sandbox with exactly five thousand rows of data.

Three channels are not settings the operator can point anywhere:

* ``apistats`` has no path of its own — it is tallied from ``calls`` as calls
  are attached to their process, so it is populated exactly when ``calls``
  is, and named unavailable exactly when ``calls`` is.
* ``generic_events`` and ``screenshots`` have no ``RestMappingConfig`` field
  at all. No REST sandbox this mapping has been built against publishes
  either through a documented API, so both are named unavailable
  unconditionally — the same call Triage's own adapter makes for the same
  two channels.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from itertools import islice
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

# A sha256 candidate that survives normalisation: lower-cased, 64 hex digits.
# Anything else is not a hash this project can key CTI lookups on, so it is
# dropped rather than carried through half-formed (a "0x"-prefixed value, an
# md5, a truncated copy-paste).
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# The fields each mapping-shaped channel carries into its consumer row.
_FIELDS: dict[str, tuple[str, ...]] = {
    "processes": ("pid", "ppid", "name", "command_line"),
    "calls": ("pid", "api", "args", "timestamp"),
    "signatures": ("name", "description", "severity", "ttps"),
    "dns": ("request", "type", "answers"),
    "tcp": ("dst", "dport"),
    "udp": ("dst", "dport"),
    "dropped_files": ("name", "sha256", "size"),
    # http stays a passthrough channel (an arbitrary sandbox's own field names
    # ride along unchanged, see ``_coerce``) but a rename must still be able
    # to land a source field under the canonical name every extractor reads
    # (``host``, ``uri``, ...) -- the same contract every other channel gives
    # ``field_names`` (F12).
    "http": ("host", "uri", "method", "status", "port", "encrypted", "user_agent"),
}


@dataclass(frozen=True)
class ChannelStats:
    """What one channel's path selected, and what survived coercion."""

    matched: int = 0
    kept: int = 0
    dropped: int = 0
    sample_rows: list[Any] = field(default_factory=list)
    error: str = ""
    truncated: bool = False


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
        # Passthrough first (every field the sandbox's own payload carries
        # survives, whatever it calls them), then a configured rename
        # overlays its canonical field -- a real value only, so an
        # unconfigured or unmatched rename never blanks a field passthrough
        # already supplied.
        merged = dict(raw)
        merged.update({k: v for k, v in row.items() if v is not None})
        row = merged
    for required in _REQUIRED.get(channel, ()):
        if row.get(required) in (None, ""):
            return None
    return row


def _normalize_sha256(value: Any) -> tuple[str, str]:
    """A lower-cased 64-hex sha256, or an empty string and the reason it is not one."""
    text = value.strip().lower() if isinstance(value, str) else ""
    if _SHA256_RE.match(text):
        return text, ""
    return "", f"{value!r} is not a 64-character lowercase hex sha256"


def _select(
    compiled: CompiledMapping, channel: str, payload: dict[str, Any]
) -> tuple[ChannelStats, list[Any]]:
    """Run one channel's path and coerce what it selected.

    ``finditer`` is only ever pulled through ``islice(..., MAX_ROWS_PER_CHANNEL
    + 1)`` — one past the cap, never the whole thing — so a path that selects
    a million rows never materialises more than 5001 of them before this
    function knows to stop and say ``truncated``.

    Returns ``(stats, kept_rows)`` rather than smuggling the rows onto the
    frozen ``ChannelStats`` through ``object.__setattr__`` (F15): that hid a
    second, undeclared field a stats-only rebuild (the calls/orphan case in
    ``apply_mapping``) would silently drop, and mutating a frozen dataclass at
    all only works by accident of it not truly being read-only in Python.
    """
    path = compiled.paths.get(channel)
    if path is None:
        return ChannelStats(), []
    try:
        values = (node.value for node in path.finditer(payload))
        peeked = list(islice(values, MAX_ROWS_PER_CHANNEL + 1))
    except Exception as exc:  # noqa: BLE001 — a path valid in isolation can still fail on data
        return ChannelStats(error=f"{type(exc).__name__}: {exc}"), []
    truncated = len(peeked) > MAX_ROWS_PER_CHANNEL
    matches = peeked[:MAX_ROWS_PER_CHANNEL]
    if truncated:
        logger.warning(
            "rest mapping: %s: more than %d rows, truncated", channel, MAX_ROWS_PER_CHANNEL
        )
    names = compiled.config.field_names
    kept: list[Any] = []
    dropped = 0
    for raw in matches:
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
        truncated=truncated,
    )
    return stats, kept


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

    selected = {channel: _select(compiled, channel, payload) for channel in CHANNELS}
    stats: dict[str, ChannelStats] = {c: s for c, (s, _rows) in selected.items()}
    rows: dict[str, list[Any]] = {c: list(r) for c, (_s, r) in selected.items()}

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
            truncated=stats["calls"].truncated,
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
        if found:
            sha256, reason = _normalize_sha256(found[0])
            if reason:
                # ``target.sha256`` stays empty rather than carry a value that
                # cannot key a CTI lookup. The REST provider (Task 11) reads
                # this same field into ``SandboxRun.sample_sha256`` — with it
                # empty, that provider falls back to the sha256 of the file it
                # itself submitted rather than trust an unmatched value.
                stats["target_sha256"] = ChannelStats(matched=1, dropped=1, error=reason)

    unavailable_set = {c for c in CHANNELS if c not in compiled.paths}
    # ``generic_events``/``screenshots`` have no path of their own — this
    # mapping can never produce them — and ``apistats`` is only ever derived
    # from ``calls``, so it is unavailable exactly when ``calls`` is.
    unavailable_set.update({"generic_events", "screenshots"})
    if "calls" in unavailable_set:
        unavailable_set.add("apistats")
    unavailable = sorted(unavailable_set)
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
