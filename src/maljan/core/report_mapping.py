"""Where each part of a sandbox report sits, as JSONPaths: the mapping a report is read through.

The mapping reader (``providers.sandbox.readers``, ``generic``) reads any
sandbox's JSON through a :class:`RestMappingConfig`: the REST provider's
``sandbox.rest.mapping``, or a declared report format's own ``mapping``
(``core.report_formats.ReportFormat.mapping``), which the upload route and the
REST provider read alike.

A JSONPath's descendant segment (``..``) walks every node below where it
stands; one walks the report once, but a path with two walks the report again
under every node the first reached, so its cost grows with the report's size
times its depth. :func:`costly_paths` names each such path, and the settings
save says so beside it (the save is never refused for it).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class RestMappingConfig(BaseModel):
    """RFC 9535 JSONPaths selecting each consumer channel out of a report.

    Read only when ``report.format`` is ``generic``. An empty path is not a
    mistake: it says the sandbox does not publish that channel, and the
    provider lists it in ``SandboxReport.unavailable`` so a rendered report
    never reads like a clean sample by omission.
    """

    target_sha256: str = "$.target.sha256"
    processes: str = ""  # each match: {pid, ppid, name, command_line}
    calls: str = ""  # each match: {pid, api, args, timestamp}
    signatures: str = ""  # each match: {name, description, severity, ttps}
    dns: str = ""  # each match: {request, type, answers[]}
    http: str = ""
    tcp: str = ""  # each match: {dst, dport}
    udp: str = ""
    hosts: str = ""  # each match: a string
    domains: str = ""
    dropped_files: str = ""  # each match: {name, sha256, size}
    registry: str = ""  # each match: a string
    # "<channel>.<consumer field>" -> the field name this sandbox uses,
    # e.g. {"processes.command_line": "cmdline"}.
    field_names: dict[str, str] = Field(default_factory=dict)
    # Channels this schema has no field for: "<name>" -> JSONPath, landing in
    # SandboxReport.channels under that name. Namespace the name by platform,
    # e.g. {"android.permissions": "$.apk.permissions[*]"}.
    channels: dict[str, str] = Field(default_factory=dict)
    # The report's places with no channel above (``schemas.sandbox_document.
    # OPEN_PLACES``: the process tree, the resolved API names, what the
    # sandbox extracted, the process dumps, the memory regions, the IDS
    # alerts): "<place>" -> JSONPath, each match kept as the sandbox published
    # it, e.g. {"extracted": "$.configs[*]"}.
    places: dict[str, str] = Field(default_factory=dict)

    @field_validator("places")
    @classmethod
    def _places_are_open_places(cls, value: dict[str, str]) -> dict[str, str]:
        from maljan.schemas.sandbox_document import OPEN_PLACES

        unknown = sorted(set(value) - set(OPEN_PLACES))
        if unknown:
            raise ValueError(
                f"no such report place {', '.join(unknown)}; the places a path may name are "
                f"{', '.join(OPEN_PLACES)}"
            )
        return value


# The fixed channels of a mapping, each one JSONPath.
_PATH_FIELDS = (
    "target_sha256",
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

COSTLY_PATH = (
    "this path descends ({count} '..' segments) under every node an earlier one reached, so "
    "reading it costs the report's size times its depth; anchor it (start it at the block it "
    "reads, '$.block[*]') to read in time linear in the report"
)


COSTLY_FILTER_PATH = (
    "this path's filter reads the whole report again ('$' with a '..' segment) for every "
    "candidate it tests, so reading it costs the report's size times the candidates; test "
    "the candidate itself ('@') in the filter to read in time linear in the report"
)


def descendant_segments(expression: str) -> int:
    """How many descendant segments (``..``) ``expression`` holds outside its quoted names."""
    return _segments(expression)[0]


def _segments(expression: str) -> tuple[int, bool]:
    """``(descendant segments, whether a filter reads `$` with a descendant segment)``.

    Outside quoted names. A filter (``[?...]``) runs its query once per
    candidate: an absolute query in it (``$``) that descends reads the whole
    report each time.
    """
    count = 0
    quote = ""
    index = 0
    # The bracket depth each open filter began at, and whether it has read ``$``.
    filters: list[list[Any]] = []
    depth = 0
    absolute_descent = False
    while index < len(expression):
        char = expression[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in ("'", '"'):
            quote = char
        elif expression.startswith("..", index):
            count += 1
            if filters and filters[-1][1]:
                absolute_descent = True
            index += 2
            continue
        elif char == "[":
            depth += 1
            if expression.startswith("?", index + 1):
                filters.append([depth, False])
        elif char == "]":
            if filters and filters[-1][0] == depth:
                filters.pop()
            depth -= 1
        elif char == "$" and filters:
            filters[-1][1] = True
        index += 1
    return count, absolute_descent


def costly_paths(mapping: Any) -> dict[str, str]:
    """``{field: warning}`` for each path of ``mapping`` whose reading is not linear in the report.

    A path is costly where it holds more than one descendant segment, or a
    filter whose absolute query descends (``[?count($..x) > 0]``). The
    field is the mapping's own: ``places.extracted``, ``channels.<name>``,
    ``processes``. Linear in the paths' text.
    """
    out: dict[str, str] = {}
    named: list[tuple[str, Any]] = [(name, getattr(mapping, name, "")) for name in _PATH_FIELDS]
    named += [(f"channels.{k}", v) for k, v in (getattr(mapping, "channels", None) or {}).items()]
    named += [(f"places.{k}", v) for k, v in (getattr(mapping, "places", None) or {}).items()]
    for name, expression in named:
        count, absolute_descent = _segments(str(expression or ""))
        if count > 1:
            out[name] = COSTLY_PATH.format(count=count)
        elif absolute_descent:
            out[name] = COSTLY_FILTER_PATH
    return out


def check_mapping_paths(mapping: Any) -> None:
    """Refuse a mapping holding a path that is not a JSONPath, naming the field."""
    import jsonpath_rfc9535

    named: list[tuple[str, Any]] = [(name, getattr(mapping, name, "")) for name in _PATH_FIELDS]
    named += [(f"channels.{k}", v) for k, v in mapping.channels.items()]
    named += [(f"places.{k}", v) for k, v in mapping.places.items()]
    for name, expression in named:
        if not expression:
            continue
        try:
            jsonpath_rfc9535.compile(expression)
        except Exception as exc:  # noqa: BLE001 — the library raises its own error type
            raise ValueError(
                f"mapping.{name}: {expression!r} is not a valid JSONPath ({type(exc).__name__})"
            ) from exc
