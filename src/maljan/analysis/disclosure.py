"""What a run sent beyond this machine, said once, from what the run recorded.

The **Disclosure** block of the run summary (``run_summary["disclosure"]``)
and of the report (Appendix B, in the markdown and the HTML made from it).
It is built when the run's last model call and last tool call have been made
(the report node, and for a stopped run its summary and its partial report)
from four records and nothing else:

* the settings the run ran with, as their snapshot holds them (dotted keys,
  ``core.settings_overrides.public_snapshot``): each tool server's and each
  provider block's transport and address, each agent's model list, the
  sandbox provider's address, the memory store's address and the tracing
  switch;
* each ledger entry's recorded source (``LedgerEntry.source``), which names
  the settings block its call went through, and the facts its tool declared
  when the entry was written (``LedgerEntry.facts``): whether it asks a
  service about the sample or an indicator
  (``core.reputation.asks_about_an_indicator``), the argument roles it takes
  an indicator in, and whether it sends the sample out (``discloses_sample``);
* the token ledger's counts per agent, each call filed under the label of the
  model that answered it, which carries the endpoint the call was sent to
  (``core.model_assignments.model_label``);
* the sample submissions the run made to its sandbox provider
  (``MaljanApp._submit_to_sandbox``).

Never a tool's name. Every host is classified by the one rule in
``core.host_locality``: local, remote, or unknown when no host is recorded.

**Right or absent.** ``nothing_left`` is true only when every destination the
record names is local, nothing is left unplaced, tracing is off and the
record is complete. Otherwise the block says what went where, and says that
it cannot be told where the platform cannot tell. A tool server the settings
start on this machine (stdio) is taken to work on this machine unless its
tool declares that it asks a service about an indicator or sends the sample
out: where such a server sends what it is given is not in the settings, and
the block says so. A model endpoint in an agent's model list that recorded no
answered call is named too, because a request that failed is not always
recorded.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from maljan.analysis.run_summary import count_label
from maljan.core.host_locality import LOCAL, REMOTE, UNKNOWN, host_locality, host_of

# The version of the stored record's shape.
DISCLOSURE_VERSION = 1

# The transports a tool server is reached over at an address.
HTTP_TRANSPORTS = frozenset({"http", "streamable-http", "sse"})
# The transport a tool server is started on this machine with.
STDIO_TRANSPORT = "stdio"
# The setting that sends every prompt and answer to the tracing service.
TRACING_SETTING = "langchain_tracing_v2"

# What a stopped run's record says it is missing (``pipeline.stopped_run``).
STOPPED_PART_WAY = "the run was stopped part-way"

NOTHING_LEFT_SENTENCE = (
    "Nothing left this machine: every model endpoint, tool server and store this run "
    "reached is local, and no lookup service or sandbox outside it was sent anything."
)
INTRO_SENTENCE = (
    "**Disclosure:** what this run sent beyond this machine, read from the settings it ran "
    "with and the recorded source of each model call and tool call. Local is a loopback, "
    "private, link-local or shared address, a name only a local resolver answers, or a "
    "compose service name."
)

# The order rows are listed in: what went outside first.
_WHERE_ORDER = {REMOTE: 0, UNKNOWN: 1, LOCAL: 2}

# The agent key of the calls the token ledger filed under no agent: no agent's
# key is empty, since the ledger keeps a tally only for a named one.
NO_AGENT = ""

# Why a destination cannot be placed, each a clause the sentences go on from
# with "so where it went cannot be told".
_NO_HOST = "the address recorded for it names no host"
_NO_MODEL = "the token ledger filed them under no model"
_NO_ENDPOINT = "its provider records no endpoint"
_NO_SOURCE = "their ledger entries record no source"
_ON_THIS_MACHINE = (
    "the settings do not say where a tool server run on this machine sends what it is given"
)


@dataclass(frozen=True)
class _Place:
    """Where one destination is: its host or service name, its locality, and why if unknown."""

    host: str = ""
    service: str = ""
    where: str = UNKNOWN
    why: str = ""

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.host, self.service, self.where, self.why)


def _field(entry: Any, name: str) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def _url_place(url: object) -> _Place:
    host = host_of(url)
    if not host:
        return _Place(why=_NO_HOST)
    return _Place(host=host, where=host_locality(host))


def _vendor_place(provider: str) -> _Place:
    """Where a provider sends a call with no address configured: its own API, named."""
    if not provider:
        return _Place(why=_NO_ENDPOINT)
    from maljan.llm.provider_base import facts_of

    default = str(getattr(facts_of(provider), "default_endpoint", "") or "")
    if "://" in default:
        return _url_place(default)
    if default:
        return _Place(service=default, where=REMOTE)
    return _Place(why=_NO_ENDPOINT)


def _label_place(label: str) -> _Place:
    """Where the model a call was filed under was served, from its label.

    A label carries `` @ <scheme>://<host>[:<port>]`` when its endpoint is an
    address (``model_assignments.model_label``); without one the call went to
    its provider's own API.
    """
    _head, sep, tail = label.rpartition(" @ ")
    if sep and "://" in tail:
        return _url_place(tail)
    provider = label.partition("/")[0] if "/" in label else ""
    return _vendor_place(provider)


def _configured(snapshot: Mapping[str, Any], provider: str) -> str | None:
    """The provider's own configured address, as the snapshot holds it."""
    from maljan.llm.provider_base import facts_of

    leaf = facts_of(provider).base_url_leaf
    value = snapshot.get(f"llm.{provider}.{leaf}") if leaf else None
    return str(value) if value else None


def model_list(snapshot: Mapping[str, Any], agent: str) -> list[tuple[str, str]]:
    """``(provider, endpoint)`` of every model ``agent`` may call, in the order it tries them.

    The snapshot's reading of ``model_assignments.assignment_chain_for``: the
    agent's own entry and its fallbacks where the registry builds the entry's
    provider, the global provider otherwise.
    """
    from maljan.core.model_assignments import builds_provider, endpoint_where

    prefix = f"llm.agents.{agent}."
    provider = str(snapshot.get(prefix + "provider") or "")
    choices: list[tuple[str, Any]]
    if provider and builds_provider(provider):
        choices = [(provider, snapshot.get(prefix + "base_url"))]
        for choice in snapshot.get(prefix + "fallbacks") or []:
            if isinstance(choice, Mapping) and choice.get("provider"):
                choices.append((str(choice["provider"]), choice.get("base_url")))
    else:
        choices = [(str(snapshot.get("llm.provider") or ""), None)]
    return [
        (name, endpoint_where(name, base_url, configured=_configured(snapshot, name)))
        for name, base_url in choices
        if name
    ]


def _endpoint_place(provider: str, endpoint: str) -> _Place:
    if "://" in endpoint:
        return _url_place(endpoint)
    return _vendor_place(provider)


def _model_row(place: _Place) -> dict[str, Any]:
    return {
        "host": place.host,
        "service": place.service,
        "where": place.where,
        "calls": 0,
        "agents": {},
        "configured_for": [],
        "why": place.why,
    }


def _model_rows(
    snapshot: Mapping[str, Any], tokens: Mapping[str, Any] | None, agents: Iterable[str]
) -> list[dict[str, Any]]:
    """One row per endpoint that answered a call or is in a model list of the run's agents."""
    tokens = tokens if isinstance(tokens, Mapping) else {}
    per_agent = tokens.get("per_agent")
    per_agent = per_agent if isinstance(per_agent, Mapping) else {}
    rows: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    unplaced: dict[str, int] = {}
    counted = 0
    for agent, tally in sorted(per_agent.items()):
        if not isinstance(tally, Mapping):
            continue
        labelled = 0
        for label, count in sorted((tally.get("models") or {}).items()):
            calls = int(count or 0)
            place = _label_place(str(label))
            row = rows.setdefault(place.key, _model_row(place))
            row["calls"] += calls
            row["agents"][str(agent)] = row["agents"].get(str(agent), 0) + calls
            labelled += calls
        made = int(tally.get("llm_calls") or 0)
        counted += made
        if made > labelled:
            unplaced[str(agent)] = made - labelled
    no_agent = int(tokens.get("llm_calls") or 0) - counted
    for agent in sorted({str(name) for name in per_agent} | {str(name) for name in agents}):
        for provider, endpoint in model_list(snapshot, agent):
            place = _endpoint_place(provider, endpoint)
            row = rows.setdefault(place.key, _model_row(place))
            if agent not in row["agents"] and agent not in row["configured_for"]:
                row["configured_for"].append(agent)
    out = list(rows.values())
    if no_agent > 0:
        # Filed under no agent: the key no agent can have.
        unplaced[NO_AGENT] = no_agent
    if unplaced:
        row = _model_row(_Place(why=_NO_MODEL))
        row["calls"] = sum(unplaced.values())
        row["agents"] = dict(sorted(unplaced.items()))
        out.append(row)
    for row in out:
        row["agents"] = dict(sorted(row["agents"].items()))
    return sorted(out, key=lambda r: (_WHERE_ORDER[r["where"]], r["host"], r["service"], r["why"]))


def _block_path(source: str) -> str | None:
    """The dotted settings path of the block a recorded source names, or ``None``."""
    kind, _, key = source.partition(":")
    if kind == "mcp" and key:
        return f"mcp.servers.{key}"
    if kind == "provider" and key:
        from maljan.core.tool_declarations import provider_blocks

        return provider_blocks().get(source)
    return None


def _in_process_sources() -> frozenset[str]:
    """The platform's own in-process sources: their calls never leave the worker."""
    from maljan.core.builtin_declarations import in_process_declarations

    return frozenset(str(ref) for ref in in_process_declarations())


@dataclass(frozen=True)
class _Route:
    """How one source's calls travel: transport, place, and whether a process here runs it."""

    transport: str
    place: _Place
    on_this_machine: bool = False


def _route(snapshot: Mapping[str, Any], source: str) -> _Route:
    """How a source's calls travel, from its settings block's ``transport`` and ``url``."""
    path = _block_path(source)
    if path is None or f"{path}.transport" not in snapshot:
        # Every tool server block records its transport, so none is no block.
        return _Route("", _Place(why=f"the settings name no tool server block for {source}"))
    transport = str(snapshot.get(f"{path}.transport") or "")
    if transport == STDIO_TRANSPORT:
        return _Route(transport, _Place(where=LOCAL), on_this_machine=True)
    if transport in HTTP_TRANSPORTS:
        return _Route(transport, _url_place(snapshot.get(f"{path}.url")))
    return _Route(transport, _Place(why=f"the settings name no known transport for {source}"))


def _tool_row(source: str, route: _Route, place: _Place) -> dict[str, Any]:
    return {
        "source": source,
        "transport": route.transport,
        "host": place.host,
        "where": place.where,
        "calls": 0,
        "why": place.why,
    }


def _filled(entry: Any, argument: str) -> bool:
    """Whether the call gave ``argument``; a record without its arguments counts it as given."""
    args = _field(entry, "args")
    if not isinstance(args, Mapping):
        return True
    return args.get(argument) not in (None, "")


def _tool_rows(
    snapshot: Mapping[str, Any], entries: Iterable[Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """``(lookups, uploads by a tool, tool servers)`` from the ledger's calls, each call once."""
    from maljan.agents.delegation import TEAM_SERVER
    from maljan.core.declared_reading import kind_free_facts
    from maljan.core.reputation import INDICATOR_ARGUMENTS, asks_about_an_indicator

    in_process = _in_process_sources()
    routes: dict[str, _Route] = {}
    lookups: dict[tuple[Any, ...], dict[str, Any]] = {}
    uploads: dict[tuple[Any, ...], dict[str, Any]] = {}
    servers: dict[tuple[Any, ...], dict[str, Any]] = {}
    for entry in entries:
        if _field(entry, "repeated_of"):
            # Answered from an earlier entry or by a guard: no call was made.
            continue
        source = str(_field(entry, "source") or "")
        if source in in_process:
            continue
        if not source:
            name = str(_field(entry, "server") or "")
            if not name or name == TEAM_SERVER:
                # An in-process tool (no server), or a question put to another
                # agent of the team, whose own calls are entries of their own.
                continue
            route = _Route("", _Place(why=_NO_SOURCE))
            key: tuple[Any, ...] = (name, route.place.key)
            row = servers.setdefault(key, _tool_row(name, route, route.place))
            row["calls"] += 1
            continue
        route = routes.get(source) or routes.setdefault(source, _route(snapshot, source))
        facts = kind_free_facts(entry)
        place = route.place
        if route.on_this_machine and (facts.discloses_sample or asks_about_an_indicator(facts)):
            place = _Place(why=_ON_THIS_MACHINE)
        key = (source, route.transport, place.key)
        if facts.discloses_sample:
            row = uploads.setdefault(
                key, {"by": "tool", **_tool_row(source, route, place), "failed": 0}
            )
            row["calls"] += 1
            row["failed"] += 0 if _field(entry, "ok") is not False else 1
        elif asks_about_an_indicator(facts):
            row = lookups.setdefault(
                key, {**_tool_row(source, route, place), "kinds": {}, "without_indicator": 0}
            )
            row["calls"] += 1
            # The indicator kinds a call carried are the roles its declaration
            # names for the arguments it gave; a call that gave none of them
            # is counted apart rather than guessed from its argument names.
            roles = [
                role
                for role in INDICATOR_ARGUMENTS
                if role in facts.arguments and _filled(entry, facts.arguments[role])
            ]
            for role in roles:
                row["kinds"][role] = row["kinds"].get(role, 0) + 1
            if not roles:
                row["without_indicator"] += 1
        elif not route.on_this_machine:
            row = servers.setdefault(key, _tool_row(source, route, place))
            row["calls"] += 1
    for row in lookups.values():
        row["kinds"] = dict(sorted(row["kinds"].items()))
    return _ordered(lookups), _ordered(uploads), _ordered(servers)


def _ordered(rows: Mapping[Any, dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        rows.values(),
        key=lambda r: (_WHERE_ORDER[r["where"]], r["host"], r["source"], r["transport"], r["why"]),
    )


def upload_record(provider: str, *, submitted: bool) -> dict[str, Any]:
    """One submission of the sample to the sandbox provider, as the run records it."""
    return {"provider": str(provider), "submitted": bool(submitted)}


def _sandbox_uploads(
    snapshot: Mapping[str, Any], uploads: Iterable[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """One row per sandbox provider the sample was submitted to, with its address."""
    rows: dict[str, dict[str, Any]] = {}
    for upload in uploads:
        provider = str(upload.get("provider") or "")
        if not provider:
            continue
        row = rows.get(provider)
        if row is None:
            # A sandbox provider's own block is ``sandbox.<id>`` and its address
            # ``base_url`` there (``MaljanApp._poll_budget`` reads the block alike).
            url = snapshot.get(f"sandbox.{provider}.base_url")
            place = (
                _url_place(url)
                if url
                else _Place(why=f"the settings record no address for {provider}")
            )
            row = rows[provider] = {
                "by": "sandbox",
                "source": provider,
                "transport": "",
                "host": place.host,
                "where": place.where,
                "calls": 0,
                "why": place.why,
                "failed": 0,
            }
        row["calls"] += 1
        row["failed"] += 0 if upload.get("submitted") else 1
    return list(rows.values())


def _stores(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The long-term memory store, where its backend reaches one at an address."""
    backend = str(snapshot.get("memory.backend") or "")
    if not backend:
        return []
    prefix = f"memory.{backend}."
    url = snapshot.get(prefix + "url")
    if url is not None:
        place = _url_place(url)
    elif any(str(key).startswith(prefix) for key in snapshot):
        place = _Place(why=f"the settings record no address for the {backend} store")
    else:
        # A backend with no settings of its own keeps its store in the process.
        return []
    return [{"backend": backend, "host": place.host, "where": place.where, "why": place.why}]


def disclosure_record(
    snapshot: Mapping[str, Any],
    *,
    entries: Iterable[Any] = (),
    tokens: Mapping[str, Any] | None = None,
    agents: Iterable[str] = (),
    uploads: Iterable[Mapping[str, Any]] = (),
    partial_reason: str = "",
) -> dict[str, Any]:
    """What the run sent beyond this machine, as the run summary stores it.

    ``snapshot`` is the run's settings in dotted keys; ``entries`` its ledger
    entries; ``tokens`` the run summary's ``tokens`` block; ``agents`` the
    agents the run's stages ran, whose model lists are read beside the calls
    the ledger filed; ``uploads`` the sandbox submissions (:func:`upload_record`);
    ``partial_reason`` says why the record may miss a call, and keeps it from
    saying that nothing left. Linear in the entries and the snapshot.
    """
    lookups, tool_uploads, servers = _tool_rows(snapshot, entries)
    record: dict[str, Any] = {
        "v": DISCLOSURE_VERSION,
        "nothing_left": False,
        "partial_reason": str(partial_reason or ""),
        "models": _model_rows(snapshot, tokens, agents),
        "lookups": lookups,
        "uploads": [*_sandbox_uploads(snapshot, uploads), *tool_uploads],
        "servers": servers,
        "stores": _stores(snapshot),
        "tracing": snapshot.get(TRACING_SETTING) is True,
    }
    rows = [
        row
        for part in ("models", "lookups", "uploads", "servers", "stores")
        for row in record[part]
    ]
    record["nothing_left"] = (
        not record["partial_reason"]
        and not record["tracing"]
        and all(row["where"] == LOCAL for row in rows)
    )
    return record


def configured_hosts(settings: Any) -> set[str]:
    """Every host ``settings`` address: each address leaf's, and each model endpoint's.

    The address leaves are the snapshot's keys whose last part is ``url`` or
    ``base_url`` (tool servers, provider blocks, sandboxes, model providers,
    the memory store); the model endpoints add a provider's default address,
    which no leaf holds (``model_assignments.configured_endpoint_labels``).
    """
    from maljan.core.model_assignments import configured_endpoint_labels
    from maljan.core.settings_overrides import public_snapshot

    hosts = {
        host_of(value)
        for key, value in public_snapshot(settings, ()).items()
        if isinstance(value, str) and str(key).rsplit(".", 1)[-1] in ("url", "base_url")
    }
    hosts.update(host_of(label) for label in configured_endpoint_labels(settings))
    hosts.discard("")
    return hosts


def stage_agents(stages: Any) -> list[str]:
    """The agents of the stages that ran, in the rollup's order, each once."""
    names: dict[str, None] = {}
    for row in stages or []:
        if isinstance(row, Mapping) and row.get("ran"):
            for agent in row.get("agents") or []:
                names.setdefault(str(agent), None)
    return list(names)


def run_disclosure(
    container: Any,
    *,
    entries: Iterable[Any],
    tokens: Mapping[str, Any] | None,
    stages: Any = None,
    partial_reason: str = "",
) -> dict[str, Any] | None:
    """The record of the run ``container`` holds, or ``None`` when it cannot be built.

    The snapshot is taken of the job's own settings (``container.config``) by
    the function the stored settings snapshot is made with
    (``core.settings_overrides.public_snapshot``), so the record reads the
    values the run summary's ``settings_snapshot`` records. Never raises: a
    record that cannot be built is absent, with a warning, never a guess.
    """
    try:
        from maljan.core.config import Settings
        from maljan.core.settings_overrides import public_snapshot

        settings = getattr(container, "config", None)
        if not isinstance(settings, Settings):
            # No job settings to read where anything went: no record.
            return None
        uploads = getattr(container, "sample_uploads", None)
        return disclosure_record(
            public_snapshot(settings, ()),
            entries=entries,
            tokens=tokens,
            agents=stage_agents(stages),
            uploads=list(uploads) if isinstance(uploads, list) else [],
            partial_reason=partial_reason,
        )
    except Exception as exc:  # noqa: BLE001 — an absent block is right; a guessed one is not
        from maljan.core.logger import logger

        logger.warning(
            "disclosure: the run's disclosure block was not built (%s); the report carries none.",
            type(exc).__name__,
        )
        return None


# ---------------------------------------------------------------------------
# The sentences
# ---------------------------------------------------------------------------


def _code(text: str) -> str:
    return f"`{text}`"


def _mark(row: Mapping[str, Any]) -> str:
    """What a placed row's host is: local, or outside this machine."""
    return "(local)" if row.get("where") == LOCAL else "(outside this machine)"


def _untold(row: Mapping[str, Any], what: str = "they") -> str:
    """``; <why>, so where <what> went cannot be told`` for a row nothing places."""
    why = str(row.get("why") or "the record does not say")
    return f"; {why}, so where {what} went cannot be told"


def _joined(names: Iterable[str]) -> str:
    items = [str(name) for name in names]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _counts(counts: Mapping[str, Any]) -> str:
    return ", ".join(
        f"{name if name != NO_AGENT else 'no agent'} {int(n or 0)}" for name, n in counts.items()
    )


def _times(count: int) -> str:
    return "once" if count == 1 else f"{count} times"


def _server(source: str, code: Callable[[str], str]) -> str:
    kind, _, key = source.partition(":")
    if kind == "mcp" and key:
        return f"tool server {code(key)}"
    if kind == "provider" and key:
        return f"the {code(key)} provider's tool server"
    return f"tool server {code(source)}" if source else "a tool server"


def _model_line(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    calls = int(row.get("calls") or 0)
    agents = dict(row.get("agents") or {})
    listed = list(row.get("configured_for") or [])
    if not row.get("host") and not row.get("service"):
        by = f" ({_counts(agents)})" if agents else ""
        what = "it" if calls == 1 else "they"
        return f"Model prompts: {count_label(calls, 'call')}{by}{_untold(row, what)}."
    name = code(str(row["host"])) if row.get("host") else str(row["service"])
    if calls:
        line = f"Model prompts: {name} {_mark(row)} received {count_label(calls, 'call')}"
        line += f" ({_counts(agents)})." if agents else "."
        if listed:
            line += (
                f" It is also in the model list of {_joined(listed)}, which recorded no "
                "answered call there."
            )
        return line
    return (
        f"Model prompts: {name} {_mark(row)} is in the model list of {_joined(listed)}, which "
        "recorded no answered call there; a request that failed is not always recorded, so "
        "whether it received prompts cannot be told."
    )


def _kinds(row: Mapping[str, Any]) -> str:
    parts = [_counts(dict(row.get("kinds") or {}))] if row.get("kinds") else []
    without = int(row.get("without_indicator") or 0)
    if without:
        parts.append(f"{without} giving no argument declared as an indicator")
    return ", ".join(part for part in parts if part)


def _how(row: Mapping[str, Any]) -> str:
    """The transport, as a reader is told it."""
    transport = str(row.get("transport") or "")
    if transport == STDIO_TRANSPORT:
        return "stdio, run on this machine"
    return transport or "transport not recorded"


def _lookup_line(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    calls = int(row.get("calls") or 0)
    server = _server(str(row.get("source") or ""), code)
    asked = f"was asked {_times(calls)}"
    kinds = _kinds(row)
    if row.get("host"):
        return (
            f"Lookups: {code(str(row['host']))} {_mark(row)} {asked} through {server} "
            f"({_how(row)}): {kinds}."
        )
    return f"Lookups: {server} ({_how(row)}) {asked}: {kinds}{_untold(row)}."


def _upload_line(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    calls = int(row.get("calls") or 0)
    failed = int(row.get("failed") or 0)
    times = _times(calls)
    at = f" at {code(str(row['host']))} {_mark(row)}" if row.get("host") else ""
    failure = (
        f"; {failed} of the attempts failed, so whether {'it' if failed == 1 else 'they'} "
        "arrived cannot be told"
        if failed
        else ""
    )
    untold = "" if row.get("host") else _untold(row, "it")
    if row.get("by") == "sandbox":
        return (
            f"Sample upload: the sample was submitted {times} to the "
            f"{code(str(row.get('source') or ''))} sandbox{at}{failure}{untold}."
        )
    server = _server(str(row.get("source") or ""), code)
    return (
        f"Sample upload: {server} ({_how(row)}){at} was handed the sample {times} by a tool "
        f"declared to send it out of the deployment{failure}{untold}."
    )


def _server_line(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    calls = count_label(int(row.get("calls") or 0), "call")
    server = _server(str(row.get("source") or ""), code)
    if row.get("host"):
        return (
            f"Tool calls: {server} over {row.get('transport')} at {code(str(row['host']))} "
            f"{_mark(row)}: {calls}."
        )
    return f"Tool calls: {server} ({_how(row)}): {calls}{_untold(row)}."


def _store_line(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    store = f"the {code(str(row.get('backend') or ''))} store"
    if row.get("host"):
        return (
            f"Case memory: {store} at {code(str(row['host']))} {_mark(row)}, which this job "
            "reads similar cases from and stores its case in."
        )
    return f"Case memory: {store}{_untold(row, 'its cases')}."


TRACING_SENTENCE = (
    f"Tracing is on (`{TRACING_SETTING}`): every prompt and answer was also sent to the "
    "tracing service, whose address the settings do not record, so where they went cannot "
    "be told."
)


def disclosure_lines(record: Any, code: Callable[[str], str] = _code) -> list[str]:
    """The block's sentences, one per line, for a list; ``[]`` for no record.

    ``code`` writes a host or a key as printed; the report renderer passes one
    that keeps a configured address from its closing defang pass.
    """
    if not isinstance(record, Mapping):
        return []
    lines: list[str] = []
    if record.get("nothing_left"):
        lines.append(NOTHING_LEFT_SENTENCE)
    elif record.get("partial_reason"):
        lines.append(
            f"This record may be incomplete: {record['partial_reason']}, and a call made in the "
            "step it stopped in may not be recorded, so it cannot be said that nothing left "
            "this machine."
        )
    writers: tuple[tuple[str, Callable[[Mapping[str, Any], Callable[[str], str]], str]], ...] = (
        ("models", _model_line),
        ("lookups", _lookup_line),
        ("uploads", _upload_line),
        ("servers", _server_line),
        ("stores", _store_line),
    )
    for part, write in writers:
        for row in record.get(part) or []:
            if isinstance(row, Mapping):
                lines.append(write(row, code))
    if record.get("tracing"):
        lines.append(TRACING_SENTENCE)
    return lines
