"""What a run sent beyond this machine, said once, from what the run recorded.

The **Disclosure** block of the run summary (``run_summary["disclosure"]``)
and of the report (Appendix B, in the markdown and the HTML made from it).
It is built when the run's last model call and last tool call have been made
(the report node, and for a stopped run its summary and its partial report)
from the run's own records and nothing else:

* the settings the run ran with, as their snapshot holds them (dotted keys,
  ``core.settings_overrides.public_snapshot``): each tool server's and each
  provider block's transport, address, roles and tool declarations, every
  agent's model list and the global model, the memory store's address and the
  tracing switch;
* each ledger entry's recorded source (``LedgerEntry.source``), which names
  the settings block its call went through, and the facts its tool declared
  when the entry was written (``LedgerEntry.facts``);
* the token ledger's counts per agent, each call filed under the label of the
  model that answered it, which carries the endpoint the call was sent to
  (``core.model_assignments.model_label``);
* the endpoints whose window probe answered as a model runtime during the run
  (``ServiceContainer.runtime_answers``);
* the sample's submissions to the sandbox provider (with the host the
  provider resolves its submission URL to) and its stagings to tool servers
  (``MaljanApp._submit_to_sandbox``, ``agents.sample_staging``);
* the effective tracing state (``core.tracing``);
* what the job noted of the processes that read the sample, for the isolation
  part (``analysis.isolation``), which says where the sample's bytes were read
  and what kept each reader from the worker;
* what each tool the run called is declared to do beyond answering, for the
  effects part (``analysis.tool_effects``): run the sample's code, reach the
  network, send the sample's hash or bytes to a third party. A tool that sends
  the sample's bytes is an upload row here by the same rule
  (``tool_effects.sends_sample_bytes``), and a tool that ran the sample's code
  is told with the isolation row of its source.

Never a tool's name. Every host is classified by the one rule in
``core.host_locality``.

**Nothing needs positive knowledge for every path.** ``nothing_left`` is true
only when every destination the record names is local and known to stop
there, nothing is left unplaced, tracing is off and the record is complete.
In particular:

* a model endpoint at a local address counts only when it answered the window
  probe as a model runtime in this run; any other local address may be a
  gateway that forwards the prompts;
* every model list in the settings is read, and the global model, because a
  request that failed is not always recorded;
* a local tool server (started over stdio, or at a local address) is a
  gateway when its block declares a lookup or sandbox role, or any of its
  tools declares a lookup or that it sends the sample out: every call through
  it cannot be placed. A lookup or an upload through any local server cannot
  be placed either;
* a call to a tool that declares nothing at all cannot be shown to stay on
  the machine; one that declares no kind but declares that it reaches no
  network (``ToolEffects.network`` false) is placed by its server;
* a call through a local server to a tool that declares that it reaches the
  network cannot be placed; a server's own hint (``openWorldHint``) moves no
  call to another row, and is said on the undeclared row it stays in;
* a ledger row the report could not read is a call that cannot be placed.

When the block does say "nothing", it says what it rests on. When enrichment
follows the report, the worker names it here (:func:`with_enrichment`) and
the enrichment job adds what it asked (:func:`with_enrichment_asked`).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from maljan.analysis.run_summary import count_label
from maljan.core.host_locality import (
    LOCAL,
    REMOTE,
    UNKNOWN,
    host_locality,
    host_of,
    normal_host,
    taken_as_service_name,
)

# The version of the stored record's shape. Version 2 adds the isolation part
# (``analysis.isolation``), version 3 the effects part (``analysis.tool_effects``);
# a record of an earlier version has neither of the later parts and renders as
# before.
DISCLOSURE_VERSION = 3

# The transports a tool server is reached over at an address.
HTTP_TRANSPORTS = frozenset({"http", "streamable-http", "sse"})
# The transport a tool server is started on this machine with.
STDIO_TRANSPORT = "stdio"
# The setting that sends every prompt and answer to the tracing service.
TRACING_SETTING = "langchain_tracing_v2"

# What a stopped run's record says it is missing (``pipeline.stopped_run``).
STOPPED_PART_WAY = "the run was stopped part-way"

INTRO_SENTENCE = (
    "**Disclosure:** what this run sent beyond this machine, read from the settings it ran "
    "with and the recorded source of each model call, tool call and sample upload."
)
FOOTNOTE_SENTENCE = (
    "_This machine, here, covers its loopback addresses, the private, link-local and shared "
    "address ranges, names only a local resolver answers, and single-label names, which are "
    "taken as a compose service's._"
)

# The order rows are listed in: what went outside first.
_WHERE_ORDER = {REMOTE: 0, UNKNOWN: 1, LOCAL: 2}

# The agent key of the calls the token ledger filed under no agent: no agent's
# key is empty, since the ledger keeps a tally only for a named one.
NO_AGENT = ""

# The upload rows' kinds.
BY_SANDBOX = "sandbox"
BY_STAGING = "staging"
BY_TOOL = "tool"

# Why a destination cannot be placed, each a clause the sentences go on from
# with "so where it went cannot be told".
_NO_HOST = "the address recorded for it names no host"
_NO_MODEL = "the token ledger filed them under no model"
_NO_ENDPOINT = "its provider records no endpoint"
_NO_SOURCE = "their ledger entries record no source"
_LOCAL_SERVER = "the settings do not say where a local tool server sends what it is given"
_GATEWAY = (
    "it is a local tool server that declares a lookup or a sandbox, so a call through it may "
    "go on to a service the settings do not name"
)
_NOT_A_RUNTIME = "a local address that did not answer as a model runtime may forward the prompts"
# Why a call through a local server to a tool declared to reach the network
# cannot be placed.
_REACHES = "its tool declares that it reaches the network, and " + _LOCAL_SERVER
# What "nothing" assumes of a runtime answer: the probe proves a runtime
# answered, not where it runs, and a tunnel or proxy looks the same.
RUNTIME_ASSUMPTION = (
    "a local address that answered as a model runtime is taken as running here, and a tunnel "
    "or proxy to a remote runtime cannot be told apart"
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


def _endpoint_label(url: str) -> str:
    """The endpoint as a run records it: scheme, host and port (``endpoint_label``)."""
    from maljan.core.model_assignments import endpoint_label

    return endpoint_label(url) if "://" in url else ""


def _label_endpoint(label: str) -> tuple[_Place, str]:
    """Where the model a call was filed under was served, and its endpoint label.

    A label carries `` @ <scheme>://<host>[:<port>]`` when its endpoint is an
    address (``model_assignments.model_label``); without one the call went to
    its provider's own API.
    """
    _head, sep, tail = label.rpartition(" @ ")
    if sep and "://" in tail:
        return _url_place(tail), _endpoint_label(tail)
    provider = label.partition("/")[0] if "/" in label else ""
    return _vendor_place(provider), ""


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
    provider = str(snapshot.get(prefix + "provider") or "") if agent else ""
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


def configured_agents(snapshot: Mapping[str, Any]) -> list[str]:
    """Every agent the snapshot gives a model entry of its own (``llm.agents.<key>``)."""
    found = {
        str(key)[len("llm.agents.") : -len(".provider")]
        for key in snapshot
        if str(key).startswith("llm.agents.") and str(key).endswith(".provider")
    }
    return sorted(name for name in found if name and "." not in name)


def _endpoint_place(provider: str, endpoint: str) -> tuple[_Place, str]:
    if "://" in endpoint:
        return _url_place(endpoint), _endpoint_label(endpoint)
    return _vendor_place(provider), ""


@dataclass
class _ModelRow:
    place: _Place
    calls: int = 0
    agents: dict[str, int] = field(default_factory=dict)
    configured_for: list[str] = field(default_factory=list)
    is_global: bool = False
    endpoints: set[str] = field(default_factory=set)

    def stored(self, runtimes: Mapping[str, str]) -> dict[str, Any]:
        runtime = ""
        if self.place.where == LOCAL and self.endpoints:
            answers = [runtimes.get(endpoint, "") for endpoint in sorted(self.endpoints)]
            if all(answers):
                runtime = ", ".join(dict.fromkeys(answers))
        return {
            "host": self.place.host,
            "service": self.place.service,
            "where": self.place.where,
            "calls": self.calls,
            "agents": dict(sorted(self.agents.items())),
            "configured_for": list(self.configured_for),
            "global": self.is_global,
            "runtime": runtime,
            "why": self.place.why,
        }


def _model_rows(
    snapshot: Mapping[str, Any],
    tokens: Mapping[str, Any] | None,
    agents: Iterable[str],
    runtimes: Mapping[str, str],
) -> list[dict[str, Any]]:
    """One row per endpoint that answered a call or is in a model list the settings hold."""
    tokens = tokens if isinstance(tokens, Mapping) else {}
    per_agent = tokens.get("per_agent")
    per_agent = per_agent if isinstance(per_agent, Mapping) else {}
    rows: dict[tuple[str, str, str, str], _ModelRow] = {}
    unplaced: dict[str, int] = {}
    counted = 0

    def _row(place: _Place) -> _ModelRow:
        return rows.setdefault(place.key, _ModelRow(place))

    for agent, tally in sorted(per_agent.items()):
        if not isinstance(tally, Mapping):
            continue
        labelled = 0
        for label, count in sorted((tally.get("models") or {}).items()):
            calls = int(count or 0)
            place, endpoint = _label_endpoint(str(label))
            row = _row(place)
            row.calls += calls
            row.agents[str(agent)] = row.agents.get(str(agent), 0) + calls
            if endpoint:
                row.endpoints.add(endpoint)
            labelled += calls
        made = int(tally.get("llm_calls") or 0)
        counted += made
        if made > labelled:
            unplaced[str(agent)] = made - labelled
    no_agent = int(tokens.get("llm_calls") or 0) - counted
    named = (
        {str(name) for name in per_agent}
        | {str(name) for name in agents}
        | set(configured_agents(snapshot))
    )
    for agent in sorted(named):
        for provider, endpoint in model_list(snapshot, agent):
            place, label = _endpoint_place(provider, endpoint)
            row = _row(place)
            if label:
                row.endpoints.add(label)
            if agent not in row.agents and agent not in row.configured_for:
                row.configured_for.append(agent)
    # The global model: every agent without a model entry of its own calls it.
    for provider, endpoint in model_list(snapshot, ""):
        place, label = _endpoint_place(provider, endpoint)
        row = _row(place)
        row.is_global = True
        if label:
            row.endpoints.add(label)
    out = [row.stored(runtimes) for row in rows.values()]
    if no_agent > 0:
        # Filed under no agent: the key no agent can have.
        unplaced[NO_AGENT] = no_agent
    if unplaced:
        lost = _ModelRow(_Place(why=_NO_MODEL), calls=sum(unplaced.values()), agents=unplaced)
        out.append(lost.stored(runtimes))
    return sorted(out, key=lambda r: (_WHERE_ORDER[r["where"]], r["host"], r["service"], r["why"]))


def _model_blocks(row: Mapping[str, Any]) -> bool:
    """Whether a model row keeps "nothing" from being said."""
    if row.get("where") != LOCAL:
        return True
    return not row.get("runtime")


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


def gateway_blocks(snapshot: Mapping[str, Any]) -> frozenset[str]:
    """The settings blocks that declare a lookup or a sandbox, read in one pass over the snapshot.

    A block whose ``roles`` hold the reputation or the sandbox role, or any of
    whose tools declares a kind that reaches outside the deployment by its
    meaning (``builtin_declarations.OUTWARD_KINDS``: the lookups and the
    submissions), an indicator argument role, or that it sends the sample out
    (``tool_facts.<tool>.discloses_sample``, or ``effects.third_party`` of
    ``bytes``: ``tool_effects.sends_sample_bytes``).
    """
    from maljan.core.builtin_declarations import OUTWARD_KINDS
    from maljan.core.reputation import INDICATOR_ARGUMENTS, REPUTATION_ROLE
    from maljan.core.tool_declarations import SANDBOX_ROLE, THIRD_PARTY_BYTES

    lookup_kinds = set(OUTWARD_KINDS)
    roles = {REPUTATION_ROLE, SANDBOX_ROLE}
    out: set[str] = set()
    for key, value in snapshot.items():
        text = str(key)
        head, sep, rest = text.partition(".tool_facts.")
        if sep:
            if rest.endswith(".discloses_sample") and value is True:
                out.add(head)
            elif rest.endswith(".effects.third_party") and value == THIRD_PARTY_BYTES:
                out.add(head)
            elif rest.endswith(".kind") and value in lookup_kinds:
                out.add(head)
            elif ".arguments." in rest and rest.rsplit(".", 1)[-1] in INDICATOR_ARGUMENTS:
                out.add(head)
        elif text.endswith(".roles") and isinstance(value, list):
            if any(str(role) in roles for role in value):
                out.add(text[: -len(".roles")])
    return frozenset(out)


@dataclass(frozen=True)
class _Route:
    """How one source's calls travel: transport, place, and whether it is a gateway."""

    transport: str
    place: _Place
    on_this_machine: bool = False
    gateway: bool = False


def _route(snapshot: Mapping[str, Any], source: str, gateways: frozenset[str]) -> _Route:
    """How a source's calls travel, from its settings block's ``transport`` and ``url``."""
    path = _block_path(source)
    if path is None or f"{path}.transport" not in snapshot:
        # Every tool server block records its transport, so none is no block.
        return _Route("", _Place(why=f"the settings name no tool server block for {source}"))
    transport = str(snapshot.get(f"{path}.transport") or "")
    gateway = path in gateways
    if transport == STDIO_TRANSPORT:
        return _Route(transport, _Place(where=LOCAL), on_this_machine=True, gateway=gateway)
    if transport in HTTP_TRANSPORTS:
        return _Route(transport, _url_place(snapshot.get(f"{path}.url")), gateway=gateway)
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


def _stored_kind(entry: Any) -> str:
    """The kind the facts the entry stored name, ``""`` for none."""
    held = _field(entry, "facts")
    return str(held.get("kind") or "").strip() if isinstance(held, Mapping) else ""


def _declares_a_kind(entry: Any) -> bool:
    """Whether the entry's tool counts as declared: by the platform's rule, a named kind.

    A declaration that states other facts only (a display name, words) is an
    undeclared tool to every reading (``undeclared_tools.declares_a_kind``),
    and what such a tool did cannot be told from it.
    """
    from types import SimpleNamespace

    from maljan.core.undeclared_tools import declares_a_kind

    return declares_a_kind(SimpleNamespace(kind=_stored_kind(entry) or None))


@dataclass
class _ToolRows:
    lookups: dict[tuple[Any, ...], dict[str, Any]] = field(default_factory=dict)
    uploads: dict[tuple[Any, ...], dict[str, Any]] = field(default_factory=dict)
    servers: dict[tuple[Any, ...], dict[str, Any]] = field(default_factory=dict)
    undeclared: dict[tuple[Any, ...], dict[str, Any]] = field(default_factory=dict)
    local_servers: dict[str, None] = field(default_factory=dict)
    # Where each ``(source, tool)`` was placed, as its row says it: read by the
    # effects part, so the two never place one call differently.
    places: dict[tuple[str, str], dict[str, str]] = field(default_factory=dict)


def _tool_rows(snapshot: Mapping[str, Any], entries: Iterable[Any]) -> _ToolRows:
    """The ledger's calls, each once: lookups, uploads by a tool, servers, undeclared tools."""
    from maljan.analysis.tool_effects import (
        DECLARED,
        entry_effects,
        is_platform_internal,
        sends_sample_bytes,
    )
    from maljan.core.builtin_declarations import OUTWARD_KINDS
    from maljan.core.declared_reading import kind_free_facts, server_hints
    from maljan.core.reputation import INDICATOR_ARGUMENTS, asks_about_an_indicator
    from maljan.core.tool_declarations import NETWORK_OPERATOR_SANDBOX

    in_process = _in_process_sources()
    gateways = gateway_blocks(snapshot)
    routes: dict[str, _Route] = {}
    out = _ToolRows()
    for entry in entries:
        if _field(entry, "repeated_of"):
            # Answered from an earlier entry or by a guard: no call was made.
            continue
        source = str(_field(entry, "source") or "")
        if source in in_process:
            continue
        if is_platform_internal(entry):
            # An in-process tool (no server), or a question put to another
            # agent of the team, whose own calls are entries of their own.
            continue
        if not source:
            name = str(_field(entry, "server") or "")
            unrouted = _Route("", _Place(why=_NO_SOURCE))
            key: tuple[Any, ...] = (name, unrouted.place.key)
            row = out.servers.setdefault(key, _tool_row(name, unrouted, unrouted.place))
            row["calls"] += 1
            continue
        if source not in routes:
            routes[source] = _route(snapshot, source, gateways)
        route = routes[source]
        facts = kind_free_facts(entry)
        lookup = asks_about_an_indicator(facts)
        sends = sends_sample_bytes(facts)
        effects = entry_effects(entry)
        # Only a declaration places a call by its network: a server's own hint
        # adds to what is said of a call, never moves it to another row.
        reaches = effects.network_by == DECLARED and (
            effects.network is True or effects.network == NETWORK_OPERATOR_SANDBOX
        )
        kind = _stored_kind(entry)
        outward = kind in OUTWARD_KINDS
        place = route.place
        local = place.where == LOCAL
        if local and (sends or lookup or outward or route.gateway or reaches):
            # A local server is not where a lookup, a sample sent out, a call of
            # a kind that reaches outside, a call through a declared gateway or
            # a call of a tool that reaches the network ends: it goes on to a
            # service the settings do not name.
            if sends or lookup:
                why = _LOCAL_SERVER
            elif route.gateway:
                why = _GATEWAY
            elif outward:
                why = (
                    f"its tool declares the kind {kind}, which {OUTWARD_KINDS[kind]} outside "
                    "the deployment, and " + _LOCAL_SERVER
                )
            else:
                why = _REACHES
            place = _Place(host=place.host, why=why)
        out.places.setdefault(
            (source, str(_field(entry, "tool") or "")),
            {"where": place.where, "host": place.host, "why": place.why},
        )
        key = (source, route.transport, place.key)
        if sends:
            row = out.uploads.setdefault(
                key, {"by": BY_TOOL, **_tool_row(source, route, place), "failed": 0}
            )
            row["calls"] += 1
            row["failed"] += 0 if _field(entry, "ok") is not False else 1
        elif lookup:
            row = out.lookups.setdefault(
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
        elif local and (route.gateway or outward or reaches):
            row = out.servers.setdefault(key, _tool_row(source, route, place))
            row["calls"] += 1
        elif (
            local
            and not _declares_a_kind(entry)
            and not (effects.network is False and effects.network_by == DECLARED)
        ):
            row = out.undeclared.setdefault(key, _tool_row(source, route, place))
            row["calls"] += 1
            if server_hints(entry).get("openWorldHint") is True:
                # Said, not placed: the row stays undeclared.
                row["open_world_hints"] = int(row.get("open_world_hints") or 0) + 1
        elif local:
            out.local_servers.setdefault(source, None)
            if not route.on_this_machine:
                row = out.servers.setdefault(key, _tool_row(source, route, place))
                row["calls"] += 1
        else:
            row = out.servers.setdefault(key, _tool_row(source, route, place))
            row["calls"] += 1
    for row in out.lookups.values():
        row["kinds"] = dict(sorted(row["kinds"].items()))
    return out


def _ordered(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        rows,
        key=lambda r: (_WHERE_ORDER[r["where"]], r["host"], r["source"], r["transport"], r["why"]),
    )


# ---------------------------------------------------------------------------
# Sandbox submissions and sample stagings
# ---------------------------------------------------------------------------


def submission_host(provider: Any) -> str | None:
    """The host a sandbox provider's submission sends the sample to.

    ``None`` for a provider whose submission never leaves the worker,
    ``""`` for one that does not say (``SandboxProvider.submission_address``).
    """
    ask = getattr(provider, "submission_address", None)
    if not callable(ask):
        return ""
    try:
        where = ask()
    except Exception:  # noqa: BLE001 — a provider that cannot say is one that does not say
        return ""
    return None if where is None else str(where)


def upload_record(provider: str, *, submitted: bool, host: str = "") -> dict[str, Any]:
    """One submission of the sample to the sandbox provider, as the run records it.

    ``host`` is the host the provider resolved its submission URL to
    (:func:`submission_host`); empty where it does not say.
    """
    return {"provider": str(provider), "submitted": bool(submitted), "host": str(host)}


# A staging's states, as ``agents.sample_staging`` records them.
STAGING_ATTEMPTED = "attempted"
STAGING_DONE = "done"
STAGING_FAILED = "failed"


def staging_record(server: str, *, transport: str, url: str, state: str) -> dict[str, Any]:
    """One staging of the sample to a tool server, as the run records it: never the URL whole."""
    return {
        "server": str(server),
        "transport": str(transport),
        "host": host_of(url),
        "state": state,
    }


def _upload_row(by: str, source: str, transport: str, host: str, why: str) -> dict[str, Any]:
    where = host_locality(host) if host else UNKNOWN
    return {
        "by": by,
        "source": source,
        "transport": transport,
        "host": host,
        "where": where,
        "calls": 0,
        "why": "" if host else why,
        "failed": 0,
    }


def _sandbox_uploads(uploads: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """One row per sandbox provider the sample was submitted to, with its host."""
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for upload in uploads:
        provider = str(upload.get("provider") or "")
        if not provider:
            continue
        host = normal_host(upload.get("host"))
        key = (provider, host)
        if key not in rows:
            rows[key] = _upload_row(
                BY_SANDBOX,
                provider,
                "",
                host,
                f"the {provider} provider does not say where it sends the sample",
            )
        rows[key]["calls"] += 1
        rows[key]["failed"] += 0 if upload.get("submitted") else 1
    return list(rows.values())


def _staging_uploads(stagings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """One row per tool server the sample was staged to, with the host of its block's address."""
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for staging in stagings:
        server = str(staging.get("server") or "")
        if not server:
            continue
        host = str(staging.get("host") or "")
        key = (server, host)
        if key not in rows:
            rows[key] = _upload_row(
                BY_STAGING,
                f"mcp:{server}",
                str(staging.get("transport") or ""),
                host,
                f"the address of tool server {server} names no host",
            )
        rows[key]["calls"] += 1
        rows[key]["failed"] += 0 if staging.get("state") == STAGING_DONE else 1
    return list(rows.values())


# ---------------------------------------------------------------------------
# The memory store
# ---------------------------------------------------------------------------


def memory_backends() -> dict[str, dict[str, Any]]:
    """What each registered memory backend declares about where its store is."""
    try:
        from maljan.memory.store_factory import declared_backends
    except Exception:  # noqa: BLE001 — no registry, no declarations
        return {}
    return declared_backends()


def _stores(
    snapshot: Mapping[str, Any], backends: Mapping[str, Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """The long-term memory store, placed by what its backend declares.

    In the process: no row. An address leaf: the host the snapshot holds there.
    Neither declared: a row that cannot be placed.
    """
    backend = str(snapshot.get("memory.backend") or "")
    if not backend:
        return []
    declared = backends.get(backend) or {}
    if declared.get("in_process"):
        return []
    leaf = str(declared.get("address_leaf") or "")
    if leaf:
        place = _url_place(snapshot.get(f"memory.{backend}.{leaf}"))
    else:
        place = _Place(
            why=f"the {backend} backend declares neither an address nor that it runs in the process"
        )
    return [{"backend": backend, "host": place.host, "where": place.where, "why": place.why}]


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------


def addressed_hosts(snapshot: Mapping[str, Any]) -> list[str]:
    """Every host the run's settings address: each address leaf's, and each model endpoint's.

    The address leaves are the snapshot's keys whose last part is ``url`` or
    ``base_url``; the model endpoints add the default address a provider
    calls where no leaf holds one. The report prints these hosts as written
    and defangs any other (``reporting.renderers.markdown``).
    """
    hosts = {
        host_of(value)
        for key, value in snapshot.items()
        if isinstance(value, str) and str(key).rsplit(".", 1)[-1] in ("url", "base_url")
    }
    for agent in ["", *configured_agents(snapshot)]:
        for _provider, endpoint in model_list(snapshot, agent):
            if "://" in endpoint:
                hosts.add(host_of(endpoint))
    hosts.discard("")
    return sorted(hosts)


def _setting_on(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("true", "1", "yes", "on")


def disclosure_record(
    snapshot: Mapping[str, Any],
    *,
    entries: Iterable[Any] = (),
    tokens: Mapping[str, Any] | None = None,
    agents: Iterable[str] = (),
    uploads: Iterable[Mapping[str, Any]] = (),
    stagings: Iterable[Mapping[str, Any]] = (),
    runtimes: Mapping[str, str] | None = None,
    tracing: bool = False,
    unreadable: int = 0,
    backends: Mapping[str, Mapping[str, Any]] | None = None,
    partial_reason: str = "",
    opened: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    worker: Mapping[str, Any] | None = None,
    sample_paths: Iterable[str] = (),
) -> dict[str, Any]:
    """What the run sent beyond this machine, as the run summary stores it.

    ``snapshot`` is the run's settings in dotted keys; ``entries`` its ledger
    entries; ``tokens`` the run summary's ``tokens`` block; ``agents`` the
    agents its stages ran; ``uploads`` the sandbox submissions
    (:func:`upload_record`) and ``stagings`` the sample's stagings to tool
    servers (:func:`staging_record`); ``runtimes`` the endpoints (as
    ``endpoint_label`` writes them) whose window probe answered as a model
    runtime in this run, each with what answered; ``tracing`` the effective
    tracing state; ``unreadable`` the ledger rows that could not be read;
    ``backends`` what each memory backend declares (the registry's where
    ``None``); ``partial_reason`` why the record may miss a call; ``opened``
    what the job noted of the processes that read the sample and of the reads
    in the worker that write no entry (``analysis.isolation.noted``), and
    ``worker`` the worker's own facts (``analysis.isolation.worker_facts``,
    read here where ``None``); ``sample_paths`` the job's paths to the sample,
    a call handed one of which read it. Linear in the entries and the snapshot.
    """
    entries = list(entries)
    tools = _tool_rows(snapshot, entries)
    record: dict[str, Any] = {
        "v": DISCLOSURE_VERSION,
        "nothing_left": False,
        "partial_reason": str(partial_reason or ""),
        "models": _model_rows(snapshot, tokens, agents, runtimes or {}),
        "lookups": _ordered(tools.lookups.values()),
        "uploads": _ordered(
            [*_sandbox_uploads(uploads), *_staging_uploads(stagings), *tools.uploads.values()]
        ),
        "servers": _ordered(tools.servers.values()),
        "undeclared": _ordered(tools.undeclared.values()),
        "local_servers": sorted(tools.local_servers),
        "stores": _stores(snapshot, memory_backends() if backends is None else backends),
        "tracing": bool(tracing) or _setting_on(snapshot.get(TRACING_SETTING)),
        "unreadable_entries": max(0, int(unreadable or 0)),
        "addressed": addressed_hosts(snapshot),
        "isolation": _isolation(snapshot, entries, opened or {}, worker, sample_paths),
    }
    from maljan.analysis.tool_effects import effects_part

    record["effects"] = effects_part(
        entries,
        isolation=record["isolation"],
        partial_reason=record["partial_reason"],
        places=tools.places,
    )
    record["nothing_left"] = _nothing_left(record)
    return record


def _isolation(
    snapshot: Mapping[str, Any],
    entries: list[Any],
    opened: Mapping[str, Sequence[Mapping[str, Any]]],
    worker: Mapping[str, Any] | None,
    sample_paths: Iterable[str] = (),
) -> dict[str, Any]:
    """The isolation part: each source that read the sample, placed by its settings block."""
    from maljan.analysis.isolation import isolation_part, sample_readers, worker_facts
    from maljan.core.builtin_declarations import in_process_declarations

    gateways = gateway_blocks(snapshot)
    routes: dict[str, _Route] = {}

    def _held(source: str) -> _Route:
        if source not in routes:
            routes[source] = _route(snapshot, source, gateways)
        return routes[source]

    def _placed(source: str) -> tuple[str, str, str, str]:
        route = _held(source)
        return (route.transport, route.place.host, route.place.where, route.place.why)

    readers, unsourced = sample_readers(snapshot, entries, _block_path, sample_paths)
    return isolation_part(
        readers,
        unsourced,
        opened,
        worker=worker_facts() if worker is None else worker,
        in_process={str(ref): cfg.label for ref, cfg in in_process_declarations().items()},
        route=_placed,
        needs_network=lambda source: _held(source).gateway,
    )


def _nothing_left(record: Mapping[str, Any]) -> bool:
    if record.get("partial_reason") or record.get("tracing") or record.get("unreadable_entries"):
        return False
    if record.get("enrichment") or record.get("undeclared") or record.get("lookups"):
        return False
    if any(_model_blocks(row) for row in record.get("models") or []):
        return False
    return all(
        row.get("where") == LOCAL
        for part in ("uploads", "servers", "stores")
        for row in record.get(part) or []
    )


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

# The registry lookup the enrichment asks about a public address with no key,
# named as its client names it (``enrichment.whois_client``).
RDAP_SOURCE = "rdap"
ENRICHMENT_QUEUED = "queued"
# Written before the job's first question goes out, so a job that dies after
# it leaves a record that never says "nothing".
ENRICHMENT_RUNNING = "running"
ENRICHMENT_DONE = "done"
# The job failed or was stopped after it began asking; what it asked until
# then is recorded.
ENRICHMENT_STOPPED = "stopped"


def enrichment_source_row(
    source: str,
    *,
    kinds: Iterable[str],
    hosts: Iterable[str] = (),
    server: str = "",
    transport: str = "",
    server_url: str = "",
) -> dict[str, Any]:
    """One place the enrichment may ask: a source's hosts, or the server it is asked through."""
    named = sorted({normal_host(h) for h in hosts if normal_host(h)})
    if server:
        place = (
            _url_place(server_url) if transport in HTTP_TRANSPORTS else _Place(why=_LOCAL_SERVER)
        )
        if place.where == LOCAL:
            place = _Place(host=place.host, why=_LOCAL_SERVER)
        named = [place.host] if place.host else []
        where, why = place.where, place.why
    elif named:
        places = [host_locality(h) for h in named]
        where = REMOTE if REMOTE in places else (UNKNOWN if UNKNOWN in places else LOCAL)
        why = ""
    else:
        where, why = UNKNOWN, f"source {source} names no host"
    return {
        "source": str(source),
        "kinds": sorted({str(k) for k in kinds}),
        "hosts": named,
        "server": str(server),
        "transport": str(transport),
        "where": where,
        "why": why,
    }


def rdap_row() -> dict[str, Any]:
    """RDAP from the ARIN bootstrap, asked about a public address with no key."""
    from maljan.enrichment.whois_client import RDAP_HOST
    from maljan.enrichment.whois_client import RDAP_SOURCE as SOURCE

    return enrichment_source_row(SOURCE, kinds=["ip"], hosts=[RDAP_HOST])


def registry_rows() -> list[dict[str, Any]]:
    """Every lookup with no key an enrichment of an address may make, each with its host.

    RDAP from the ARIN bootstrap, and where ipwhois is installed its own RDAP
    and ASN lookups too (``enrichment.whois_client.registry_lookups``).
    """
    from maljan.enrichment.whois_client import registry_lookups

    return [
        enrichment_source_row(source, kinds=["ip"], hosts=[host])
        for source, host in registry_lookups()
    ]


# Why the sources an enrichment may ask are not named.
ENRICHMENT_SOURCES_UNREAD = "the enrichment sources in force could not be read"


def unread_sources_row(kinds: Iterable[str]) -> dict[str, Any]:
    """The configured sources, when they could not be read: asked about ``kinds``, no host named."""
    row = enrichment_source_row("", kinds=kinds)
    row["why"] = ENRICHMENT_SOURCES_UNREAD
    return row


def with_enrichment(
    record: Mapping[str, Any], may_reach: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    """``record`` naming the enrichment job queued after the report, and what it may reach.

    Built by the worker from the job's enrichment settings: RDAP, which needs
    no key, and every configured source (:func:`enrichment_source_row`). The
    record never says "nothing" while it holds the enrichment.
    """
    rows = [dict(row) for row in may_reach]
    out = _with_addressed(record, (h for row in rows for h in row.get("hosts") or []))
    out["enrichment"] = {"state": ENRICHMENT_QUEUED, "may_reach": rows, "asked": []}
    out["nothing_left"] = False
    return out


def with_enrichment_started(record: Mapping[str, Any]) -> dict[str, Any]:
    """``record`` saying an enrichment job is about to send its first question.

    Written before that question goes out, so whatever happens to the job
    after it, the record never says that nothing left the machine. What an
    earlier enrichment asked is kept.
    """
    out = dict(record)
    held = dict(out.get("enrichment") or {"may_reach": [], "asked": []})
    held["state"] = ENRICHMENT_RUNNING
    held.setdefault("asked", [])
    out["enrichment"] = held
    out["nothing_left"] = False
    return out


def with_enrichment_asked(
    record: Mapping[str, Any],
    asked: Iterable[Mapping[str, Any]],
    *,
    state: str = ENRICHMENT_DONE,
    withheld: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """``record`` with what the enrichment job asked: per source and host, the kinds and counts.

    ``withheld`` are the server tools a source names that their host withheld
    (``server``, ``tool``, ``reason``: a credential not configured, a library
    not installed): kept under ``withheld``, added to an earlier enrichment's,
    and said in the block, so a source that was never asked is not silent.

    Added to what an earlier enrichment of the same report asked, so a report
    enriched twice says every question either run sent. A row's ``failed``
    counts the questions that failed in transport or never finished, which
    may have arrived. ``state`` is ``done``, or ``stopped`` for a job that
    failed or was stopped part-way.
    """
    out = dict(record)
    held = dict(out.get("enrichment") or {"may_reach": []})
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    before = held.get("asked")
    earlier: list[Any] = list(before) if isinstance(before, list) else []
    for row in [*earlier, *asked]:
        if not isinstance(row, Mapping):
            continue
        host = str(row.get("host") or "")
        source = str(row.get("source") or "")
        why = "" if host else str(row.get("why") or _LOCAL_SERVER)
        kept = merged.setdefault(
            (source, host, why),
            {
                "source": source,
                "host": host,
                "where": host_locality(host) if host else UNKNOWN,
                "kinds": {},
                "failed": 0,
                "why": why,
            },
        )
        for kind, count in dict(row.get("kinds") or {}).items():
            kept["kinds"][str(kind)] = kept["kinds"].get(str(kind), 0) + int(count or 0)
        kept["failed"] += int(row.get("failed") or 0)
    rows = [{**row, "kinds": dict(sorted(row["kinds"].items()))} for row in merged.values()]
    kept_withheld: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in [*list(held.get("withheld") or []), *withheld]:
        if isinstance(row, Mapping):
            entry = {name: str(row.get(name) or "") for name in ("server", "tool", "reason")}
            kept_withheld[(entry["server"], entry["tool"], entry["reason"])] = entry
    if kept_withheld:
        held["withheld"] = [kept_withheld[key] for key in sorted(kept_withheld)]
    held["state"] = state
    held["asked"] = sorted(rows, key=lambda r: (r["source"], r["host"]))
    out = _with_addressed(out, (row["host"] for row in rows))
    out["enrichment"] = held
    out["nothing_left"] = False
    return out


def _with_addressed(record: Mapping[str, Any], hosts: Iterable[str]) -> dict[str, Any]:
    """``record`` whose addressed hosts also hold ``hosts``: the enrichment's, from its settings.

    The hosts an enrichment source's declaration fixes, RDAP's and a server
    block's are settings, never the sample's, so the report prints them as
    configured, as it prints the analysis settings' own addresses.
    """
    out = dict(record)
    held = out.get("addressed")
    named = {str(h) for h in held} if isinstance(held, list) else set()
    named.update(normal_host(h) for h in hosts if normal_host(h))
    out["addressed"] = sorted(named)
    return out


class EnrichmentAsks:
    """The questions an enrichment job sends, counted per source, host and server, by kind.

    Handed to the enrichment as its listener (``enrichment.declared.AskListener``),
    then read as the rows :func:`with_enrichment_asked` takes. Each question is
    counted as attempted when it is about to be sent; the call answers with a
    settle function the asker calls once the question was answered or failed,
    so one that never settles (the job stopped under it) counts as failed.
    """

    def __init__(self) -> None:
        self._counts: dict[tuple[str, str, str], dict[str, int]] = {}
        self._answered: dict[tuple[str, str, str], int] = {}

    def __call__(self, source: str, host: str, kind: str, server: str) -> Callable[[bool], None]:
        key = (str(source), str(host), str(server))
        kinds = self._counts.setdefault(key, {})
        kinds[str(kind)] = kinds.get(str(kind), 0) + 1
        settled: list[bool] = []

        def settle(answered: bool) -> None:
            if settled:
                return
            settled.append(True)
            if answered:
                self._answered[key] = self._answered.get(key, 0) + 1

        return settle

    @property
    def asked_any(self) -> bool:
        return bool(self._counts)

    def rows(self, servers: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        """One row per place asked; a server source's host is its block's, where it is remote.

        ``servers`` are the tool servers in force (``mcp.servers``). A question
        through a server started on this machine or reached at a local address
        goes on to a service the settings do not name, and its row has no host.
        """
        out: list[dict[str, Any]] = []
        for (source, host, server), kinds in sorted(self._counts.items()):
            key_host = host
            why = ""
            if server:
                cfg = (servers or {}).get(server)
                transport = str(getattr(cfg, "transport", "") or "")
                place = (
                    _url_place(getattr(cfg, "url", ""))
                    if transport in HTTP_TRANSPORTS
                    else _Place(why=_LOCAL_SERVER)
                )
                host = place.host if place.where == REMOTE else ""
                why = "" if host else (place.why or _LOCAL_SERVER)
            failed = sum(kinds.values()) - self._answered.get((source, key_host, server), 0)
            out.append(
                {
                    "source": source,
                    "host": host,
                    "kinds": dict(kinds),
                    "failed": max(0, failed),
                    "why": why,
                }
            )
        return out


def after_enrichment(
    payload: Mapping[str, Any],
    rows: Iterable[Mapping[str, Any]],
    *,
    state: str = ENRICHMENT_DONE,
) -> dict[str, Any]:
    """A stored report payload whose run summary's disclosure record holds what was asked.

    ``payload`` is the stored ``malware_report``, which every rendering is made
    from. A payload with no record (a run stored before the block existed) is
    returned as it was.
    """
    held = list(rows)
    return in_payload(payload, lambda record: with_enrichment_asked(record, held, state=state))


def in_payload(
    payload: Mapping[str, Any], change: Callable[[Mapping[str, Any]], dict[str, Any]]
) -> dict[str, Any]:
    """``payload`` with ``change`` applied to its run summary's disclosure record, if it has one."""
    out = dict(payload)
    summary = out.get("run_summary")
    if isinstance(summary, Mapping) and isinstance(summary.get("disclosure"), Mapping):
        if "models" in summary["disclosure"]:
            out["run_summary"] = {**summary, "disclosure": change(summary["disclosure"])}
    return out


# ---------------------------------------------------------------------------
# The record of a run, from its container
# ---------------------------------------------------------------------------


def stage_agents(stages: Any) -> list[str]:
    """The agents of the stages that ran, in the rollup's order, each once."""
    names: dict[str, None] = {}
    for row in stages or []:
        if isinstance(row, Mapping) and row.get("ran"):
            for agent in row.get("agents") or []:
                names.setdefault(str(agent), None)
    return list(names)


def job_sample_paths(container: Any) -> list[str]:
    """Every path the job's sample was given under: the worker's copy, the path each
    server that declares a mount sees it at, and each static provider's mirror."""
    paths: list[str] = []
    held = getattr(container, "sample_path", None)
    if isinstance(held, str):
        paths.append(held)
    for name in ("server_sample_paths", "static_sample_paths"):
        mapping = getattr(container, name, None)
        if isinstance(mapping, Mapping):
            paths.extend(str(value) for value in mapping.values() if isinstance(value, str))
    return paths


def run_disclosure(
    container: Any,
    *,
    entries: Iterable[Any],
    tokens: Mapping[str, Any] | None,
    stages: Any = None,
    unreadable: int = 0,
    partial_reason: str = "",
) -> dict[str, Any] | None:
    """The record of the run ``container`` holds, or ``None`` when it cannot be built.

    The snapshot is taken of the job's own settings (``container.config``) by
    the function the stored settings snapshot is made with
    (``core.settings_overrides.public_snapshot``). The submissions, stagings
    and runtime answers are the container's; tracing is read as the process
    environment and the setting leave it (``core.tracing``). Never raises: a
    record that cannot be built is absent, with a warning, never a guess.
    """
    try:
        from maljan.core.config import Settings
        from maljan.core.settings_overrides import public_snapshot
        from maljan.core.tracing import tracing_in_environment

        settings = getattr(container, "config", None)
        if not isinstance(settings, Settings):
            # No job settings to read where anything went: no record.
            return None

        def _held(name: str) -> list[Any]:
            value = getattr(container, name, None)
            return list(value) if isinstance(value, list) else []

        from maljan.analysis.isolation import noted

        answers = getattr(container, "runtime_answers", None)
        job_key = getattr(container, "job_key", None)
        return disclosure_record(
            public_snapshot(settings, ()),
            entries=entries,
            tokens=tokens,
            agents=stage_agents(stages),
            uploads=_held("sample_uploads"),
            stagings=_held("sample_stagings"),
            runtimes=dict(answers) if isinstance(answers, Mapping) else {},
            tracing=tracing_in_environment(),
            unreadable=unreadable,
            partial_reason=partial_reason,
            opened=noted(str(job_key())) if callable(job_key) else {},
            sample_paths=job_sample_paths(container),
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
    """What a placed row's host is: local (a service name, where only assumed), or outside."""
    if row.get("where") != LOCAL:
        return "(outside this machine)"
    if taken_as_service_name(row.get("host")):
        return "(taken as local: a service name)"
    return "(local)"


def _placed(row: Mapping[str, Any]) -> bool:
    return row.get("where") in (LOCAL, REMOTE)


def _at(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    """`` at <host> (local)``, the mark left off for a row nothing places; ``""`` with no host."""
    if not row.get("host"):
        return ""
    mark = f" {_mark(row)}" if _placed(row) else ""
    return f" at {code(str(row['host']))}{mark}"


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


def _how(row: Mapping[str, Any]) -> str:
    """The transport, as a reader is told it."""
    transport = str(row.get("transport") or "")
    if transport == STDIO_TRANSPORT:
        return "stdio, run on this machine"
    return transport or "transport not recorded"


def _model_line(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    calls = int(row.get("calls") or 0)
    agents = dict(row.get("agents") or {})
    listed = list(row.get("configured_for") or [])
    if not row.get("host") and not row.get("service"):
        by = f" ({_counts(agents)})" if agents else ""
        what = "it" if calls == 1 else "they"
        return f"Model prompts: {count_label(calls, 'call')}{by}{_untold(row, what)}."
    name = code(str(row["host"])) if row.get("host") else str(row["service"])
    local = row.get("where") == LOCAL
    runtime = str(row.get("runtime") or "")
    if calls:
        line = f"Model prompts: {name} {_mark(row)} received {count_label(calls, 'call')}"
        line += f" ({_counts(agents)})" if agents else ""
        if local and runtime:
            line += f"; it answered as a model runtime ({runtime})"
        elif local:
            line += f"; {_NOT_A_RUNTIME}, so where they went cannot be told"
        line += "."
        if listed:
            line += (
                f" It is also in the model list of {_joined(listed)}, which recorded no "
                "answered call there."
            )
        return line
    whose = (
        f"the model list of {_joined(listed)}, which recorded no answered call there"
        if listed
        else "no model list of an agent that called a model"
    )
    if row.get("global"):
        whose = (
            "the endpoint of the global model, which every agent without a model entry of its "
            "own calls" + (f", and in {whose}" if listed else "")
        )
        line = f"Model prompts: {name} {_mark(row)} is {whose}; no answered call is recorded there"
    else:
        line = f"Model prompts: {name} {_mark(row)} is in {whose}"
    if local and runtime:
        return line + f"; it answered as a model runtime ({runtime})."
    return (
        line + "; a request that failed is not always recorded, so whether it received prompts "
        "cannot be told."
    )


def _kinds(row: Mapping[str, Any]) -> str:
    parts = [_counts(dict(row.get("kinds") or {}))] if row.get("kinds") else []
    without = int(row.get("without_indicator") or 0)
    if without:
        parts.append(f"{without} giving no argument declared as an indicator")
    return ", ".join(part for part in parts if part)


def _lookup_line(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    calls = int(row.get("calls") or 0)
    server = _server(str(row.get("source") or ""), code)
    asked = f"was asked {_times(calls)}"
    kinds = _kinds(row)
    if _placed(row) and row.get("host"):
        return (
            f"Lookups: {code(str(row['host']))} {_mark(row)} {asked} through {server} "
            f"({_how(row)}): {kinds}."
        )
    return f"Lookups: {server} ({_how(row)}){_at(row, code)} {asked}: {kinds}{_untold(row)}."


def _upload_line(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    calls = int(row.get("calls") or 0)
    failed = int(row.get("failed") or 0)
    times = _times(calls)
    at = _at(row, code)
    failure = (
        f"; {failed} of the attempts failed or did not finish, so whether "
        f"{'it' if failed == 1 else 'they'} arrived cannot be told"
        if failed
        else ""
    )
    untold = "" if _placed(row) else _untold(row, "it")
    by = row.get("by")
    if by == BY_SANDBOX:
        return (
            f"Sample upload: the sample was submitted {times} to the "
            f"{code(str(row.get('source') or ''))} sandbox{at}{failure}{untold}."
        )
    server = _server(str(row.get("source") or ""), code)
    if by == BY_STAGING:
        return (
            f"Sample upload: the sample was staged {times} to {server} ({_how(row)}){at} through "
            f"its put_sample tools, for its tools to read{failure}{untold}."
        )
    return (
        f"Sample upload: {server} ({_how(row)}){at} was handed the sample {times} by a tool "
        f"declared to send it out of the deployment{failure}{untold}."
    )


def _server_line(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    calls = count_label(int(row.get("calls") or 0), "call")
    server = _server(str(row.get("source") or ""), code)
    if _placed(row) and row.get("host"):
        return (
            f"Tool calls: {server} over {row.get('transport')} at {code(str(row['host']))} "
            f"{_mark(row)}: {calls}."
        )
    return f"Tool calls: {server} ({_how(row)}){_at(row, code)}: {calls}{_untold(row)}."


def _undeclared_line(rows: list[Mapping[str, Any]], code: Callable[[str], str]) -> str:
    total = sum(int(row.get("calls") or 0) for row in rows)
    by_server = ", ".join(
        f"{_server(str(row.get('source') or ''), code)} ({_how(row)}) {int(row.get('calls') or 0)}"
        for row in rows
    )
    hinted = sum(int(row.get("open_world_hints") or 0) for row in rows)
    said = (
        f"; the servers' own hints (openWorldHint) say {count_label(hinted, 'of them', 'of them')} "
        "may reach it"
        if hinted
        else ""
    )
    return (
        f"Tool calls: {count_label(total, 'call')} to tools that declare no effects "
        f"({by_server}): whether they reached the network cannot be told{said}."
    )


def _store_line(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    store = f"the {code(str(row.get('backend') or ''))} case-memory store"
    if _placed(row) and row.get("host"):
        return (
            f"Case memory: {store} at {code(str(row['host']))} {_mark(row)}, which this job "
            "reads similar cases from and stores its case in."
        )
    return f"Case memory: {store}{_at(row, code)}{_untold(row, 'its cases')}."


TRACING_SENTENCE = (
    "Tracing is on (the setting `langchain_tracing_v2`, or the process environment): every "
    "prompt and answer was also sent to the tracing service, whose address the settings do "
    "not record, so where they went cannot be told."
)


def _unreadable_line(count: int) -> str:
    return (
        f"The ledger held {count_label(count, 'row')} the report could not read, so where "
        f"{'its call' if count == 1 else 'their calls'} went cannot be told."
    )


def _reach(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    kinds = ", ".join(str(k) for k in row.get("kinds") or [])
    if not row.get("source"):
        return f"the configured sources ({kinds}), not named here because {row.get('why')}"
    name, path = _source_name(row, code)
    hosts = [str(h) for h in row.get("hosts") or []]
    if row.get("server"):
        how = _how(row)
        at = f" at {code(hosts[0])}" if hosts else ""
        where = f"through {_server('mcp:' + str(row['server']), code)} ({how}){at}"
    elif hosts:
        where = "at " + ", ".join(code(h) for h in hosts)
    else:
        where = "with no host named"
    note = f" ({path}), with no key" if path else ""
    return f"{name} ({kinds}) {where}{note}"


def _source_name(row: Mapping[str, Any], code: Callable[[str], str]) -> tuple[str, str]:
    """A source as the block names it, and the path a lookup with no key takes (else ``""``)."""
    from maljan.enrichment.whois_client import REGISTRY_LOOKUPS

    source = str(row.get("source") or "")
    if source in REGISTRY_LOOKUPS:
        return REGISTRY_LOOKUPS[source]
    return f"source {code(source)}", ""


def _asked_parts(asked: list[Mapping[str, Any]], code: Callable[[str], str]) -> str:
    parts = []
    for row in asked:
        kinds = _counts(dict(row.get("kinds") or {}))
        name, path = _source_name(row, code)
        name = f"{name}, {path}" if path else name
        if row.get("host"):
            place = f"{code(str(row['host']))} {_mark(row)}"
        else:
            place = f"a tool server{_untold(row, 'the questions')}"
        failed = int(row.get("failed") or 0)
        tail = (
            f", {failed} of them failed in transport or did not finish and may have arrived"
            if failed
            else ""
        )
        parts.append(f"{place} about {kinds} ({name}{tail})")
    return "; ".join(parts)


def _withheld_lines(held: Mapping[str, Any], code: Callable[[str], str]) -> list[str]:
    """One sentence per source tool its host withheld, so it was never asked."""
    return [
        f"Enrichment: {code(str(row.get('server') or ''))}'s tool "
        f"{code(str(row.get('tool') or ''))} was not asked, because its host withheld it: "
        f"{row.get('reason') or 'no reason was given'}."
        for row in held.get("withheld") or []
        if isinstance(row, Mapping)
    ]


def _enrichment_lines(held: Mapping[str, Any], code: Callable[[str], str]) -> list[str]:
    return _enrichment_state_lines(held, code) + _withheld_lines(held, code)


def _enrichment_state_lines(held: Mapping[str, Any], code: Callable[[str], str]) -> list[str]:
    state = held.get("state")
    asked = [row for row in held.get("asked") or [] if isinstance(row, Mapping)]
    if state == ENRICHMENT_DONE:
        if not asked:
            return ["Enrichment: the follow-up job ran and asked no service about an indicator."]
        return ["Enrichment: the follow-up job asked " + _asked_parts(asked, code) + "."]
    if state == ENRICHMENT_STOPPED:
        what = f" after asking {_asked_parts(asked, code)}" if asked else ""
        return [
            f"Enrichment: the follow-up job stopped part-way{what}; a question in flight when it "
            "stopped is counted as not finished."
        ]
    if state == ENRICHMENT_RUNNING:
        earlier = f" An earlier enrichment asked {_asked_parts(asked, code)}." if asked else ""
        return [
            "Enrichment: a follow-up job began sending questions about the report's indicators "
            "and recorded nothing after that, so where its questions went cannot be told." + earlier
        ]
    reach = [row for row in held.get("may_reach") or [] if isinstance(row, Mapping)]
    named = "; ".join(_reach(row, code) for row in reach) or "no source"
    return [
        "Enrichment: a follow-up job queued after this report may send the report's public "
        f"domains and addresses to {named}. What it sends is added here once it has run."
    ]


def _nothing_sentence(record: Mapping[str, Any], code: Callable[[str], str]) -> str:
    """ "Nothing left this machine", with what it rests on."""
    parts: list[str] = []
    models = [row for row in record.get("models") or [] if isinstance(row, Mapping)]
    if models:
        named = ", ".join(f"{code(str(row.get('host')))} ({row.get('runtime')})" for row in models)
        parts.append(
            "every model endpoint in this run's settings is a local address that answered as a "
            f"model runtime: {named} ({RUNTIME_ASSUMPTION})"
        )
    local_servers = list(record.get("local_servers") or [])
    if local_servers:
        servers = ", ".join(_server(str(source), code) for source in local_servers)
        parts.append(
            f"the local tool servers called ({servers}) were taken as local by their tools' "
            "declarations"
        )
    stores = [row for row in record.get("stores") or [] if isinstance(row, Mapping)]
    if stores:
        parts.append("the case-memory store is at a local address")
    else:
        parts.append("the case-memory store is kept in the process or not configured")
    uploads = [row for row in record.get("uploads") or [] if isinstance(row, Mapping)]
    if uploads:
        parts.append("the sample went only to local addresses")
    parts.append("no lookup was asked, and tracing is off")
    return "Nothing left this machine. This rests on: " + "; ".join(parts) + "."


def disclosure_lines(record: Any, code: Callable[[str], str] = _code) -> list[str]:
    """The block's sentences, one per line, for a list; ``[]`` for no record.

    ``code`` writes a host or a key as printed; the report renderer passes one
    that keeps an address the run's settings name from its closing defang pass.
    """
    if not isinstance(record, Mapping) or "models" not in record:
        return []
    lines: list[str] = []
    if record.get("nothing_left"):
        lines.append(_nothing_sentence(record, code))
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
    undeclared = [row for row in record.get("undeclared") or [] if isinstance(row, Mapping)]
    if undeclared:
        lines.append(_undeclared_line(undeclared, code))
    unreadable = int(record.get("unreadable_entries") or 0)
    if unreadable:
        lines.append(_unreadable_line(unreadable))
    if record.get("tracing"):
        lines.append(TRACING_SENTENCE)
    enrichment = record.get("enrichment")
    if isinstance(enrichment, Mapping):
        lines.extend(_enrichment_lines(enrichment, code))
    return lines


# Why a stored run summary carries no record (:func:`not_built`).
NOT_BUILT_REPORTING_OFF = (
    "reporting is off for this job (reporting.enabled), and the block is built by the report step"
)
NOT_BUILT_NO_SUMMARY = (
    "the judge wrote no run summary (the mock provider's judge writes none), and the block is "
    "built on it"
)
NOT_BUILT_UNREAD = "the block could not be built from the run's records"


def not_built(reason: str) -> dict[str, Any]:
    """The record of a run whose block was not built, and why: told apart from a stored run."""
    return {"not_built": str(reason)}


def not_built_line(block: str, record: Any) -> str:
    """One line naming a block whose record was not built and why; ``""`` for any other record."""
    if isinstance(record, Mapping) and "not_built" in record and "v" not in record:
        return f"The {block} block was not built: {record['not_built']}."
    return ""


def not_built_reason(*, reporting: bool, summary_written: bool) -> str:
    """Why a run's record is absent: reporting off, no run summary, or a build that failed."""
    if not reporting:
        return NOT_BUILT_REPORTING_OFF
    if not summary_written:
        return NOT_BUILT_NO_SUMMARY
    return NOT_BUILT_UNREAD
