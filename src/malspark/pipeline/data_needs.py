"""Whether an analysis stage holds any of the data its analysts declare they read.

A stage of analysts that each read only a kind of data the job does not have
(a network stage on a job with no capture and no network rows, a dynamic stage
on a job no sandbox ran for) would spend a loop per analyst writing that there
is nothing to read. Such a stage is skipped before any of its analysts is
built, and the stage says why (``nodes.make_stage_agent_node``).

The decision reads declarations only, never an agent's or a tool's name:

* **What an analyst is handed** is its definition's ``data_sources``, or, with
  none named, the slice its role has always been handed
  (``container.load_data_for_agent``). A role handed the sample itself
  (``nodes.SAMPLE_FED_ROLES``) always holds data: the sample always exists.
* **What its tools read** is declared by their source. The job's sandbox
  report source (``ToolRef(kind="sandbox")``) reads the sandbox report. The
  tool servers are every server the agent reaches, however it is bound: a
  reference by key, a capability resolved to the servers that serve it, and a
  server whose own ``agents`` list names it, less what its profile withholds
  (``agents.composition.servers_bound_to``). A server reads only job data
  when every role its declaration names is one :data:`ROLE_READS` ties to a
  kind; any other role, no role at all, a static provider and an ask of
  another agent are read as reading data the job may hold, so the analyst
  holding one is never skipped.

``reference`` is read as no job data: such a server answers lookups over what
the caller hands it (a technique, an API name, a command line, a text), and
none of its tools takes a path. It may be told the sample's hash, but only to
leave the sample's own record out of a similarity answer, which is no reading
of the sample.

An analyst holds data when anything it is handed or any tool it holds reads a
kind the job has. A stage is skipped only when every one of its analysts holds
none, and never while a stage it depends on and injects found something.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

# The kinds of job data a declaration names, in the words a skip reason uses.
SAMPLE = "the sample"
STORED = "stored data for this sample"
SANDBOX_REPORT = "a sandbox report"
SANDBOX_TARGET = "the sandbox report's target block"
NETWORK = "network data"
CAPTURE = "a packet capture"

# The roles a tool source declares (``MCPServerConfig.roles``) that tie what
# its tools read to one kind of job data, or to none (``None``: a reference
# over what the caller hands it, such as a technique catalogue). Declaration
# vocabulary, never a server.
ROLE_READS: Mapping[str, str | None] = {"capture": CAPTURE, "reference": None}

# Each data source an agent may name (``config.DATA_SOURCES``) and the kind it
# reads. ``sample.chunks`` is the stored per-sample data of the agent's own
# kind, except for a role handed the sample itself.
SOURCE_READS: Mapping[str, str] = {
    "sample.path": SAMPLE,
    "sample.chunks": STORED,
    "sandbox.target": SANDBOX_TARGET,
    "sandbox.behavior": SANDBOX_REPORT,
    "sandbox.network": NETWORK,
    "sandbox.full": SANDBOX_REPORT,
}


@dataclass(frozen=True)
class Reads:
    """What one analyst reads: the job data kinds, and whether anything it holds is untied.

    ``untied`` is true when the analyst holds something no declaration ties to
    a kind of job data; such an analyst is never skipped.
    """

    kinds: frozenset[str] = field(default_factory=frozenset)
    untied: bool = False


@dataclass(frozen=True)
class JobData:
    """The kinds of data one job holds before a stage starts.

    ``stored`` answers whether stored per-sample data exists for an agent.
    """

    held: frozenset[str]
    sandbox_report: bool
    stored: Callable[[str], bool] = lambda _agent: True

    def holds(self, kind: str, agent: str) -> bool:
        if kind == STORED:
            return bool(self.stored(agent))
        return kind in self.held


def _filled(value: Any) -> bool:
    """Whether ``value`` holds anything: a non-empty collection or string, any other set value."""
    if value is None:
        return False
    if isinstance(value, str | bytes | Mapping | list | tuple | set | frozenset):
        return bool(value)
    return True


def job_data(
    sandbox_report: Any,
    captures: Sequence[str] = (),
    stored: Callable[[str], bool] | None = None,
) -> JobData:
    """What a job holds: the sample always, and what its sandbox report and captures add.

    ``sandbox_report`` is the run's report document when a sandbox ran
    (``sandbox_status.observed_report``), else ``None``. Network data is any
    filled value of the report's network block, of whatever kind, or a
    capture.
    """
    from malspark.schemas.sandbox_document import place

    held = {SAMPLE}
    report = sandbox_report if isinstance(sandbox_report, dict) and sandbox_report else None
    if report is not None:
        held.add(SANDBOX_REPORT)
        if _filled(place(report, "target")):
            held.add(SANDBOX_TARGET)
        network = report.get("network")
        if isinstance(network, Mapping) and any(_filled(value) for value in network.values()):
            held.add(NETWORK)
    if captures:
        held.update((CAPTURE, NETWORK))
    return JobData(
        held=frozenset(held),
        sandbox_report=report is not None,
        stored=stored or (lambda _agent: True),
    )


def _role_slice(role: str, sandbox_report: bool) -> str:
    """The kind a role with no ``data_sources`` is handed (``container._legacy_role_data``)."""
    if not sandbox_report:
        return STORED
    return NETWORK if role == "network" else SANDBOX_REPORT


def _source_reads(roles: Iterable[str]) -> tuple[frozenset[str], bool]:
    """The kinds a tool source of ``roles`` reads, and whether it is untied."""
    declared = [str(role) for role in roles]
    if not declared or any(role not in ROLE_READS for role in declared):
        return frozenset(), True
    return frozenset(k for k in (ROLE_READS[role] for role in declared) if k is not None), False


def agent_reads(
    definition: Any,
    role: str,
    *,
    sample_fed: bool,
    sandbox_report: bool,
    servers: Iterable[str] | None,
    server_roles: Callable[[str], Sequence[str] | None],
) -> Reads:
    """What the analyst of ``definition`` reads, from its declarations alone.

    ``servers`` is every tool server the agent reaches (``None`` where that
    cannot be read: untied), and ``server_roles`` answers a server's declared
    roles, ``None`` where its declaration cannot be read (untied). The
    definition's own server and capability references are among ``servers``
    and are not read again here. A definition that cannot be read is untied.
    """
    if definition is None:
        return Reads(untied=True)
    kinds: set[str] = set()
    if sample_fed:
        kinds.add(SAMPLE)
    sources = [str(s) for s in (getattr(definition, "data_sources", None) or ())]
    if sources:
        for source in sources:
            kind = SOURCE_READS.get(source)
            if kind is None:
                return Reads(untied=True)
            kinds.add(kind)
    elif not sample_fed:
        kinds.add(_role_slice(role, sandbox_report))
    if servers is None:
        return Reads(kinds=frozenset(kinds), untied=True)
    for ref in getattr(definition, "tools", None) or ():
        ref_kind = str(getattr(ref, "kind", "") or "")
        if ref_kind == "sandbox":
            kinds.add(SANDBOX_REPORT)
        elif ref_kind not in ("mcp", "capability"):
            # A static provider reads the sample; an ask reaches an agent of
            # its own, whose data this one cannot see.
            return Reads(kinds=frozenset(kinds), untied=True)
    for server in sorted(str(name) for name in servers):
        roles = server_roles(server)
        tied, untied = _source_reads(roles) if roles is not None else (frozenset(), True)
        if untied:
            return Reads(kinds=frozenset(kinds), untied=True)
        kinds.update(tied)
    return Reads(kinds=frozenset(kinds))


def missing_kinds(reads: Reads, job: JobData, agent: str) -> frozenset[str] | None:
    """The kinds ``agent`` reads that the job lacks, or ``None`` when it holds data."""
    if reads.untied or not reads.kinds:
        return None
    if any(job.holds(kind, agent) for kind in reads.kinds):
        return None
    return reads.kinds


def dataless_reason(missing: Mapping[str, frozenset[str]]) -> str:
    """The skip reason for a stage whose analysts each lack every kind named in ``missing``."""
    kinds = sorted({kind for lacking in missing.values() for kind in lacking})
    return f"the job holds none of the data its analysts read ({', '.join(kinds)})"
