"""The triage pack: the deterministic tools, run by the pipeline, written to the ledger.

A human analyst runs the same dozen commands on every sample before opening a
disassembler: what is it, what are its hashes, is it signed, what does the
header say, what strings and indicators does it carry, which rules fire, what
did the sandbox see, what does a reputation service know about the hash. The
live runs showed that the local model rarely asks for any of it, and a fact a
model may or may not ask for is not a fact the run can rely on.

So the pipeline establishes them itself. Each tool call here is an ordinary
``LedgerEntry`` with ``agent="pipeline"`` and ``server="pipeline"``: it has an
id the analysts, the judge and the report cite exactly as they cite a call the
model made, it renders on the console's ledger tab like any other entry, and
the tools stay callable on demand for anyone who wants more than the head.

Three rules hold throughout. The pack states facts and draws no conclusion:
a tool's output is recorded as the tool returned it, and nothing here rewrites
what a model later says. The order is fixed, so the ids a given sample produces
are the same from one run to the next and a golden can pin them. And nothing
in the pack can fail the job: a tool that raises, answers with an error or is
unavailable becomes an entry with ``ok=False`` and a degradation reason, and
the next tool runs.

The in-process calls go straight to ``maljan.tools``, the same code the
analysis sidecar serves, rather than through a subprocess of it. The one
network call — the reputation lookup — goes through the tool server exactly as
an agent's call does, and is recorded under that server rather than under the
pipeline, because which server a ledger entry came from is how the rest of the
pipeline knows the question was asked.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

from maljan.agents.evidence_recorder import EvidenceRecorder, result_text
from maljan.core.logger import logger
from maljan.extractors.sample_identity import ARCHIVE_FILE_TYPES, DOCUMENT_FILE_TYPES
from maljan.pipeline.conditions import TriageFacts
from maljan.providers import sandbox_tools
from maljan.schemas.evidence import LedgerEntry, apply_budget
from maljan.tools import binary, identify, knowledge, pcap, rules, strings

__all__ = [
    "PIPELINE",
    "CapaSettings",
    "PackInputs",
    "PackResult",
    "ReputationLookup",
    "failure_reason",
    "malicious_count",
    "run_pack",
]

# The agent and server every in-process entry of the pack is recorded under.
PIPELINE = "pipeline"

# The shortest printable run the strings head keeps. Six characters is where
# a run stops being an accident of the byte stream and starts being a token
# a person would read.
STRINGS_MIN_LEN = 6

# The format tool for each routed file type. A type this table does not name
# gets no format entry: the identity entry already says what the sample is,
# and a guess at a parser would be a guess.
_FORMAT_TOOLS: dict[str, tuple[str, Callable[..., dict[str, Any]]]] = {
    "pe": ("pe_info", binary.pe_info),
    "elf": ("elf_info", binary.elf_info),
    "mach-o": ("macho_info", binary.macho_info),
    "apk": ("apk_info", binary.apk_info),
    "dex": ("apk_info", binary.apk_info),
    **{name: ("document_info", binary.document_info) for name in DOCUMENT_FILE_TYPES},
    **{name: ("archive_list", binary.archive_list) for name in ARCHIVE_FILE_TYPES},
    "jar": ("archive_list", binary.archive_list),
}

# How a reputation answer says how many engines flagged the hash. The
# structured form is VirusTotal's own ``last_analysis_stats``; the prose form
# is what the threat-intel sidecar writes ("55/70 detections").
_DETECTIONS_RE = re.compile(r"\b(\d+)\s*/\s*\d+\s+detections?\b", re.IGNORECASE)


def failure_reason(tool: str) -> str:
    """The degradation reason one failed entry of the pack contributes."""
    return f"triage.{tool}_failed"


@dataclass(frozen=True)
class CapaSettings:
    """What ``capa`` is run with: the operator's rule sources and budget."""

    rules_dir: str
    signatures_dir: str
    timeout_s: int
    backend: str = "auto"


@dataclass(frozen=True)
class PackInputs:
    """Everything the pack reads, gathered by the node so the pack itself is a function."""

    sample_path: str
    sha256: str
    file_type: str
    strings_head: int
    capa: CapaSettings
    sandbox_report: dict[str, Any] | None = None
    evidence_budget_bytes: int = 0


# The one reputation call, made by the node through the tool server. It takes
# the recorder so the entry it writes lands in the pack's own sequence, and it
# answers with the entry it wrote.
ReputationLookup = Callable[[EvidenceRecorder], LedgerEntry]

# The exact-match attribution step, made by the node when a function-hash
# store and a provider that can hash functions are both present. It answers
# with the tool's arguments and its result, and the pack records them.
FunctionMatches = Callable[[], tuple[dict[str, Any], dict[str, Any]]]


@dataclass
class PackResult:
    """What one run of the pack produced."""

    entries: list[LedgerEntry] = field(default_factory=list)
    facts: TriageFacts = field(default_factory=TriageFacts)
    failed: list[str] = field(default_factory=list)
    duration_ms: int = 0

    @property
    def degradation_reasons(self) -> list[str]:
        return [failure_reason(tool) for tool in self.failed]

    def to_state(self) -> dict[str, Any]:
        """The channel value the node writes: the facts, the counts, the reasons."""
        return {
            **self.facts.to_dict(),
            "entries": len(self.entries),
            "failed": len(self.failed),
            "duration_ms": self.duration_ms,
            "degradation_reasons": self.degradation_reasons,
        }


def malicious_count(output: str) -> int | None:
    """How many engines a reputation answer says flagged the hash, or ``None``.

    ``None`` is the honest answer for a hash the service does not know, a
    lookup that failed and an answer in a shape this does not read. Zero
    means the service answered and counted nothing, which is a different
    fact and the one a condition wants to tell apart.
    """
    text = (output or "").strip()
    if not text:
        return None
    parsed: Any = None
    if text[0] in "{[":
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            parsed = None
    found = _stats_malicious(parsed)
    if found is not None:
        return found
    match = _DETECTIONS_RE.search(text)
    return int(match.group(1)) if match else None


def _stats_malicious(value: Any) -> int | None:
    """``last_analysis_stats.malicious`` wherever it sits in a VirusTotal answer."""
    if isinstance(value, dict):
        stats = value.get("last_analysis_stats")
        if isinstance(stats, dict) and isinstance(stats.get("malicious"), int):
            return int(stats["malicious"])
        for child in value.values():
            found = _stats_malicious(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _stats_malicious(child)
            if found is not None:
                return found
    return None


class _Pack:
    """One run of the pack over one sample, step by step, in the fixed order."""

    def __init__(
        self,
        recorder: EvidenceRecorder,
        inputs: PackInputs,
        *,
        reputation: ReputationLookup | None,
        function_matches: FunctionMatches | None,
    ) -> None:
        self.recorder = recorder
        self.inputs = inputs
        self.reputation = reputation
        self.function_matches = function_matches
        self.result = PackResult()
        self.has_signature = False
        self.yara_hits = 0
        self.capa_hits = 0
        self.reputation_malicious: int | None = None

    # -- recording --------------------------------------------------------

    def record(
        self, tool: str, args: dict[str, Any], call: Callable[[], Any]
    ) -> dict[str, Any] | None:
        """Run one tool, write its entry, and hand back its dict when it gave one.

        A tool that answers with an ``error`` key did not establish its fact,
        and is recorded as a failure exactly as one that raised: the output is
        kept either way, because what the tool said is the evidence.
        """
        started, wall_clock = time.monotonic(), time.time()
        try:
            value = call()
        except Exception as exc:  # noqa: BLE001 — a failed tool is an entry, never a crash
            message = f"{type(exc).__name__}: {exc}"
            entry = self.recorder.record(
                tool=tool,
                args=args,
                server=PIPELINE,
                output=message,
                ok=False,
                error=message,
                started_at=wall_clock,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            self._failed(tool, entry)
            return None
        error = value.get("error") if isinstance(value, dict) else None
        entry = self.recorder.record(
            tool=tool,
            args=args,
            server=PIPELINE,
            output=result_text(value),
            ok=not error,
            error=str(error) if error else None,
            started_at=wall_clock,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        if error:
            self._failed(tool, entry)
            return None
        return value if isinstance(value, dict) else None

    def _failed(self, tool: str, entry: LedgerEntry) -> None:
        self.result.failed.append(tool)
        logger.warning("triage pack: %s failed (%s).", tool, entry.error)

    # -- the steps --------------------------------------------------------

    def run(self) -> PackResult:
        started = time.monotonic()
        path = self.inputs.sample_path
        identity = self.record(
            "identify_file", {"path": path}, lambda: identify.identify_file(path)
        )
        self.record("hashes", {"path": path}, lambda: identify.hashes(path))
        signing = self.record("signing_info", {"path": path}, lambda: identify.signing_info(path))
        self.has_signature = _carries_signature(signing)

        format_facts = self._format_facts(identity)
        self._strings_and_iocs()
        self._rules()
        self._catalogue_lookups(format_facts)
        self._sandbox_summary()
        self._reputation()
        self._function_matches()

        # The recorder holds every entry in the order the ids were issued,
        # the reputation call's included, so it is the one list to publish.
        self.result.entries = list(self.recorder.entries)
        self.result.duration_ms = int((time.monotonic() - started) * 1000)
        self.result.facts = TriageFacts(
            has_signature=self.has_signature,
            reputation_malicious=self.reputation_malicious,
            yara_hits=self.yara_hits,
            capa_hits=self.capa_hits,
        )
        return self.result

    def _format_facts(self, identity: dict[str, Any] | None) -> dict[str, Any] | None:
        """The header facts for the routed format, falling back to what identity saw."""
        routed = (self.inputs.file_type or "").strip().lower()
        if routed in ("", "unknown") and identity:
            routed = str(identity.get("file_type") or "").strip().lower()
        selected = _FORMAT_TOOLS.get(routed)
        if selected is None:
            return None
        tool, call = selected
        path = self.inputs.sample_path
        return self.record(tool, {"path": path}, lambda: call(path))

    def _strings_and_iocs(self) -> None:
        path = self.inputs.sample_path
        head = max(1, int(self.inputs.strings_head))
        args = {"path": path, "min_len": STRINGS_MIN_LEN, "limit": head}
        self.record(
            "strings", args, lambda: strings.strings(path, min_len=STRINGS_MIN_LEN, limit=head)
        )
        self.record("iocs_from_file", {"path": path}, lambda: strings.iocs_from_file(path))

    def _rules(self) -> None:
        path = self.inputs.sample_path
        scanned = self.record("yara_scan", {"path": path}, lambda: rules.yara_scan(path=path))
        if scanned is not None:
            self.yara_hits = len(scanned.get("matches") or [])
        capa = self.inputs.capa
        capa_args = {
            "path": path,
            "timeout_s": capa.timeout_s,
            "backend": capa.backend,
            "rules_dir": capa.rules_dir,
            "signatures_dir": capa.signatures_dir,
        }
        found = self.record(
            "capa",
            capa_args,
            lambda: rules.capa(
                path,
                timeout_s=capa.timeout_s,
                backend=capa.backend,
                rules_dir=capa.rules_dir,
                signatures_dir=capa.signatures_dir,
            ),
        )
        if found is not None:
            self.capa_hits = len(found.get("capabilities") or [])
        report = self.inputs.sandbox_report
        if report:
            self.record(
                "sigma_match_sandbox",
                {"report": "<the job's sandbox report>"},
                lambda: rules.sigma_match_sandbox(report),
            )

    def _catalogue_lookups(self, format_facts: dict[str, Any] | None) -> None:
        names = _imported_names(format_facts)
        if names:
            self.record(
                "api_capability",
                {"api_names": names},
                lambda: knowledge.api_capability(names),
            )
        report = self.inputs.sandbox_report
        if report:
            commands = _command_lines(report)
            self.record(
                "lolbin_lookup",
                {"command_lines": commands},
                lambda: knowledge.lolbin_lookup(commands),
            )

    def _sandbox_summary(self) -> None:
        report = self.inputs.sandbox_report
        if not report:
            return
        for tool, call in (
            ("sandbox_processes", sandbox_tools.sandbox_processes),
            ("sandbox_network", sandbox_tools.sandbox_network),
            ("sandbox_signatures", sandbox_tools.sandbox_signatures),
            ("sandbox_dropped_files", sandbox_tools.sandbox_dropped_files),
            ("sandbox_channels", sandbox_tools.sandbox_channels),
        ):
            self.record(tool, {}, partial(call, report))
        capture = _capture_path(report)
        if capture:
            self.record("pcap_summary", {"path": capture}, lambda: pcap.pcap_summary(capture))

    def _reputation(self) -> None:
        """The one network call, or the entry that says why there was none.

        A skip — no reputation server enabled, or the setting off — is an
        entry under the pipeline with ``ok=False`` and no degradation reason:
        the run is not thinner than it was configured to be. A call that was
        made and failed is recorded under the server it was made to, and that
        one does degrade the run.
        """
        if self.reputation is None:
            return
        try:
            entry = self.reputation(self.recorder)
        except Exception as exc:  # noqa: BLE001 — the lookup degrades, the pack goes on
            message = f"{type(exc).__name__}: {exc}"
            entry = self.recorder.record(
                tool="reputation",
                args={"sha256": self.inputs.sha256},
                server=PIPELINE,
                output=message,
                ok=False,
                error=message,
                started_at=time.time(),
            )
            self._failed("reputation", entry)
            return
        if not entry.ok:
            if entry.server != PIPELINE:
                self._failed(entry.tool, entry)
            return
        self.reputation_malicious = malicious_count(entry.output)

    def _function_matches(self) -> None:
        if self.function_matches is None:
            return
        try:
            args, value = self.function_matches()
        except Exception as exc:  # noqa: BLE001
            message = f"{type(exc).__name__}: {exc}"
            entry = self.recorder.record(
                tool="function_matches",
                args={"exclude_sample_id": self.inputs.sha256},
                server=PIPELINE,
                output=message,
                ok=False,
                error=message,
                started_at=time.time(),
            )
            self._failed("function_matches", entry)
            return
        if "reason" in value and not value.get("matches"):
            value = {**value, "error": value["reason"]}
        self.record("function_matches", args, lambda: value)


def run_pack(
    recorder: EvidenceRecorder,
    inputs: PackInputs,
    *,
    reputation: ReputationLookup | None = None,
    function_matches: FunctionMatches | None = None,
) -> PackResult:
    """Run the whole pack over ``inputs``, recording every step on ``recorder``.

    Synchronous on purpose: every in-process tool is synchronous and capa
    spawns a subprocess, so the node runs this on a worker thread the way the
    report node runs the evidence-only provider.
    """
    result = _Pack(recorder, inputs, reputation=reputation, function_matches=function_matches).run()
    budget = int(inputs.evidence_budget_bytes or 0)
    trimmed, _ = apply_budget(result.entries, budget)
    if trimmed:
        logger.warning(
            "triage pack: %d of %d entries exceeded the %d-byte budget and kept only "
            "their call record.",
            trimmed,
            len(result.entries),
            budget,
        )
    return result


# ---------------------------------------------------------------------------
# Reading the tools' answers
# ---------------------------------------------------------------------------


def _carries_signature(signing: dict[str, Any] | None) -> bool:
    """Whether any of the three signature blocks reports a signature present."""
    if not signing:
        return False
    for key in ("authenticode", "apk", "macho"):
        block = signing.get(key)
        if isinstance(block, dict) and block.get("present"):
            return True
    return False


def _imported_names(format_facts: dict[str, Any] | None) -> list[str]:
    """The imported function names a format tool listed, once each, in order.

    Ordinal-only rows carry no name to look up and are left out; the import
    table itself is in the format entry for anyone who wants them.
    """
    if not format_facts:
        return []
    names: list[str] = []
    seen: set[str] = set()
    for key in ("imports", "delay_imports"):
        for row in format_facts.get(key) or []:
            if not isinstance(row, dict):
                continue
            name = str(row.get("function") or "").strip()
            if not name or name.startswith("Ordinal_") or name in seen:
                continue
            seen.add(name)
            names.append(name)
    return names


def _command_lines(report: dict[str, Any]) -> list[str]:
    """Every distinct command line the sandbox's process tree recorded."""
    rows = sandbox_tools.sandbox_processes(report).get("processes") or []
    out: list[str] = []
    seen: set[str] = set()
    for row in rows:
        command = str(row.get("command_line") or "").strip() if isinstance(row, dict) else ""
        if command and command not in seen:
            seen.add(command)
            out.append(command)
    return out


def _capture_path(report: dict[str, Any]) -> str:
    """The capture the sandbox provider fetched beside the report, when it did."""
    network = report.get("network")
    path = network.get("pcap_local_path") if isinstance(network, dict) else None
    if isinstance(path, str) and path and Path(path).is_file():
        return path
    return ""
