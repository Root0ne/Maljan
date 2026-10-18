"""Validation with other tools: one scenario at a time, each a function, each gated.

Every scenario builds its own settings, runs the rehearsal in this process
(``scripts.rehearsal.inprocess.rehearse``: the stub model, the real pipeline,
the repository's own sidecars), and holds each run to

* the base gate: every ``checklist.check_run`` check passes, but a row the
  rehearsal matrix pins for the same scenario and wire
  (``tests/fixtures/rehearsal/known_defects.json``);
* the evidence-reach readings E1–E6 for the newcomer's entries
  (``scripts.validation.reach``), the rows the scenario requires;
* the scenario's own gates.

Each run writes ``<out>/<scenario>/<run>.{json,md}`` (the checklist's own JSON
and Markdown, the reach table and the gates) and each scenario
``<out>/<scenario>.{json,md}``. The exit status is non-zero when any gate of
any run missed. ``<out>`` may hold no path segment starting with a dot: the
radare2 provider refuses such paths, and a worktree path holds one.

Scenarios (the plan's letters): ``a`` an r2-only team; ``b`` a second
decompiler of another make over MCP (the JVM one — named explicitly, never
part of the default set); ``c1`` uploaded sandbox reports in two formats;
``d`` a third memory backend; ``e`` a reputation server of the operator's;
``f1``–``f3`` an operator kit whose tool names collide with built-in ones;
``c2`` and ``f4`` are placeholders until the work they need is merged.

This is a script, not a test module: the suite's live test count is read by
others and is not moved by it. No model is paid, nothing reaches a network;
the sample is the rehearsal's synthetic image and the sandbox reports are JSON
fixtures.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import functools
import json
import os
import shutil
import sys
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.rehearsal.checklist import RunRecord, as_json, as_markdown, check_run  # noqa: E402
from scripts.rehearsal.inprocess import Rehearsal, rehearse  # noqa: E402
from scripts.validation import reach as reach_mod  # noqa: E402

FIXTURES = _ROOT / "tests" / "fixtures"
REP_STUB = FIXTURES / "validation" / "rep_stub.py"
KIT_STUB = FIXTURES / "validation" / "kit_stub.py"
SANDBOX_FIXTURES = FIXTURES / "sandbox"
PINS_FILE = FIXTURES / "rehearsal" / "known_defects.json"
# Product gaps a validation run is known to show: each row excuses one miss of
# one run, matched exactly (scenario, run, wire, check, detail), and names the
# gap it stands for. Nothing is excused by a pattern.
GAP_PINS_FILE = FIXTURES / "validation" / "known_defects.json"
JOB_DEADLINE_S = 600.0
ALL_E = ("E1", "E2", "E3", "E4", "E5", "E6")

Gates = dict[str, tuple[bool, str]]


# ---------------------------------------------------------------------------
# Context and one run
# ---------------------------------------------------------------------------


@dataclass
class Context:
    """Where results go and where the external tools a scenario plugs in are found."""

    out: Path
    wires: tuple[str, ...] = ("openai", "anthropic")
    python: str = sys.executable
    r2mcp: str = ""
    # Where r2mcp was looked for, said when a scenario needing it is skipped.
    r2mcp_searched: str = "--r2mcp"
    pyghidra: str = ""
    ghidra_dir: str = ""
    java_home: str = ""


@dataclass
class RunResult:
    """One run's outcome against its gates."""

    scenario: str
    name: str
    wire: str
    status: str
    base_failures: dict[str, str]
    excused: dict[str, str]
    reach: list[dict[str, Any]]
    required: dict[str, tuple[str, ...]]
    gates: Gates
    notes: dict[str, Any] = field(default_factory=dict)
    # Misses a product gap pin excuses: check -> the gap's reference.
    pinned: dict[str, str] = field(default_factory=dict)

    @property
    def reach_misses(self) -> list[str]:
        return [k.removeprefix("reach:") for k in self.reach_miss_details]

    @property
    def reach_miss_details(self) -> dict[str, str]:
        misses = {}
        for row in self.reach:
            for e in self.required.get(row["server"], ()):
                if not row[e]["ok"]:
                    misses[f"reach:{row['server']}:{e}"] = str(row[e].get("why") or "")
        return misses

    @property
    def misses(self) -> dict[str, str]:
        """Every miss of this run, check -> detail, pinned or not."""
        return {
            **{f"base:{k}": v for k, v in self.base_failures.items()},
            **self.reach_miss_details,
            **{k: d for k, (ok, d) in self.gates.items() if not ok},
        }

    @property
    def unpinned(self) -> dict[str, str]:
        return {k: v for k, v in self.misses.items() if k not in self.pinned}

    @property
    def held_back(self) -> bool:
        """A run that did not happen: skipped for a missing tool, or pending other work."""
        return self.status in ("skipped", "pending")

    @property
    def ok(self) -> bool:
        return not self.unpinned and not self.held_back

    @property
    def label(self) -> str:
        if self.held_back:
            return self.status.upper()
        if self.unpinned:
            return "MISS"
        return "ok (pinned gap)" if self.pinned else "ok"

    def summary(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "run": self.name,
            "wire": self.wire,
            "ok": self.ok,
            "label": self.label,
            "job_status": self.status,
            "base_failures": self.base_failures,
            "excused": self.excused,
            "reach_misses": self.reach_misses,
            "gates": {k: {"ok": ok, "detail": d} for k, (ok, d) in self.gates.items()},
            "pinned": {k: {"gap": g, "detail": self.misses.get(k)} for k, g in self.pinned.items()},
            "unpinned": self.unpinned,
            "notes": self.notes,
        }


# Where an r2mcp installed by hand outside PATH and radare2's own install
# places is commonly kept (``static.r2.binary_path`` names it in settings).
KNOWN_R2MCP = ("~/tools/bin/r2mcp",)


def find_r2mcp(given: str = "") -> tuple[str, str]:
    """The r2mcp to use, and every place looked, in words.

    ``--r2mcp`` or ``VALIDATION_R2MCP`` first; then the product's own lookup
    of the shipped ``static.r2.binary_path`` (PATH, then radare2's install
    places); then the known places above.
    """
    from maljan.providers.static.r2 import resolve_r2_binary

    looked: list[str] = []
    for value in (given, os.environ.get("VALIDATION_R2MCP", "")):
        if value:
            looked.append(value)
            if os.access(value, os.X_OK) and Path(value).is_file():
                return value, "; ".join(looked)
    found = resolve_r2_binary(_defaults().static.r2.binary_path)
    looked.extend(found.looked)
    if found.path:
        return found.path, "; ".join(looked)
    for known in KNOWN_R2MCP:
        path = str(Path(known).expanduser())
        looked.append(path)
        if os.access(path, os.X_OK) and Path(path).is_file():
            return path, "; ".join(looked)
    return "", "looked in: " + "; ".join(looked)


def clean_outputs(out: Path, scenarios: list[str]) -> list[str]:
    """Take away what an earlier run left in ``out`` for ``scenarios``; returns what went.

    Each named scenario's directory (every run of it, any name an earlier
    harness version wrote there included) and its summary files go; nothing
    else in ``out`` is touched.
    """
    gone: list[str] = []
    for scenario in scenarios:
        for entry in (out / scenario, out / f"{scenario}.json", out / f"{scenario}.md"):
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            elif entry.exists() or entry.is_symlink():
                entry.unlink()
            else:
                continue
            gone.append(entry.name)
    return gone


def no_hidden_segment(path: Path) -> Path:
    """``path`` made absolute, refused when a segment of it starts with a dot."""
    resolved = Path(path).expanduser().resolve()
    if any(part.startswith(".") for part in resolved.parts[1:]):
        raise SystemExit(f"{resolved} holds a path segment starting with a dot; pick another --out")
    return resolved


def gap_pins() -> dict[tuple[str, str, str, str], tuple[str, str]]:
    """The product gap pins: (scenario, run, wire, check) -> (detail, gap)."""
    if not GAP_PINS_FILE.is_file():
        return {}
    rows = json.loads(GAP_PINS_FILE.read_text(encoding="utf-8"))["pins"]
    return {(r["scenario"], r["run"], r["wire"], r["check"]): (r["detail"], r["gap"]) for r in rows}


def apply_pins(result: RunResult) -> None:
    """Excuse each miss of ``result`` a gap pin names with exactly its detail."""
    pins = gap_pins()
    for check, detail in result.misses.items():
        held = pins.get((result.scenario, result.name, result.wire, check))
        if held is not None and held[0] == detail:
            result.pinned[check] = held[1]


def _known_defects() -> dict[tuple[str, str], dict[str, str]]:
    pinned = json.loads(PINS_FILE.read_text(encoding="utf-8"))
    out: dict[tuple[str, str], dict[str, str]] = {}
    for row in pinned["pins"]:
        out.setdefault((row["scenario"], row["wire"]), {})[row["check"]] = row["detail"]
    return out


def run_one(
    ctx: Context,
    scenario: str,
    name: str,
    rehearsal: Rehearsal,
    *,
    servers: dict[str, tuple[str, ...]],
    matches: dict[str, reach_mod.Match] | None = None,
    absent: tuple[str, ...] = (),
    gates: Callable[[RunRecord, dict[str, dict[str, Any]], Path], Gates] | None = None,
    notes: dict[str, Any] | None = None,
    watch: Callable[[], Gates] | None = None,
) -> tuple[RunResult, RunRecord]:
    """Run ``rehearsal`` once, read it against every gate and write its result files.

    ``watch`` is read right after the run ends (before any reading): gates of
    what the run left behind on the machine.
    """
    run_dir = ctx.out / scenario / name
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    rehearsal = replace(rehearsal, work_dir=run_dir / "work", dump_dir=run_dir / "dump")
    record = asyncio.run(rehearse(rehearsal))
    left = watch() if watch else {}
    # The run's own report, kept beside the gates for whoever reads a miss.
    (run_dir / "report.md").write_text(record.markdown, encoding="utf-8")
    (run_dir / "report.json").write_text(
        json.dumps(record.malware_report, indent=1, default=str), encoding="utf-8"
    )
    checks = check_run(record)
    known = _known_defects().get((rehearsal.scenario, rehearsal.provider), {})
    failed = {c.name: c.detail for c in checks if not c.ok}
    excused = {k: v for k, v in failed.items() if known.get(k) == v}
    base_failures = {k: v for k, v in failed.items() if k not in excused}
    rows = [
        reach_mod.reach(
            record,
            rehearsal.dump_dir,
            key,
            match=(matches or {}).get(key),
            absent=absent,
            expect_cited="E2" in servers[key],
        )
        for key in servers
    ]
    by_key = {row["server"]: row for row in rows}
    own = {**left, **(gates(record, by_key, run_dir / "dump") if gates else {})}
    if absent:
        named = reach_mod.absent_names(record, absent)
        own.setdefault("names_absent", (not named, json.dumps(named) if named else "none named"))
    result = RunResult(
        scenario=scenario,
        name=name,
        wire=rehearsal.provider,
        status=record.job_status,
        base_failures=base_failures,
        excused=excused,
        reach=rows,
        required=servers,
        gates=own,
        notes={
            "job_error": record.job_error,
            "elapsed_s": round(record.elapsed_s, 1),
            "degradation_reasons": record.malware_report.get("degradation_reasons"),
            "empty_evidence_sections": record.empty_evidence_sections,
            "identity": record.malware_report.get("identity"),
            "reputation": record.malware_report.get("reputation"),
            **(notes or {}),
        },
    )
    apply_pins(result)
    payload = {**as_json(record, checks), "validation": result.summary(), "reach": rows}
    (run_dir.parent / f"{name}.json").write_text(
        json.dumps(payload, indent=1, default=str), encoding="utf-8"
    )
    md = [
        as_markdown(record, checks),
        "",
        "## Evidence reach",
        "",
        reach_mod.reach_markdown(rows) if rows else "(no source read)",
        "",
        "## Gates",
        "",
        *(f"- {'ok' if ok else 'MISS'} {k}: {d}" for k, (ok, d) in own.items()),
        f"- {'ok' if not base_failures else 'MISS'} base gate: "
        + (json.dumps(base_failures) if base_failures else "every check passes"),
        f"- {'ok' if not result.reach_misses else 'MISS'} reach: "
        + (
            "; ".join(f"{k}: {v}" for k, v in result.reach_miss_details.items())
            or "every required row"
        ),
        *(f"- pinned {k}: product gap {g}" for k, g in result.pinned.items()),
        f"- run: {result.label}",
    ]
    (run_dir.parent / f"{name}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return result, record


def _rehearsal(wire: str, scenario: str = "normal", **kwargs: Any) -> Rehearsal:
    return Rehearsal(
        scenario=scenario,
        provider=wire,
        job_timeout_s=JOB_DEADLINE_S,
        loop_steps=kwargs.pop("loop_steps", 8 if scenario == "long_loop" else None),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Settings helpers (data only)
# ---------------------------------------------------------------------------


def _defaults() -> Any:
    from maljan.core.settings_overrides import build_settings

    return build_settings({})


def default_stages() -> list[dict[str, Any]]:
    """The default profile's stages as stored data."""
    profile = _defaults().agents.profiles["default"].model_dump(mode="json")
    return copy.deepcopy(profile["stages"])


def stages_with(
    stage: dict[str, Any], *, after: str = "analysis", before: str = "debate"
) -> list[dict[str, Any]]:
    """The default stages with ``stage`` placed after ``after``, ``before`` depending on it."""
    stages = default_stages()
    out: list[dict[str, Any]] = []
    for row in stages:
        if row["key"] == before:
            row = {**row, "depends_on": [stage["key"]]}
        out.append(row)
        if row["key"] == after:
            out.append({"depends_on": [after], "inject_upstream": "findings", **stage})
    return out


def stages_before_analysis(stage: dict[str, Any]) -> list[dict[str, Any]]:
    """The default stages with ``stage`` run first and the analysis stage depending on it."""
    out: list[dict[str, Any]] = []
    for row in default_stages():
        if row["key"] == "analysis":
            out.append({"depends_on": [], "inject_upstream": "none", **stage})
            row = {**row, "depends_on": [stage["key"]]}
        out.append(row)
    return out


def profile(key: str, stages: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "agents.profiles": {key: {"label": key, "stages": stages}},
        "agents.profile": key,
    }


def shipped_server(key: str, **changes: Any) -> dict[str, Any]:
    """A shipped server entry as stored data, with ``changes`` applied."""
    entry: dict[str, Any] = _defaults().mcp.servers[key].model_dump(mode="json")
    entry.pop("auth_token", None)
    entry.update(changes)
    return entry


def stdio_server(ctx: Context, script: Path, **changes: Any) -> dict[str, Any]:
    """An operator's stdio server entry running ``script`` with this interpreter."""
    return {
        "enabled": True,
        "transport": "stdio",
        "command": ctx.python,
        "args": [str(script)],
        "env_allow": ["PATH", "HOME"],
        **changes,
    }


GENERIC_PROMPT = (
    "You are an analysis step of a malware-analysis team. Use the tools in your list on the "
    "sample you are given, report every finding with the evidence id of the tool call it came "
    "from, and say what each finding lets someone conclude."
)


def _entry_kinds(record: RunRecord, match: reach_mod.Match) -> list[str]:
    return [
        str((e.get("facts") or {}).get("kind") or "") for e in reach_mod.entries_of(record, match)
    ]


# ---------------------------------------------------------------------------
# (a) a team with no Ghidra: radare2 only
# ---------------------------------------------------------------------------


def preflight_r2(ctx: Context, times: int = 3) -> dict[str, Any]:
    """The r2 server's own tool listing, ``times`` times over one stdio handshake each."""
    from maljan.providers.static.r2 import enumerate_r2_tools

    counts = []
    for _ in range(times):
        counts.append(len(asyncio.run(enumerate_r2_tools(ctx.r2mcp))))
    return {"ok": all(n >= 30 for n in counts), "tool_counts": counts}


# The tool calls a long-loop run gives each analyst (scenarios a and b).
LONG_LOOP_STEPS = 16


def scenario_a(ctx: Context) -> list[RunResult]:
    if not ctx.r2mcp or not Path(ctx.r2mcp).is_file():
        return [_skipped("a", f"r2mcp not found ({ctx.r2mcp_searched})")]
    pre = preflight_r2(ctx)
    extra = {
        "static.provider": "r2",
        "static.r2.binary_path": ctx.r2mcp,
        "static.r2.enabled": True,
        **profile(
            "validation_r2",
            stages_with(
                {
                    "key": "reversing",
                    "label": "Reversing",
                    "kind": "analysis",
                    "agents": ["reverser"],
                }
            ),
        ),
    }

    def gates(record: RunRecord, rows: dict[str, Any], _dump: Path, deep: bool = True) -> Gates:
        own: Gates = {"preflight": (pre["ok"], json.dumps(pre))}
        if not deep:
            return own
        e5 = rows["r2"]["E5"]
        own.update(
            {
                # Code read where the product itself said a function starts:
                # a decompile or disassembly answer that holds code, at a
                # place a function or entry-point listing of r2 returned.
                "code_entry": _code_entry_gate(e5["code"]),
                "code_listing_figure": (
                    e5["listing_from_source"],
                    f"{e5['code_listing_figures']} code listing figure(s)",
                ),
                # "Functions examined" must stand on a function actually
                # read as code, never on a listing call.
                "functions_examined": (
                    e5["functions_examined_by_code"],
                    "cites a credited code entry"
                    if e5["functions_examined_by_code"]
                    else (
                        "cites no credited code entry"
                        if e5["functions_examined"]
                        else "no Functions examined section cites r2"
                    ),
                ),
            }
        )
        return own

    # A normal run gives each analyst two tool calls, which the stub spends on
    # the preferred tools: its r2 reach is recorded there and held in the long
    # loop, whose sixteen calls follow the answers into the code.
    results = []
    runs = [(w, "normal", 2) for w in ctx.wires] + [(ctx.wires[0], "long_loop", LONG_LOOP_STEPS)]
    for wire, scenario, steps in runs:
        rehearsal = replace(
            _rehearsal(
                wire,
                scenario,
                extra=extra,
                static_sample_paths={"r2": ""},
                fill_from_results=True,
            ),
            loop_steps=steps,
        )
        deep = scenario == "long_loop"
        result, _ = run_one(
            ctx,
            "a",
            f"{scenario}-{wire}",
            rehearsal,
            servers={"r2": ALL_E if deep else ()},
            absent=("Ghidra",),
            gates=functools.partial(gates, deep=deep),
        )
        results.append(result)
    return results


# ---------------------------------------------------------------------------
# (b) a second decompiler of another make, over MCP (run alone: it starts a JVM)
# ---------------------------------------------------------------------------


def _code_entry_gate(code: dict[str, Any]) -> tuple[bool, str]:
    """The code-entry gate from ``reach.code_evidence``, its detail free of entry ids."""
    if code["credited"]:
        return True, f"{len(code['credited'])} code entr(y/ies) at a listed function start"
    reasons = sorted(set(code["refused"].values()))
    return False, (
        f"{len(code['code_entries'])} code entr(y/ies), none credited"
        + (f" ({'; '.join(reasons)})" if reasons else "")
        + f"; {len(code['function_starts'])} function start(s) listed"
    )


# The argument a server takes its project directory by: the scenario's own
# directory, given after it, marks every process the scenario started.
PROJECT_FLAG = "--project-path"


def _proc_table() -> dict[int, tuple[list[str], int]]:
    """Every process's argv and parent pid, read from ``/proc``."""
    table: dict[int, tuple[list[str], int]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
            stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
            parent = int(stat.rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            continue
        argv = [a.decode("utf-8", errors="replace") for a in raw.split(b"\0") if a]
        table[int(entry.name)] = (argv, parent)
    return table


def _names_project(argv: list[str], project: str) -> bool:
    """Whether ``argv`` gives exactly ``project`` as its ``--project-path``."""
    for index, arg in enumerate(argv):
        if arg == PROJECT_FLAG and index + 1 < len(argv) and argv[index + 1] == project:
            return True
        if arg == f"{PROJECT_FLAG}={project}":
            return True
    return False


def _held_by(table: dict[int, tuple[list[str], int]], project: str) -> set[int]:
    """The processes started for ``project`` and their children, never this one or its parents."""
    mine = {os.getpid()}
    pid = os.getpid()
    while pid in table and table[pid][1] not in mine and table[pid][1] > 0:
        pid = table[pid][1]
        mine.add(pid)
    held = {pid for pid, (argv, _p) in table.items() if _names_project(argv, project)} - mine
    grew = True
    while grew:
        children = {pid for pid, (_a, parent) in table.items() if parent in held} - held - mine
        grew = bool(children)
        held |= children
    return held


def processes_naming(project: str) -> dict[int, str]:
    """Every process given ``project`` as its ``--project-path``, with its descendants: pid -> line.

    The argv element after the flag must be the path exactly; a process that
    merely mentions the path is not one of them, nor is this process or any
    of its ancestors.
    """
    table = _proc_table()
    return {pid: " ".join(table[pid][0])[:300] for pid in sorted(_held_by(table, project))}


def end_survivors(project: str, grace_s: float = 15.0) -> dict[int, str]:
    """The processes still held by ``project`` after ``grace_s``, each then ended by its pid.

    A survivor is asked to end (SIGTERM), then made to (SIGKILL). Right before
    each signal the process table is read again and the pid is signalled only
    while it is still held (its own argv names the project, or it descends
    from one that does), so a reused pid is never touched. Returns the
    survivors as found.
    """
    import signal
    import time

    deadline = time.monotonic() + grace_s
    survivors = processes_naming(project)
    while survivors and time.monotonic() < deadline:
        time.sleep(0.5)
        survivors = processes_naming(project)
    for sig in (signal.SIGTERM, signal.SIGKILL) if survivors else ():
        for pid in processes_naming(project):
            if pid not in _held_by(_proc_table(), project):
                continue
            try:
                os.kill(pid, sig)
            except OSError:
                pass
        end = time.monotonic() + 10.0
        while processes_naming(project) and time.monotonic() < end:
            time.sleep(0.5)
    return survivors


def survivor_gate(marker: str) -> Gates:
    """A gate that misses when a process started for ``marker`` outlived the step (then ended)."""
    left = end_survivors(marker)
    return {
        "no_survivor": (
            not left,
            "no process left" if not left else f"ended by pid: {json.dumps(left)}",
        )
    }


def _pyghidra_entry(ctx: Context, **changes: Any) -> dict[str, Any]:
    project = ctx.out / "b" / "pyghidra-proj"
    project.mkdir(parents=True, exist_ok=True)
    return {
        "enabled": True,
        "transport": "stdio",
        "command": ctx.pyghidra,
        "args": ["--project-path", str(project), "--project-name", "validation"],
        "env": {
            "GHIDRA_INSTALL_DIR": ctx.ghidra_dir,
            "JAVA_HOME": ctx.java_home,
            "JAVA_TOOL_OPTIONS": "-Xmx2g",
        },
        "env_allow": ["PATH", "HOME"],
        "call_timeout_seconds": 600,
        "tools": None,
        **changes,
    }


def _probe_mcp(name: str, entry: dict[str, Any], confirmed: list[str] | None = None) -> Any:
    from app.services.settings_probes import probe_mcp

    return asyncio.run(
        probe_mcp({"name": name, "entry": entry, "confirmed_calls": list(confirmed or [])})
    )


def accepted_proposal(name: str, entry: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """``entry`` with every field the connection test proposes accepted, and the proposal.

    The probe is asked twice, as an admin would: once to list the harmless
    calls it plans, then with every planned call confirmed, so the answers can
    propose what the schemas alone do not say.
    """
    from maljan.core.config import MCPServerConfig

    first = _probe_mcp(name, entry)
    planned = [
        str(call.get("tool"))
        for call in ((first.details or {}).get("proposals") or {}).get("planned") or []
    ]
    second = _probe_mcp(name, entry, planned) if planned else first
    proposals = (second.details or {}).get("proposals") or {}
    tool_facts = {tool: held["facts"] for tool, held in (proposals.get("tools") or {}).items()}
    accepted = {**entry, "tool_facts": {**entry.get("tool_facts", {}), **tool_facts}}
    fields = set(MCPServerConfig.model_fields)
    for key, held in (proposals.get("server") or {}).items():
        value = held.get("value", held) if isinstance(held, dict) else held
        if key in fields:
            accepted[key] = value
    return accepted, {
        "ok": bool(second.ok),
        "detail": second.detail,
        "planned": planned,
        "proposals": proposals,
    }


PYGHIDRA_DECLARED = {
    "decompile_function": {
        "kind": "decompile",
        "arguments": {"address": "name_or_address", "program": "binary_name"},
    },
    "disassemble": {"kind": "disassembly"},
    "list_xrefs": {"kind": "xrefs"},
    "search_strings": {"kind": "strings"},
    "list_imports": {"kind": "import_listing"},
    "list_exports": {"kind": "export_listing"},
    "import_binary": {"long_running": True, "timeout_seconds": 600},
}
PYGHIDRA_READ_ONLY = [
    "import_binary",
    "list_project_binaries",
    "list_project_binary_metadata",
    "decompile_function",
    "disassemble",
    "list_xrefs",
    "search_strings",
    "search_symbols_by_name",
    "search_code",
    "list_imports",
    "list_exports",
    "read_bytes",
    "gen_callgraph",
]


def scenario_b(ctx: Context) -> list[RunResult]:
    if not ctx.pyghidra or not Path(ctx.pyghidra).is_file():
        return [_skipped("b", "pyghidra-mcp not found (--pyghidra)")]
    if not Path(ctx.ghidra_dir).is_dir() or not Path(ctx.java_home).is_dir():
        return [_skipped("b", "Ghidra or the JDK not found (--ghidra-dir, --java-home)")]
    wire = ctx.wires[0]
    reverser = {
        "role": "generic",
        "label": "Reverser (second decompiler)",
        "prompt": GENERIC_PROMPT,
        "tools": [{"kind": "mcp", "server": "pyghidra"}, {"kind": "mcp", "server": "knowledge"}],
    }
    stages = stages_with(
        {
            "key": "reversing",
            "label": "Reversing",
            "kind": "analysis",
            "agents": ["reverser_pyghidra"],
        }
    )
    b1 = _pyghidra_entry(ctx)
    b2 = _pyghidra_entry(
        ctx,
        tool_facts=PYGHIDRA_DECLARED,
        sample_open={"open_tool": "import_binary", "path_argument": "binary_path"},
        auto_name_prefixes=["FUN_"],
        tools=PYGHIDRA_READ_ONLY,
    )
    # Every pyghidra process (the JVM it hosts included) names the project
    # path on its command line: none may outlive a probe or a run.
    marker = str(b1["args"][1])
    before = end_survivors(marker, grace_s=0.0)
    pre = []
    left: dict[str, Any] = {"before": before} if before else {}
    for index in range(3):
        pre.append(_probe_mcp("pyghidra", b1))
        survived = end_survivors(marker)
        if survived:
            left[f"probe {index + 1}"] = survived
            break
    preflight = {
        "ok": len(pre) == 3 and all(p.ok and len(p.tools or []) >= 20 for p in pre) and not left,
        "tools": [len(p.tools or []) for p in pre],
        "details": [p.detail for p in pre],
        "survivors_ended_by_pid": left,
    }
    if left:
        # A process outlived a probe: the scenario stops here (each was ended by pid).
        return [_stopped("b", "preflight", preflight)]
    b2p, proposal = accepted_proposal("pyghidra", b1)
    survived = end_survivors(marker)
    if survived:
        return [_stopped("b", "proposal", {"survivors_ended_by_pid": survived})]
    pg = reach_mod.by_server("pyghidra")

    def gates(record: RunRecord, rows: dict[str, Any], _dump: Path) -> Gates:
        return {
            "preflight": (preflight["ok"], json.dumps(preflight)),
            "code_listing_figure": (rows["pyghidra"]["E5"]["listing_from_source"], ""),
            "functions_examined": (rows["pyghidra"]["E5"]["functions_examined"], ""),
            "entry_kinds": (True, json.dumps(_entry_kinds(record, pg))),
        }

    variants = [
        ("b1-undeclared", b1, ("E1", "E2", "E4", "E5", "E6")),
        ("b2-declared", b2, ALL_E),
        ("b2p-proposed", b2p, ALL_E),
    ]
    proposal_notes = {
        "proposal": proposal,
        "proposal_vs_declared": _facts_diff(PYGHIDRA_DECLARED, b2p.get("tool_facts") or {}),
    }
    results = []
    for name, entry, required in variants:
        extra = {
            "static.provider": "none",
            "mcp.servers": {"pyghidra": entry},
            "agents.definitions": {"reverser_pyghidra": reverser},
            **profile("validation_pyghidra", stages),
        }
        result, _ = run_one(
            ctx,
            "b",
            name,
            # The long loop scenario a holds its code gates with: a normal
            # run's two calls are spent before the reverser reaches its
            # decompiler, so the loop follows the answers through import,
            # listing and decompile instead.
            replace(
                _rehearsal(wire, "long_loop", extra=extra, fill_from_results=True),
                loop_steps=LONG_LOOP_STEPS,
            ),
            servers={"pyghidra": required},
            gates=gates,
            notes=proposal_notes if name.startswith("b2p") else None,
            watch=functools.partial(survivor_gate, marker),
        )
        results.append(result)
        if not result.gates["no_survivor"][0]:
            # Ended by pid and reported; no further JVM is started.
            break
    return results


def _facts_diff(declared: dict[str, Any], proposed: dict[str, Any]) -> dict[str, Any]:
    """Per tool, each declared field the proposal leaves out or gives another value."""
    out: dict[str, Any] = {}
    for tool, facts in declared.items():
        got = proposed.get(tool) or {}
        diff = {
            k: {"declared": v, "proposed": got.get(k)} for k, v in facts.items() if got.get(k) != v
        }
        if diff:
            out[tool] = diff
    return out


# ---------------------------------------------------------------------------
# (c1) uploaded sandbox reports of two formats
# ---------------------------------------------------------------------------


def _sample_sha256() -> str:
    import hashlib

    from scripts.rehearsal.sample import sample_bytes

    return hashlib.sha256(sample_bytes()).hexdigest()


def _sandbox_entries(entry: dict[str, Any]) -> bool:
    return str((entry.get("facts") or {}).get("kind") or "").startswith("sandbox_")


def _upload_client(sandbox: Any) -> Any:
    """A test client over the upload route itself, the API's own way (no server, no database).

    Only the seams the route's own tests replace are replaced: the sample
    lookup, the row write, the object store, the audit record and the stored
    settings read (``sandbox`` stands for them); format reading, the allowed
    list, the reader check and the size cap are the route's.
    """
    import uuid
    from contextlib import ExitStack
    from unittest import mock

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.v1 import sandbox_reports as module
    from app.database import get_db
    from app.deps import get_current_user, require_active_user

    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    user = mock.MagicMock(id=uuid.uuid4())
    sample = mock.MagicMock(id=uuid.uuid4(), sha256=_sample_sha256(), uploaded_by=user.id)
    stack = ExitStack()
    stack.enter_context(
        mock.patch.object(module, "_load_sample", mock.MagicMock(return_value=sample))
    )
    stack.enter_context(
        mock.patch.object(module, "_sandbox_settings", mock.AsyncMock(return_value=sandbox))
    )
    stack.enter_context(mock.patch.object(module, "put_object", mock.AsyncMock()))
    stack.enter_context(
        mock.patch.object(module, "_persist", mock.MagicMock(side_effect=lambda db, row: row))
    )
    stack.enter_context(mock.patch.object(module.audit, "record", mock.AsyncMock()))
    app.dependency_overrides[get_db] = lambda: mock.MagicMock()
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[require_active_user] = lambda: user
    return stack, TestClient(app), sample


def _post_report(sandbox: Any, name: str, blob: bytes) -> dict[str, Any]:
    stack, client, sample = _upload_client(sandbox)
    with stack:
        response = client.post(
            f"/api/v1/samples/{sample.id}/sandbox-reports",
            files={"file": (name, blob, "application/json")},
        )
    body = response.json() if response.content else {}
    return {
        "status": response.status_code,
        "format": body.get("format"),
        "task_id": body.get("task_id"),
        "sample_sha256_match": body.get("sample_sha256_match"),
        "detail": body.get("detail"),
    }


def upload_checks() -> dict[str, Any]:
    """The upload route's answer for each fixture, through the API's test client.

    Beside the three fixtures: the reader check (a recognised, allowed format
    whose declaration names no registered reader is refused, 422) and the
    size cap (a report over the configured maximum is refused, 413).
    """
    from app.api.v1.sandbox_reports import _read_declared, sandbox_formats

    sandbox = _defaults().sandbox
    out: dict[str, Any] = {}
    for name in ("cape2_report.json", "triage_overview.json", "triage_report_behavioral1.json"):
        out[name] = _post_report(sandbox, name, (SANDBOX_FIXTURES / name).read_bytes())
    # The reader check: the format the first fixture is read as, declared with no reader.
    blob = (SANDBOX_FIXTURES / "cape2_report.json").read_bytes()
    fmt, _task, _target = _read_declared(json.loads(blob), sandbox_formats(sandbox.report_formats))
    from maljan.core.report_formats import effective_formats

    declared = next(
        (d for d in effective_formats(sandbox.report_formats) if fmt and d.name == fmt.name), None
    )
    if declared is None:
        out["format without a reader"] = {"status": None, "detail": "not checked: no declaration"}
    else:
        raw = sandbox.model_dump(mode="json")
        raw["report_formats"] = [
            *(r for r in raw.get("report_formats") or [] if r.get("name") != declared.name),
            {**declared.model_dump(mode="json"), "reader": ""},
        ]
        out["format without a reader"] = _post_report(
            type(sandbox).model_validate(raw), "no-reader.json", blob
        )
    capped = {**sandbox.model_dump(mode="json")}
    capped["upload"] = {**capped["upload"], "max_report_bytes": max(1, len(blob) // 2)}
    try:
        small = type(sandbox).model_validate(capped)
    except ValueError as exc:
        out["over the size cap"] = {"status": None, "detail": f"not checked: {exc}"}
    else:
        out["over the size cap"] = _post_report(small, "too-large.json", blob)
    return out


def scenario_c1(ctx: Context) -> list[RunResult]:
    wire = ctx.wires[0]
    api = upload_checks()
    reports = [
        ("cape2_report.json", "cape2", ("Triage",)),
        ("triage_overview.json", "triage", ("CAPE",)),
    ]
    results = []
    for fixture, fmt, others in reports:
        for recorded in (fmt, None):
            name = f"{fmt}-{'explicit' if recorded else 'sniffed'}"

            def gates(
                record: RunRecord,
                rows: dict[str, Any],
                _dump: Path,
                fixture: str = fixture,
                fmt: str = fmt,
            ) -> Gates:
                return {
                    "upload_route": (
                        api[fixture]["status"] == 201 and api[fixture]["format"] == fmt,
                        json.dumps(api[fixture]),
                    ),
                    "upload_route_refusals": (
                        api["triage_report_behavioral1.json"]["status"] == 415
                        and api["format without a reader"]["status"] == 422
                        and api["over the size cap"]["status"] in (413, None),
                        json.dumps(
                            {
                                k: api[k]
                                for k in (
                                    "triage_report_behavioral1.json",
                                    "format without a reader",
                                    "over the size cap",
                                )
                            }
                        ),
                    ),
                    "dynamic_sections": (
                        bool(rows["sandbox"]["E5"]["sections"]),
                        json.dumps(rows["sandbox"]["E5"]["sections"]),
                    ),
                }

            result, record = run_one(
                ctx,
                "c1",
                name,
                _rehearsal(
                    wire,
                    extra={"sandbox.provider": "upload"},
                    attach_report=(SANDBOX_FIXTURES / fixture, recorded),
                ),
                servers={"sandbox": ALL_E},
                matches={"sandbox": _sandbox_entries},
                absent=others,
                gates=gates,
                notes={
                    "upload_route": api,
                    # The fixture's target hash is not the rehearsal sample's:
                    # the worker degrades such a run, the in-process run does not.
                    "target_matches_sample": api[fixture]["sample_sha256_match"],
                },
            )
            results.append(result)
    return results


def scenario_c2(ctx: Context) -> list[RunResult]:
    return [_pending("c2", "needs G10c: an unknown report format read unread, then accepted")]


# ---------------------------------------------------------------------------
# (d) a third, registered memory backend
# ---------------------------------------------------------------------------


def memory_api_checks() -> dict[str, Any]:
    """The registry's readers outside a run: save, connection test, catalogue, health."""
    from scripts.validation.memory_backend import BACKEND_ID, PROBE_LABEL

    from app.services import settings_catalog_api
    from app.services.provider_facts import probe_labels
    from app.services.settings_probes import run_probe
    from app.services.settings_service import SettingsService, SettingsValidationError
    from maljan.core.settings_overrides import build_settings
    from maljan.memory.store_factory import MemoryBackendNotConfiguredError, build_memory_store

    out: dict[str, Any] = {}
    settings_catalog_api.catalog_index.cache_clear()
    service = SettingsService(None)  # type: ignore[arg-type]  # check_keys reads no database

    def refused(value: str) -> str:
        try:
            service.check_keys({"core.memory.backend": value}, {})
        except SettingsValidationError as exc:
            return json.dumps(exc.errors)
        return ""

    out["save_accepts_registered"] = not refused(BACKEND_ID)
    out["save_refuses_unregistered"] = bool(refused("validation_unregistered"))
    probe = asyncio.run(run_probe(BACKEND_ID, {}, {}))
    out["connection_test"] = {"ok": bool(probe.ok), "detail": probe.detail}
    out["probe_label"] = probe_labels().get(BACKEND_ID) == PROBE_LABEL
    stored = build_settings({"memory.backend": "validation_unregistered"})
    try:
        build_memory_store(stored)
        out["stored_unregistered"] = "built"
    except MemoryBackendNotConfiguredError as exc:
        out["stored_unregistered"] = f"refused at build (unavailable={exc.unavailable})"
    out["health"] = _health_memory(build_settings({"memory.backend": BACKEND_ID}))
    return out


def _health_memory(core: Any) -> Any:
    """``/health``'s memory probe over ``core``, without the API's stored settings."""
    try:
        from app import main
        from app.runtime_config import runtime_config
    except Exception as exc:  # noqa: BLE001 — recorded, never a crash
        return f"not checked: {type(exc).__name__}: {exc}"

    async def held() -> Any:
        return core

    kept = runtime_config.core
    runtime_config.core = held  # type: ignore[method-assign]
    try:
        return asyncio.run(main._probe_memory())
    except Exception as exc:  # noqa: BLE001 — recorded, never a crash
        return f"not checked: {type(exc).__name__}: {exc}"
    finally:
        runtime_config.core = kept  # type: ignore[method-assign]


def _memory_api_gates(api: dict[str, Any]) -> Gates:
    health = api.get("health")
    stored = str(api.get("stored_unregistered") or "")
    return {
        "save_accepts_registered": (api["save_accepts_registered"] is True, ""),
        "save_refuses_unregistered": (api["save_refuses_unregistered"] is True, ""),
        "connection_test": (api["connection_test"]["ok"], json.dumps(api["connection_test"])),
        "probe_label": (api["probe_label"] is True, ""),
        "stored_unregistered": (stored.startswith("refused at build (unavailable=False)"), stored),
        "health": (
            isinstance(health, dict) and health.get("ok") is True,
            json.dumps(health, default=str),
        ),
    }


def scenario_d(ctx: Context) -> list[RunResult]:
    from scripts.validation import memory_backend

    store = memory_backend.register()
    store.clear()
    store.writes.clear()
    wire = ctx.wires[0]
    extra = {"memory.backend": memory_backend.BACKEND_ID}
    results: list[RunResult] = []
    try:
        api = memory_api_checks()
        first_sha = ""
        for index in (1, 2):
            before = len(store.writes)

            def gates(
                record: RunRecord,
                _rows: dict[str, Any],
                dump: Path,
                before: int = before,
                index: int = index,
                first_sha: str = first_sha,
            ) -> Gates:
                wrote = store.writes[before:]
                text = json.dumps(record.events, default=str) + json.dumps(
                    record.malware_report.get("degradation_reasons") or []
                )
                own = {
                    "ltm_written_once": (len(wrote) == 1, f"writes this run: {wrote}"),
                    "no_other_backend_named": ("qdrant" not in text.lower(), ""),
                    # The backend keeps no function hashes: nothing may be attributed by them.
                    "no_attribution_claimed": (
                        not (record.malware_report.get("attribution") or {}).get(
                            "function_hash_matches"
                        ),
                        json.dumps(record.malware_report.get("attribution"), default=str)[:300],
                    ),
                }
                if index == 1:
                    own.update({f"api.{k}": v for k, v in _memory_api_gates(api).items()})
                else:
                    judge = reach_mod.requests_of_role(dump, "judge")
                    own["judge_reads_earlier_case"] = (
                        bool(first_sha) and any(first_sha in t for t in judge),
                        f"run 1 sha {first_sha[:12]} in {len(judge)} judge request(s)",
                    )
                return own

            result, record = run_one(
                ctx,
                "d",
                f"run{index}-{wire}",
                _rehearsal(
                    wire,
                    extra=extra,
                    remember=True,
                    sample_overlay=b"" if index == 1 else b"validation-second-sample",
                ),
                servers={},
                gates=gates,
            )
            if index == 1:
                first_sha = str(record.run_summary.get("file_hash") or "")
            results.append(result)
    finally:
        memory_backend.unregister()
    return results


# ---------------------------------------------------------------------------
# (e) a reputation server of the operator's
# ---------------------------------------------------------------------------

REP_DECLARED: dict[str, Any] = {
    "lookup_hash": {
        "kind": "reputation",
        "arguments": {"hash": "sha256"},
        "display_name": "Stub reputation",
        "reputation": {
            "stats": "/data/attributes/stats",
            "malicious": "/data/attributes/stats/malicious",
            "total": "/data/attributes/stats/total",
            "labels": ["/data/attributes/label"],
            "first_seen": ["/data/attributes/first_seen"],
            "rank": 50,
        },
    }
}


def expected_first_lookup(servers: dict[str, Any]) -> str:
    """The service the pack asks first: the lowest declared reputation rank, read as data."""
    from maljan.core.settings_overrides import build_settings

    settings = build_settings({"mcp.servers": servers})
    ranked = []
    for order, (key, entry) in enumerate(settings.mcp.servers.items()):
        if not entry.enabled:
            continue
        for facts in entry.tool_facts.values():
            if facts.kind == "reputation" and facts.reputation is not None:
                service = facts.reputation.service or facts.display_name or key
                ranked.append((facts.reputation.rank, order, service))
    return min(ranked)[2] if ranked else ""


# The rows a reputation lookup the pack asks is held to. E2 is read, not
# required: the stub's analysts cite the entries their own requests offer,
# and a pack lookup is the judge's to cite.
REPUTATION_E = ("E1", "E3", "E4", "E5", "E6")
STUB_SERVICE = "Stub reputation"
# The stub's server key: the service an accepted proposal names the stub by,
# since a probe proposes no display name for a tool whose server gives no
# title (``core.reputation``: service, display name, then the server).
STUB_KEY = "repstub"
STUB_NAMES = frozenset({STUB_SERVICE, STUB_KEY})


def scenario_e(ctx: Context) -> list[RunResult]:
    base = stdio_server(ctx, REP_STUB, agents=["judge"], label=STUB_SERVICE)
    e1 = {**base, "roles": ["reputation"], "tool_facts": REP_DECLARED}
    first_rank: dict[str, Any] = copy.deepcopy(REP_DECLARED)
    first_rank["lookup_hash"]["reputation"]["rank"] = 0
    e1_first = {**e1, "tool_facts": first_rank}
    e2 = dict(base)
    e2p, proposal = accepted_proposal("repstub", e2)
    ti_off = shipped_server("threatintel", enabled=False)
    variants = [
        ("e1-declared", {"repstub": e1, "threatintel": ti_off}, ctx.wires),
        ("e2-undeclared", {"repstub": e2, "threatintel": ti_off}, ctx.wires),
        ("e2p-proposed", {"repstub": e2p, "threatintel": ti_off}, ctx.wires),
        ("e3-ranked-after-shipped", {"repstub": e1}, ctx.wires[:1]),
        ("e3-ranked-before-shipped", {"repstub": e1_first}, ctx.wires[:1]),
    ]
    results = []
    for name, servers, wires in variants:
        expected = expected_first_lookup(servers)
        if name.startswith("e2p") and expected not in STUB_NAMES:
            # An accepted proposal is held to what the hand declaration gets:
            # the stub asked first, whatever name the accepted facts give it.
            expected = STUB_SERVICE
        for wire in wires:

            def gates(
                record: RunRecord, rows: dict[str, Any], _dump: Path, expected: str = expected
            ) -> Gates:
                rep = record.malware_report.get("reputation") or []
                first = rep[0] if rep else {}
                stub: dict[str, Any] = next((r for r in rep if r.get("service") in STUB_NAMES), {})
                own: Gates = {
                    "first_service": (
                        (first.get("service") or "") == expected,
                        f"expected {expected or 'none asked'!r}: "
                        + json.dumps(first, default=str)[:300],
                    ),
                }
                if expected in STUB_NAMES or stub:
                    own["stub_counts_read"] = (
                        stub.get("malicious") == 3 and stub.get("total") == 60,
                        f"{stub.get('malicious')}/{stub.get('total')}",
                    )
                return own

            asked = expected in STUB_NAMES
            result, _ = run_one(
                ctx,
                "e",
                f"{name}-{wire}",
                _rehearsal(wire, extra={"mcp.servers": servers}, fill_from_results=True),
                servers={"repstub": REPUTATION_E if asked else ()},
                gates=gates,
                notes={"proposal": proposal} if name.startswith("e2p") else None,
            )
            results.append(result)
    return results


# ---------------------------------------------------------------------------
# (f) an operator kit whose tool names collide with built-in ones
# ---------------------------------------------------------------------------

KIT_DECLARED = {
    "strings": {"kind": "strings", "rows": "/runs/*", "values": {"text": "/value"}},
    "decompile_function": {"kind": "decompile", "arguments": {"address": "address"}},
}


def _kit_read_by_its_own_facts(record: RunRecord, declared: dict[str, Any]) -> tuple[bool, str]:
    """Every kit entry carries the kit's facts: its declared kind, or none when undeclared."""
    wrong = []
    for entry in reach_mod.entries_of(record, reach_mod.by_server("kit")):
        kind = str((entry.get("facts") or {}).get("kind") or "")
        own = str((declared.get(str(entry.get("tool"))) or {}).get("kind") or "")
        if kind != own:
            wrong.append(f"{entry.get('id')} {entry.get('tool')}: kind {kind!r}, own {own!r}")
    return not wrong, "; ".join(wrong) or "every kit entry read by its own facts"


def kit_tools() -> dict[str, str]:
    """The kit's own tools as its server lists them: name -> description."""
    import runpy

    server = runpy.run_path(str(KIT_STUB))["server"]
    return {t.name: str(t.description or "") for t in asyncio.run(server.list_tools())}


def builtin_sources(extra: dict[str, Any], newcomer: str) -> dict[str, set[str]]:
    """Each built-in source of the run's settings and the tool names it declares.

    The enabled servers other than ``newcomer`` by their key, and the static
    provider by its id: read as settings data (``tool_facts``), never by name.
    """
    from maljan.core.settings_overrides import build_settings
    from maljan.core.tool_declarations import block_at, provider_blocks

    settings = build_settings(extra)
    out = {
        key: set(entry.tool_facts or {})
        for key, entry in settings.mcp.servers.items()
        if key != newcomer and entry.enabled
    }
    provider = str(settings.static.provider or "")
    block = provider_blocks().get(f"provider:{provider}")
    if block:
        out[provider] = set(block_at(settings, block).tool_facts or {})
    return out


def offered_name_findings(
    requests: list[dict[str, str]],
    newcomer: str,
    own: dict[str, str],
    builtins: dict[str, set[str]],
) -> list[str]:
    """What each request offers wrong when the newcomer's names collide with a built-in's.

    In a request holding a built-in source (any of its other tools offered),
    a built-in tool the newcomer's tool shares a name with keeps its bare
    name: offered as ``<source>__<name>`` it was renamed; offered not at all
    while the newcomer's copy is, it was hidden. The newcomer's copy is known
    by its own description.
    """
    found: set[str] = set()
    # A name several built-in sources declare (each server's own status tool)
    # says nothing about which of them a request holds.
    counts: dict[str, int] = {}
    for declared in builtins.values():
        for name in declared:
            counts[name] = counts.get(name, 0) + 1
    for offered in requests:
        theirs = {
            name for name, text in offered.items() if any(d and d in text for d in own.values())
        }
        for source, declared in builtins.items():
            shared = declared & set(own)
            if not shared:
                continue
            unique = {n for n in declared - set(own) if counts[n] == 1}
            held = {n for n in offered if n not in theirs and n in unique} | {
                n for n in offered if n.startswith(f"{source}__")
            }
            if not held:
                continue
            for name in sorted(shared):
                if f"{source}__{name}" in offered:
                    found.add(f"built-in {source} {name} renamed {source}__{name}")
                bare_builtin = name in offered and name not in theirs
                if (
                    not bare_builtin
                    and f"{source}__{name}" not in offered
                    and theirs
                    & {
                        name,
                        f"{newcomer}__{name}",
                    }
                ):
                    found.add(f"built-in {source} {name} hidden behind the {newcomer} copy")
    return sorted(found)


def _kit_gates(extra: dict[str, Any], declared: dict[str, Any]) -> Callable[..., Gates]:
    own = kit_tools()
    builtins = builtin_sources(extra, "kit")

    def gates(record: RunRecord, _rows: dict[str, Any], dump: Path) -> Gates:
        kit_tools_called = [
            str(e.get("tool")) for e in reach_mod.entries_of(record, reach_mod.by_server("kit"))
        ]
        findings = offered_name_findings(reach_mod.offers(dump), "kit", own, builtins)
        degradations = [str(d) for d in record.malware_report.get("degradation_reasons") or []]
        # A built-in renamed or hidden is a change the operator must be told
        # of; a degradation naming the kit's server unavailable is false.
        untold = [f for f in findings if not any(f.split()[2] in d for d in degradations)]
        kit_unavailable = sorted(
            d for d in degradations if "kit" in d.split(".") and "unavailable" in d.lower()
        )
        return {
            "own_facts": _kit_read_by_its_own_facts(record, declared),
            "kit_entries": (bool(kit_tools_called), json.dumps(kit_tools_called)),
            "offered_names": (
                not findings,
                json.dumps(findings) if findings else "every built-in keeps its bare name",
            ),
            "degradations": (
                not untold and not kit_unavailable,
                json.dumps({"changed_untold": untold, "kit_unavailable": kit_unavailable})
                if untold or kit_unavailable
                else "nothing changed untold, the kit never named unavailable",
            ),
        }

    return gates


def _kit_run(
    ctx: Context, name: str, extra: dict[str, Any], declared: dict[str, Any], **kw: Any
) -> RunResult:
    result, _record = run_one(
        ctx,
        name.split("-", 1)[0],
        name,
        _rehearsal(ctx.wires[0], extra=extra, **{"fill_from_results": True, **kw}),
        servers={"kit": ALL_E},
        gates=_kit_gates(extra, declared),
    )
    return result


def scenario_f1(ctx: Context) -> list[RunResult]:
    """The kit bound to the static analyst beside the built-in servers."""
    results = []
    for label, facts in (("undeclared", {}), ("declared", KIT_DECLARED)):
        kit = stdio_server(ctx, KIT_STUB, agents=["static"], tool_facts=facts)
        results.append(_kit_run(ctx, f"f1-{label}", {"mcp.servers": {"kit": kit}}, facts))
    if ctx.r2mcp and Path(ctx.r2mcp).is_file():
        kit = stdio_server(ctx, KIT_STUB, agents=["static"])
        extra = {
            "mcp.servers": {"kit": kit},
            "static.provider": "r2",
            "static.r2.binary_path": ctx.r2mcp,
            "static.r2.enabled": True,
        }
        # Every kit tool shares its name with one of the static analyst's own
        # (r2's decompiler, the built-in servers'), so each is offered as
        # ``kit__<name>``. The loop turns through its tools rather than
        # following r2's answers, which would spend every step on r2.
        results.append(
            _kit_run(
                ctx,
                "f1-with-r2",
                extra,
                {},
                static_sample_paths={"r2": ""},
                fill_from_results=False,
            )
        )
    return results


def _triage_team(kit_facts: dict[str, Any]) -> dict[str, Any]:
    agent = {
        "role": "generic",
        "label": "Triage (operator kit)",
        "prompt": GENERIC_PROMPT,
        "tools": [{"kind": "mcp", "server": "kit"}],
    }
    return {
        "agents.definitions": {"validation_kit_triage": agent},
        **profile(
            "validation_kit",
            stages_before_analysis(
                {
                    "key": "kit_triage",
                    "label": "Kit triage",
                    "kind": "analysis",
                    "agents": ["validation_kit_triage"],
                }
            ),
        ),
    }


def scenario_f2(ctx: Context) -> list[RunResult]:
    """The kit held only by a generic agent; the built-in server only by the static analyst."""
    results = []
    for label, facts in (("undeclared", {}), ("declared", KIT_DECLARED)):
        kit = stdio_server(ctx, KIT_STUB, tool_facts=facts)
        extra = {"mcp.servers": {"kit": kit}, **_triage_team(facts)}
        results.append(_kit_run(ctx, f"f2-{label}", extra, facts))
    return results


def scenario_f3(ctx: Context) -> list[RunResult]:
    """The agent holding the kit holds no built-in server of the same tool names.

    A clone of the built-in static analyst (built-ins are cloned, never
    changed) with the kit in place of the analysis server takes the static
    analyst's place in the default stages.
    """
    clone = _defaults().agents.definitions["static"].model_dump(mode="json", exclude_none=True)
    clone["label"] = "Static analyst (operator kit)"
    clone.pop("tab", None)
    # The kit takes the analysis server's place after the clone's other
    # servers, as an operator adds a server to an agent that already holds some.
    clone["tools"] = [
        *[t for t in clone.get("tools") or [] if t.get("server") != "analysis"],
        {"kind": "mcp", "server": "kit"},
    ]
    stages = default_stages()
    for stage in stages:
        stage["agents"] = [
            "validation_static" if a == "static" else a for a in stage.get("agents") or []
        ]
    results = []
    for label, facts in (("undeclared", {}), ("declared", KIT_DECLARED)):
        kit = stdio_server(ctx, KIT_STUB, tool_facts=facts)
        extra = {
            "mcp.servers": {"kit": kit},
            "agents.definitions": {"validation_static": clone},
            **profile("validation_kit_alone", stages),
        }
        results.append(_kit_run(ctx, f"f3-{label}", extra, facts))
    return results


def scenario_f4(ctx: Context) -> list[RunResult]:
    return [_pending("f4", "needs G9b: a declared pack step that runs the kit's identify_file")]


# ---------------------------------------------------------------------------
# Placeholders, the driver
# ---------------------------------------------------------------------------


def _stopped(scenario: str, step: str, detail: dict[str, Any]) -> RunResult:
    return RunResult(
        scenario,
        f"stopped-at-{step}",
        "",
        "stopped",
        {},
        {},
        [],
        {},
        {"no_survivor": (False, json.dumps(detail, default=str))},
    )


def _skipped(scenario: str, why: str) -> RunResult:
    return RunResult(scenario, "skipped", "", "skipped", {}, {}, [], {}, {"skipped": (True, why)})


def _pending(scenario: str, why: str) -> RunResult:
    return RunResult(scenario, "pending", "", "pending", {}, {}, [], {}, {"pending": (True, why)})


SCENARIOS: dict[str, Callable[[Context], list[RunResult]]] = {
    "a": scenario_a,
    "b": scenario_b,
    "c1": scenario_c1,
    "c2": scenario_c2,
    "d": scenario_d,
    "e": scenario_e,
    "f1": scenario_f1,
    "f2": scenario_f2,
    "f3": scenario_f3,
    "f4": scenario_f4,
}
# ``b`` starts a JVM: it runs only when named.
DEFAULT_SET = ("d", "c1", "e", "f1", "f2", "f3", "a", "c2", "f4")


def write_scenario(ctx: Context, scenario: str, results: list[RunResult]) -> None:
    rows = [r.summary() for r in results]
    (ctx.out / f"{scenario}.json").write_text(json.dumps(rows, indent=1, default=str), "utf-8")
    lines = [f"# Scenario {scenario}", "", "| Run | Wire | Job | Gate |", "|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r.name} | {r.wire} | {r.status} | {r.label} |")
    for r in results:
        if r.misses or r.held_back:
            lines += ["", f"## {r.name} ({r.wire})"]
            for check, detail in r.misses.items():
                gap = r.pinned.get(check)
                lines.append(f"- {'pinned ' + gap if gap else 'MISS'} {check}: {detail}")
            if r.held_back:
                lines += [f"- {r.status}: {d}" for _ok, d in r.gates.values()]
    (ctx.out / f"{scenario}.md").write_text("\n".join(lines) + "\n", "utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", type=Path, help="results directory (no dot-segment in its path)")
    parser.add_argument("--scenarios", nargs="*", default=list(DEFAULT_SET))
    parser.add_argument("--wires", nargs="*", default=["openai", "anthropic"])
    parser.add_argument("--r2mcp", default="", help="r2mcp to use (else looked for)")
    parser.add_argument(
        "--allow-skips",
        action="store_true",
        help="a skipped or pending scenario does not make the exit status non-zero",
    )
    parser.add_argument(
        "--pyghidra",
        default=os.environ.get("VALIDATION_PYGHIDRA") or shutil.which("pyghidra-mcp") or "",
    )
    parser.add_argument("--ghidra-dir", default=os.environ.get("GHIDRA_INSTALL_DIR", ""))
    parser.add_argument("--java-home", default=os.environ.get("JAVA_HOME", ""))
    parser.add_argument(
        "--self-check", action="store_true", help="run the harness self-checks only"
    )
    args = parser.parse_args(argv)
    if args.self_check:
        from scripts.validation.self_check import run_self_checks

        return run_self_checks()
    if args.out is None:
        parser.error("--out is required")
    unknown = [s for s in args.scenarios if s not in SCENARIOS]
    if unknown:
        parser.error(f"unknown scenario(s) {unknown}; one of {sorted(SCENARIOS)}")
    r2mcp, searched = find_r2mcp(args.r2mcp)
    ctx = Context(
        out=no_hidden_segment(args.out),
        wires=tuple(args.wires),
        r2mcp=r2mcp,
        r2mcp_searched=searched,
        pyghidra=args.pyghidra,
        ghidra_dir=args.ghidra_dir,
        java_home=args.java_home,
    )
    ctx.out.mkdir(parents=True, exist_ok=True)
    for name in clean_outputs(ctx.out, list(args.scenarios)):
        print(f"cleaned {name}")
    missed = 0
    held_back = 0
    for scenario in args.scenarios:
        try:
            results = SCENARIOS[scenario](ctx)
        except Exception as exc:  # noqa: BLE001 — a harness crash is a recorded miss
            detail = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
            results = [
                RunResult(
                    scenario, "crashed", "", "crashed", {}, {}, [], {}, {"crashed": (False, detail)}
                )
            ]
        write_scenario(ctx, scenario, results)
        for r in results:
            held_back += r.held_back
            missed += not r.ok and not r.held_back
            print(f"{scenario:3} {r.name:32} {r.wire:9} {r.status:9} {r.label}")
            if r.held_back:
                print(f"    {r.status}: {'; '.join(d for _ok, d in r.gates.values())}")
    if missed:
        return 1
    if held_back and not args.allow_skips:
        print(f"{held_back} scenario(s) skipped or pending; --allow-skips accepts that")
        return 2
    return 0


if __name__ == "__main__":
    # The run's pipeline is in this process: before any thread or the YARA
    # engine loads, C code is pinned to fold case as ASCII does.
    from maljan.core.ctype_locale import pin_character_classification

    pin_character_classification()
    raise SystemExit(main())
