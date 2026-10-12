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

    @property
    def reach_misses(self) -> list[str]:
        misses = []
        for row in self.reach:
            for e in self.required.get(row["server"], ()):
                if not row[e]["ok"]:
                    misses.append(f"{row['server']}:{e}")
        return misses

    @property
    def ok(self) -> bool:
        return (
            not self.base_failures
            and not self.reach_misses
            and all(ok for ok, _detail in self.gates.values())
        )

    def summary(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "run": self.name,
            "wire": self.wire,
            "ok": self.ok,
            "job_status": self.status,
            "base_failures": self.base_failures,
            "excused": self.excused,
            "reach_misses": self.reach_misses,
            "gates": {k: {"ok": ok, "detail": d} for k, (ok, d) in self.gates.items()},
            "notes": self.notes,
        }


def no_hidden_segment(path: Path) -> Path:
    """``path`` made absolute, refused when a segment of it starts with a dot."""
    resolved = Path(path).expanduser().resolve()
    if any(part.startswith(".") for part in resolved.parts[1:]):
        raise SystemExit(f"{resolved} holds a path segment starting with a dot; pick another --out")
    return resolved


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
) -> tuple[RunResult, RunRecord]:
    """Run ``rehearsal`` once, read it against every gate and write its result files."""
    run_dir = ctx.out / scenario / name
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    rehearsal = replace(rehearsal, work_dir=run_dir / "work", dump_dir=run_dir / "dump")
    record = asyncio.run(rehearse(rehearsal))
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
        )
        for key in servers
    ]
    by_key = {row["server"]: row for row in rows}
    own = gates(record, by_key, run_dir / "dump") if gates else {}
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
        + (", ".join(result.reach_misses) or "every required row"),
    ]
    (run_dir.parent / f"{name}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return result, record


def _rehearsal(wire: str, scenario: str = "normal", **kwargs: Any) -> Rehearsal:
    return Rehearsal(
        scenario=scenario,
        provider=wire,
        job_timeout_s=JOB_DEADLINE_S,
        loop_steps=8 if scenario == "long_loop" else None,
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


def scenario_a(ctx: Context) -> list[RunResult]:
    if not ctx.r2mcp or not Path(ctx.r2mcp).is_file():
        return [_skipped("a", "r2mcp not found (--r2mcp)")]
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
    r2_ok = lambda e: reach_mod.by_server("r2")(e) and bool(e.get("ok"))  # noqa: E731

    def gates(record: RunRecord, rows: dict[str, Any], _dump: Path, deep: bool = True) -> Gates:
        own: Gates = {"preflight": (pre["ok"], json.dumps(pre))}
        if not deep:
            return own
        kinds = _entry_kinds(record, r2_ok)
        code = [k for k in kinds if k in ("decompile", "disassembly", "function_disassembly")]
        own.update(
            {
                "code_entry": (bool(code), f"r2 entry kinds filed ok: {kinds}"),
                "code_listing_figure": (
                    rows["r2"]["E5"]["listing_from_source"],
                    f"{rows['r2']['E5']['code_listing_figures']} code listing figure(s)",
                ),
                "functions_examined": (rows["r2"]["E5"]["functions_examined"], ""),
            }
        )
        return own

    # A normal run gives each analyst two tool calls, which the stub spends on
    # the preferred tools: its r2 reach is recorded there and held in the long
    # loop, whose sixteen calls follow the answers into the code.
    results = []
    runs = [(w, "normal", 2) for w in ctx.wires] + [(ctx.wires[0], "long_loop", 16)]
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
    pre = [_probe_mcp("pyghidra", b1) for _ in range(3)]
    preflight = {
        "ok": all(p.ok and len(p.tools or []) >= 20 for p in pre),
        "tools": [len(p.tools or []) for p in pre],
        "details": [p.detail for p in pre],
    }
    b2p, proposal = accepted_proposal("pyghidra", b1)
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
            _rehearsal(wire, extra=extra, fill_from_results=True),
            servers={"pyghidra": required},
            gates=gates,
            notes=proposal_notes if name.startswith("b2p") else None,
        )
        results.append(result)
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


def upload_checks() -> dict[str, Any]:
    """What the upload route decides for each fixture, read through its own functions."""
    from app.api.v1.sandbox_reports import _read_declared, sandbox_formats

    settings = _defaults()
    allowed = set(settings.sandbox.upload.allowed_formats)
    formats = sandbox_formats(settings.sandbox.report_formats)
    out: dict[str, Any] = {}
    for name in ("cape2_report.json", "triage_overview.json", "triage_report_behavioral1.json"):
        payload = json.loads((SANDBOX_FIXTURES / name).read_text(encoding="utf-8"))
        fmt, task_id, target = _read_declared(payload, formats)
        accepted = fmt is not None and fmt.name in allowed
        out[name] = {
            "format": getattr(fmt, "name", None),
            "status": 201 if accepted else 415,
            "task_id": task_id,
            "target_sha256": target,
        }
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
                    "target_matches_sample": api[fixture]["target_sha256"] == _sample_sha256(),
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
        if name.startswith("e2p"):
            # An accepted proposal is held to what the hand declaration gets.
            expected = STUB_SERVICE
        for wire in wires:

            def gates(
                record: RunRecord, rows: dict[str, Any], _dump: Path, expected: str = expected
            ) -> Gates:
                rep = record.malware_report.get("reputation") or []
                first = rep[0] if rep else {}
                stub: dict[str, Any] = next(
                    (r for r in rep if r.get("service") == STUB_SERVICE), {}
                )
                own: Gates = {
                    "first_service": (
                        (first.get("service") or "") == expected,
                        f"expected {expected or 'none asked'!r}: "
                        + json.dumps(first, default=str)[:300],
                    ),
                }
                if expected == STUB_SERVICE or stub:
                    own["stub_counts_read"] = (
                        stub.get("malicious") == 3 and stub.get("total") == 60,
                        f"{stub.get('malicious')}/{stub.get('total')}",
                    )
                return own

            asked = expected == STUB_SERVICE
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


def _kit_gates(declared: dict[str, Any]) -> Callable[..., Gates]:
    def gates(record: RunRecord, _rows: dict[str, Any], dump: Path) -> Gates:
        kit_tools = [
            str(e.get("tool")) for e in reach_mod.entries_of(record, reach_mod.by_server("kit"))
        ]
        kit_names = {"strings", "pe_info", "attck_lookup", "identify_file", "decompile_function"}
        offered = [
            name
            for name in reach_mod.tools_offered(dump)
            if name in kit_names or name.startswith("kit")
        ]
        degradations = record.malware_report.get("degradation_reasons") or []
        return {
            "own_facts": _kit_read_by_its_own_facts(record, declared),
            "kit_entries": (bool(kit_tools), json.dumps(kit_tools)),
            "offered_names": (True, json.dumps(offered)),
            "degradations": (True, json.dumps(degradations)),
        }

    return gates


def _kit_run(
    ctx: Context, name: str, extra: dict[str, Any], declared: dict[str, Any], **kw: Any
) -> RunResult:
    result, _record = run_one(
        ctx,
        name.split("-", 1)[0],
        name,
        _rehearsal(ctx.wires[0], extra=extra, fill_from_results=True, **kw),
        servers={"kit": ALL_E},
        gates=_kit_gates(declared),
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
        results.append(_kit_run(ctx, "f1-with-r2", extra, {}, static_sample_paths={"r2": ""}))
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
    clone["tools"] = [
        {"kind": "mcp", "server": "kit"},
        *[t for t in clone.get("tools") or [] if t.get("server") != "analysis"],
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
        lines.append(f"| {r.name} | {r.wire} | {r.status} | {'ok' if r.ok else 'MISS'} |")
    for r in results:
        misses = [k for k, (ok, _d) in r.gates.items() if not ok]
        if r.base_failures or r.reach_misses or misses:
            lines += ["", f"## {r.name} ({r.wire})"]
            lines += [f"- base: {k}: {v}" for k, v in r.base_failures.items()]
            lines += [f"- reach: {m}" for m in r.reach_misses]
            lines += [f"- gate: {k}: {r.gates[k][1]}" for k in misses]
    (ctx.out / f"{scenario}.md").write_text("\n".join(lines) + "\n", "utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", type=Path, help="results directory (no dot-segment in its path)")
    parser.add_argument("--scenarios", nargs="*", default=list(DEFAULT_SET))
    parser.add_argument("--wires", nargs="*", default=["openai", "anthropic"])
    parser.add_argument(
        "--r2mcp", default=os.environ.get("VALIDATION_R2MCP") or shutil.which("r2mcp") or ""
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
    ctx = Context(
        out=no_hidden_segment(args.out),
        wires=tuple(args.wires),
        r2mcp=args.r2mcp,
        pyghidra=args.pyghidra,
        ghidra_dir=args.ghidra_dir,
        java_home=args.java_home,
    )
    ctx.out.mkdir(parents=True, exist_ok=True)
    missed = 0
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
            missed += not r.ok
            print(f"{scenario:3} {r.name:32} {r.wire:9} {r.status:9} {'ok' if r.ok else 'MISS'}")
    return 1 if missed else 0


if __name__ == "__main__":
    raise SystemExit(main())
