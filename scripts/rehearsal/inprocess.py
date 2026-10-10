"""One rehearsal run inside this process: the stub model, the real pipeline, no Docker.

The pipeline is ``MaljanApp`` with the default profile, the mock sandbox, the
repository's own tool sidecars (started as the worker starts them, over
stdio), and every model call going to the stub on a loopback port through the
settings a deployment would set: ``llm.openai.base_url`` or
``llm.anthropic.base_url``. The settings are built by ``build_settings``, the
application's own construction path, and the models are real ones —
``claude-haiku-5-5`` on the Anthropic wire, ``deepseek-v4-flash`` with a
``deepseek-v4-pro`` judge on the OpenAI-compatible wire — so the stub refuses
what the paid API refuses for them and the run's spend is priced from the
vendored table. Before the run the product's own connection test
(``settings_probes.run_probe("llm")``) is asked against the stub.

How this differs from a paid run on the stack (``scripts/rehearsal/run.py``
in gate mode is the gate):

* no API, no queue, no worker: the job bookkeeping, the probe gate a job is
  submitted through, the stored report and the worker's job timeout
  (``core.job_timeout``) are exercised only against the stack; the deadline
  here is ``asyncio.wait_for``;
* the static provider is ``none`` (no Ghidra or radare2) and long-term
  memory is in memory (no Qdrant);
* the rehearsal's own settings, not the operator's: effort ``high`` (judge
  ``medium`` / ``max``), the judge's cap, step and time limits, a spend
  ceiling so the run summary carries its spend, ``compat`` ``deepseek`` and
  parallel analysts as a hosted DeepSeek endpoint resolves them.

Every process-wide setting a run installs is put back when it ends: the
settings singleton, the sidecars' sample roots and the learned window, output
and capability facts.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.rehearsal.checklist import COMPOSED, RunRecord  # noqa: E402
from scripts.rehearsal.roles import Brain  # noqa: E402
from scripts.rehearsal.sample import write_sample  # noqa: E402
from scripts.rehearsal.stub_model import Pace, StubServer, StubState  # noqa: E402

API_KEY = "rehearsal-stub-key"
# The models each wire rehearses, by role.
MODELS = {
    "anthropic": {"expert": "claude-haiku-5-5", "judge": "claude-haiku-5-5"},
    "openai": {"expert": "deepseek-v4-flash", "judge": "deepseek-v4-pro"},
}
JUDGE_EFFORT = {"anthropic": "medium", "openai": "max"}
# The window each wire's models are served and declared with, where no stored
# description or table row documents one: the harness's own setting, served
# by the stub and declared to the product as ``llm.openai.context_size``, as
# an operator declares the window of a hosted model the table does not name.
HARNESS_WINDOW: dict[str, int | None] = {"anthropic": None, "openai": 200_000}
# The deadline ``deadline_hit`` is held to, short enough that it fires.
DEADLINE_HIT_S = 12.0
# How long a run stopped at its deadline is given for its in-flight work to see the stop.
STRAGGLER_WAIT_S = 5.0


@dataclass
class Rehearsal:
    """What one in-process run is asked to do."""

    scenario: str = "normal"
    provider: str = "openai"
    work_dir: Path = field(default_factory=lambda: Path("rehearsal-results") / "work")
    tokens_per_second: float = 0.0
    first_token_seconds: float = 0.0
    loop_steps: int | None = None
    slow_seconds: float | None = None
    # The stage ``deadline_hit`` aims its deadline at (``roles.STAGE_ROLES``):
    # only that stage's calls are held, so the deadline lands in it.
    deadline_in: str | None = None
    # The deadline the whole run is held to, standing in for the worker's job
    # timeout; ``None`` holds it to none (``deadline_hit`` sets its own).
    job_timeout_s: float | None = None
    effort: str = "high"
    judge_max_tokens: int = 9000
    max_steps: int = 40
    agent_timeout_s: int = 900
    spend_ceiling_usd: float = 1000.0
    chars_per_token: int = 4
    extra: dict[str, Any] = field(default_factory=dict)
    # Where every request body the stub receives is written; ``None`` writes none.
    dump_dir: Path | None = None

    @property
    def deadline_s(self) -> float | None:
        if self.scenario == "deadline_hit":
            return self.job_timeout_s or DEADLINE_HIT_S
        return self.job_timeout_s


def settings_for(rehearsal: Rehearsal, root: str) -> dict[str, Any]:
    """The overrides a run is built from: the stub's address and the settings it checks."""
    models = MODELS[rehearsal.provider]
    judge_effort = JUDGE_EFFORT[rehearsal.provider]
    common: dict[str, Any] = {
        "llm.provider": rehearsal.provider,
        "llm.judge_max_tokens": rehearsal.judge_max_tokens,
        "llm.max_spend_usd_per_job": rehearsal.spend_ceiling_usd,
        "memory.backend": "memory",
        "sandbox.provider": "mock",
        "static.provider": "none",
        "react_agent_max_steps": rehearsal.max_steps,
        "react_agent_timeout": rehearsal.agent_timeout_s,
    }
    if rehearsal.provider == "anthropic":
        common.update(
            {
                "llm.anthropic.base_url": root,
                "llm.anthropic.api_key": API_KEY,
                "llm.anthropic.expert_model": models["expert"],
                "llm.anthropic.judge_model": models["expert"],
                "llm.anthropic.effort": rehearsal.effort,
                "llm.agents": {
                    "judge": {
                        "provider": "anthropic",
                        "model": models["judge"],
                        "effort": judge_effort,
                    }
                },
            }
        )
    else:
        common.update(
            {
                "llm.openai.base_url": f"{root}/v1",
                "llm.openai.api_key": API_KEY,
                "llm.openai.compat": "deepseek",
                "llm.openai.context_size": HARNESS_WINDOW["openai"],
                "llm.parallel_analysts": "true",
                "llm.openai.expert_model": models["expert"],
                "llm.openai.judge_model": models["expert"],
                "llm.openai.reasoning_effort": rehearsal.effort,
                "llm.agents": {
                    "judge": {
                        "provider": "openai",
                        "model": models["judge"],
                        "base_url": f"{root}/v1",
                        "effort": judge_effort,
                    }
                },
            }
        )
    common.update(rehearsal.extra)
    return common


def expected_for(rehearsal: Rehearsal) -> dict[str, Any]:
    """What the checklist finds in force when the settings above took effect."""
    models = MODELS[rehearsal.provider]
    return {
        "model.static": models["expert"],
        "model.judge": models["judge"],
        "model.mediator": models["expert"],
        "model.reporter": models["expert"],
        "effort.static": rehearsal.effort,
        "effort.judge": JUDGE_EFFORT[rehearsal.provider],
        "effort.mediator": rehearsal.effort,
        "effort.reporter": rehearsal.effort,
        "max_tokens.judge": rehearsal.judge_max_tokens,
        "max_steps": rehearsal.max_steps,
        "timeout_s": rehearsal.agent_timeout_s,
    }


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        dumped = dump(mode="json", by_alias=True, exclude_none=True)
        return dumped if isinstance(dumped, dict) else {}
    return {}


def claims_from_events(events: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Each analyst's answer in force: the claims of the last message it said with claims."""
    out: dict[str, list[str]] = {}
    for event in events:
        if event.get("type") != "agent_message" or event.get("role") not in (None, "analyst"):
            continue
        claims = event.get("claims")
        speaker = str(event.get("speaker") or "")
        if isinstance(claims, list) and claims and speaker:
            out[speaker] = [str(c.get("claim") or "") for c in claims if isinstance(c, dict)]
    return out


def empty_evidence_sections(
    malware_report: dict[str, Any], claims: dict[str, list[dict[str, Any]]]
) -> list[str]:
    """The sections whose evidence the product's own bundling finds empty.

    The composer skips such a section without asking the model and without a
    mark; this is the product's own reading of the stored report, so a section
    it lists was never the model's to write.
    """
    from maljan.reporting.evidence_bundles import bundle_for, is_empty
    from maljan.reporting.models import MalwareReport
    from maljan.schemas.isr_models import AgentISR, ClaimEvidence

    report = MalwareReport.model_validate(malware_report)
    isr = {
        agent: AgentISR(
            agent_id=agent,
            domain=agent,
            claims=[
                ClaimEvidence(
                    claim=str(c.get("claim") or ""),
                    evidence_ref=str(c.get("evidence_ref") or ""),
                    confidence=float(c.get("confidence") or 0.0),
                    technique_id=c.get("technique_id") or None,
                )
                for c in rows
            ],
        )
        for agent, rows in claims.items()
    }
    return [
        section
        for section in COMPOSED
        if is_empty(bundle_for(section, report, report.technical_evidence, isr))
    ]


def _claim_rows(isr_reports: Any) -> dict[str, list[dict[str, Any]]]:
    rows: dict[str, list[dict[str, Any]]] = {}
    for agent, report in (isr_reports or {}).items():
        rows[str(agent)] = [
            {
                "claim": getattr(c, "claim", ""),
                "evidence_ref": getattr(c, "evidence_ref", ""),
                "confidence": getattr(c, "confidence", 0.0),
                "technique_id": getattr(c, "technique_id", None),
            }
            for c in getattr(report, "claims", None) or []
        ]
    return rows


class _ProcessState:
    """The process-wide state a run changes, kept and put back."""

    def __init__(self) -> None:
        from maljan.core import config
        from maljan.tools.roots import SAMPLE_ROOTS_ENV

        self._config = config
        self._settings = config._settings_instance
        self._roots_env = SAMPLE_ROOTS_ENV
        self._roots = os.environ.get(SAMPLE_ROOTS_ENV)

    def restore(self) -> None:
        from maljan.llm import context_window, model_capabilities, model_output_limits

        self._config._settings_instance = self._settings
        if self._roots is None:
            os.environ.pop(self._roots_env, None)
        else:
            os.environ[self._roots_env] = self._roots
        context_window.forget_learned_windows()
        model_output_limits.forget_learned()
        model_capabilities.forget_capabilities()


async def _probe(overrides: dict[str, Any]) -> tuple[bool, str]:
    """The product's connection test over these settings, against the stub."""
    from app.services.settings_probes import run_probe

    values = {f"core.{key}": value for key, value in overrides.items()}
    result = await run_probe("llm", values, {})
    return bool(result.ok), str(result.detail)


async def rehearse(rehearsal: Rehearsal) -> RunRecord:
    """Run the pipeline once against a fresh stub; answer the run's record."""
    from scripts.rehearsal import wire

    from maljan.app import MaljanApp
    from maljan.core.config import install_settings
    from maljan.core.settings_overrides import build_settings

    kept = _ProcessState()
    wire.set_chars_per_token(rehearsal.chars_per_token)
    brain = Brain(
        scenario=rehearsal.scenario,
        loop_steps=rehearsal.loop_steps,
        slow_seconds=rehearsal.slow_seconds,
        deadline_in=rehearsal.deadline_in,
    )
    state = StubState(
        brain=brain,
        pace=Pace(rehearsal.first_token_seconds, rehearsal.tokens_per_second),
        api_key=API_KEY,
        dump_dir=rehearsal.dump_dir,
        window=HARNESS_WINDOW[rehearsal.provider],
    )
    events: list[dict[str, Any]] = []
    sample_path, sha256 = write_sample(rehearsal.work_dir)
    status, error, result = "failed", "", {}
    probe_ok, probe_detail = False, ""
    started = time.monotonic()
    try:
        with StubServer(state) as server:
            overrides = settings_for(rehearsal, server.root)
            # The connection test is answered as a normal model would; its
            # calls are not the run's and spend none of the scenario's faults.
            state.brain = Brain(scenario="normal")
            probe_ok, probe_detail = await _probe(overrides)
            with state.lock:
                probe_calls = list(state.log)
                state.log.clear()
            state.brain = brain
            settings = build_settings(overrides)
            install_settings(settings)
            started = time.monotonic()
            app = MaljanApp(
                config=settings,
                job_id=f"rehearsal-{rehearsal.scenario}",
                event_sink=lambda kind, payload: events.append({"type": kind, **payload}),
            )
            try:
                run = app.arun(sha256, file_name=sample_path.name, sample_path=str(sample_path))
                result = await asyncio.wait_for(run, timeout=rehearsal.deadline_s)
                status = "completed" if app.failed_step is None else "failed"
            except TimeoutError:
                status = "failed"
                error = f"the run passed its {rehearsal.deadline_s}s deadline"
                result = dict(app.built_report or {})
                # Stop the run's own work the way the worker stops a job, and
                # let what is still in flight see it while the stub answers,
                # so nothing of this run outlives it.
                app.container.cancellation.cancel(error)
                await asyncio.sleep(STRAGGLER_WAIT_S)
            except Exception as exc:  # noqa: BLE001 — a failed run is a record, not a crash
                status, error = "failed", f"{type(exc).__name__}: {exc}"
            finally:
                await app.aclose()
            log = state.calls()
        elapsed = time.monotonic() - started
        # Read while the run's settings are still installed: the product's own
        # readers below would otherwise build a default Settings of their own.
        malware_report = _as_dict(result.get("malware_report"))
        empty: list[str] | None = None
        if malware_report:
            try:
                empty = empty_evidence_sections(
                    malware_report, _claim_rows(result.get("isr_reports"))
                )
            except Exception:  # noqa: BLE001 — sections nothing can vouch for are not excused
                empty = None
        required = _required_stages()
    finally:
        kept.restore()
    return RunRecord(
        scenario=rehearsal.scenario,
        api=rehearsal.provider,
        job_status=status,
        job_error=error,
        verdict=str(result.get("final_decision") or ""),
        run_summary=_as_dict(result.get("run_summary")),
        malware_report=malware_report,
        markdown=str(result.get("malware_report_markdown") or ""),
        stix_bundle=_as_dict(result.get("stix_output")),
        stix_extended=_as_dict(result.get("stix_bundle_extended")),
        claims_in_force=claims_from_events(events),
        events=events,
        stub_log=log,
        expected=expected_for(rehearsal),
        required_stages=required,
        empty_evidence_sections=empty,
        probe={"ok": probe_ok, "detail": probe_detail, "calls": len(probe_calls)},
        scenario_params={
            "loop_steps": brain.loop_steps,
            "slow_seconds": brain.slow_seconds,
            "job_timeout_s": rehearsal.deadline_s,
            "deadline_in": brain.deadline_in,
            "slow_roles": sorted(brain.slow_roles),
            "mode": "in_process",
            "served_windows": {
                model: state.facts(model).window
                for model in sorted(set(MODELS[rehearsal.provider].values()))
            },
        },
        elapsed_s=elapsed,
    )


def _required_stages() -> dict[str, list[str]]:
    """The default profile's stages, each with the agents it names."""
    from maljan.agents.composition import active_profile
    from maljan.core.settings_overrides import build_settings

    profile = active_profile(build_settings({}))
    return {str(stage.key): [str(a) for a in stage.agents] for stage in profile.stages}
