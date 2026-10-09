"""One rehearsal run inside this process: the stub model, the real pipeline, no Docker.

The pipeline is ``MaljanApp`` with the default profile, the mock sandbox, the
repository's own tool sidecars (started as the worker starts them, over
stdio), long-term memory in memory, and every model call going to the stub on
a loopback port through the settings a deployment would set:
``llm.openai.base_url`` or ``llm.anthropic.base_url``. Nothing here is a code
path of the product: the settings are built by ``build_settings``, the
application's own construction path.

What it does not cover is what only the stack has: the API, the queue, the
worker's job bookkeeping and the stored report. ``scripts/rehearsal/run.py``
rehearses those against the running stack.
"""

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.rehearsal.checklist import RunRecord  # noqa: E402
from scripts.rehearsal.roles import Brain  # noqa: E402
from scripts.rehearsal.sample import write_sample  # noqa: E402
from scripts.rehearsal.stub_model import ModelFacts, Pace, StubServer, StubState  # noqa: E402

API_KEY = "rehearsal-stub-key"
EXPERT_MODEL = "rehearsal-expert"
JUDGE_MODEL = "rehearsal-judge"


@dataclass
class Rehearsal:
    """What one in-process run is asked to do."""

    scenario: str = "normal"
    provider: str = "openai"
    work_dir: Path = field(default_factory=lambda: Path("rehearsal-work"))
    tokens_per_second: float = 0.0
    first_token_seconds: float = 0.0
    loop_steps: int | None = None
    slow_seconds: float | None = None
    # The deadline the whole run is held to, standing in for the worker's job
    # timeout; ``None`` holds it to none.
    job_timeout_s: float | None = None
    # The settings the run is configured with beyond the stub's address, and
    # what the checklist expects to find in force because of them.
    effort: str = "high"
    judge_max_tokens: int = 9000
    max_steps: int = 40
    agent_timeout_s: int = 900
    extra: dict[str, Any] = field(default_factory=dict)
    # Where every request body the stub receives is written; ``None`` writes none.
    dump_dir: Path | None = None


def settings_for(rehearsal: Rehearsal, root: str) -> dict[str, Any]:
    """The overrides a run is built from: the stub's address and the settings it checks."""
    common: dict[str, Any] = {
        "llm.provider": rehearsal.provider,
        "llm.require_probe": False,
        "llm.judge_max_tokens": rehearsal.judge_max_tokens,
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
                "llm.anthropic.expert_model": EXPERT_MODEL,
                "llm.anthropic.judge_model": EXPERT_MODEL,
                "llm.anthropic.effort": rehearsal.effort,
                "llm.agents": {"judge": {"provider": "anthropic", "model": JUDGE_MODEL}},
            }
        )
    else:
        common.update(
            {
                "llm.openai.base_url": f"{root}/v1",
                "llm.openai.api_key": API_KEY,
                "llm.openai.expert_model": EXPERT_MODEL,
                "llm.openai.judge_model": EXPERT_MODEL,
                "llm.openai.reasoning_effort": rehearsal.effort,
                "llm.agents": {
                    "judge": {"provider": "openai", "model": JUDGE_MODEL, "base_url": f"{root}/v1"}
                },
            }
        )
    common.update(rehearsal.extra)
    return common


def expected_for(rehearsal: Rehearsal) -> dict[str, Any]:
    """What the checklist finds in force when the settings above took effect."""
    return {
        "model.static": EXPERT_MODEL,
        "model.judge": JUDGE_MODEL,
        "model.mediator": EXPERT_MODEL,
        "model.reporter": EXPERT_MODEL,
        "effort": rehearsal.effort,
        "max_tokens.judge": rehearsal.judge_max_tokens,
        "max_steps": rehearsal.max_steps,
        "timeout_s": rehearsal.agent_timeout_s,
    }


def _claims_of(isr_reports: Any) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for agent, report in (isr_reports or {}).items():
        claims = getattr(report, "claims", None)
        if claims is None and isinstance(report, dict):
            claims = report.get("claims")
        texts = []
        for claim in claims or []:
            text = getattr(claim, "claim", None)
            if text is None and isinstance(claim, dict):
                text = claim.get("claim")
            if text:
                texts.append(str(text))
        out[str(agent)] = texts
    return out


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        dumped = dump(mode="json", by_alias=True, exclude_none=True)
        return dumped if isinstance(dumped, dict) else {}
    return {}


async def rehearse(rehearsal: Rehearsal) -> RunRecord:
    """Run the pipeline once against a fresh stub; answer the run's record."""
    from maljan.app import MaljanApp
    from maljan.core.config import install_settings
    from maljan.core.settings_overrides import build_settings

    brain = Brain(
        scenario=rehearsal.scenario,
        loop_steps=rehearsal.loop_steps,
        slow_seconds=rehearsal.slow_seconds,
    )
    state = StubState(
        brain=brain,
        pace=Pace(rehearsal.first_token_seconds, rehearsal.tokens_per_second),
        facts=ModelFacts(),
        dump_dir=rehearsal.dump_dir,
    )
    events: list[dict[str, Any]] = []
    sample_path, sha256 = write_sample(rehearsal.work_dir)
    status, error, result = "failed", "", {}
    started = time.monotonic()
    with StubServer(state) as server:
        settings = build_settings(settings_for(rehearsal, server.root))
        install_settings(settings)
        app = MaljanApp(
            config=settings,
            job_id=f"rehearsal-{rehearsal.scenario}",
            event_sink=lambda kind, payload: events.append({"type": kind, **payload}),
        )
        try:
            run = app.arun(sha256, file_name=sample_path.name, sample_path=str(sample_path))
            result = await asyncio.wait_for(run, timeout=rehearsal.job_timeout_s)
            status = "completed" if app.failed_step is None else "failed"
        except TimeoutError:
            status, error = "failed", f"the run passed its {rehearsal.job_timeout_s}s deadline"
        except Exception as exc:  # noqa: BLE001 — a failed run is a record, not a crash
            status, error = "failed", f"{type(exc).__name__}: {exc}"
        finally:
            await app.aclose()
        log = list(state.log)
    elapsed = time.monotonic() - started
    return RunRecord(
        scenario=rehearsal.scenario,
        job_status=status,
        job_error=error,
        verdict=str(result.get("final_decision") or ""),
        run_summary=_as_dict(result.get("run_summary")),
        malware_report=_as_dict(result.get("malware_report")),
        markdown=str(result.get("malware_report_markdown") or ""),
        stix_bundle=_as_dict(result.get("stix_output")),
        stix_extended=_as_dict(result.get("stix_bundle_extended")),
        claims_in_force=_claims_of(result.get("isr_reports")),
        events=events,
        stub_log=log,
        expected=expected_for(rehearsal),
        scenario_params={"loop_steps": brain.loop_steps, "slow_seconds": brain.slow_seconds},
        elapsed_s=elapsed,
    )
