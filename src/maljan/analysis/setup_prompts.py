"""Every system prompt the platform can send for a job, rendered by the code that builds it.

The run fingerprint (``analysis.efficiency``) hashes the job's setup, never
its traffic: the same code, settings and servers give the same fingerprint
whether or not a run asked a validation retry, reached a revision round,
cleared tool answers or took the mediator's fast path, and on any sample.

So each system prompt is rendered here by the very builder that sends it, with
one fixed placeholder job (:data:`PLACEHOLDER_SHA256`, :data:`PLACEHOLDER_PATH`,
:data:`PLACEHOLDER_NAME`, :data:`PLACEHOLDER_JOB` and the neutral sample
format) in place of the job's own values. The hash is the text the builder
produces, so an edit to any part of it — a constant, a sentence a function
writes, a fragment — moves it, and no real value is masked out of anything:

- each analyst of the active profile, as it was resolved
  (``composition.prompt_for``), for the tools its loop binds (the resolved ones
  until a loop has bound them) and for a tools-free call, and its revision
  prompt (``base_agent.revision_messages``) for both;
- the mediator's prompt (``judge_agent.mediator_system_prompt``) for every case
  of its tool sentence, with the judge's and the mediator's tools as set up;
- the narrative's (``narrative_agent.system_prompt``), every format fragment
  ``prompt_fragments.format_fragment`` can produce, and the prompts a call
  sends as a constant: the view prompts, the judge's verdict and technique
  questions, the composer's, the question round's and the summariser's.

``PROMPT_SITES`` names, for every place in the code that builds a system
message, which of these renders it. The proof that the map is complete is
run-time: the in-process rehearsal sends every request through its stub, and
a test re-renders each system prompt the stub received with the placeholder
job and finds it among these (``tests/integration``).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

# The one placeholder job every prompt is rendered for: a fixed sha256, path,
# file name and job id, and the format a container that was never told sends.
PLACEHOLDER_SHA256 = "0" * 64
PLACEHOLDER_NAME = "sample.bin"
PLACEHOLDER_PATH = f"/placeholder/{PLACEHOLDER_NAME}"
PLACEHOLDER_JOB = "placeholder-job"
PLACEHOLDER_FORMAT = ("unknown", "unknown")

# The prompts a call sends as a constant, by the name the fingerprint gives
# them: read from their module at render time, so an edited constant is the
# rendered text.
PROMPT_CONSTANTS: dict[str, tuple[tuple[str, str], ...]] = {
    "views": (
        ("maljan.agents.base_agent", "_VIEW_SYSTEM"),
        ("maljan.agents.base_agent", "_VIEW_SYSTEM_WITHOUT_TECHNIQUES"),
    ),
    "judge verdict": (("maljan.agents.judge_agent", "JUDGE_VERDICT_SYSTEM"),),
    "mediation extraction": (("maljan.agents.judge_agent", "MEDIATION_EXTRACTION_SYSTEM"),),
    "technique questions": (("maljan.agents.judge_agent", "TECHNIQUE_QUESTION_SYSTEM"),),
    "composer": (("maljan.reporting.composer", "_SYSTEM"),),
    "questions": (("maljan.reporting.question_round", "SYSTEM_PROMPT"),),
    "summarizer": (
        ("maljan.analysis.function_summarizer", "_SUMMARIZE_SYSTEM"),
        ("maljan.analysis.function_summarizer", "_MERGE_SYSTEM"),
    ),
}

# The analysts' own prompts: one part per analyst of the active profile,
# named ``analyst:<key>``, and its revision prompts beside it, ``revision:<key>``.
ANALYSTS = "analysts"
REVISION = "revision"

# Every place that builds a system message, and what renders it. ``None`` is a
# place that builds no model prompt; its reason is the comment beside it.
PROMPT_SITES: dict[str, str | None] = {
    "maljan.agents.base_agent:prompt_to_messages": ANALYSTS,
    "maljan.agents.base_agent:revision_messages": REVISION,
    "maljan.agents.base_agent:BaseAnalyst._run_tool_loop": ANALYSTS,
    "maljan.agents.base_agent:BaseAnalyst._synthesise_from_answered_asks": ANALYSTS,
    "maljan.agents.base_agent:BaseAnalyst._validate_isr": ANALYSTS,
    "maljan.agents.base_agent:BaseAnalyst.answer_task": ANALYSTS,
    "maljan.agents.base_agent:BaseAnalyst._invoke_view": "views",
    "maljan.agents.configurable_analyst:ConfigurableAnalyst.analyze": ANALYSTS,
    "maljan.agents.configurable_analyst:ConfigurableAnalyst.analyze_isr": ANALYSTS,
    "maljan.agents.dynamic_analyst:DynamicAnalyst.analyze_isr": ANALYSTS,
    "maljan.agents.dynamic_analyst:DynamicAnalyst.revise_isr": ANALYSTS,
    "maljan.agents.network_analyst:NetworkAnalyst.analyze_isr": ANALYSTS,
    "maljan.agents.static_analyst:StaticAnalyst.analyze_isr": ANALYSTS,
    "maljan.agents.static_analyst:StaticAnalyst.revise_isr": ANALYSTS,
    # The mediator's own prompt, and the structured extraction it sends after it.
    "maljan.agents.judge_agent:JudgeAgent._mediate_round": "mediator",
    "maljan.agents.judge_agent:JudgeAgent.execute_tool_loop": "mediator",
    "maljan.agents.judge_agent:JudgeAgent._ask_for_contradictions_block": "mediator",
    "maljan.agents.judge_agent:JudgeAgent.give_verdict": "judge verdict",
    "maljan.agents.judge_agent:JudgeAgent.decide_techniques": "technique questions",
    "maljan.reporting.composer:ReportComposer._author._turns": "composer",
    "maljan.reporting.narrative_agent:NarrativeAgent._build_prompt": "narrative",
    "maljan.reporting.question_round:build_messages": "questions",
    "maljan.analysis.function_summarizer:FunctionSummarizer.summarize_chunk": "summarizer",
    "maljan.analysis.function_summarizer:FunctionSummarizer._merge_summaries": "summarizer",
    # A settings section's label ("system"), not a model prompt.
    "maljan.core.settings_annotations:<module>": None,
}


class PlaceholderJob:
    """The job's container, answering every per-job value with the placeholder job's."""

    sample_format = PLACEHOLDER_FORMAT
    sample_sha256 = PLACEHOLDER_SHA256
    sample_path = PLACEHOLDER_PATH
    job_id = PLACEHOLDER_JOB

    def __init__(self, container: Any) -> None:
        self._container = container
        self.server_sample_paths: dict[str, str] = {}

    def job_key(self) -> str:
        return PLACEHOLDER_JOB

    def __getattr__(self, name: str) -> Any:
        return getattr(self._container, name)


def _constants() -> dict[str, list[str]]:
    import importlib

    return {
        name: [str(getattr(importlib.import_module(module), attr)) for module, attr in sources]
        for name, sources in PROMPT_CONSTANTS.items()
    }


def format_fragments() -> list[str]:
    """Every paragraph ``format_fragment`` produces, over every file type and platform it reads."""
    from maljan.agents import prompt_fragments
    from maljan.extractors.sample_identity import ARCHIVE_FILE_TYPES, SCRIPT_FILE_TYPES

    file_types = sorted({*prompt_fragments._BY_FILE_TYPE, *SCRIPT_FILE_TYPES, *ARCHIVE_FILE_TYPES})
    platforms = sorted(prompt_fragments._BY_PLATFORM)
    rendered = {
        prompt_fragments.format_fragment(file_type, platform)
        for file_type in [*file_types, "unknown"]
        for platform in [*platforms, "unknown"]
    }
    return sorted(rendered)


def _revision_systems(prompts: Iterable[str]) -> list[str]:
    """The revision round's system prompt for each of an analyst's prompts."""
    from maljan.agents.base_agent import revision_messages

    return [revision_messages(prompt, "", "", {}, "", isr=True)[0][1] for prompt in prompts]


def analyst_prompts(container: Any, analysts: Iterable[str]) -> dict[str, list[str]]:
    """Each analyst's prompts and revision prompts, for the placeholder job, by key.

    Only an analyst the job resolved is rendered; ``analysts`` names the ones
    the fingerprint covers (the active profile's).
    """
    from maljan.agents.composition import prompt_for

    resolved_of = getattr(container, "resolved_agents", None)
    resolved = resolved_of() if callable(resolved_of) else {}
    tools_of = getattr(container, "setup_tools", None)
    set_up = tools_of() if callable(tools_of) else {}
    job = PlaceholderJob(container)
    out: dict[str, list[str]] = {}
    for key in sorted(analysts):
        agent = resolved.get(key)
        if agent is None:
            continue
        bound: list[Any] = list(set_up.get(key, getattr(agent, "tools", None) or []))
        none: list[Any] = []
        prompts = [prompt_for(agent, job, tools) for tools in (bound, none)]
        out[f"analyst:{key}"] = prompts
        out[f"revision:{key}"] = _revision_systems(prompts)
    return out


def mediator_prompts(tool_sets: Iterable[list[Any]]) -> list[str]:
    """The mediator's system prompt for every case of its tool sentence, for each tool set."""
    from maljan.agents.judge_agent import mediator_system_prompt

    rendered: set[str] = set()
    for tools in [[], *tool_sets]:
        for identity, lookup, needs in (
            (True, True, True),
            (False, True, True),
            (False, False, True),
            (False, False, False),
        ):
            rendered.add(
                mediator_system_prompt(
                    identity_unanswered=identity,
                    lookup_attached=lookup,
                    needs_tools=needs,
                    sha256=PLACEHOLDER_SHA256,
                    tools=tools,
                )
            )
        rendered.add(
            mediator_system_prompt(
                identity_unanswered=True,
                lookup_attached=True,
                needs_tools=True,
                sha256="",
                tools=tools,
            )
        )
    return sorted(rendered)


def setup_prompts(
    container: Any,
    analysts: Iterable[str],
    judge_tools: Iterable[list[Any]] = (),
) -> dict[str, list[str]]:
    """Every system prompt the platform can send for this job, by name, for the placeholder job."""
    from maljan.reporting.narrative_agent import system_prompt as narrative_prompt

    return {
        **_constants(),
        "format fragments": format_fragments(),
        "mediator": mediator_prompts(judge_tools),
        "narrative": [narrative_prompt(None)],
        **analyst_prompts(container, analysts),
    }


def covered_names(names: Iterable[str]) -> set[str]:
    """The ``PROMPT_SITES`` names ``names`` covers (``analyst:*``, ``revision:*`` by their kind)."""
    out: set[str] = set()
    for name in names:
        if name.startswith("analyst:"):
            out.add(ANALYSTS)
        elif name.startswith("revision:"):
            out.add(REVISION)
        else:
            out.add(name)
    return out
