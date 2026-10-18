"""Every system prompt the platform can send for a job, as its setup fixes it.

The run fingerprint (``analysis.efficiency``) hashes the job's setup, never
its traffic: the same code, settings and servers give the same fingerprint
whether or not a run asked a validation retry, reached a revision round,
cleared tool answers or took the mediator's fast path, and on any sample.

So the prompts are read from where each is built, not from the requests a run
sent:

- each resolved agent's own prompt, composed as its calls compose it
  (``composition.prompt_for``) for the tools it was resolved with and for a
  tools-free call, with the sample's format fragment held at the neutral one
  and the job's own identifiers masked (``core.input_meter.job_identifiers``);
- every other system prompt as its fixed template: the revision framing, the
  view prompts, every format fragment, the mediator's head and each of its
  tool sentences, the judge's verdict and technique-question prompts, the
  composer's, the narrative's and the summariser's.

The run-dependent text a call adds in its human turn (a retry's question, a
notice, the evidence) is not a system prompt and is not here.

``PROMPT_SITES`` names, for every place in the code that builds a system
message, which of these covers it; a test walks the source and fails on a
place this map does not name, so a new prompt cannot be left out unseen.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterable, Mapping
from typing import Any

# The neutral sample a setup prompt is composed for: the format fragment it
# carries is the one a container that was never told the format sends, and
# every other fragment is hashed as its fixed template below.
_NEUTRAL_FORMAT = ("unknown", "unknown")

# Each fixed template, by the name the fingerprint gives it: the module and the
# attribute it is read from at hash time, so an edited constant is the hashed
# constant. A mapping's values are each a template.
PROMPT_CONSTANTS: dict[str, tuple[tuple[str, str], ...]] = {
    "revision": (("maljan.agents.base_agent", "_REVISION_ISR_FRAMING"),),
    "views": (
        ("maljan.agents.base_agent", "_VIEW_SYSTEM"),
        ("maljan.agents.base_agent", "_VIEW_SYSTEM_WITHOUT_TECHNIQUES"),
    ),
    "format fragments": (
        ("maljan.agents.prompt_fragments", "_BY_FILE_TYPE"),
        ("maljan.agents.prompt_fragments", "_BY_PLATFORM"),
        ("maljan.agents.prompt_fragments", "_SCRIPT_FRAGMENT"),
        ("maljan.agents.prompt_fragments", "_ARCHIVE_FRAGMENT"),
        ("maljan.agents.prompt_fragments", "_NEUTRAL"),
    ),
    "mediator": (
        ("maljan.agents.judge_agent", "MEDIATOR_SYSTEM_HEAD"),
        ("maljan.agents.judge_agent", "MEDIATOR_LOOKUP_ONCE_BY_HASH"),
        ("maljan.agents.judge_agent", "MEDIATOR_LOOKUP_ONCE"),
        ("maljan.agents.judge_agent", "MEDIATOR_TI_TOOLS"),
        ("maljan.agents.judge_agent", "_NO_TOOLS_NEEDED"),
    ),
    "judge verdict": (("maljan.agents.judge_agent", "JUDGE_VERDICT_SYSTEM"),),
    "technique questions": (("maljan.agents.judge_agent", "TECHNIQUE_QUESTION_SYSTEM"),),
    "composer": (("maljan.reporting.composer", "_SYSTEM"),),
    "narrative": (("maljan.reporting.narrative_agent", "_SYSTEM_PROMPT_TEMPLATE"),),
    "summarizer": (
        ("maljan.analysis.function_summarizer", "_SUMMARIZE_SYSTEM"),
        ("maljan.analysis.function_summarizer", "_MERGE_SYSTEM"),
    ),
}

# The analysts' own prompts: one part per resolved agent, named ``analyst:<key>``.
ANALYSTS = "analysts"

# Every place that builds a system message, and what covers it. ``None`` is a
# place that builds no model prompt; its reason is the comment beside it.
PROMPT_SITES: dict[str, str | None] = {
    "maljan.agents.base_agent:prompt_to_messages": ANALYSTS,
    "maljan.agents.base_agent:revision_messages": "revision",
    "maljan.agents.base_agent:BaseAnalyst._run_tool_loop": ANALYSTS,
    "maljan.agents.base_agent:BaseAnalyst._synthesise_from_answered_asks": ANALYSTS,
    "maljan.agents.base_agent:BaseAnalyst._validate_isr": ANALYSTS,
    "maljan.agents.base_agent:BaseAnalyst.answer_task": ANALYSTS,
    "maljan.agents.base_agent:BaseAnalyst._invoke_view": "views",
    "maljan.agents.configurable_analyst:ConfigurableAnalyst.analyze": ANALYSTS,
    "maljan.agents.configurable_analyst:ConfigurableAnalyst.analyze_isr": ANALYSTS,
    "maljan.agents.dynamic_analyst:DynamicAnalyst.analyze": ANALYSTS,
    "maljan.agents.dynamic_analyst:DynamicAnalyst.analyze_isr": ANALYSTS,
    "maljan.agents.dynamic_analyst:DynamicAnalyst.revise": ANALYSTS,
    "maljan.agents.dynamic_analyst:DynamicAnalyst.revise_isr": ANALYSTS,
    "maljan.agents.network_analyst:NetworkAnalyst.analyze": ANALYSTS,
    "maljan.agents.network_analyst:NetworkAnalyst.analyze_isr": ANALYSTS,
    "maljan.agents.static_analyst:StaticAnalyst.analyze": ANALYSTS,
    "maljan.agents.static_analyst:StaticAnalyst.analyze_isr": ANALYSTS,
    "maljan.agents.static_analyst:StaticAnalyst.revise": ANALYSTS,
    "maljan.agents.static_analyst:StaticAnalyst.revise_isr": ANALYSTS,
    "maljan.agents.judge_agent:JudgeAgent.mediate": "mediator",
    "maljan.agents.judge_agent:JudgeAgent.execute_tool_loop": "mediator",
    "maljan.agents.judge_agent:JudgeAgent._ask_for_contradictions_block": "mediator",
    "maljan.agents.judge_agent:JudgeAgent.give_verdict": "judge verdict",
    "maljan.agents.judge_agent:JudgeAgent.decide_techniques": "technique questions",
    "maljan.reporting.composer:ReportComposer._author._turns": "composer",
    "maljan.reporting.narrative_agent:NarrativeAgent._build_prompt": "narrative",
    "maljan.analysis.function_summarizer:FunctionSummarizer.summarize_chunk": "summarizer",
    "maljan.analysis.function_summarizer:FunctionSummarizer._merge_summaries": "summarizer",
    # A settings section's label ("system"), not a model prompt.
    "maljan.core.settings_annotations:<module>": None,
}


def _templates(value: Any) -> list[str]:
    """A constant's template text: a string, or each value of a mapping in key order."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [str(value[key]) for key in sorted(value)]
    return [str(value)]


def constant_templates() -> dict[str, list[str]]:
    """Each fixed template of :data:`PROMPT_CONSTANTS`, read from its module now."""
    from maljan.agents.prompt_fragments import tools_statement

    out: dict[str, list[str]] = {}
    for name, sources in PROMPT_CONSTANTS.items():
        texts: list[str] = []
        for module, attr in sources:
            texts.extend(_templates(getattr(importlib.import_module(module), attr)))
        out[name] = texts
    # The mediator's sentence about tools for a loop with none, as the
    # platform words it; for a loop with tools the statement is the tools'.
    out["mediator"].append(tools_statement(()))
    return out


class _NeutralSample:
    """The job's container, answering the sample's format as the neutral one."""

    sample_format = _NEUTRAL_FORMAT

    def __init__(self, container: Any) -> None:
        self._container = container

    def __getattr__(self, name: str) -> Any:
        return getattr(self._container, name)


def analyst_prompts(
    container: Any, mask: Callable[[str], str] = lambda text: text
) -> dict[str, list[str]]:
    """Each resolved agent's prompts, for its resolved tools and for none, by ``analyst:<key>``."""
    from maljan.agents.composition import prompt_for

    resolved_of = getattr(container, "resolved_agents", None)
    resolved = resolved_of() if callable(resolved_of) else {}
    neutral = _NeutralSample(container)
    out: dict[str, list[str]] = {}
    for key, agent in sorted(resolved.items()):
        texts = [
            mask(prompt_for(agent, neutral, list(tools)))
            for tools in (getattr(agent, "tools", None) or [], [])
        ]
        out[f"analyst:{key}"] = texts
    return out


def setup_prompts(
    container: Any, mask: Callable[[str], str] = lambda text: text
) -> dict[str, list[str]]:
    """Every system prompt the platform can send for this job, by name, as the setup fixes it."""
    return {**constant_templates(), **analyst_prompts(container, mask)}


def covered_names(names: Iterable[str]) -> set[str]:
    """The ``PROMPT_SITES`` names ``names`` covers (``analyst:*`` covers the analysts)."""
    return {ANALYSTS if name.startswith("analyst:") else name for name in names}
