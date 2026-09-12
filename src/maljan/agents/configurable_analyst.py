"""The analyst an operator declares rather than writes.

One class, parametrised by a ``ResolvedAgent``. Deliberately thin: the three
built-in analysts carry provider-specific ISR extraction that goldens pin —
Ghidra program info, CAPE signature shapes, PCAP heuristics — and reproducing
any of that generically would be a guess. What is left is the part that is the
same for every analyst: send the prompt, run the ReAct loop when there are
tools and a plain call when there are none, and wrap whatever comes back into
an ISR under the agent's own key.

The degradation policy is the one applied to custom servers: a
custom analyst never fails a job. A tool server that would not attach, a tool
that is not there, an LLM call that raises — each becomes a reason on
``degradation_reasons`` and a ``[WARN]`` report, so the run summary says the
ensemble was thinner rather than the job dying on an agent the operator added
this morning.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.agents.base_agent import BaseAnalyst, describe_exception, revision_messages
from maljan.agents.composition import ResolvedAgent
from maljan.schemas.isr_models import AgentISR

# Appended to the agent's own prompt on the ISR paths. The operator writes what
# their agent is *for*; this is the shape the ISR parsers read, and asking them
# to reproduce it by hand would make a working definition a matter of luck.
_ISR_FORMAT_INSTRUCTION = (
    "Return a structured list of findings. For each finding state: the claim, "
    "the exact artifact reference, your confidence (0.0-1.0), and the MITRE "
    "ATT&CK technique ID.\n\n"
    "Format each finding as:\n"
    "CLAIM: <claim text>\n"
    "EVIDENCE: <artifact reference>\n"
    "CONFIDENCE: <float>\n"
    "TECHNIQUE: <T-ID or NONE>\n"
    "---\n\n"
)

# Prefix on the *report text* shown when a run degraded — cosmetic only. Never
# inspected: whether a run degraded is carried by ``_Run.degraded``, not by
# sniffing this prefix, so a custom agent's own model output starting with the
# same words is never mistaken for a degradation notice.
_WARN_PREFIX = "[WARN]"

# BUG 11, second round (live 2026-09-07, S5c). A generic agent's system prompt
# is the operator's own text and says nothing about where the sample is; the
# only place the path appeared was a field inside the JSON data block, and
# `static_qu1cksc0pe` called every tool with the sample's bare *filename*
# instead — which Qu1cksc0pe then resolved against its own working directory.
# The static role has never had this problem because its human turn opens with
# an explicit line naming the path. The framework states it here for every
# custom agent, so an operator does not have to know to write it.
_PATH_HEADER = (
    "Sample path (use exactly this string, verbatim, wherever a tool asks for "
    "a file or a path): {path}\n"
    "It is an absolute path. Never pass the file name on its own — a tool "
    "resolves a bare name against its own working directory, not ours.\n\n"
)


def _analysis_path_in(data: str) -> str | None:
    """The ``analysis_file_path`` spliced into a head chunk, when there is one.

    Mirrors the static analyst's own extraction rather than importing it: the
    static module pulls in Ghidra, RAG and sink-reachability machinery a custom
    agent has no business loading.
    """
    stripped = data.strip()
    if not stripped.startswith("{"):
        return None
    try:
        parsed = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    path = parsed.get("analysis_file_path")
    return path if isinstance(path, str) and path else None


@dataclass(frozen=True)
class _Run:
    """What one loop invocation produced, plus whether it actually ran."""

    text: str
    degraded: bool


class ConfigurableAnalyst(BaseAnalyst):
    """A ``BaseAnalyst`` whose prompt, tools and LLM come from configuration."""

    def __init__(self, definition_key: str, resolved: ResolvedAgent, llm: BaseChatModel) -> None:
        super().__init__(llm=llm, name=definition_key, tools=list(resolved.tools))
        self._resolved = resolved
        # Reasons resolution already produced (a referenced tool that is not
        # there) start the list; the analyst appends its own as it runs.
        self.degradation_reasons = list(resolved.degradation_reasons)

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def _initialize_mcp_client(self) -> None:
        """Nothing to attach: resolution already did it.

        Present because ``BaseAnalyst._try_initialize_mcp`` calls it. A custom
        analyst has no provider lifecycle of its own — its tools arrived in the
        ``ResolvedAgent`` — so this is deliberately a no-op rather than a
        second attachment path that could disagree with the first.
        """
        return None

    def _infer_domain(self) -> str:
        """The definition key. A custom agent's domain is its own name."""
        return self.name

    def _with_path_header(self, data: str) -> str:
        """The data, preceded by an explicit statement of the sample path.

        The path is the pinned one when the analyst node set it, otherwise the
        one spliced into the head chunk's JSON — a chunked run hands later
        chunks no JSON at all, so the pin is what keeps every chunk pointed at
        the same file. When neither exists the data is returned untouched: an
        agent that never reads a file is not given a line about one, and the
        pre-fix prompt is preserved byte for byte.
        """
        path = self._analysis_file_path or _analysis_path_in(data)
        if not path:
            return data
        return _PATH_HEADER.format(path=path) + data

    # ------------------------------------------------------------------
    # Text interface
    # ------------------------------------------------------------------

    def _run(self, prompt_messages: list[tuple[str, str]], what: str) -> _Run:
        """Run the loop and turn any failure into a report the pipeline can read.

        ``degraded`` is the signal callers act on; the returned text is only
        ever shown, never inspected — a custom agent's genuine model output is
        free to start with the same words as the warning prefix without being
        mistaken for one.
        """
        try:
            return _Run(text=str(self.execute_tool_loop(prompt_messages)), degraded=False)
        except Exception as exc:  # noqa: BLE001 — a custom analyst never fails a job
            reason = f"agent '{self.name}': {describe_exception(exc)}"
            self.logger.warning("%s failed during %s: %s", self.name, what, reason)
            if reason not in self.degradation_reasons:
                self.degradation_reasons.append(reason)
            return _Run(text=f"{_WARN_PREFIX} {reason}", degraded=True)

    def analyze(self, data: str) -> str:
        self.logger.info("Executing '%s' analysis (%d tools).", self.name, len(self.tools))
        return self._run(
            [("system", self._resolved.prompt), ("human", self._with_path_header(data))],
            "analysis",
        ).text

    def revise(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        self.logger.info("Revising '%s' analysis based on peer feedback...", self.name)
        return self._run(
            revision_messages(
                self._resolved.prompt,
                self._with_path_header(original_data),
                own_report,
                peer_reports,
                mediator_feedback,
                isr=False,
            ),
            "revision",
        ).text

    # ------------------------------------------------------------------
    # ISR interface
    # ------------------------------------------------------------------

    def _isr_for(self, run: _Run, revision_round: int) -> AgentISR:
        """Wrap a run's text into an ISR — zero-claim when the run degraded.

        A degraded run's text is a warning, not analysis; passing it through
        ``_text_to_isr``'s free-text sentence splitter would mint a fake
        0.5-confidence claim out of the warning sentence itself. Short-
        circuiting on ``run.degraded`` — never on the text — keeps the same
        rule ``_text_to_isr`` already applies to its own placeholder text: a
        failure is zero claims, never a claim, and a genuine finding is never
        mistaken for one because of how it happens to start.
        """
        if run.degraded:
            return AgentISR(
                agent_id=self.name,
                domain=self._infer_domain(),
                claims=[],
                dissent_items=[],
                revision_round=revision_round,
            )
        return self._text_to_isr(run.text, revision_round=revision_round)

    def analyze_isr(self, data: str) -> AgentISR:
        self.logger.info("Executing '%s' ISR analysis...", self.name)
        run = self._run(
            [
                ("system", self._resolved.prompt),
                ("human", _ISR_FORMAT_INSTRUCTION + self._with_path_header(data)),
            ],
            "ISR analysis",
        )
        return self._isr_for(run, revision_round=0)

    def revise_isr(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
        revision_round: int = 1,
    ) -> tuple[str, AgentISR]:
        self.logger.info("Executing '%s' ISR revision (round %d)...", self.name, revision_round)
        run = self._run(
            revision_messages(
                self._resolved.prompt,
                self._with_path_header(original_data),
                own_report,
                peer_reports,
                mediator_feedback,
                isr=True,
                revision_round=revision_round,
            ),
            "ISR revision",
        )
        return run.text, self._isr_for(run, revision_round=revision_round)
