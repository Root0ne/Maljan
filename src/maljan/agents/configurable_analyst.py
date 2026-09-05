"""The analyst an operator declares rather than writes.

One class, parametrised by a ``ResolvedAgent``. Deliberately thin: the three
built-in analysts carry provider-specific ISR extraction that goldens pin —
Ghidra program info, CAPE signature shapes, PCAP heuristics — and reproducing
any of that generically would be a guess. What is left is the part that is the
same for every analyst: send the prompt, run the ReAct loop when there are
tools and a plain call when there are none, and wrap whatever comes back into
an ISR under the agent's own key.

The degradation policy is the one sub-project B applies to custom servers: a
custom analyst never fails a job. A tool server that would not attach, a tool
that is not there, an LLM call that raises — each becomes a reason on
``degradation_reasons`` and a ``[WARN]`` report, so the run summary says the
ensemble was thinner rather than the job dying on an agent the operator added
this morning.
"""

from __future__ import annotations

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

    # ------------------------------------------------------------------
    # Text interface
    # ------------------------------------------------------------------

    def _run(self, prompt_messages: list[tuple[str, str]], what: str) -> str:
        """Run the loop and turn any failure into a report the pipeline can read."""
        try:
            return str(self.execute_tool_loop(prompt_messages))
        except Exception as exc:  # noqa: BLE001 — a custom analyst never fails a job
            reason = f"agent '{self.name}': {describe_exception(exc)}"
            self.logger.warning("%s failed during %s: %s", self.name, what, reason)
            if reason not in self.degradation_reasons:
                self.degradation_reasons.append(reason)
            return f"[WARN] {reason}"

    def analyze(self, data: str) -> str:
        self.logger.info("Executing '%s' analysis (%d tools).", self.name, len(self.tools))
        return self._run([("system", self._resolved.prompt), ("human", data)], "analysis")

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
                original_data,
                own_report,
                peer_reports,
                mediator_feedback,
                isr=False,
            ),
            "revision",
        )

    # ------------------------------------------------------------------
    # ISR interface
    # ------------------------------------------------------------------

    def _isr_for(self, text: str, revision_round: int) -> AgentISR:
        """Wrap ``text`` into an ISR — zero-claim when ``_run`` degraded.

        A ``[WARN]`` report is a degradation notice, not analysis; passing it
        through ``_text_to_isr``'s free-text sentence splitter would mint a
        fake 0.5-confidence claim out of the warning sentence itself. Short-
        circuiting here keeps the same rule ``_text_to_isr`` already applies to
        its own placeholder text: a failure is zero claims, never a claim.
        """
        if text.startswith("[WARN]"):
            return AgentISR(
                agent_id=self.name,
                domain=self._infer_domain(),
                claims=[],
                dissent_items=[],
                revision_round=revision_round,
            )
        return self._text_to_isr(text, revision_round=revision_round)

    def analyze_isr(self, data: str) -> AgentISR:
        self.logger.info("Executing '%s' ISR analysis...", self.name)
        text = self._run(
            [
                ("system", self._resolved.prompt),
                ("human", _ISR_FORMAT_INSTRUCTION + data),
            ],
            "ISR analysis",
        )
        return self._isr_for(text, revision_round=0)

    def revise_isr(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
        revision_round: int = 1,
    ) -> tuple[str, AgentISR]:
        self.logger.info("Executing '%s' ISR revision (round %d)...", self.name, revision_round)
        text = self._run(
            revision_messages(
                self._resolved.prompt,
                original_data,
                own_report,
                peer_reports,
                mediator_feedback,
                isr=True,
                revision_round=revision_round,
            ),
            "ISR revision",
        )
        return text, self._isr_for(text, revision_round=revision_round)
