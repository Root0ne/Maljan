"""BUG-07 regression tests (2026-06-23 live-UI audit).

On a freshly-uploaded sample there is no pre-extracted
``data/samples/static/<sha>.json`` fixture, so the deterministic raw-data slot
carries the file-loader placeholder "No static data available for sample ...".
That text used to talk the small reasoning model into a defeatist "static
analysis could not be performed" claim which (a) overwrote its real live-Ghidra
findings and (b) slipped past the meta-claim guardrail because it parsed as a
well-formed ``CLAIM`` block — so the run passed as non-degraded with a fake
high-confidence "I couldn't analyse" claim.

Two-part fix, both exercised here with a MagicMock / tiny callable LLM only
(no llama-server dependency):
  A) ``_reframe_static_raw_data`` rephrases the placeholder when the analyst has
     live Ghidra tools, pointing the model back at its ORIGINAL REPORT.
  B) ``_is_meta_claim_text`` / ``_drop_meta_claims`` recognise the defeatist
     re-wordings and collapse a no-real-finding analyst to a zero-claim ISR so
     the confidence cap honestly marks the run degraded.
"""

from unittest.mock import MagicMock, patch

from maljan.agents.static_analyst import StaticAnalyst, _reframe_static_raw_data
from maljan.schemas.isr_models import ClaimEvidence

_PLACEHOLDER = "No static data available for sample 007257bf103de1173f536937eae72ea."
_DEFEATIST_BLOCK = (
    "CLAIM: Static analysis could not be performed due to missing binary data.\n"
    "EVIDENCE: RAW DATA explicitly states 'No static data available'.\n"
    "CONFIDENCE: 1.0\n"
    "TECHNIQUE: NONE\n"
    "---\n"
)
_REAL_BLOCK = (
    "CLAIM: VirtualAllocEx import confirms process-injection capability.\n"
    "EVIDENCE: API import: VirtualAllocEx\n"
    "CONFIDENCE: 0.8\n"
    "TECHNIQUE: T1055\n"
    "---\n"
)


class _FixedLLM:
    """Minimal callable LLM stub returning a fixed-content message for any input.

    langchain coerces a plain callable into a ``RunnableLambda`` inside the
    ``prompt | llm`` chain, so this controls ``response.content`` deterministically
    without a real chat model.
    """

    def __init__(self, content: str) -> None:
        self._content = content

    def __call__(self, *_args: object, **_kwargs: object) -> MagicMock:
        return MagicMock(content=self._content)


# ---------------------------------------------------------------------------
# Part A — placeholder reframing
# ---------------------------------------------------------------------------


class TestReframeStaticRawData:
    def test_placeholder_rephrased_when_tools_present(self) -> None:
        out = _reframe_static_raw_data(_PLACEHOLDER, has_tools=True)
        assert "No static data available" not in out
        assert "ORIGINAL REPORT" in out

    def test_real_data_unchanged_when_tools_present(self) -> None:
        real = "Imports: VirtualAllocEx, WriteProcessMemory; .text entropy 7.8"
        assert _reframe_static_raw_data(real, has_tools=True) == real

    def test_placeholder_unchanged_without_tools(self) -> None:
        # No tools => the placeholder genuinely means "no evidence"; leave it.
        assert _reframe_static_raw_data(_PLACEHOLDER, has_tools=False) == _PLACEHOLDER

    def test_empty_unchanged(self) -> None:
        assert _reframe_static_raw_data("", has_tools=True) == ""


# ---------------------------------------------------------------------------
# Part B — meta-claim detection + filtering
# ---------------------------------------------------------------------------


class TestMetaClaimDetection:
    def _agent(self) -> StaticAnalyst:
        return StaticAnalyst(llm=MagicMock(), name="StaticAnalyst")

    def test_placeholder_is_meta(self) -> None:
        assert self._agent()._is_meta_claim_text("No static data available for sample abc.")

    def test_defeatist_could_not_be_performed_is_meta(self) -> None:
        assert self._agent()._is_meta_claim_text(
            "Static analysis could not be performed due to missing binary data."
        )

    def test_defeatist_with_claim_label_is_meta(self) -> None:
        assert self._agent()._is_meta_claim_text(
            "CLAIM: Static analysis could not be performed due to missing binary data."
        )

    def test_missing_binary_data_is_meta(self) -> None:
        assert self._agent()._is_meta_claim_text("Missing binary data; nothing to analyse.")

    def test_legitimate_partial_finding_not_meta(self) -> None:
        # "could not confirm" is a real partial finding, NOT "could not be performed".
        assert not self._agent()._is_meta_claim_text(
            "Static analysis could not confirm RC4 but found an XOR key at .data+0x40."
        )

    def test_real_claim_not_meta(self) -> None:
        assert not self._agent()._is_meta_claim_text(
            "VirtualAllocEx import indicates process-injection capability."
        )


class TestDropMetaClaims:
    def _agent(self) -> StaticAnalyst:
        return StaticAnalyst(llm=MagicMock(), name="StaticAnalyst")

    def test_mixed_keeps_only_real(self) -> None:
        claims = [
            ClaimEvidence(
                claim="VirtualAllocEx indicates injection",
                evidence_ref="import",
                confidence=0.8,
                technique_id="T1055",
            ),
            ClaimEvidence(
                claim="Static analysis could not be performed due to missing binary data",
                evidence_ref="RAW DATA",
                confidence=1.0,
                technique_id=None,
            ),
        ]
        kept = self._agent()._drop_meta_claims(claims)
        assert len(kept) == 1
        assert "VirtualAllocEx" in kept[0].claim

    def test_all_meta_drops_to_empty(self) -> None:
        claims = [
            ClaimEvidence(
                claim="No static data available for sample abc",
                evidence_ref="x",
                confidence=1.0,
                technique_id=None,
            ),
            ClaimEvidence(
                claim="Static analysis could not be performed due to missing binary data",
                evidence_ref="x",
                confidence=1.0,
                technique_id=None,
            ),
        ]
        assert self._agent()._drop_meta_claims(claims) == []


# ---------------------------------------------------------------------------
# End-to-end wiring (mock LLM, no llama)
# ---------------------------------------------------------------------------


class TestReviseIsrBug07:
    def _agent(self, content: str) -> StaticAnalyst:
        return StaticAnalyst(llm=_FixedLLM(content), name="StaticAnalyst", tools=[MagicMock()])

    def test_defeatist_revision_collapses_to_zero_claim(self) -> None:
        agent = self._agent(_DEFEATIST_BLOCK)
        _text, isr = agent.revise_isr(
            original_data=_PLACEHOLDER,
            own_report="CLAIM: VirtualAllocEx indicates injection ...",
            peer_reports={"dynamic": "found persistence"},
            mediator_feedback="static disputed",
            revision_round=1,
        )
        # BUG-07: the defeatist claim is dropped -> zero-claim, run marked degraded.
        assert isr.claims == []

    def test_real_revision_keeps_claims(self) -> None:
        agent = self._agent(_REAL_BLOCK)
        _text, isr = agent.revise_isr(
            original_data=_PLACEHOLDER,
            own_report="original",
            peer_reports={"dynamic": "found persistence"},
            mediator_feedback="static disputed",
            revision_round=1,
        )
        assert len(isr.claims) == 1
        assert isr.claims[0].technique_id == "T1055"


class TestAnalyzeIsrBug07:
    def test_defeatist_initial_collapses_to_zero_claim(self) -> None:
        agent = StaticAnalyst(llm=MagicMock(), name="StaticAnalyst", tools=[MagicMock()])
        with (
            patch.object(agent, "_initialize_mcp_client"),
            patch.object(agent, "execute_tool_loop", return_value=_DEFEATIST_BLOCK),
        ):
            # Plain non-JSON, non-path data -> the deterministic hint pre-passes
            # are skipped and only the (patched) tool loop runs.
            isr = agent.analyze_isr("decompiled summary text")
        assert isr.claims == []

    def test_real_initial_keeps_claims(self) -> None:
        agent = StaticAnalyst(llm=MagicMock(), name="StaticAnalyst", tools=[MagicMock()])
        with (
            patch.object(agent, "_initialize_mcp_client"),
            patch.object(agent, "execute_tool_loop", return_value=_REAL_BLOCK),
        ):
            isr = agent.analyze_isr("decompiled summary text")
        assert len(isr.claims) == 1
        assert isr.claims[0].technique_id == "T1055"
