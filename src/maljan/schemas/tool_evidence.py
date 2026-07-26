"""Captured MCP/Ghidra tool outputs — durable raw material for deep reporting.

The ReAct tool loop (``base_agent.execute_tool_loop``) previously discarded every
``ToolMessage`` (``decompile_function``, ``detect_crypto_constants``,
``emulate_function``, ``analyze_dataflow``, …), returning only the model's final
prose. That made a professional technical spine (encryption-scheme reversing,
CLI-flag tables, ransom-note extraction, per-function walkthroughs) impossible —
the only durable analyst signal was the ≤200-char ``ClaimEvidence.evidence_ref``.

This module defines the structured, size-capped container the loop now emits so
the report Composer (and an optional appendix) can ground deep sections in real
tool output instead of hallucinating. Capture is best-effort: it must never break
an analysis, and it is trimmed hard so it cannot blow the token / JSONB budget.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

# Hard caps so captured evidence can never blow the token / JSONB budget. The
# tool outputs are already guardrail-capped inside ``ghidra_http_client`` /
# ``max_tool_output_chars``; these are a second, report-facing ceiling.
MAX_OUTPUT_CHARS: int = 6000
MAX_OUTPUTS_PER_AGENT: int = 40


class CapturedToolOutput(BaseModel):
    """One tool call + its result, paired from the ReAct message stream.

    Paired by ``tool_call_id`` (not positional order) so provider-specific
    interleaving of AI/tool messages cannot mis-associate an output.
    """

    model_config = ConfigDict(extra="ignore")

    agent_id: str = Field(..., description="Owning analyst, e.g. 'static'.")
    tool_name: str = Field(..., description="MCP tool name, e.g. 'decompile_function'.")
    args: dict = Field(default_factory=dict, description="Arguments the model passed.")
    symbol: str | None = Field(
        None,
        description="Function name / address / file the call targeted, parsed from args.",
    )
    output: str = Field("", description="Tool result text (already guardrail-capped, re-trimmed).")
    seq: int = Field(0, description="Call order within the agent's loop (0-based).")


def _symbol_from_args(args: dict) -> str | None:
    """Best-effort human label for a captured call (function/address/file)."""
    if not isinstance(args, dict):
        return None
    for key in ("function_name", "name", "function", "symbol", "address", "addr", "file", "path"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()[:120]
    return None


def trim_output(text: str, max_chars: int = MAX_OUTPUT_CHARS) -> str:
    """Cap a single tool output for report storage, marking truncation."""
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1] + "…"
