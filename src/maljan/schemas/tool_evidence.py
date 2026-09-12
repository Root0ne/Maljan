"""The previous capture shape, kept while its readers migrate.

Superseded by ``schemas.evidence.LedgerEntry``, which records the same call
with an id to cite it by, its timing, its outcome and its parsed result.
``LedgerEntry.to_captured`` and ``LedgerEntry.from_captured`` convert between
the two, so a consumer written against this model keeps working for a release.

What it holds is one ReAct tool call paired with its result — the loop used to
return only the model's final prose, so the only durable analyst signal was the
200-character ``ClaimEvidence.evidence_ref`` and no report section could be
grounded in what a tool actually said. Capture is best-effort and hard-trimmed:
it must never break an analysis, and it must never blow the JSONB budget.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

# A hard cap so captured evidence can never blow the token / JSONB budget. The
# tool outputs are already guardrail-capped inside ``ghidra_http_client`` /
# ``max_tool_output_chars``; this is a second, report-facing ceiling. How much
# an agent may keep is a byte budget now rather than a call count —
# ``report.evidence_budget_bytes``, applied in ``schemas.evidence``.
MAX_OUTPUT_CHARS: int = 6000


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
