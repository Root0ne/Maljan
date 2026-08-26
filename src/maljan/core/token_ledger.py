"""Per-run LLM token/cost accounting (MARD-style, findings-log §4 Item 1).

LangChain responses carry ``usage_metadata`` (``input_tokens`` / ``output_tokens``
/ ``total_tokens``) but the pipeline previously read only ``.content``, so a run's
LLM cost was invisible. ``TokenLedger`` is a thread-safe accumulator: one instance
lives on the ``ServiceContainer`` (one per analysis run / worker), agents and the
judge add each call's usage to it, and the judge node snapshots it into the
``RunSummary``.

When a provider (notably a local llama-server) omits ``usage_metadata`` the call is
counted with a cheap character-based estimate (``~chars / 4``, the same convention
as ``binary_chunker.token_estimate``) and flagged so the report can disclose how
much of the figure is estimated. Recording never raises — telemetry must not break
analysis.
"""

from __future__ import annotations

import threading
from typing import Any


def estimate_tokens(text: str) -> int:
    """Cheap, dependency-free token estimate (~4 chars/token)."""
    if not text:
        return 0
    return max(1, len(text) // 4)


class TokenLedger:
    """Thread-safe tally of LLM token usage across one analysis run."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.input_tokens = 0
        self.output_tokens = 0
        self.calls = 0
        self.estimated_calls = 0

    def add(
        self,
        input_tokens: int,
        output_tokens: int,
        *,
        estimated: bool = False,
    ) -> None:
        with self._lock:
            self.input_tokens += max(0, int(input_tokens))
            self.output_tokens += max(0, int(output_tokens))
            self.calls += 1
            if estimated:
                self.estimated_calls += 1

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def snapshot(self) -> dict[str, int]:
        """A plain-dict copy for handing to the RunSummary builder."""
        with self._lock:
            return {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "total_tokens": self.input_tokens + self.output_tokens,
                "llm_calls": self.calls,
                "estimated_calls": self.estimated_calls,
            }


def record_response_usage(
    ledger: TokenLedger | None,
    response: Any,
    *,
    prompt_text: str = "",
) -> None:
    """Add one LLM response's token usage to ``ledger`` (no-op if ledger is None).

    Prefers the provider's ``usage_metadata``; falls back to a character-based
    estimate (flagged) when it is absent. Never raises.
    """
    if ledger is None:
        return
    try:
        usage = getattr(response, "usage_metadata", None)
        if isinstance(usage, dict) and usage.get("input_tokens") is not None:
            ledger.add(
                int(usage.get("input_tokens") or 0),
                int(usage.get("output_tokens") or 0),
            )
            return
        # Fallback: estimate from prompt + response text.
        content = getattr(response, "content", response)
        ledger.add(
            estimate_tokens(prompt_text),
            estimate_tokens(str(content)),
            estimated=True,
        )
    except Exception:  # noqa: BLE001 — telemetry must never break analysis
        return
