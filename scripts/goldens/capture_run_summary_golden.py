"""Pin the summary a run is *stored* with, not the dataclass it starts as.

``RunSummary.to_dict()`` is where the summary begins. What the API stores,
what the report renders and what an evaluation script reads back is that dict
plus four keys written onto it after the dataclass exists: ``dedupe`` from the
report builder, ``evidence`` and ``sections_without_evidence`` from the report
node, and ``fp_warnings`` from the post-pipeline linter — and
``settings_snapshot``, which the worker adds. The golden used to cover only
the dataclass, so ``dedupe`` was pinned by nothing at all and a rename of
``indicators_merged`` would have kept every test green.

Each of the four is built here by the code that builds it in a run —
``MergeTally.as_dict``, ``evidence_summary``, ``FPWarning.to_dict`` — so the
golden follows a rename instead of merely agreeing with a copy.
``settings_snapshot`` is the exception: it is a public view of the whole
``Settings`` tree, which grows with every new setting, so its presence is
pinned and its contents are left opaque.

Run: ``uv run python scripts/goldens/capture_run_summary_golden.py``.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "run_summary_keys.json"


def _claim(technique_id: str, confidence: float) -> Any:
    from maljan.schemas.isr_models import ClaimEvidence

    return ClaimEvidence(
        claim=f"claim for {technique_id}",
        evidence_ref="ref",
        confidence=confidence,
        technique_id=technique_id,
    )


def _isr(agent_id: str, domain: str) -> Any:
    from maljan.schemas.isr_models import AgentISR

    return AgentISR(
        agent_id=agent_id,
        domain=domain,
        claims=[_claim("T1055", 0.8)],
        dissent_items=[],
        revision_round=1,
    )


def default_profile_summary() -> dict[str, Any]:
    """A default-profile run with every optional section of the dataclass filled."""
    from maljan.analysis.run_summary import RunSummaryBuilder

    analysts = ["static", "dynamic", "network"]
    isr_reports = {key: _isr(key, key) for key in analysts}

    builder = RunSummaryBuilder(start_time=time.time() - 1.0)
    builder.set_sample("abc123", "evil.exe")
    builder.set_verdict("Malware", 12)
    builder.set_negotiation(
        {
            "file_hash": "abc123",
            "file_name": "evil.exe",
            "iteration_count": 2,
            "is_consensus": True,
            "confidence_history": [0.7, 0.85, 0.91],
            "sycophancy_detected": False,
            "discussion_history": [],
            "_max_iterations": 5,
        }
    )
    builder.set_isr_stats(isr_reports)
    builder.set_validation(
        {
            "retries": 1,
            "by_code": {"attck.unknown_id": 1},
            "unresolved": [
                {"agent": "static", "code": "attck.unknown_id", "message": "no such id"}
            ],
            "not_run": ["attck.unknown_id"],
        }
    )
    builder.set_corroboration(
        {"T1055": {"asserted_by": ["capa"], "claimed_by": ["static", "dynamic", "network"]}}
    )
    builder.set_profile("default", analysts, [])
    builder.set_stages(
        [
            {
                "key": "analysis",
                "kind": "analysis",
                "ran": True,
                "reason": "",
                "agents": analysts,
                "duration_ms": 1200,
            },
            {
                "key": "debate",
                "kind": "debate",
                "ran": True,
                "reason": "",
                "agents": [],
                "duration_ms": 300,
            },
        ]
    )
    builder.set_triage({"entries": 11, "failed": 1, "duration_ms": 900, "yara_hits": 2})
    builder.set_nudge({"static": "invalid_tool_calls_dropped"})
    builder.set_budget(
        {
            "static": [
                {
                    "stage": "analysis",
                    "steps_used": 12,
                    "max_steps": 40,
                    "elapsed_s": 88.0,
                    "timeout_s": 1500.0,
                    "delegated_steps": 0,
                    "cap": "steps",
                }
            ]
        }
    )
    builder.set_degraded_mode(False, [])
    builder.set_failed_analysts([])
    # Through the ledger a run records on, so the golden follows its shape:
    # one reported call with a cost, one a fallback answered with none.
    from maljan.core.token_ledger import TokenLedger

    ledger = TokenLedger()
    ledger.add(
        {"input_tokens": 10, "output_tokens": 20, "cost": 0.001},
        agent="static",
        model="openai/qwen",
    )
    ledger.add(None, agent="static", model="ollama/gemma", fallback="openai/qwen: timed out")
    builder.set_token_usage(ledger.snapshot())
    builder.set_server_rests(
        [{"server": "analysis", "failures": 3, "cooldown_s": 60.0, "reason": "timed out"}]
    )
    builder.set_truncation(
        {
            "tool_output_calls": 4,
            "tool_output_over_limit": 1,
            "tool_output_summarised": 1,
            "tool_output_hard_truncated": 0,
            "tool_output_chars_dropped": 12,
            "react_invocations": 3,
            "react_step_cap_hits": 0,
            "judge_invocations": 1,
            "judge_token_cap_hits": 0,
            "integrity_invocations": 1,
            "integrity_objects_removed": 0,
            "integrity_dropped": {"indicator": 0},
            "evidence_corpus_answers": 12,
            "evidence_corpus_bytes_held": 4096,
            "evidence_corpus_bytes_ceiling": 16777216,
        }
    )
    return builder.build().to_dict()


def _ledger() -> list[Any]:
    """One call that answered and one that did not, so ``failures`` has a row."""
    from maljan.schemas.evidence import LedgerEntry

    return [
        LedgerEntry(id="ev_0001", agent="static", tool="pe_info", ok=True, output="{}", seq=1),
        LedgerEntry(
            id="ev_0002",
            agent="static",
            server="analysis",
            tool="strings",
            ok=False,
            error="the tool server did not answer",
            remediation="start the analysis sidecar",
            seq=2,
        ),
    ]


def stored_summary() -> dict[str, Any]:
    """The dataclass, plus every key written onto the dict after it exists."""
    from maljan.pipeline.nodes import evidence_summary
    from maljan.qa.fp_linter import FPWarning
    from maljan.reporting.dedupe import MergeTally

    summary = default_profile_summary()

    # `builder.py`, once the report's sections are built.
    tally = MergeTally()
    tally.indicator()
    tally.finding()
    summary["dedupe"] = tally.as_dict(extra_indicators=1)

    # `report_node`, once the report is standing.
    summary["evidence"] = evidence_summary(_ledger())
    summary["sections_without_evidence"] = 0

    # The post-pipeline linter, once every other mutation has happened.
    summary["fp_warnings"] = [
        FPWarning(
            rule="C1",
            severity="warn",
            message="the executive summary names a capability no finding supports",
            field="malware_report.executive_summary",
            explanation="no claim carries a technique id for it",
        ).to_dict()
    ]

    # The worker, once the job is being written down.
    summary["settings_snapshot"] = {"overridden_keys": []}
    return summary


# Several of the maps in the summary are keyed by data rather than by schema --
# one technique layer per layer that produced a technique, one integrity
# counter per object kind that was dropped. Their contents are a property of
# the run, not of the format, so they are pinned as present and opaque.
# `settings_snapshot` is opaque for a different reason: it is a view of the
# whole settings tree, which grows with every new setting, and the catalogue
# has its own pins.
DATA_KEYED = frozenset(
    {
        "techniques_by_layer",
        "truncation.integrity_dropped",
        "corroboration",
        "validation.by_code",
        "nudge.retry_mode",
        "budget",
        "evidence.by_tool",
        "settings_snapshot",
        # One row per agent that made a model call, keyed by the agent.
        "models",
        "tokens.per_agent",
    }
)


def key_shape(value: Any, path: str = "") -> Any:
    """Keys all the way down; a list contributes the shape of its first item."""
    if path in DATA_KEYED:
        return "<data-keyed map>"
    if isinstance(value, dict):
        return {
            key: key_shape(value[key], f"{path}.{key}" if path else key) for key in sorted(value)
        }
    if isinstance(value, list):
        return [key_shape(value[0], f"{path}[]")] if value else []
    return None


def main() -> None:
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    payload = key_shape(stored_summary())
    GOLDEN.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {GOLDEN}")


if __name__ == "__main__":
    main()
