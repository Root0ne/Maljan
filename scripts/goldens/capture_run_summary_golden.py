"""Pin the summary a run is *stored* with, not the dataclass it starts as.

``RunSummary.to_dict()`` is where the summary begins. What the API stores,
what the report renders and what an evaluation script reads back is that dict
plus six keys written onto it after the dataclass exists: ``dedupe`` from the
report builder, ``evidence``, ``sections_without_evidence``, ``disclosure`` and
``efficiency`` from the report node, and ``fp_warnings`` from the post-pipeline linter — and
``settings_snapshot``, which the worker adds. The golden used to cover only
the dataclass, so ``dedupe`` was pinned by nothing at all and a rename of
``indicators_merged`` would have kept every test green.

Each of the six is built here by the code that builds it in a run —
``MergeTally.as_dict``, ``evidence_summary``, ``disclosure_record``,
``efficiency_record``, ``FPWarning.to_dict`` — so the golden follows a rename instead of merely
agreeing with a copy.
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
    # The mock sandbox's stand-in, so the key is pinned with its shape.
    builder.set_sandbox({"synthetic": True})
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
    from maljan.llm.generation_rate import GenerationRates

    rates = GenerationRates()
    rates.observe("qwen", 380, 100.0, "ollama eval_count/eval_duration")
    rates.call_timeout("judge:verdict", "qwen", 600.0, 8192)
    builder.set_generation(rates.snapshot())
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


def _disclosure(summary: dict[str, Any]) -> dict[str, Any]:
    """The disclosure record, built by the run's builder, with a row in every part.

    A model endpoint outside the machine, a lookup over HTTP, a sample
    submission to a sandbox on a private address and a staging to a tool
    server, an entry that records no source, a call to a tool that declares
    nothing and one to a declared tool on a server run on this machine, and a
    memory store at a compose service name; in the isolation part, the
    worker's own read of the sample. Then the enrichment, as the
    worker names it and as its job adds what it asked: the summary a run is
    stored with once both have written it.
    """
    from maljan.analysis.disclosure import (
        STAGING_DONE,
        disclosure_record,
        rdap_row,
        stage_agents,
        staging_record,
        upload_record,
        with_enrichment,
        with_enrichment_asked,
    )
    from maljan.schemas.evidence import LedgerEntry

    snapshot = {
        "llm.provider": "openai",
        "llm.openai.base_url": "https://llm.example.org/v1",
        "mcp.servers.intel.transport": "streamable-http",
        "mcp.servers.intel.url": "https://intel.example.org/mcp",
        "mcp.servers.analysis.transport": "stdio",
        "sandbox.provider": "cape2",
        "sandbox.cape2.base_url": "http://10.0.0.5:8000",
        "memory.backend": "qdrant",
        "memory.qdrant.url": "http://qdrant:6333",
        "langchain_tracing_v2": False,
    }
    lookup = LedgerEntry(
        id="ev_0003",
        agent="static",
        server="intel",
        tool="file_lookup",
        args={"sha256": "abc123"},
        source="mcp:intel",
        facts={"v": 1, "kind": "reputation", "arguments": {"hash": "sha256"}},
        seq=3,
    )
    undeclared = LedgerEntry(
        id="ev_0004",
        agent="static",
        server="analysis",
        tool="anything",
        source="mcp:analysis",
        facts={"v": 1},
        seq=4,
    )
    declared = LedgerEntry(
        id="ev_0005",
        agent="static",
        server="analysis",
        tool="strings",
        source="mcp:analysis",
        facts={"v": 1, "kind": "strings"},
        seq=5,
    )
    record = disclosure_record(
        snapshot,
        entries=[*_ledger(), lookup, undeclared, declared],
        tokens=summary.get("tokens"),
        agents=stage_agents(summary.get("stages")),
        uploads=[upload_record("cape2", submitted=True, host="10.0.0.5")],
        stagings=[
            staging_record(
                "intel",
                transport="streamable-http",
                url="https://intel.example.org/mcp",
                state=STAGING_DONE,
            )
        ],
        runtimes={},
        opened={"worker": [{"where": "in_process", "label": "the platform's own readers"}]},
        worker={
            "uid": 10001,
            "cap_eff_zero": True,
            "cap_prm_zero": True,
            "cap_amb_zero": True,
            "no_new_privs": True,
            "platform_names_in_env": ["DATABASE_URL"],
        },
    )
    record = with_enrichment(record, [rdap_row()])
    return with_enrichment_asked(
        record, [{"source": "rdap", "host": "rdap.arin.net", "kinds": {"ip": 1}, "why": ""}]
    )


def _efficiency() -> dict[str, Any]:
    """The efficiency record, built by the run's builder over a meter and a ledger that hold a row.

    One tool loop turn of the static analyst, measured as the loop's hook
    measures it, closed with the usage its provider reported, and one single
    call; the token ledger holds the calls. Over the ledger above, a claim
    cites the first entry and none the second.
    """
    from types import SimpleNamespace

    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

    from maljan.analysis.efficiency import efficiency_record
    from maljan.core.input_meter import InputMeter, request_parts
    from maljan.core.token_ledger import TokenLedger

    meter = InputMeter()
    loop = object()
    turn = [
        SystemMessage(content="You are the static analyst."),
        HumanMessage(content="PACK\n\nAnalyse the sample."),
        AIMessage(content="", tool_calls=[{"name": "pe_info", "args": {}, "id": "c1"}]),
        ToolMessage(content="[ev_0001] {}", tool_call_id="c1"),
    ]
    meter.request("static", request_parts(turn, pack="PACK", definitions=120), loop=loop)
    meter.close("static", loop, [{"input_tokens": 40, "output_tokens": 5}])
    single = meter.request("static", request_parts(turn[:2]), kind="validation retry")
    meter.answered(single, {"input_tokens": 12, "output_tokens": 3})
    ledger = TokenLedger()
    ledger.add({"input_tokens": 40, "output_tokens": 5}, agent="static", model="openai/qwen")
    ledger.add({"input_tokens": 12, "output_tokens": 3}, agent="static", model="openai/qwen")
    container = SimpleNamespace(input_meter=meter, get_token_ledger=lambda: ledger)
    from maljan.schemas.isr_models import AgentISR, ClaimEvidence

    cites = ClaimEvidence(claim="imports", evidence_ref="pe_info [ev_0001]", confidence=0.8)
    record = efficiency_record(
        container,
        entries=_ledger(),
        isr_reports={"static": AgentISR(agent_id="static", domain="static", claims=[cites])},
    )
    assert record is not None
    return record


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
    # `report_node`, once the run's last model and tool calls are made.
    summary["disclosure"] = _disclosure(summary)
    summary["efficiency"] = _efficiency()

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
        # Keyed by the model measured, and by the calls a run sized.
        "generation.models",
        "generation.timeouts",
        # Keyed by the agent that made the calls, and by the indicator role.
        "disclosure.models[].agents",
        "disclosure.lookups[].kinds",
        "disclosure.enrichment.asked[].kinds",
        # Keyed by the agent that made the calls.
        "efficiency.inputs.calls",
        "efficiency.uncited.by_agent",
        "efficiency.uncited.by_tool",
        "efficiency.calls.by_agent",
        "efficiency.calls.by_tool",
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
