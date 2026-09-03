"""Typer CLI - thin wrapper over MaljanApp.

The CLI only parses arguments and delegates to the application layer.
It does not mutate global settings or know about internal architecture.
"""

import json
from pathlib import Path
from typing import Any, cast, get_args

import typer

from maljan.app import MaljanApp
from maljan.core.config import LLMConfig, Settings
from maljan.core.logger import logger

app = typer.Typer(
    name="maljan",
    help="Multi-Agent Malware Analysis Pipeline powered by LangGraph.",
    no_args_is_help=True,
)


@app.command()
def analyze(
    file_hash: str = typer.Argument(
        help="Sample identifier (hash) matching filenames under data/samples/.",
    ),
    file_name: str | None = typer.Option(
        None, "--name", "-n", help="Optional human-readable filename."
    ),
    sample_path: str | None = typer.Option(
        None, "--sample", "-s", help="Path to the malware sample file for sandbox submission."
    ),
    provider: str = typer.Option(
        "openai", "--provider", "-p", help="LLM provider: openai, anthropic, ollama, gemini."
    ),
    max_iterations: int = typer.Option(
        2, "--max-iterations", "-i", min=1, help="Maximum negotiation rounds."
    ),
    mock: bool = typer.Option(
        False, "--mock", "-m", help="Run in mock mode without real LLM calls."
    ),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Path to write STIX JSON output file."
    ),
    report: str | None = typer.Option(
        None,
        "--report",
        "-r",
        help="Path to write the Markdown analysis report (e.g. report.md).",
    ),
) -> None:
    """Run the full malware analysis pipeline on a sample."""

    # Build config at construction time — no post-init mutation
    config = Settings()
    if not mock:
        allowed = get_args(LLMConfig.model_fields["provider"].annotation)
        if provider not in allowed:
            raise typer.BadParameter(f"provider must be one of {', '.join(allowed)}")
        config.llm.provider = cast(Any, provider)
    config.negotiation.max_iterations = max_iterations

    # Create and run
    try:
        maljan_app = MaljanApp(config=config, mock=mock)
        result = maljan_app.run(file_hash=file_hash, file_name=file_name, sample_path=sample_path)
    except Exception as e:
        logger.error(f"Pipeline execution failed: {e}")
        raise typer.Exit(code=1) from None

    # Core verdict
    decision = result.get("final_decision", "Unknown")
    iterations = result.get("iteration_count", 0)
    consensus = result.get("is_consensus", False)

    typer.echo(f"\n--- VERDICT: {decision} ---")
    typer.echo(f"Negotiation rounds: {iterations}")
    typer.echo(f"Consensus reached: {consensus}")

    # RunSummary — inline Markdown preview (first section only)
    run_summary_dict = result.get("run_summary")
    if run_summary_dict:
        _print_run_summary_inline(run_summary_dict)

    # Write full Markdown report to disk
    if report:
        _write_markdown_report(result, report)

    # Judge report
    judge_report = result.get("judge_report", "")
    if judge_report:
        typer.echo(f"\nJudge Report: {judge_report}")

    # STIX output — prefer the rich Bundle from ``report_node`` (54+ SDOs:
    # Identity / Indicator / ObservedData / Note / Report) over the minimal
    # judge fallback. ``stix_output`` remains the fallback for runs where the
    # MalwareReport pipeline was disabled.
    stix = result.get("stix_bundle_extended") or result.get("stix_output", {})
    if stix:
        stix_json = json.dumps(stix, indent=2, default=str)
        typer.echo(f"\nSTIX 2.1 Bundle:\n{stix_json}")
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(stix_json)
            typer.echo(f"\nSTIX output written to: {output}")
    else:
        typer.echo("\nNo STIX output generated.")


def _print_run_summary_inline(run_summary_dict: dict) -> None:
    """Print a compact inline summary from the run_summary dict."""
    neg = run_summary_dict.get("negotiation", {})
    cascade = run_summary_dict.get("cascade") or {}
    validation = run_summary_dict.get("validation") or {}
    agent_stats = run_summary_dict.get("agent_stats", [])

    typer.echo("\n--- Analysis Summary ---")
    typer.echo(
        f"Termination: {neg.get('termination_reason', 'unknown')} | "
        f"Final confidence: {neg.get('final_confidence', 0.0):.3f}"
    )
    if neg.get("sycophancy_events", 0):
        typer.echo(f"Sycophancy events: {neg['sycophancy_events']} (forced dissent applied)")

    if agent_stats:
        typer.echo("\nAgents:")
        for s in agent_stats:
            ttps = ", ".join(s.get("technique_ids", [])) or "—"
            typer.echo(
                f"  {s['agent_id']:12s}  claims={s['claim_count']}  "
                f"conf={s['mean_confidence']:.2f}  TTPs=[{ttps}]"
            )

    if cascade:
        typer.echo(
            f"\nTTP Cascade: {cascade.get('total_techniques', 0)} techniques | "
            f"{cascade.get('corroborated_count', 0)} corroborated | "
            f"{cascade.get('consensus_count', 0)} consensus"
        )
        for t in (cascade.get("top_techniques") or [])[:3]:
            layers = ", ".join(t.get("layers", []))
            typer.echo(
                f"  [{t['label']:13s}] {t['technique_id']}  "
                f"conf={t['confidence']:.3f}  layers=[{layers}]"
            )

    if validation:
        rate = validation.get("hallucination_rate", 0.0)
        typer.echo(
            f"\nATT&CK Validation: {validation.get('valid_ids', 0)}/"
            f"{validation.get('total_claims', 0)} valid | "
            f"hallucination rate={rate:.1%}"
        )


def _write_markdown_report(result: dict, report_path: str) -> None:
    """Write the Markdown report to disk.

    Prefers the comprehensive ``MalwareReport`` rendering that the
    ``report`` pipeline node leaves in ``result["malware_report_markdown"]``
    (added in Phase 2 of the reporting refactor).

    Falls back to the legacy ``RunSummary.to_markdown()`` when the new
    payload is absent — happens when ``MALJAN_REPORTING__ENABLED=false``
    flips the pipeline back to the pre-Phase 2 ``judge → END`` edge.
    """
    new_markdown = result.get("malware_report_markdown")
    if isinstance(new_markdown, str) and new_markdown.strip():
        try:
            Path(report_path).write_text(new_markdown, encoding="utf-8")
            typer.echo(f"\nMalwareReport markdown written to: {report_path}")
            return
        except OSError as exc:
            logger.warning(f"Failed to write malware_report_markdown: {exc}")

    run_summary_dict = result.get("run_summary")
    if not run_summary_dict:
        typer.echo("\nNo run summary available to write.")
        return

    try:
        from maljan.analysis.run_summary import (
            CascadeMetrics,
            ISRAgentStats,
            NegotiationMetrics,
            RunSummary,
            ValidationMetrics,
        )

        n_data = run_summary_dict.get("negotiation", {})
        negotiation = NegotiationMetrics(
            rounds_completed=n_data.get("rounds_completed", 0),
            max_rounds=n_data.get("max_rounds", 0),
            termination_reason=n_data.get("termination_reason", "unknown"),
            sycophancy_events=n_data.get("sycophancy_events", 0),
            confidence_history=n_data.get("confidence_history", []),
            final_confidence=n_data.get("final_confidence", 0.0),
        )

        agent_stats = [
            ISRAgentStats(
                agent_id=s["agent_id"],
                domain=s["domain"],
                revision_round=s["revision_round"],
                claim_count=s["claim_count"],
                mean_confidence=s["mean_confidence"],
                technique_ids=s["technique_ids"],
                has_dissent=s["has_dissent"],
            )
            for s in run_summary_dict.get("agent_stats", [])
        ]

        c_data = run_summary_dict.get("cascade")
        cascade = (
            CascadeMetrics(
                total_techniques=c_data["total_techniques"],
                corroborated_count=c_data["corroborated_count"],
                consensus_count=c_data["consensus_count"],
                top_techniques=c_data["top_techniques"],
            )
            if c_data
            else None
        )

        v_data = run_summary_dict.get("validation")
        validation = (
            ValidationMetrics(
                total_claims=v_data["total_claims"],
                valid_ids=v_data["valid_ids"],
                invalid_ids=v_data["invalid_ids"],
                low_alignment=v_data["low_alignment"],
                hallucination_rate=v_data["hallucination_rate"],
            )
            if v_data
            else None
        )

        summary = RunSummary(
            file_hash=run_summary_dict.get("file_hash", ""),
            file_name=run_summary_dict.get("file_name"),
            final_decision=run_summary_dict.get("final_decision", "Unknown"),
            stix_object_count=run_summary_dict.get("stix_object_count", 0),
            negotiation=negotiation,
            agent_stats=agent_stats,
            validation=validation,
            cascade=cascade,
            elapsed_seconds=run_summary_dict.get("elapsed_seconds", 0.0),
            timestamp=run_summary_dict.get("timestamp", 0.0),
        )

        Path(report_path).write_text(summary.to_markdown(), encoding="utf-8")
        typer.echo(f"\nLegacy run-summary report written to: {report_path}")

    except Exception as e:
        logger.warning(f"Failed to write report: {e}")


@app.command()
def info() -> None:
    """Show current configuration and registered components."""
    from maljan.agents.registry import AgentRegistry
    from maljan.parsers.registry import ParserRegistry

    config = Settings()
    agent_reg = AgentRegistry()
    parser_reg = ParserRegistry()

    typer.echo("Maljan Configuration:")
    typer.echo(f"  LLM Provider: {config.llm.provider}")
    typer.echo(f"  Expert Model: {config.llm.expert_model}")
    typer.echo(f"  Judge Model: {config.llm.judge_model}")
    typer.echo(f"  Max Iterations: {config.negotiation.max_iterations}")
    typer.echo(f"  Max Token Limit: {config.max_token_limit}")
    typer.echo(f"\nRegistered Agents: {agent_reg.list_agents()}")
    typer.echo(f"Registered Parsers: {parser_reg.list_parsers()}")


@app.command()
def benchmark(
    fixtures_dir: str | None = typer.Option(
        None,
        "--fixtures-dir",
        "-f",
        help="Path to ground truth fixtures directory (default: tests/evaluation/fixtures/).",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional path to write the report (e.g., benchmark_report.md).",
    ),
    fmt: str = typer.Option(
        "markdown",
        "--format",
        help="Output format: markdown (default) or json.",
    ),
) -> None:
    """Run the Phase 8.2 evaluation benchmark suite against all ground truth fixtures.

    Loads every *.json ground truth file from the fixtures directory, synthesizes
    pipeline outputs from the known technique IDs (perfect-precision baseline), and
    evaluates TTP accuracy, STIX quality, and negotiation efficiency metrics.

    This command is safe to run without an LLM: no API keys or network access required.

    The benchmark suite lives under ``tests/evaluation/`` which is only present
    in source checkouts. When Maljan is invoked from a pip-installed wheel
    without the dev extra, the import fails — we surface a clear actionable
    message instead of the raw ``ModuleNotFoundError``.
    """
    # ``tests/`` is a sibling of ``src/`` in the source checkout; add the
    # repo root to sys.path so the import resolves even when ``maljan`` is
    # invoked from an installed entry-point (where the package no longer
    # sees its sibling ``tests/`` directory automatically).
    import sys

    _repo_root = Path(__file__).resolve().parents[2]
    if _repo_root.is_dir() and str(_repo_root) not in sys.path:
        sys.path.insert(0, str(_repo_root))

    try:
        from tests.evaluation.benchmark_suite import run_fixture_benchmark
    except ModuleNotFoundError as exc:
        typer.echo(
            f"benchmark unavailable: {exc}.\n"
            "The benchmark suite ships only with a source checkout. "
            "Clone the repository and run from its root, or install the "
            "package with: uv pip install -e '.[dev]'",
            err=True,
        )
        raise typer.Exit(code=2) from None

    result = run_fixture_benchmark(
        fixtures_dir=fixtures_dir,
        output_path=output,
        output_format=fmt,
    )
    typer.echo(result.to_markdown())
    if output:
        typer.echo(f"\nReport written to: {output}", err=True)


memory_app = typer.Typer(
    name="memory",
    help="Inspect and maintain the long-term case memory store.",
    no_args_is_help=True,
)
app.add_typer(memory_app, name="memory")


def _build_memory_store_cli() -> object:
    """Build a MemoryStore matching the operator's configuration.

    Mirrors the API admin route; lives here so the CLI works without
    requiring the API service to be running.
    """
    from maljan.memory.in_memory_store import InMemoryStore

    cfg = Settings()
    backend = cfg.memory.backend.lower()
    if backend == "qdrant":
        from maljan.memory.qdrant_store import QdrantStore

        return QdrantStore(
            url=cfg.memory.qdrant_url,
            collection=cfg.memory.qdrant_collection,
            api_key=(
                cfg.memory.qdrant_api_key.get_secret_value() if cfg.memory.qdrant_api_key else None
            ),
        )
    return InMemoryStore()


@memory_app.command("stats")
def memory_stats() -> None:
    """Show the configured backend and current case count."""
    store = _build_memory_store_cli()
    typer.echo(f"Backend: {type(store).__name__}")
    typer.echo(f"Cases:   {store.count()}")  # type: ignore[attr-defined]


@memory_app.command("purge-low-quality")
def memory_purge_low_quality(
    max_total_techniques: int = typer.Option(
        1,
        "--max-techniques",
        help=(
            "Purge cases whose total_techniques is <= this value (set -1 to "
            "disable the technique-count branch)."
        ),
    ),
    require_uncorroborated: bool = typer.Option(
        True,
        "--require-uncorroborated/--allow-corroborated",
        help="Also require corroborated_count == 0 before purging.",
    ),
    include_analyst_errors: bool = typer.Option(
        True,
        "--include-errors/--skip-errors",
        help="Also purge cases recorded with any analyst [ERROR] output.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show how many cases would be removed without deleting."
    ),
) -> None:
    """Retroactively purge low-quality LTM entries per the LTM-01 gate.

    Helpful after the audit 2026-05-17 fixes: older Qdrant points stored
    before the quality gate landed are still in the collection and would
    otherwise keep biasing new analyses via the few-shot retrieval prior.
    """
    store = _build_memory_store_cli()
    backend = type(store).__name__
    if dry_run:
        # Approximate by snapshotting count, running the purge against a
        # detached InMemoryStore copy for cheap and accurate counting.
        from maljan.memory.in_memory_store import InMemoryStore

        if isinstance(store, InMemoryStore):
            before = store.count()
            removed = InMemoryStore()
            removed._cases = list(store._cases)  # noqa: SLF001
            n = removed.purge_low_quality(
                max_total_techniques=max_total_techniques,
                require_uncorroborated=require_uncorroborated,
                include_analyst_errors=include_analyst_errors,
            )
            typer.echo(f"[dry-run] backend={backend} would remove {n} of {before} cases.")
            return
        # Qdrant: walk the same scroll loop the purge would use, but skip
        # the delete step. Keeping the logic inside the store avoids
        # leaking internals here — for now fall back to a count-only
        # estimate via the in-memory simulator after retrieving all cases.
        typer.echo(
            "[dry-run] Qdrant dry-run requires the API admin endpoint "
            "(POST /api/v1/system/ltm/purge with dry_run=true). The CLI "
            "would have to scroll the whole collection — call the API."
        )
        return

    n = store.purge_low_quality(  # type: ignore[attr-defined]
        max_total_techniques=max_total_techniques,
        require_uncorroborated=require_uncorroborated,
        include_analyst_errors=include_analyst_errors,
    )
    typer.echo(f"backend={backend} removed={n}")


def main() -> None:
    """Application entrypoint."""
    app()


if __name__ == "__main__":
    main()
