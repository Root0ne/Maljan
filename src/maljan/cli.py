"""Typer CLI - thin wrapper over MaljanApp.

The CLI only parses arguments and delegates to the application layer.
It does not mutate global settings or know about internal architecture.
"""

import json
from pathlib import Path

import typer

from maljan.app import MaljanApp
from maljan.core.config import Settings
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
    provider: str = typer.Option(
        "openai", "--provider", "-p", help="LLM provider: openai, anthropic, ollama."
    ),
    max_iterations: int = typer.Option(
        2, "--max-iterations", "-i", help="Maximum negotiation rounds."
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
    from maljan.core.config import LLMConfig, NegotiationConfig

    llm_cfg = LLMConfig(provider=provider) if not mock else LLMConfig()
    config = Settings(
        llm=llm_cfg,
        negotiation=NegotiationConfig(max_iterations=max_iterations),
    )

    # Create and run
    try:
        maljan_app = MaljanApp(config=config, mock=mock)
        result = maljan_app.run(file_hash=file_hash, file_name=file_name)
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

    # STIX output
    stix = result.get("stix_output", {})
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
    """Reconstruct a RunSummary from the result dict and write a Markdown report."""
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
        typer.echo(f"\nAnalysis report written to: {report_path}")

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


def main() -> None:
    """Application entrypoint."""
    app()


if __name__ == "__main__":
    main()
