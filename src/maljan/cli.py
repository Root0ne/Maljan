"""Typer CLI - thin wrapper over MaljanApp.

The CLI only parses arguments and delegates to the application layer.
It does not mutate global settings or know about internal architecture.
"""

import json

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
) -> None:
    """Run the full malware analysis pipeline on a sample."""

    # Build config from CLI args (no global mutation)
    config = Settings()
    if not mock:
        config.llm.provider = provider
    config.negotiation.max_iterations = max_iterations

    # Create and run
    try:
        maljan_app = MaljanApp(config=config, mock=mock)
        result = maljan_app.run(file_hash=file_hash, file_name=file_name)
    except Exception as e:
        logger.error(f"Pipeline execution failed: {e}")
        raise typer.Exit(code=1) from None

    # Display results
    decision = result.get("final_decision", "Unknown")
    iterations = result.get("iteration_count", 0)
    consensus = result.get("is_consensus", False)

    typer.echo(f"\n--- VERDICT: {decision} ---")
    typer.echo(f"Negotiation rounds: {iterations}")
    typer.echo(f"Consensus reached: {consensus}")

    # Discussion history
    history = result.get("discussion_history", [])
    if history:
        typer.echo(f"\nDiscussion history ({len(history)} arguments):")
        for i, arg in enumerate(history, 1):
            typer.echo(f"  [{i}] {arg.agent_name} (conf: {arg.confidence_score:.2f})")

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
