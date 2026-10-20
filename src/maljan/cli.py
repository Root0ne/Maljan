"""Typer CLI - thin wrapper over MaljanApp.

The CLI only parses arguments and delegates to the application layer.
It does not mutate global settings or know about internal architecture.
"""

import asyncio
import json
from pathlib import Path
from typing import Any, cast

import typer

from maljan.analysis.run_summary import NOT_APPLICABLE_SENTENCE
from maljan.app import MaljanApp
from maljan.core.config import Settings
from maljan.core.logger import logger
from maljan.core.plugins import id_refusal, install_allow_list, load_allowed, shipped_ids
from maljan.memory.long_term_memory import MemoryStore

app = typer.Typer(
    name="maljan",
    help="Multi-Agent Malware Analysis Pipeline powered by LangGraph.",
    no_args_is_help=True,
)


def _settings() -> Settings:
    """The command line's settings, read after the plugins their allow-list names are loaded.

    As the worker does: the list is read, its plugins loaded, and the settings
    read again, so a plugin's own block is read with its model.
    """
    allowed = Settings().plugins.allowed
    install_allow_list(allowed)
    load_allowed(allowed)
    return Settings()


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
    provider: str | None = typer.Option(
        None,
        "--provider",
        "-p",
        help="A registered LLM provider's name (default: the configured one).",
    ),
    max_iterations: int | None = typer.Option(
        None,
        "--max-iterations",
        "-i",
        min=1,
        help="Maximum negotiation rounds (default: the configured number).",
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
    config = _settings()
    if provider is not None and not mock:
        # Only an option the operator gave replaces the configured value; a
        # default of the command's own would silently overwrite their settings.
        # The same judgement a save and a job make: a shipped id, or an
        # installed plugin these settings' allow-list names.
        refused = id_refusal("llm", provider, config.plugins.allowed)
        if refused:
            known = ", ".join(shipped_ids("llm"))
            raise typer.BadParameter(f"provider must be one of {known}; {refused}")
        config.llm.provider = cast(Any, provider)
    if max_iterations is not None:
        config.negotiation.max_iterations = max_iterations

    # Create and run. The ``finally`` covers the whole of it — a completed
    # run, a failed one and an interrupted one alike — because what the run
    # staged is live malware and there is no worker behind this to take it
    # away: the tool servers it opened and the directory they staged in belong
    # to this run and end with it (``MaljanApp.aclose``). Everything below the
    # block only reads ``result``.
    maljan_app: MaljanApp | None = None
    try:
        maljan_app = MaljanApp(config=config, mock=mock)
        result = maljan_app.run(file_hash=file_hash, file_name=file_name, sample_path=sample_path)
        # The run completed: the case its judge built may now teach the next.
        maljan_app.remember_the_run()
    except Exception as e:
        logger.error(f"Pipeline execution failed: {e}")
        raise typer.Exit(code=1) from None
    finally:
        _release(maljan_app)

    # Core verdict
    decision = result.get("final_decision", "Unknown")
    iterations = result.get("iteration_count", 0)
    consensus = result.get("is_consensus", False)

    typer.echo(f"\n--- VERDICT: {decision} ---")
    typer.echo(f"Negotiation rounds: {iterations}")
    typer.echo(
        NOT_APPLICABLE_SENTENCE
        if result.get("consensus_applicable") is False
        else f"Consensus reached: {consensus}"
    )

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
    corroboration = run_summary_dict.get("corroboration") or {}
    validation = run_summary_dict.get("validation") or {}
    agent_stats = run_summary_dict.get("agent_stats", [])

    typer.echo("\n--- Analysis Summary ---")
    final = neg.get("final_confidence")
    if final is not None:
        shown = f"{final:.3f}"
    elif neg.get("termination_reason", "unknown") == "unknown":
        shown = "not recorded"
    else:
        shown = "not applicable"
    typer.echo(
        f"Termination: {neg.get('termination_reason', 'unknown')} | Final confidence: {shown}"
    )
    if neg.get("sycophancy_events", 0):
        typer.echo(f"Sycophancy events: {neg['sycophancy_events']} (forced dissent applied)")

    if agent_stats:
        typer.echo("\nAgents:")
        for s in agent_stats:
            ttps = ", ".join(s.get("technique_ids", [])) or "—"
            note = f"  [{s['status']}]" if s.get("status") else ""
            typer.echo(
                f"  {s['agent_id']:12s}  claims={s['claim_count']}  "
                f"conf={s['mean_confidence']:.2f}  TTPs=[{ttps}]{note}"
            )

    if corroboration:
        from maljan.pipeline.validation import corroboration_sources

        multi = sum(1 for row in corroboration.values() if len(corroboration_sources(row)) > 1)
        # Every id any producer named, claimed or asserted by a rule, and not
        # the published count: the line says "named" for that reason.
        typer.echo(
            f"\nCorroboration: {len(corroboration)} technique(s) named | "
            f"{multi} named by more than one source"
        )
        # Most sources first, which is the order a reader wants and the same
        # order the judge was shown them in. Rows are read in either shape.
        ranked = sorted(
            corroboration.items(),
            key=lambda item: (-len(corroboration_sources(item[1])), item[0]),
        )
        for tid, row in ranked[:3]:
            typer.echo(f"  {tid:14s} {', '.join(corroboration_sources(row))}")

    if validation:
        from maljan.pipeline.validation import unresolved_total

        unresolved = validation.get("unresolved") or []
        typer.echo(
            f"\nValidation: {validation.get('retries', 0)} feedback retr"
            f"{'y' if validation.get('retries', 0) == 1 else 'ies'} | "
            f"{unresolved_total(unresolved)} unresolved"
        )
        for row in unresolved[:3]:
            typer.echo(
                f"  {row.get('agent', '?')}/{row.get('code', '?')}: {row.get('message', '')}"
            )


def _write_markdown_report(result: dict, report_path: str) -> None:
    """Write the Markdown report to disk.

    Prefers the comprehensive ``MalwareReport`` rendering that the
    ``report`` pipeline node leaves in ``result["malware_report_markdown"]``
    (added by the reporting refactor).

    Falls back to the legacy ``RunSummary.to_markdown()`` when the new
    payload is absent — happens when ``MALJAN_REPORTING__ENABLED=false``
    flips the pipeline back to the legacy ``judge → END`` edge.
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
            # Absent when no agreement was measured; ``None`` then, not 0.0.
            final_confidence=n_data.get("final_confidence"),
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
                # Both say why an analyst has no claims, and a summary read
                # back without them cannot tell an analyst with nothing to
                # read from one whose model never answered.
                no_data=bool(s.get("no_data", False)),
                status=str(s.get("status", "") or ""),
            )
            for s in run_summary_dict.get("agent_stats", [])
        ]

        v_data = run_summary_dict.get("validation")
        validation = (
            ValidationMetrics(
                retries=v_data.get("retries", 0),
                by_code=dict(v_data.get("by_code") or {}),
                unresolved=[dict(row) for row in v_data.get("unresolved") or []],
            )
            if v_data
            else None
        )

        summary = RunSummary(
            file_hash=run_summary_dict.get("file_hash", ""),
            file_name=run_summary_dict.get("file_name"),
            final_decision=run_summary_dict.get("final_decision", "Unknown"),
            stix_object_count=run_summary_dict.get("stix_object_count", 0),
            judge_stix_object_count=run_summary_dict.get("judge_stix_object_count", 0),
            negotiation=negotiation,
            agent_stats=agent_stats,
            validation=validation,
            elapsed_seconds=run_summary_dict.get("elapsed_seconds", 0.0),
            corroboration=dict(run_summary_dict.get("corroboration") or {}),
            timestamp=run_summary_dict.get("timestamp", 0.0),
            degraded_mode=bool(run_summary_dict.get("degraded_mode", False)),
            degradation_reasons=[str(r) for r in run_summary_dict.get("degradation_reasons") or []],
        )

        Path(report_path).write_text(summary.to_markdown(), encoding="utf-8")
        typer.echo(f"\nLegacy run-summary report written to: {report_path}")

    except Exception as e:
        logger.warning(f"Failed to write report: {e}")


def _release(maljan_app: MaljanApp | None) -> None:
    """Close a run's tool servers and take away what it staged. Never raises.

    The command line has no worker teardown behind it, so this is the only
    place a run's sidecars are released and the only place its staging
    directory, carved payloads and sandbox capture go away. A failure here
    costs the caller nothing it can act on — the analysis is already done or
    already lost — so it is logged and swallowed, and the staging sweep takes
    whatever is left.
    """
    if maljan_app is None:
        return
    try:
        asyncio.run(maljan_app.aclose())
    except Exception as exc:  # noqa: BLE001 — a cleanup never fails a finished run
        logger.warning("Releasing this run failed (non-fatal): %s", exc)


@app.command()
def info() -> None:
    """Show current configuration and registered components."""
    from maljan.core.container import ServiceContainer
    from maljan.parsers.registry import ParserRegistry

    config = _settings()
    container = ServiceContainer(config, mock=True)
    parser_reg = ParserRegistry()

    typer.echo("Maljan Configuration:")
    typer.echo(f"  LLM Provider: {config.llm.provider}")
    typer.echo(f"  Expert Model: {config.llm.expert_model}")
    typer.echo(f"  Judge Model: {config.llm.judge_model}")
    typer.echo(f"  Max Iterations: {config.negotiation.max_iterations}")
    typer.echo(f"  Max Token Limit: {config.max_token_limit or 'derived from the window'}")
    typer.echo(f"\nActive profile: {container.config.agents.profile}")
    typer.echo(f"Analysts: {container.analyst_keys()}")
    typer.echo(f"Registered Parsers: {parser_reg.list_parsers()}")


memory_app = typer.Typer(
    name="memory",
    help="Inspect and maintain the long-term case memory store.",
    no_args_is_help=True,
)
app.add_typer(memory_app, name="memory")


def _build_memory_store_cli() -> MemoryStore:
    """The configured MemoryStore, from the factory the API and the workers use.

    Lives here so the CLI works without requiring the API service to be running.
    """
    from maljan.memory.store_factory import build_memory_store

    return build_memory_store(_settings())


@memory_app.command("stats")
def memory_stats() -> None:
    """Show the configured backend and current case count."""
    store = _build_memory_store_cli()
    typer.echo(f"Backend: {type(store).__name__}")
    typer.echo(f"Cases:   {store.count()}")


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
    """Retroactively purge low-quality LTM entries per the write-time gate.

    Older cases stored before the quality gate landed are still in the
    store and would otherwise keep biasing new analyses via the few-shot
    retrieval prior.
    """
    store = _build_memory_store_cli()
    backend = type(store).__name__
    n = store.purge_low_quality(
        max_total_techniques=max_total_techniques,
        require_uncorroborated=require_uncorroborated,
        include_analyst_errors=include_analyst_errors,
        dry_run=dry_run,
    )
    if dry_run:
        typer.echo(f"[dry-run] backend={backend} would remove {n} of {store.count()} cases.")
        return
    typer.echo(f"backend={backend} removed={n}")


def main() -> None:
    """Application entrypoint."""
    # Before any command runs, and so before any thread or the YARA engine
    # loads: C code folds case by LC_CTYPE (``core.ctype_locale``).
    from maljan.core.ctype_locale import pin_character_classification

    pin_character_classification()
    app()


if __name__ == "__main__":
    main()
