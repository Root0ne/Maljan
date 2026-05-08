#!/usr/bin/env python3
"""Standalone script to run the Maljan analysis pipeline.

This script provides a direct entry point (no ``pip install`` required)
for running a malware analysis on a given sample.  It accepts either a
**file path** (``*.exe``, ``*.dll``, ``*.bin``, ...) or a pre-registered
**sample hash/ID** that already exists under ``data/samples/``.

Usage examples
--------------
::

    # Analyse a file on disk (SHA-256 hash is computed automatically)
    python scripts/run_analysis.py path/to/malware.exe

    # Analyse a pre-registered sample by hash
    python scripts/run_analysis.py sample_1

    # Use Gemini provider, limit to 1 round, write STIX + Markdown reports
    python scripts/run_analysis.py sample_1 \\
        --provider gemini --max-iterations 1 \\
        --output report.stix.json --report report.md

    # Quick smoke-test with mock mode (no LLM calls)
    python scripts/run_analysis.py sample_1 --mock
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path

# Ensure the project ``src/`` directory is on the import path so that the
# script can be executed directly without a prior ``pip install -e .``.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from maljan.app import MaljanApp  # noqa: E402
from maljan.core.config import NegotiationConfig, Settings  # noqa: E402
from maljan.core.logger import logger  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(path: Path) -> str:
    """Return the hex SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _prepare_sample(file_path: Path, samples_dir: Path) -> tuple[str, str]:
    """Copy *file_path* into each domain sub-directory under *samples_dir*.

    Returns ``(file_hash, file_name)`` where *file_hash* is the SHA-256
    digest used as the sample identifier throughout the pipeline.

    The pipeline expects ``data/samples/{domain}/{file_hash}.json`` for
    each registered domain.  For a raw binary we create a minimal JSON
    wrapper that the built-in loaders can consume.
    """
    file_hash = _sha256(file_path)
    file_name = file_path.name

    for domain in ("static", "dynamic", "network"):
        domain_dir = samples_dir / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        target = domain_dir / f"{file_hash}.json"
        if target.exists():
            continue

        # Build a minimal fixture that matches the format expected by the
        # data loader.  Real pipelines will populate richer data via their
        # respective MCP/sandbox integrations during analysis.
        fixture = [
            {
                "file": file_name,
                "source": "run_analysis.py import",
                "note": f"Auto-generated stub for {domain} domain.",
            }
        ]
        target.write_text(json.dumps(fixture, indent=2), encoding="utf-8")

    return file_hash, file_name


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Run the Maljan multi-agent malware analysis pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "target",
        help=(
            "Path to a sample file (.exe, .dll, ...) or a sample hash/ID "
            "already present under data/samples/."
        ),
    )
    p.add_argument(
        "--provider",
        "-p",
        default=None,
        help="LLM provider: openai, anthropic, ollama, gemini (default: from .env).",
    )
    p.add_argument(
        "--max-iterations",
        "-i",
        type=int,
        default=10,
        help="Maximum negotiation rounds (default: 10). Adaptive termination usually exits earlier.",
    )
    p.add_argument(
        "--mock",
        "-m",
        action="store_true",
        help="Run in mock mode without real LLM calls.",
    )
    p.add_argument(
        "--output",
        "-o",
        default=None,
        help="Path to write STIX 2.1 JSON output.",
    )
    p.add_argument(
        "--report",
        "-r",
        default=None,
        help="Path to write the Markdown analysis report.",
    )
    p.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    # Logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logger.setLevel(level)

    # Resolve target ---------------------------------------------------
    target_path = Path(args.target)
    samples_dir = _PROJECT_ROOT / "data" / "samples"

    if target_path.is_file():
        file_hash, file_name = _prepare_sample(target_path, samples_dir)
        logger.info("Imported %s as %s", file_name, file_hash)
    else:
        # Treat as a pre-registered sample hash/ID
        file_hash = args.target
        file_name = f"{file_hash}.exe"

    config = Settings(
        negotiation=NegotiationConfig(max_iterations=args.max_iterations),
    )

    # Override provider if specified on CLI — mutate in-place to preserve
    # all other .env-sourced model/key settings (e.g. LLM__GEMINI__EXPERT_MODEL).
    if args.provider:
        config.llm.provider = args.provider

    # Run pipeline -----------------------------------------------------
    print("=" * 60)
    print("MALJAN - Multi-Agent Malware Analysis Pipeline")
    print("=" * 60)
    print(f"Target:     {file_hash} ({file_name})")
    print(f"Provider:   {config.llm.provider}")
    print(f"Mock:       {args.mock}")
    print(f"Iterations: {args.max_iterations}")
    print("-" * 60)

    app = MaljanApp(
        config=config,
        mock=args.mock,
        samples_dir=str(samples_dir),
    )
    result = app.run(file_hash=file_hash, file_name=file_name)

    # Results ----------------------------------------------------------
    decision = result.get("final_decision", "Unknown")
    iterations = result.get("iteration_count", 0)
    consensus = result.get("is_consensus", False)

    print()
    print("=" * 60)
    print(f"VERDICT:             {decision}")
    print(f"Negotiation rounds:  {iterations}")
    print(f"Consensus reached:   {consensus}")
    print("=" * 60)

    # Judge report
    judge = result.get("judge_report", "")
    if judge:
        print(f"\nJudge Report:\n{judge[:1000]}")
        if len(judge) > 1000:
            print("... [truncated]")

    # STIX output
    stix = result.get("stix_output", {})
    if stix:
        stix_json = json.dumps(stix, indent=2, default=str)
        if args.output:
            Path(args.output).write_text(stix_json, encoding="utf-8")
            print(f"\nSTIX output written to: {args.output}")
        else:
            print(f"\nSTIX 2.1 Bundle:\n{stix_json[:2000]}")

    # Markdown report
    if args.report:
        run_summary_dict = result.get("run_summary")
        if run_summary_dict:
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

                Path(args.report).write_text(summary.to_markdown(), encoding="utf-8")
                print(f"\nMarkdown report written to: {args.report}")

            except Exception as exc:
                logger.warning("Failed to write markdown report: %s", exc)
        else:
            print("\nNo run summary available for markdown report (mock mode?).")


if __name__ == "__main__":
    main()
