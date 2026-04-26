#!/usr/bin/env python3
"""Entry point for running the Maljan pipeline E2E with MCP tools.

This script initializes the MaljanApp and runs the ReAct-based agents
(Dynamic, Static, Network) which use MCP tools (Ghidra, CAPEv2) to perform live analysis.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# Ensure src is in the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from maljan.app import MaljanApp
from maljan.core.config import Settings
from maljan.core.logger import logger


def main():
    parser = argparse.ArgumentParser(description="Run Maljan E2E Pipeline with MCP Tools")
    parser.add_argument("target", help="Target file path or hash for analysis")
    parser.add_argument("--name", "-n", help="Optional human-readable name for the sample")
    parser.add_argument("--provider", "-p", default="openai", help="LLM Provider")
    parser.add_argument("--max-iterations", "-i", type=int, default=2, help="Max iterations")
    parser.add_argument("--mock", "-m", action="store_true", help="Run in mock mode")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--report-dir", "-r", default="reports", help="Directory for reports")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    from maljan.core.config import LLMConfig, NegotiationConfig

    llm_cfg = LLMConfig(provider=args.provider) if not args.mock else LLMConfig()
    config = Settings(
        llm=llm_cfg,
        negotiation=NegotiationConfig(max_iterations=args.max_iterations),
    )

    app = MaljanApp(config=config, mock=args.mock)

    logger.info(f"Starting End-to-End Pipeline for target: {args.target}")

    # In live mode, 'target' can be an absolute path to a file.
    # If the JSON report isn't found in data/samples/, the agent will see
    # "No data available for sample <target>." and will intelligently use
    # the MCP tools (Ghidra connect, CAPE submit) using the target path.
    result = app.run(file_hash=args.target, file_name=args.name or os.path.basename(args.target))

    logger.info("Pipeline Execution Completed.")

    decision = result.get("final_decision", "Unknown")
    logger.info(f"Final Decision: {decision}")
    logger.info(f"Iterations: {result.get('iteration_count', 0)}")
    logger.info(f"Consensus Reached: {result.get('is_consensus', False)}")

    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    base_name = os.path.basename(args.target)

    stix = result.get("stix_output")
    if stix:
        stix_path = report_dir / f"{base_name}_stix.json"
        with open(stix_path, "w", encoding="utf-8") as f:
            json.dump(stix, f, indent=2)
        logger.info(f"STIX output saved to {stix_path}")

    judge_report = result.get("judge_report")
    if judge_report:
        report_path = report_dir / f"{base_name}_judge_report.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(judge_report)
        logger.info(f"Judge report saved to {report_path}")

    # Write full run summary if available
    run_summary_dict = result.get("run_summary")
    if run_summary_dict:
        try:
            # We use CLI's internal logic or build it directly
            report_md_path = report_dir / f"{base_name}_full_report.md"
            from maljan.cli import _write_markdown_report

            _write_markdown_report(result, str(report_md_path))
        except Exception as e:
            logger.warning(f"Failed to generate full markdown report: {e}")


if __name__ == "__main__":
    main()
