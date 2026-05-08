"""End-to-End Pipeline Test for ReAct autonomous execution.

Tests whether the LLM agents can effectively use MCP tools in the negotiation graph.
"""

import logging
import os
import sys

# Ensure src is in the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from maljan.app import MaljanApp
from maljan.core.config import Settings
from maljan.core.logger import logger


def main():
    # Set logging to see debug messages
    logger.setLevel(logging.INFO)

    config = Settings()
    # We use mock=False to test actual LLM connections and tool execution
    app = MaljanApp(config=config, mock=False)

    print("=== STARTING END-TO-END PIPELINE ===")

    # Run the pipeline with our sample_1
    result = app.run(file_hash="sample_1", file_name="sample_1.exe")

    print("\n=== PIPELINE FINISHED ===")
    print("Final Decision:", result.get("final_decision"))
    print("Iterations:", result.get("iteration_count"))
    print("Consensus Reached:", result.get("is_consensus"))

    if result.get("judge_report"):
        print("\nJudge Verdict Summary:")
        # Show first 500 chars of the judge report
        print(result["judge_report"][:500] + "...")

    if result.get("stix_output"):
        print("\nSTIX Output generated.")


if __name__ == "__main__":
    main()
