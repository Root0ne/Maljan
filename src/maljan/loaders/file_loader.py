"""File-based data loader that reads JSON from the data/samples/ directory.

Satisfies DataLoaderProtocol. Uses the ParserRegistry to find the correct
parser for each data type.

Phase 3 addition: load_chunked() returns a list of TextChunk objects
so agents can process large inputs incrementally without context overflow.

Phase 6 addition: load_from_sandbox() accepts a SandboxClient and a sample
file path, submits to the sandbox, waits for completion, fetches the JSON
report, and returns parsed + chunked text — same output shape as load_chunked().
This means the pipeline nodes require zero changes to support live sandbox data.
"""

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from maljan.core.config import ChunkingConfig
from maljan.core.exceptions import DataLoadError
from maljan.core.logger import logger
from maljan.loaders.binary_chunker import BinaryChunker, TextChunk
from maljan.parsers.registry import ParserRegistry

if TYPE_CHECKING:
    from maljan.loaders.sandbox_client import SandboxClient


class FileDataLoader:
    """Loads analysis data from local JSON files and parses via registered parsers."""

    def __init__(
        self,
        samples_dir: str = "data/samples",
        parser_registry: ParserRegistry | None = None,
        chunking_config: ChunkingConfig | None = None,
    ) -> None:
        self.samples_path = Path(samples_dir)
        self._parser_registry = parser_registry or ParserRegistry()
        self._chunking_config = chunking_config or ChunkingConfig()
        self._chunker = BinaryChunker(self._chunking_config)

    def load(self, sample_id: str, data_type: str) -> str:
        """Load and parse data for a given sample and data type.

        Args:
            sample_id: Hash or identifier for the sample.
            data_type: One of the registered parser names (e.g. "static", "dynamic").

        Returns:
            Parsed Markdown string ready for LLM consumption.
        """
        path = self.samples_path / data_type / f"{sample_id}.json"
        raw = self._load_json(path)

        if raw is None:
            return f"No {data_type} data available for sample {sample_id}."

        # Use registered parser if available
        try:
            parser = self._parser_registry.create(data_type)
            return parser.parse(raw)
        except KeyError:
            logger.warning(f"No parser registered for '{data_type}', returning raw JSON.")
            return json.dumps(raw, indent=2)

    def load_chunked(self, sample_id: str, data_type: str) -> list[TextChunk]:
        """Load, parse, and split data into LLM-safe chunks.

        When the parsed text fits within the configured token limit (and
        chunking_config.skip_if_fits is True), returns a list with a single
        chunk — no splitting overhead.

        Args:
            sample_id: Hash or identifier for the sample.
            data_type: Domain type (e.g. "static", "dynamic", "network").

        Returns:
            Ordered list of TextChunk objects. At least one chunk is always returned.
        """
        text = self.load(sample_id, data_type)
        chunks = self._chunker.chunk(data_type, text)
        if len(chunks) > 1:
            logger.info(
                "load_chunked: sample='%s' domain='%s' produced %d chunks.",
                sample_id,
                data_type,
                len(chunks),
            )
        return chunks

    def _load_json(self, path: Path) -> Any:
        """Load a JSON file, returning None if not found."""
        try:
            if not path.exists():
                logger.warning(f"File not found: {path}")
                return None
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON from {path}: {e}")
            raise DataLoadError(f"Corrupt data at {path}") from e
        except Exception as e:
            logger.error(f"Unexpected error loading {path}: {e}")
            raise DataLoadError(str(e)) from e

    def load_from_sandbox(
        self,
        sample_path: str,
        data_type: str,
        sandbox_client: "SandboxClient",
        timeout_seconds: int = 300,
        poll_interval_seconds: int = 10,
    ) -> list[TextChunk]:
        """Submit a sample to a sandbox, wait for completion, and return parsed chunks.

        Phase 6: CAPEv2 integration entry point.

        The returned list of TextChunk objects is identical in shape to the
        output of load_chunked(), so pipeline nodes require no changes to
        consume live sandbox data.

        Flow:
          1. sandbox_client.submit(sample_path)         -> task_id
          2. sandbox_client.wait_for_completion(task_id) -> status
          3. sandbox_client.fetch_report(task_id)        -> SubmissionResult
          4. result.report is parsed via the registered parser for data_type
          5. Parsed text is chunked via BinaryChunker

        Args:
            sample_path:            Path to the sample file to submit.
            data_type:              Parser domain ("dynamic", "network", etc.).
            sandbox_client:         Any SandboxClient-protocol object.
            timeout_seconds:        Forwarded to wait_for_completion().
            poll_interval_seconds:  Forwarded to wait_for_completion().

        Returns:
            List of TextChunk objects (same as load_chunked()).

        Raises:
            DataLoadError: When submission, polling, or report fetch fails.
        """
        from maljan.loaders.sandbox_client import SandboxError

        try:
            task_id = sandbox_client.submit(sample_path)
        except SandboxError as exc:
            raise DataLoadError(f"Sandbox submission failed: {exc}") from exc

        try:
            status = sandbox_client.wait_for_completion(
                task_id,
                timeout_seconds=timeout_seconds,
                poll_interval_seconds=poll_interval_seconds,
            )
        except SandboxError as exc:
            raise DataLoadError(f"Sandbox polling failed: {exc}") from exc

        if status not in {"reported"}:
            raise DataLoadError(
                f"Sandbox task {task_id} ended with status '{status}' (not 'reported')."
            )

        try:
            result = sandbox_client.fetch_report(task_id)
        except SandboxError as exc:
            raise DataLoadError(f"Report fetch failed: {exc}") from exc

        # Pass the raw report dict through the existing parser path
        raw = result.report
        try:
            parser = self._parser_registry.create(data_type)
            parsed_text = parser.parse(raw)
        except KeyError:
            logger.warning("load_from_sandbox: no parser for '%s', using raw JSON.", data_type)
            parsed_text = json.dumps(raw, indent=2)

        logger.info(
            "load_from_sandbox: task=%s status=%s data_type=%s sample=%s",
            task_id,
            status,
            data_type,
            sample_path,
        )
        return self._chunker.chunk(data_type, parsed_text)
