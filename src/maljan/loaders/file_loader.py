"""File-based data loader that reads JSON from the local samples directory.

Satisfies DataLoaderProtocol. Uses the ParserRegistry to find the correct
parser for each data type. Sandbox-driven runs land here through
``load_from_sandbox`` which submits, polls, fetches, and parses in one call.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from maljan.core.config import ChunkingConfig
from maljan.core.exceptions import DataLoadError, UnsafePathError
from maljan.core.logger import logger
from maljan.loaders.binary_chunker import BinaryChunker, TextChunk
from maljan.parsers.registry import ParserRegistry

if TYPE_CHECKING:
    from maljan.loaders.sandbox_client import SandboxClient


# Final sandbox statuses considered usable. ``partial`` is accepted to
# cover sandbox runs where one analyzer module failed but the rest
# produced usable artefacts.
_USABLE_SANDBOX_STATUSES: frozenset[str] = frozenset({"reported", "partial"})

# Hex-string sample identifiers (MD5/SHA-1/SHA-256/SHA-512) and a small set of
# alphanumeric IDs used in fixtures. Anything else is rejected to prevent path
# traversal via ``sample_id``.
_SAMPLE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def _validate_sample_id(sample_id: str) -> str:
    """Reject identifiers that contain separators, dots-only, or are empty.

    The regex permits hex hashes, fixture IDs like ``sample_1``, and short
    alphanumerics with limited punctuation. It explicitly forbids ``/`` and
    ``\\`` so an attacker cannot escape the samples directory.
    """
    if not sample_id or sample_id in {".", ".."} or not _SAMPLE_ID_RE.match(sample_id):
        raise UnsafePathError(f"Unsafe sample_id rejected: {sample_id!r}")
    return sample_id


def _validate_data_type(data_type: str) -> str:
    """Restrict data_type to a conservative identifier shape."""
    if not data_type or not re.match(r"^[A-Za-z0-9_]{1,32}$", data_type):
        raise UnsafePathError(f"Unsafe data_type rejected: {data_type!r}")
    return data_type


class FileDataLoader:
    """Loads analysis data from local JSON files and parses via registered parsers."""

    def __init__(
        self,
        samples_dir: str = "data/samples",
        parser_registry: ParserRegistry | None = None,
        chunking_config: ChunkingConfig | None = None,
    ) -> None:
        self.samples_path = Path(samples_dir).resolve()
        self._parser_registry = parser_registry or ParserRegistry()
        self._chunking_config = chunking_config or ChunkingConfig()
        self._chunker = BinaryChunker(self._chunking_config)

    # ------------------------------------------------------------------
    # Public chunker access
    # ------------------------------------------------------------------

    def chunk_text(self, data_type: str, text: str) -> list[TextChunk]:
        """Public entry point for chunking arbitrary already-parsed text.

        Exposes the internal :class:`BinaryChunker` without leaking the
        attribute. Callers (e.g. :class:`ServiceContainer`) should use this
        instead of touching ``loader._chunker`` directly.
        """
        return self._chunker.chunk(data_type, text)

    # ------------------------------------------------------------------
    # File-based loading
    # ------------------------------------------------------------------

    def _resolve_sample_path(self, sample_id: str, data_type: str) -> Path:
        sid = _validate_sample_id(sample_id)
        dt = _validate_data_type(data_type)
        candidate = (self.samples_path / dt / f"{sid}.json").resolve()
        # Defence-in-depth: ensure the resolved path is still inside samples_path.
        try:
            candidate.relative_to(self.samples_path)
        except ValueError as exc:
            raise UnsafePathError(f"Resolved path escapes samples directory: {candidate}") from exc
        return candidate

    def load(self, sample_id: str, data_type: str) -> str:
        """Load and parse data for a given sample and data type.

        Returns:
            Parsed Markdown string ready for LLM consumption. Returns a
            placeholder string when no data file is present for the sample.
        """
        path = self._resolve_sample_path(sample_id, data_type)
        raw = self._load_json(path)

        if raw is None:
            return f"No {data_type} data available for sample {sample_id}."

        try:
            parser = self._parser_registry.create(data_type)
            return parser.parse(raw)
        except KeyError:
            logger.warning("No parser registered for '%s', returning raw JSON.", data_type)
            return json.dumps(raw, indent=2)

    def load_chunked(self, sample_id: str, data_type: str) -> list[TextChunk]:
        """Load, parse, and split data into LLM-safe chunks."""
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
        """Load a JSON file, returning ``None`` if not found."""
        try:
            if not path.exists():
                # F12 (2026-07-05): optional per-sample fixtures (static/
                # dynamic/network ``<sha>.json``) are legitimately absent on
                # a live run — the loader returns None and the caller
                # degrades gracefully. Log at DEBUG so operators are not
                # misled into thinking real data is missing.
                logger.debug("File not found (optional): %s", path)
                return None
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error("Failed to decode JSON from %s: %s", path, e)
            raise DataLoadError(f"Corrupt data at {path}") from e
        except OSError as e:
            logger.error("Unexpected error loading %s: %s", path, e)
            raise DataLoadError(str(e)) from e

    # ------------------------------------------------------------------
    # Sandbox-driven loading
    # ------------------------------------------------------------------

    def load_from_sandbox(
        self,
        sample_path: str,
        data_type: str,
        sandbox_client: SandboxClient,
        timeout_seconds: int = 300,
        poll_interval_seconds: int = 10,
    ) -> list[TextChunk]:
        """Submit a sample to a sandbox, wait for completion, and return parsed chunks."""
        from maljan.loaders.sandbox_client import SandboxError as _SandboxError

        dt = _validate_data_type(data_type)

        try:
            task_id = sandbox_client.submit(sample_path)
        except _SandboxError as exc:
            raise DataLoadError(f"Sandbox submission failed: {exc}") from exc

        try:
            status = sandbox_client.wait_for_completion(
                task_id,
                timeout_seconds=timeout_seconds,
                poll_interval_seconds=poll_interval_seconds,
            )
        except _SandboxError as exc:
            raise DataLoadError(f"Sandbox polling failed: {exc}") from exc

        if status not in _USABLE_SANDBOX_STATUSES:
            raise DataLoadError(
                f"Sandbox task {task_id} ended with status '{status}' "
                f"(expected one of {sorted(_USABLE_SANDBOX_STATUSES)})."
            )

        try:
            result = sandbox_client.fetch_report(task_id)
        except _SandboxError as exc:
            raise DataLoadError(f"Report fetch failed: {exc}") from exc

        raw = result.report
        try:
            parser = self._parser_registry.create(dt)
            parsed_text = parser.parse(raw)
        except KeyError:
            logger.warning("load_from_sandbox: no parser for '%s', using raw JSON.", dt)
            parsed_text = json.dumps(raw, indent=2)

        logger.info(
            "load_from_sandbox: task=%s status=%s data_type=%s sample=%s",
            task_id,
            status,
            dt,
            sample_path,
        )
        return self._chunker.chunk(dt, parsed_text)
