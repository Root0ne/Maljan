"""File-based data loader that reads JSON from the data/samples/ directory.

Satisfies DataLoaderProtocol. Uses the ParserRegistry to find the correct
parser for each data type.
"""

import json
from pathlib import Path
from typing import Any

from maljan.core.exceptions import DataLoadError
from maljan.core.logger import logger
from maljan.parsers.registry import ParserRegistry


class FileDataLoader:
    """Loads analysis data from local JSON files and parses via registered parsers."""

    def __init__(
        self,
        samples_dir: str = "data/samples",
        parser_registry: ParserRegistry | None = None,
    ) -> None:
        self.samples_path = Path(samples_dir)
        self._parser_registry = parser_registry or ParserRegistry()

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
