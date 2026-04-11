import json
from pathlib import Path
from typing import Any

from maljan.core.exceptions import DataLoadError
from maljan.core.logger import logger
from maljan.parsers.dynamic_parser import DynamicParser
from maljan.parsers.network_parser import NetworkParser
from maljan.parsers.static_parser import StaticParser


class DataLoader:
    """Unified loader for Ghidra, CAPEv2, and Zeek artifacts with optional parsing."""

    def __init__(self, samples_dir: str = "data/samples") -> None:
        self.samples_path = Path(samples_dir)
        if not self.samples_path.exists():
            raise FileNotFoundError(f"Directory {samples_dir} not found.")

        # Initialize internal parsers
        self.static_parser = StaticParser()
        self.dynamic_parser = DynamicParser()
        self.network_parser = NetworkParser()

    def load_static_data(self, sample_id: str, use_parser: bool = True) -> str:
        """Loads and optionally parses decompiled summaries."""
        path = self.samples_path / "static" / f"{sample_id}.json"
        raw = self._load_json(path)
        if use_parser and raw:
            return self.static_parser.parse(raw)
        return json.dumps(raw, indent=2)

    def load_dynamic_data(self, sample_id: str, use_parser: bool = True) -> str:
        """Loads and optionally parses sandbox behavior reports."""
        path = self.samples_path / "dynamic" / f"{sample_id}.json"
        raw = self._load_json(path)
        if use_parser and raw:
            return self.dynamic_parser.parse(raw)
        return json.dumps(raw, indent=2)

    def load_network_data(self, sample_id: str, use_parser: bool = True) -> str:
        """Loads and optionally parses Zeek connection logs."""
        path = self.samples_path / "network" / f"{sample_id}.json"
        raw = self._load_json(path)
        if use_parser and raw:
            return self.network_parser.parse(raw)
        return json.dumps(raw, indent=2)

    def _load_json(self, path: Path) -> Any:
        try:
            if not path.exists():
                logger.warning(f"File not found: {path}")
                return None
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON from {path}: {str(e)}")
            raise DataLoadError(f"Corrupt data at {path}") from e
        except Exception as e:
            logger.error(f"Unexpected error loading {path}: {str(e)}")
            raise DataLoadError(str(e)) from e
