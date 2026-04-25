"""MITRE ATT&CK STIX 2.1 bundle downloader and parser.

Downloads the Enterprise ATT&CK dataset from the official MITRE CTI GitHub
repository and extracts attack-pattern objects (techniques and sub-techniques).

The raw STIX bundle is cached locally so subsequent runs avoid network calls.

Cache location: ~/.cache/maljan/attck/ (or MALJAN_ATTCK_CACHE env var)

MITRE ATT&CK data is CC BY 4.0 licensed.
Source: https://github.com/mitre/cti
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from maljan.core.logger import logger

# Official MITRE CTI GitHub raw URL for Enterprise ATT&CK
ATTCK_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)

# Local cache directory — respects MALJAN_ATTCK_CACHE env var
_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "maljan" / "attck"
ATTCK_CACHE_DIR = Path(os.environ.get("MALJAN_ATTCK_CACHE", str(_DEFAULT_CACHE_DIR)))
ATTCK_CACHE_FILE = ATTCK_CACHE_DIR / "enterprise-attack.json"

# Regex for ATT&CK technique IDs (e.g., T1055, T1055.001)
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@dataclass
class ATTCKTechnique:
    """Parsed representation of a single ATT&CK technique or sub-technique.

    Fields map directly to STIX 2.1 AttackPattern object properties.
    """

    technique_id: str  # e.g., "T1055"
    name: str  # e.g., "Process Injection"
    description: str  # Full technique description text
    tactic_phases: list[str]  # e.g., ["defense-evasion", "privilege-escalation"]
    is_subtechnique: bool  # True for T1055.001
    url: str = ""  # ATT&CK website URL
    data_sources: list[str] = field(default_factory=list)
    detection: str = ""  # Detection guidance text
    platforms: list[str] = field(default_factory=list)

    @property
    def searchable_text(self) -> str:
        """Combined text used for TF-IDF indexing and semantic search."""
        parts = [
            f"Technique {self.technique_id}: {self.name}",
            self.description[:2000],  # cap at 2000 chars
            " ".join(self.tactic_phases),
            " ".join(self.data_sources),
            self.detection[:500],
        ]
        return " ".join(filter(None, parts))


def load_attck_bundle(
    url: str = ATTCK_BUNDLE_URL,
    cache_file: Path = ATTCK_CACHE_FILE,
    force_refresh: bool = False,
) -> list[ATTCKTechnique]:
    """Load the ATT&CK STIX bundle, using a local cache when available.

    Args:
        url: STIX bundle URL to fetch if cache is missing.
        cache_file: Local path to store/load the cached bundle.
        force_refresh: If True, re-download even if cache exists.

    Returns:
        List of parsed ATTCKTechnique objects.

    Raises:
        RuntimeError: If the bundle cannot be fetched and no cache exists.
    """
    raw_bundle: dict

    if cache_file.exists() and not force_refresh:
        logger.info("Loading ATT&CK bundle from cache: %s", cache_file)
        raw_bundle = json.loads(cache_file.read_text(encoding="utf-8"))
    else:
        logger.info("Fetching ATT&CK bundle from: %s", url)
        raw_bundle = _fetch_bundle(url)
        _save_cache(raw_bundle, cache_file)

    return _parse_bundle(raw_bundle)


def _fetch_bundle(url: str) -> dict:
    """Download the STIX bundle from the given URL."""
    import urllib.request  # stdlib — no requests dependency needed for one-off download

    try:
        with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310
            data = resp.read().decode("utf-8")
        raw: dict[str, Any] = json.loads(data)
        return raw
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch ATT&CK bundle from {url}: {exc}") from exc


def _save_cache(bundle: dict, cache_file: Path) -> None:
    """Persist the raw bundle JSON to the local cache file."""
    try:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps(bundle), encoding="utf-8")
        logger.info("ATT&CK bundle cached at: %s", cache_file)
    except OSError as e:
        logger.warning("Could not write ATT&CK cache: %s", e)


def _parse_bundle(bundle: dict) -> list[ATTCKTechnique]:
    """Extract ATTCKTechnique objects from a raw STIX 2.1 bundle dict."""
    techniques: list[ATTCKTechnique] = []

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        # Extract the canonical technique ID from external_references
        technique_id: str | None = None
        url: str = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        if not technique_id or not TECHNIQUE_ID_RE.match(technique_id):
            continue

        # Kill chain phases → tactic names
        tactic_phases = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        techniques.append(
            ATTCKTechnique(
                technique_id=technique_id,
                name=obj.get("name", ""),
                description=obj.get("description", ""),
                tactic_phases=tactic_phases,
                is_subtechnique=obj.get("x_mitre_is_subtechnique", False),
                url=url,
                data_sources=obj.get("x_mitre_data_sources", []),
                detection=obj.get("x_mitre_detection", ""),
                platforms=obj.get("x_mitre_platforms", []),
            )
        )

    logger.info("Parsed %d ATT&CK techniques from bundle.", len(techniques))
    return techniques
