"""MITRE ATT&CK STIX 2.1 bundle downloader and parser.

Downloads the Enterprise ATT&CK dataset from the official MITRE
``attack-stix-data`` GitHub repository (the maintained STIX 2.1 source) and
extracts:
  - ``attack-pattern`` objects -> techniques / sub-techniques, and
  - ``x-mitre-tactic`` objects -> the tactic catalogue, in matrix column order.

The raw STIX bundle is cached locally. The cache AUTO-REFRESHES once it is older
than ``MALJAN_ATTCK_MAX_AGE_DAYS`` days (default 30), so new ATT&CK releases
(e.g. the v19 "Defense Evasion" -> "Stealth" + "Defense Impairment" split) flow
through with no code changes. If a refresh download fails, the existing (stale)
cache is reused rather than breaking the analysis run.

Cache location: ~/.cache/maljan/attck/ (or MALJAN_ATTCK_CACHE env var).
Force a refresh: ``python -m maljan.memory.attck_loader`` (or load with
force_refresh=True).

MITRE ATT&CK data is CC BY 4.0 licensed.
Source: https://github.com/mitre-attack/attack-stix-data
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from maljan.core.logger import logger

# Official, maintained MITRE ATT&CK STIX 2.1 source. The version-less
# ``enterprise-attack.json`` always points at the latest release.
ATTCK_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Local cache directory — respects MALJAN_ATTCK_CACHE env var
_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "maljan" / "attck"
ATTCK_CACHE_DIR = Path(os.environ.get("MALJAN_ATTCK_CACHE", str(_DEFAULT_CACHE_DIR)))
ATTCK_CACHE_FILE = ATTCK_CACHE_DIR / "enterprise-attack.json"

# Regexes for ATT&CK IDs
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
TACTIC_ID_RE = re.compile(r"^TA\d{4}$")


def _default_max_age_days() -> int:
    """Cache auto-refresh threshold in days (env MALJAN_ATTCK_MAX_AGE_DAYS).

    0 (or negative) disables the age check: the cache is then used until it is
    missing or a force_refresh is requested.
    """
    try:
        return int(os.environ.get("MALJAN_ATTCK_MAX_AGE_DAYS", "30"))
    except ValueError:
        return 30


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


@dataclass
class ATTCKTactic:
    """Parsed representation of a single ATT&CK tactic (a matrix column)."""

    tactic_id: str  # e.g., "TA0005"
    shortname: str  # kill-chain phase slug, e.g., "defense-evasion"
    name: str  # display name, e.g., "Defense Evasion"
    order: int = 0  # left-to-right column position in the official matrix


@dataclass
class ATTCKData:
    """Everything parsed from one ATT&CK bundle."""

    techniques: list[ATTCKTechnique]
    tactics: list[ATTCKTactic]
    version: str = ""


def load_attck_data(
    url: str = ATTCK_BUNDLE_URL,
    cache_file: Path = ATTCK_CACHE_FILE,
    force_refresh: bool = False,
    max_age_days: int | None = None,
) -> ATTCKData:
    """Load techniques + tactics + version from the ATT&CK bundle.

    Uses the local cache when it is fresh; auto-refreshes when it is older than
    ``max_age_days`` (defaults to MALJAN_ATTCK_MAX_AGE_DAYS / 30). On a failed
    refresh, falls back to the stale cache instead of raising.
    """
    raw = _load_raw_bundle(url, cache_file, force_refresh, max_age_days)
    techniques = _parse_bundle(raw)
    tactics = _parse_tactics(raw)
    version = _extract_version(raw)
    logger.info(
        "ATT&CK bundle loaded: version=%s, %d techniques, %d tactics.",
        version or "unknown",
        len(techniques),
        len(tactics),
    )
    return ATTCKData(techniques=techniques, tactics=tactics, version=version)


def load_attck_bundle(
    url: str = ATTCK_BUNDLE_URL,
    cache_file: Path = ATTCK_CACHE_FILE,
    force_refresh: bool = False,
    max_age_days: int | None = None,
) -> list[ATTCKTechnique]:
    """Back-compat wrapper returning only the technique list.

    Returns:
        List of parsed ATTCKTechnique objects.

    Raises:
        RuntimeError: If the bundle cannot be fetched and no cache exists.
    """
    return load_attck_data(url, cache_file, force_refresh, max_age_days).techniques


def _read_cache(cache_file: Path) -> dict:
    """Read + parse the cached bundle JSON (typed for strict mypy)."""
    cached: dict[str, Any] = json.loads(cache_file.read_text(encoding="utf-8"))
    return cached


def _load_raw_bundle(
    url: str,
    cache_file: Path,
    force_refresh: bool,
    max_age_days: int | None,
) -> dict:
    """Return the raw STIX bundle dict, honouring cache freshness + fallback."""
    max_age = _default_max_age_days() if max_age_days is None else max_age_days

    cache_fresh = False
    if cache_file.exists() and not force_refresh:
        if max_age <= 0:
            cache_fresh = True
        else:
            age_days = (time.time() - cache_file.stat().st_mtime) / 86400.0
            cache_fresh = age_days <= max_age
            if not cache_fresh:
                logger.info("ATT&CK cache is %.1f days old (> %d) — refreshing.", age_days, max_age)

    if cache_fresh:
        logger.info("Loading ATT&CK bundle from cache: %s", cache_file)
        return _read_cache(cache_file)

    logger.info("Fetching ATT&CK bundle from: %s", url)
    try:
        raw = _fetch_bundle(url)
    except RuntimeError as exc:
        # A failed (re)download must not break the run when a cache exists:
        # fall back to the stale copy and warn loudly.
        if cache_file.exists():
            logger.warning("ATT&CK refresh failed (%s); using stale cache: %s", exc, cache_file)
            return _read_cache(cache_file)
        raise
    _save_cache(raw, cache_file)
    return raw


def _fetch_bundle(url: str) -> dict:
    """Download the STIX bundle from the given URL (HTTP/HTTPS only)."""
    import urllib.request  # stdlib — no requests dependency needed for one-off download
    from urllib.parse import urlparse

    # Defense-in-depth for CWE-939: ``url`` is a module constant or an explicit
    # test argument (never user / request input). We additionally refuse any
    # non-HTTP(S) scheme so a stray value can never coerce urllib into reading
    # file:// / ftp:// resources.
    scheme = urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise RuntimeError(f"Refusing non-HTTP(S) ATT&CK bundle URL: {url!r}")

    try:
        # nosemgrep: dynamic-urllib-use-detected — scheme validated; trusted constant URL
        with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310
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


def _parse_tactics(bundle: dict) -> list[ATTCKTactic]:
    """Extract the tactic catalogue (matrix columns) from a STIX bundle.

    Column order is taken from the ``x-mitre-matrix`` object's ``tactic_refs``
    (the official left-to-right kill-chain order); tactics not referenced there
    sort last but stay present.
    """
    objects = bundle.get("objects", [])

    # Matrix column order: x-mitre-matrix.tactic_refs lists tactic STIX ids in
    # the official order. There can be more than one matrix object; first wins.
    order_by_stix: dict[str, int] = {}
    for obj in objects:
        if obj.get("type") != "x-mitre-matrix":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        for i, ref in enumerate(obj.get("tactic_refs", [])):
            order_by_stix.setdefault(ref, i)

    tactics: list[ATTCKTactic] = []
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        tactic_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tactic_id = ref.get("external_id", "")
                break
        if not TACTIC_ID_RE.match(tactic_id):
            continue

        tactics.append(
            ATTCKTactic(
                tactic_id=tactic_id,
                shortname=obj.get("x_mitre_shortname", ""),
                name=obj.get("name", ""),
                order=order_by_stix.get(obj.get("id", ""), 9999),
            )
        )

    tactics.sort(key=lambda t: (t.order, t.tactic_id))
    logger.info("Parsed %d ATT&CK tactics from bundle.", len(tactics))
    return tactics


def _extract_version(bundle: dict) -> str:
    """Best-effort ATT&CK version from the x-mitre-collection object."""
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            return str(obj.get("x_mitre_version", ""))
    return ""


def _main() -> None:
    """Force-refresh the cached bundle and print a summary.

    Run as: ``python -m maljan.memory.attck_loader``
    """
    data = load_attck_data(force_refresh=True)
    print(
        f"ATT&CK refreshed: version={data.version or 'unknown'}, "
        f"{len(data.techniques)} techniques, {len(data.tactics)} tactics"
    )
    for t in data.tactics:
        print(f"  {t.tactic_id}  {t.shortname:<24} {t.name}")


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    _main()
