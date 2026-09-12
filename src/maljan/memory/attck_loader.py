"""MITRE ATT&CK STIX 2.1 bundle downloader and parser.

Downloads the Enterprise, Mobile and ICS ATT&CK datasets from the official MITRE
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
# ``<domain>-attack.json`` always points at the latest release.
_BUNDLE_BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"

# The three ATT&CK domains, in the order a technique id is looked up in them.
# Enterprise is the one this project cannot run without; Mobile and ICS are
# loaded when their bundle is reachable or already cached, and their absence
# costs coverage rather than breaking a run.
DOMAINS: tuple[str, ...] = ("enterprise", "mobile", "ics")

ATTCK_BUNDLE_URLS: dict[str, str] = {
    domain: f"{_BUNDLE_BASE_URL}/{domain}-attack/{domain}-attack.json" for domain in DOMAINS
}
ATTCK_BUNDLE_URL = ATTCK_BUNDLE_URLS["enterprise"]

# Local cache directory — respects MALJAN_ATTCK_CACHE env var
_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "maljan" / "attck"
ATTCK_CACHE_DIR = Path(os.environ.get("MALJAN_ATTCK_CACHE", str(_DEFAULT_CACHE_DIR)))
ATTCK_CACHE_FILES: dict[str, Path] = {
    domain: ATTCK_CACHE_DIR / f"{domain}-attack.json" for domain in DOMAINS
}
ATTCK_CACHE_FILE = ATTCK_CACHE_FILES["enterprise"]

# The vendored technique universe, shipped so validation works with no network.
# New shape: one sorted id list per domain. The former flat list (and the
# ``{"count", "technique_ids"}`` wrapper it grew) is still read, as enterprise.
VALID_IDS_FILE = Path(__file__).resolve().parents[3] / "data" / "attck_valid_ids.json"

# Our platform vocabulary translated into MITRE's ``x_mitre_platforms`` strings.
# An empty tuple means "do not filter on platform": a cross-platform or
# undetermined sample must not lose techniques to a comparison it cannot make.
MITRE_PLATFORM_MAP: dict[str, tuple[str, ...]] = {
    "windows": ("Windows",),
    "linux": ("Linux",),
    "macos": ("macOS",),
    "android": ("Android",),
    "ios": ("iOS",),
    "multi": (),
    "unknown": (),
}


def mitre_platforms(sample_platform: str | None) -> tuple[str, ...]:
    """The MITRE platform strings a sample platform maps to, empty when it does not."""
    return MITRE_PLATFORM_MAP.get((sample_platform or "").strip().lower(), ())


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


def load_domain_data(
    domain: str,
    force_refresh: bool = False,
    max_age_days: int | None = None,
) -> ATTCKData | None:
    """One domain's bundle, or ``None`` when it is neither cached nor reachable.

    Enterprise is the domain every run needs, and its loader raises when there
    is nothing to read. Mobile and ICS are additive: a box with no network and
    no cache for them keeps working with a narrower catalog rather than losing
    the enterprise techniques it does have.
    """
    url = ATTCK_BUNDLE_URLS.get(domain)
    cache_file = ATTCK_CACHE_FILES.get(domain)
    if url is None or cache_file is None:
        raise ValueError(f"Unknown ATT&CK domain {domain!r}; known: {', '.join(DOMAINS)}")
    try:
        return load_attck_data(url, cache_file, force_refresh, max_age_days)
    except Exception as exc:  # noqa: BLE001 — a missing optional domain is not a run failure
        if domain == "enterprise":
            raise
        logger.info("ATT&CK %s bundle unavailable (%s); continuing without it.", domain, exc)
        return None


def load_all_domains(
    force_refresh: bool = False,
    max_age_days: int | None = None,
) -> dict[str, ATTCKData]:
    """Every domain bundle that is cached or reachable, keyed by domain name."""
    loaded: dict[str, ATTCKData] = {}
    for domain in DOMAINS:
        data = load_domain_data(domain, force_refresh, max_age_days)
        if data is not None:
            loaded[domain] = data
    return loaded


def _read_valid_ids_file(path: Path) -> dict[str, list[str]]:
    """The vendored technique universe per domain, in either shape it has had.

    Accepted, oldest first: a flat list of enterprise ids; a
    ``{"count", "technique_ids"}`` wrapper around one; and the current
    ``{"enterprise": [...], "mobile": [...], "ics": [...]}``. An empty or
    missing list is a domain this checkout does not ship, not an error.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("Could not read the ATT&CK id catalog at %s: %s", path, exc)
        return {domain: [] for domain in DOMAINS}

    if isinstance(raw, list):
        return {"enterprise": [str(i) for i in raw], "mobile": [], "ics": []}
    if isinstance(raw, dict) and "technique_ids" in raw:
        return {
            "enterprise": [str(i) for i in raw.get("technique_ids") or []],
            "mobile": [],
            "ics": [],
        }
    if isinstance(raw, dict):
        return {domain: [str(i) for i in (raw.get(domain) or [])] for domain in DOMAINS}
    logger.warning("The ATT&CK id catalog at %s is in no shape this loader reads.", path)
    return {domain: [] for domain in DOMAINS}


_valid_ids_cache: dict[str, list[str]] | None = None


def _valid_ids_by_domain() -> dict[str, list[str]]:
    global _valid_ids_cache
    if _valid_ids_cache is None:
        _valid_ids_cache = _read_valid_ids_file(VALID_IDS_FILE)
    return _valid_ids_cache


def valid_ids(domain: str | None = None) -> set[str]:
    """Every active technique id, or one domain's when ``domain`` is given."""
    by_domain = _valid_ids_by_domain()
    if domain is not None:
        return set(by_domain.get(domain, ()))
    return {tid for ids in by_domain.values() for tid in ids}


def domain_of(technique_id: str) -> str | None:
    """Which ATT&CK domain owns ``technique_id``, or ``None`` when none does.

    A handful of ids appear in more than one domain; the first domain in
    ``DOMAINS`` that carries the id wins, which makes the answer stable rather
    than dependent on dict ordering.
    """
    tid = (technique_id or "").strip().upper()
    if not tid:
        return None
    by_domain = _valid_ids_by_domain()
    for domain in DOMAINS:
        if tid in set(by_domain.get(domain, ())):
            return domain
    return None


_platform_cache: dict[str, tuple[str, ...]] | None = None


def _platform_catalog() -> dict[str, tuple[str, ...]]:
    """``{technique_id: (MITRE platforms,)}`` across every loadable domain.

    Built once, cached whatever the outcome. An unreachable catalog yields an
    empty map, and every caller reads that as "no platform information", never
    as "no platforms".
    """
    global _platform_cache
    if _platform_cache is not None:
        return _platform_cache
    catalog: dict[str, tuple[str, ...]] = {}
    try:
        for data in load_all_domains().values():
            for technique in data.techniques:
                catalog.setdefault(technique.technique_id, tuple(technique.platforms or ()))
    except Exception as exc:  # noqa: BLE001 — platform filtering degrades, the run does not
        # The empty result is cached too. A box that cannot reach MITRE would
        # otherwise re-attempt the download on every technique the cascade
        # checks, which is thousands of failed fetches in one job.
        # ``reset_caches`` is the way back once the network returns.
        logger.debug("Could not load the ATT&CK platform catalog: %s", exc)
    _platform_cache = catalog
    return catalog


def platforms_for(technique_id: str) -> tuple[str, ...]:
    """The MITRE platforms a technique declares; empty when it is not catalogued."""
    return _platform_catalog().get((technique_id or "").strip().upper(), ())


def reset_caches() -> None:
    """Drop the vendored-id and platform caches. For tests and the refresh CLI."""
    global _valid_ids_cache, _platform_cache
    _valid_ids_cache = None
    _platform_cache = None


def _main() -> None:
    """Force-refresh the cached bundle and print a summary.

    Run as: ``python -m maljan.memory.attck_loader``
    """
    loaded = load_all_domains(force_refresh=True)
    for domain, data in loaded.items():
        print(
            f"ATT&CK {domain} refreshed: version={data.version or 'unknown'}, "
            f"{len(data.techniques)} techniques, {len(data.tactics)} tactics"
        )
    missing = [d for d in DOMAINS if d not in loaded]
    if missing:
        print(f"Not reachable and not cached: {', '.join(missing)}")
    for t in loaded["enterprise"].tactics:
        print(f"  {t.tactic_id}  {t.shortname:<24} {t.name}")


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    _main()
