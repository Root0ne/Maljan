"""Reverse-indexed lookup for Windows imports: behaviour category and ATT&CK.

Two projections of **one** fact — the set of API names a PE actually imports.
Resolving that set is expensive (``pefile`` over the whole binary); projecting
it onto two taxonomies is nearly free, so both live behind one loader and one
cache and neither re-parses the sample.

The reverse index matters more than it looks. The obvious implementation — for
each import, walk every category's list — is O(imports x categories x names),
which at ~700 names and a few hundred imports is a measurable cost repeated at
every call site. Inverting the table once at load turns each lookup into a dict
hit. A lowercased index is kept alongside because import tables are not
case-consistent: forwarded exports and ordinal-resolved names routinely differ
in case from the canonical MSDN spelling.

Degradation is the point of the fallback path: a missing or malformed data file
logs and returns ``None``, and ``pe_extractor`` then falls back to its hardcoded
51-entry table. An analysis that loses depth is acceptable; an analysis that
fails because a JSON file moved is not.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from maljan.core.logger import logger

__all__ = [
    "ApiAttckMap",
    "ApiBehaviourDB",
    "TechniqueRule",
    "load_api_attck_map",
    "load_api_behaviour_db",
    "reset_cache",
]

# Tiers that make an import "suspicious". ``informational`` deliberately does
# not: see ``pe_extractor.classify_import`` for why the two facts are separate.
_SUSPICIOUS_TIERS = frozenset({"high", "medium"})
_VALID_TIERS = frozenset({"high", "medium", "informational"})

# Hard ceiling on any deterministic import-derived claim. The YARA layer's floor
# is 0.70; staying under it means this evidence corroborates other layers but
# can never solo-drive a verdict, which is the same rationale the import layer's
# original _CONF_BASE/_CONF_WITH_IOC constants were chosen under.
_CONFIDENCE_CEILING = 0.65


@dataclass(frozen=True)
class ApiBehaviourDB:
    """API name → (behaviour category, is_suspicious)."""

    by_name: dict[str, tuple[str, bool]]
    by_name_lower: dict[str, tuple[str, bool]]
    tiers: dict[str, str]

    def classify(self, function: str) -> tuple[str | None, bool]:
        hit = self.by_name.get(function)
        if hit is None:
            hit = self.by_name_lower.get(function.lower())
        if hit is None:
            return None, False
        return hit

    def __len__(self) -> int:
        return len(self.by_name)


@dataclass(frozen=True)
class TechniqueRule:
    """One ATT&CK technique and the imports that evidence it."""

    technique_id: str
    name: str
    apis: frozenset[str]
    apis_lower: frozenset[str]
    min_apis: int
    confidence_base: float
    confidence_max: float
    platforms: tuple[str, ...]

    def confidence_for(self, distinct_matches: int) -> float:
        """Scale confidence with corroboration, bounded at both ends.

        Each import beyond the minimum is worth a little more certainty, but the
        curve is deliberately shallow and capped: a technique evidenced by
        twelve imports is more likely than one evidenced by two, not six times
        more likely. Counting matches as a raw score — the obvious approach —
        produces exactly that six-times-more-likely claim.
        """
        extra = max(0, distinct_matches - self.min_apis)
        return round(min(self.confidence_max, self.confidence_base + 0.05 * extra), 4)


@dataclass(frozen=True)
class ApiAttckMap:
    """The technique table, plus the union of every API it references."""

    techniques: tuple[TechniqueRule, ...]
    relevant_apis_lower: frozenset[str]

    def match(self, imported: set[str]) -> list[tuple[TechniqueRule, list[str]]]:
        """Return ``[(rule, matched_apis)]`` for every rule that clears ``min_apis``.

        ``imported`` is matched case-insensitively; the returned names are the
        canonical spellings from the table so evidence strings stay consistent
        regardless of how the import table spelled them.
        """
        lowered = {name.lower() for name in imported}
        out: list[tuple[TechniqueRule, list[str]]] = []
        for rule in self.techniques:
            matched = sorted(api for api in rule.apis if api.lower() in lowered)
            if len(matched) >= rule.min_apis:
                out.append((rule, matched))
        return out

    def __len__(self) -> int:
        return len(self.techniques)


# ---------------------------------------------------------------------------
# Loading + cache
# ---------------------------------------------------------------------------

_CACHE_LOCK = threading.Lock()
_BEHAVIOUR_CACHE: dict[str, ApiBehaviourDB | None] = {}
_ATTCK_CACHE: dict[str, ApiAttckMap | None] = {}


def load_api_behaviour_db(catalog_path: str) -> ApiBehaviourDB | None:
    """Load (and cache) the behaviour map, or ``None``.

    ``None`` — never an exception — when the file is absent or malformed, so
    callers treat "no catalog" as the normal degraded state.
    """
    key = str(catalog_path)
    with _CACHE_LOCK:
        if key in _BEHAVIOUR_CACHE:
            return _BEHAVIOUR_CACHE[key]
    result = _load_behaviour_uncached(key)
    with _CACHE_LOCK:
        _BEHAVIOUR_CACHE[key] = result
    return result


def load_api_attck_map(catalog_path: str) -> ApiAttckMap | None:
    """Load (and cache) the API→ATT&CK map, or ``None``."""
    key = str(catalog_path)
    with _CACHE_LOCK:
        if key in _ATTCK_CACHE:
            return _ATTCK_CACHE[key]
    result = _load_attck_uncached(key)
    with _CACHE_LOCK:
        _ATTCK_CACHE[key] = result
    return result


def reset_cache() -> None:
    """Clear both caches (test hook; not used at runtime)."""
    with _CACHE_LOCK:
        _BEHAVIOUR_CACHE.clear()
        _ATTCK_CACHE.clear()


def _read_json(catalog_path: str, what: str) -> dict[str, Any] | None:
    if not catalog_path or not Path(catalog_path).is_file():
        logger.info("%s: catalog not found at '%s' — using the built-in table.", what, catalog_path)
        return None
    try:
        doc = json.loads(Path(catalog_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning(
            "%s: failed to read '%s' (%s) — using the built-in table.", what, catalog_path, exc
        )
        return None
    if not isinstance(doc, dict):
        logger.warning("%s: '%s' is not an object — using the built-in table.", what, catalog_path)
        return None
    return doc


def _load_behaviour_uncached(catalog_path: str) -> ApiBehaviourDB | None:
    doc = _read_json(catalog_path, "api-behaviour")
    if doc is None:
        return None

    platforms = doc.get("platforms")
    if not isinstance(platforms, dict):
        logger.warning(
            "api-behaviour: '%s' has no 'platforms' — using the built-in table.", catalog_path
        )
        return None
    windows = platforms.get("windows")
    if not isinstance(windows, dict):
        logger.warning(
            "api-behaviour: '%s' has no windows platform — using the built-in table.", catalog_path
        )
        return None

    by_name: dict[str, tuple[str, bool]] = {}
    by_name_lower: dict[str, tuple[str, bool]] = {}
    tiers: dict[str, str] = {}

    for category, spec in windows.items():
        if not isinstance(category, str) or not isinstance(spec, dict):
            continue
        tier = spec.get("tier")
        if tier not in _VALID_TIERS:
            logger.warning(
                "api-behaviour: category '%s' has bad tier %r — skipped.", category, tier
            )
            continue
        apis = spec.get("apis")
        if not isinstance(apis, list):
            continue
        tiers[category] = tier
        suspicious = tier in _SUSPICIOUS_TIERS
        for api in apis:
            if not isinstance(api, str) or not api:
                continue
            # First category wins, mirroring the build order — an API listed
            # twice is a data bug, not a reason to flip-flop between runs.
            by_name.setdefault(api, (category, suspicious))
            by_name_lower.setdefault(api.lower(), (category, suspicious))

    if not by_name:
        logger.warning(
            "api-behaviour: '%s' produced no entries — using the built-in table.", catalog_path
        )
        return None

    logger.info(
        "api-behaviour: loaded %d APIs across %d categories from '%s'.",
        len(by_name),
        len(tiers),
        catalog_path,
    )
    return ApiBehaviourDB(by_name=by_name, by_name_lower=by_name_lower, tiers=tiers)


def _load_attck_uncached(catalog_path: str) -> ApiAttckMap | None:
    doc = _read_json(catalog_path, "api-attck")
    if doc is None:
        return None

    rows = doc.get("techniques")
    if not isinstance(rows, list) or not rows:
        logger.warning("api-attck: '%s' has no 'techniques' — layer disabled.", catalog_path)
        return None

    rules: list[TechniqueRule] = []
    relevant: set[str] = set()
    for row in rows:
        rule = _parse_rule(row)
        if rule is None:
            continue
        rules.append(rule)
        relevant |= set(rule.apis_lower)

    if not rules:
        logger.warning("api-attck: '%s' produced no usable rules — layer disabled.", catalog_path)
        return None

    logger.info("api-attck: loaded %d technique rules from '%s'.", len(rules), catalog_path)
    return ApiAttckMap(techniques=tuple(rules), relevant_apis_lower=frozenset(relevant))


def _parse_rule(row: Any) -> TechniqueRule | None:
    """Narrow one untyped JSON row into a rule, or drop it with a warning."""
    if not isinstance(row, dict):
        return None
    tid = row.get("technique_id")
    apis_raw = row.get("apis")
    if not isinstance(tid, str) or not tid or not isinstance(apis_raw, list):
        return None
    apis = {a for a in apis_raw if isinstance(a, str) and a}
    if not apis:
        return None

    try:
        min_apis = max(1, int(row.get("min_apis", 2)))
        conf_base = float(row.get("confidence_base", 0.40))
        conf_max = float(row.get("confidence_max", 0.60))
    except (TypeError, ValueError):
        logger.warning("api-attck: %s has non-numeric thresholds — skipped.", tid)
        return None

    # The ceiling is enforced here as well as in the builder, because the data
    # file is editable in place and a hand-edited 0.95 would otherwise let an
    # import-table guess outrank a real YARA match.
    conf_max = min(conf_max, _CONFIDENCE_CEILING)
    conf_base = min(conf_base, conf_max)

    platforms_raw = row.get("platforms")
    platforms = tuple(
        p for p in (platforms_raw if isinstance(platforms_raw, list) else []) if isinstance(p, str)
    ) or ("windows",)

    return TechniqueRule(
        technique_id=tid,
        name=str(row.get("name") or tid),
        apis=frozenset(apis),
        apis_lower=frozenset(a.lower() for a in apis),
        min_apis=min_apis,
        confidence_base=conf_base,
        confidence_max=conf_max,
        platforms=platforms,
    )
