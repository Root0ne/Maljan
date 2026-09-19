"""Reverse-indexed lookup for a binary's imports: behaviour category and ATT&CK.

Two projections of **one** fact — the set of API names a binary actually
imports. Resolving that set is expensive (``pefile`` over the whole binary, or
the ELF's dynamic symbol table); projecting it onto two taxonomies is nearly
free, so both live behind one loader and one cache and neither re-parses the
sample.

One platform at a time. The catalogue carries a block per platform and the two
vocabularies overlap by name — ``connect``, ``send``, ``recv``, ``system`` are
in both — so a caller names the platform its imports came from and gets that
block's reverse index and that platform's technique rules alone.

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
from collections.abc import Iterable
from dataclasses import dataclass, field
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

# Tiers the catalogue itself calls "suspicious". ``informational`` deliberately
# is not one: every Windows program reads files and opens keys. The tool that
# reads this (``tools.knowledge.api_capability``) reports the tier as a
# catalogue flag, named for where it comes from, not as a finding.
_SUSPICIOUS_TIERS = frozenset({"high", "medium"})
_VALID_TIERS = frozenset({"high", "medium", "informational"})

# Hard ceiling on any deterministic import-derived claim. The YARA layer's floor
# is 0.70; staying under it means this evidence corroborates other layers but
# can never solo-drive a verdict, which is the same rationale the import layer's
# original _CONF_BASE/_CONF_WITH_IOC constants were chosen under.
_CONFIDENCE_CEILING = 0.65


def _variants(name: str) -> tuple[str, ...]:
    """``name`` plus its ANSI/wide sibling.

    Win32 ships most string-taking APIs twice — ``GetSystemDirectoryA`` and
    ``GetSystemDirectoryW`` — and an import table contains whichever one the
    binary was compiled against. A curated table naturally ends up listing one
    of each pair, so half the real imports miss.

    Measured on a live sample: 13 of 136 uncategorised imports were nothing but
    the other spelling of a name already in the catalog —
    ``GetWindowsDirectoryW``, ``LookupAccountSidW``, ``RegGetValueW`` and so on.

    Resolved here rather than by writing both spellings into the JSON. Doubling
    the asset would double what a reviewer has to read and leave the next
    contributor one forgotten suffix away from the same bug.
    """
    lowered = name.lower()
    if lowered.endswith("w"):
        return (lowered, lowered[:-1] + "a")
    if lowered.endswith("a"):
        return (lowered, lowered[:-1] + "w")
    return (lowered,)


def canonical_name(name: str) -> str:
    """The A/W-folded key of an API name, for callers comparing spellings."""
    return _canonical(name)


def _canonical(name: str) -> str:
    """Fold an API name to one key shared by its ANSI and wide spellings.

    ``GetUserNameA`` and ``GetUserNameW`` are one capability, and counting them
    as two is how a single import talks its way past ``min_apis``.
    """
    lowered = name.lower()
    return lowered[:-1] if lowered.endswith(("a", "w")) else lowered


@dataclass(frozen=True)
class ApiBehaviourDB:
    """API name → (behaviour category, is_suspicious)."""

    by_name: dict[str, tuple[str, bool]]
    by_name_lower: dict[str, tuple[str, bool]]
    tiers: dict[str, str]
    # Per category, the APIs whose presence beside it would make the group
    # mean something. A category that is informational on its own — drawing a
    # window, pumping its message queue — is not evidence, and saying so
    # without saying what would be leaves the reader to guess.
    corroborators: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # Per category, the names whose presence beside it turns the catalogue's
    # ``suspicious`` label on. A category with no gate is labelled by its tier
    # alone, which is how the label has always worked and how every Windows
    # category still works.
    flag_gates: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def corroborated_by(self, category: str | None) -> tuple[str, ...]:
        """The APIs the catalogue names as corroboration for ``category``."""
        return self.corroborators.get(category or "", ())

    def flags_with(self, category: str | None) -> tuple[str, ...]:
        """The names a gated category needs beside it before it is labelled."""
        return self.flag_gates.get(category or "", ())

    def is_flagged(self, category: str | None, tiered: bool, present: Iterable[str]) -> bool:
        """Whether the catalogue labels a row, given the whole set it was asked about.

        A gated category is labelled only when one of its gate names is in the
        set. ``memfd_create`` on its own is ordinary in the graphics and
        service stacks; the same symbol beside a call that reaches into another
        process is not, and a label that cannot tell those apart is a label a
        reader learns to ignore.
        """
        if not tiered:
            return False
        gate = self.flag_gates.get(category or "")
        if not gate:
            return True
        wanted = {_canonical(name) for name in gate}
        return any(_canonical(name) in wanted for name in present)

    def classify(self, function: str) -> tuple[str | None, bool]:
        hit = self.by_name.get(function)
        if hit is None:
            for candidate in _variants(function):
                hit = self.by_name_lower.get(candidate)
                if hit is not None:
                    break
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
    # What distinguishes two rules that evidence the same technique from
    # different imports. ``name`` stays the catalogue's name for the id, so a
    # surface printing the two together never states a name ATT&CK does not
    # use; this is the label that says which of them matched.
    rule: str
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
        """Return ``[(rule, matched_imports)]`` for every rule clearing ``min_apis``.

        Counts the *imports the binary actually has*, in the spelling it has
        them, rather than the rule entries they touched. The distinction is not
        cosmetic: a rule listing both ``GetUserNameA`` and ``GetUserNameW`` is
        described by a single import under ANSI/wide normalisation, and counting
        rule entries let one ``GetUserNameA`` clear ``min_apis=2`` on its own —
        precisely the "coincidence, not capability" promotion the threshold
        exists to stop. Caught by the test that asserts a lone GetUserNameA
        maps to nothing.

        Reporting the imported spelling also keeps the evidence honest: the
        report cites what is in the binary, not what the catalog happens to
        call it.
        """
        # canonical (A/W-folded) name -> the spelling the binary actually uses.
        # Sorted, so which of an A/W pair is cited does not depend on the
        # process's string hash seed: the record must read the same twice.
        by_canonical: dict[str, str] = {}
        for name in sorted(imported):
            by_canonical.setdefault(_canonical(name), name)

        out: list[tuple[TechniqueRule, list[str]]] = []
        for rule in self.techniques:
            rule_canonicals = {_canonical(api) for api in rule.apis}
            matched = sorted(
                original
                for canonical, original in by_canonical.items()
                if canonical in rule_canonicals
            )
            if len(matched) >= rule.min_apis:
                out.append((rule, matched))
        return out

    def __len__(self) -> int:
        return len(self.techniques)


# ---------------------------------------------------------------------------
# Loading + cache
# ---------------------------------------------------------------------------

_CACHE_LOCK = threading.Lock()
_BEHAVIOUR_CACHE: dict[tuple[str, str], ApiBehaviourDB | None] = {}
_ATTCK_CACHE: dict[tuple[str, str], ApiAttckMap | None] = {}

# The platform whose vocabulary is loaded when a caller names none. Windows was
# the only block the catalogue had, and every caller that predates the Linux
# one means Windows.
DEFAULT_PLATFORM = "windows"


def load_api_behaviour_db(
    catalog_path: str, platform: str = DEFAULT_PLATFORM
) -> ApiBehaviourDB | None:
    """Load (and cache) one platform's behaviour map, or ``None``.

    ``None`` — never an exception — when the file is absent or malformed or
    carries no block for the platform, so callers treat "no catalog" as the
    normal degraded state. Each platform is its own vocabulary and its own
    reverse index: ``connect`` and ``send`` are in both, and folding the two
    together would give a PE's imports a libc category.
    """
    key = (str(catalog_path), str(platform).strip().lower() or DEFAULT_PLATFORM)
    with _CACHE_LOCK:
        if key in _BEHAVIOUR_CACHE:
            return _BEHAVIOUR_CACHE[key]
    result = _load_behaviour_uncached(*key)
    with _CACHE_LOCK:
        _BEHAVIOUR_CACHE[key] = result
    return result


def load_api_attck_map(catalog_path: str, platform: str = DEFAULT_PLATFORM) -> ApiAttckMap | None:
    """Load (and cache) the API→ATT&CK rules that apply to one platform."""
    key = (str(catalog_path), str(platform).strip().lower() or DEFAULT_PLATFORM)
    with _CACHE_LOCK:
        if key in _ATTCK_CACHE:
            return _ATTCK_CACHE[key]
    result = _load_attck_uncached(*key)
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


def _load_behaviour_uncached(catalog_path: str, platform: str) -> ApiBehaviourDB | None:
    doc = _read_json(catalog_path, "api-behaviour")
    if doc is None:
        return None

    platforms = doc.get("platforms")
    if not isinstance(platforms, dict):
        logger.warning(
            "api-behaviour: '%s' has no 'platforms' — using the built-in table.", catalog_path
        )
        return None
    block = platforms.get(platform)
    if not isinstance(block, dict):
        logger.info(
            "api-behaviour: '%s' has no %s platform — no behaviour categories for it.",
            catalog_path,
            platform,
        )
        return None

    by_name: dict[str, tuple[str, bool]] = {}
    by_name_lower: dict[str, tuple[str, bool]] = {}
    tiers: dict[str, str] = {}
    corroborators: dict[str, tuple[str, ...]] = {}
    flag_gates: dict[str, tuple[str, ...]] = {}

    for category, spec in block.items():
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
        named = spec.get("corroborated_by")
        if isinstance(named, list):
            corroborators[category] = tuple(a for a in named if isinstance(a, str) and a)
        gate = spec.get("flags_with")
        if isinstance(gate, list):
            flag_gates[category] = tuple(a for a in gate if isinstance(a, str) and a)
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
            "api-behaviour: '%s' produced no %s entries — using the built-in table.",
            catalog_path,
            platform,
        )
        return None

    logger.info(
        "api-behaviour: loaded %d %s APIs across %d categories from '%s'.",
        len(by_name),
        platform,
        len(tiers),
        catalog_path,
    )
    return ApiBehaviourDB(
        by_name=by_name,
        by_name_lower=by_name_lower,
        tiers=tiers,
        corroborators=corroborators,
        flag_gates=flag_gates,
    )


def _load_attck_uncached(catalog_path: str, platform: str) -> ApiAttckMap | None:
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
        # A rule is matched only against the platform it is written for. The
        # two vocabularies share names — ``connect``, ``send``, ``recv`` — so a
        # PE's imports would otherwise clear a libc rule and an ELF's a Win32
        # one, each citing a technique nothing on that sample evidences.
        if rule is None or platform not in {p.lower() for p in rule.platforms}:
            continue
        rules.append(rule)
        relevant |= set(rule.apis_lower)

    if not rules:
        logger.warning(
            "api-attck: '%s' has no usable %s rules — no technique rows for it.",
            catalog_path,
            platform,
        )
        return None

    logger.info(
        "api-attck: loaded %d %s technique rules from '%s'.", len(rules), platform, catalog_path
    )
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
        rule=str(row.get("rule") or ""),
        apis=frozenset(apis),
        apis_lower=frozenset(a.lower() for a in apis),
        min_apis=min_apis,
        confidence_base=conf_base,
        confidence_max=conf_max,
        platforms=platforms,
    )
