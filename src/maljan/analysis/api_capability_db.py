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
logs and returns ``None``, and ``tools.knowledge.api_capability`` — the one
consumer, since the sidecar migration moved the import layer behind it — answers
with empty rows and a ``reason`` naming the file. An analysis that loses depth
is acceptable; an analysis that fails because a JSON file moved is not. A single
malformed row degrades the same way and no further: it is dropped with a warning
and the rest of the catalogue loads.
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
    "MeasuredRate",
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


@dataclass(frozen=True)
class MeasuredRate:
    """How much benign software an association fires on, and what that is a share of.

    The catalogue's associations are not judged, they are measured, and the
    measurement travels with the association rather than staying in whatever
    document recorded it: an import-derived row that says "T1113, screen
    capture" and nothing else invites a reader to treat it as a finding, and the
    same row saying the rule fires on 0.3% of ordinary Windows software does
    not. The model is told the rate and decides; the platform states a fact and
    stops there.

    Every field names its own direction, because the value travels and is read
    apart from this class. ``seen_on_benign_percent`` is the share of the named
    benign corpus the association fired on — never a probability that some
    sample is benign, which is the misreading the name exists to prevent.
    ``seen_on_benign_files`` is carried beside it because a share rounded to one
    decimal place reads as zero for a rule that fires on one file in three
    thousand, and an association that was never measured is ``None`` rather than
    a zero, which is a different statement.

    ``held_out_malware_profiles`` is how many distinct import profiles the
    combination was *not* chosen on that it fires on. It is support, not
    accuracy: no corpus here carries technique-level ground truth, so what was
    measured is that a combination separates binaries already known to be bad
    from binaries already known to be good.
    """

    seen_on_benign_percent: float
    seen_on_benign_files: int
    benign_corpus: str = ""
    labels_benign_percent: float | None = None
    labels_benign_files: int | None = None
    held_out_malware_profiles: int | None = None
    held_out_malware_corpus: str = ""

    def rates(self) -> dict[str, Any]:
        """The numbers alone, for a row that repeats under every matched name."""
        out: dict[str, Any] = {
            "seen_on_benign_percent": self.seen_on_benign_percent,
            "seen_on_benign_files": self.seen_on_benign_files,
        }
        if self.labels_benign_percent is not None:
            out["labels_benign_percent"] = self.labels_benign_percent
            out["labels_benign_files"] = self.labels_benign_files
        if self.held_out_malware_profiles is not None:
            out["held_out_malware_profiles"] = self.held_out_malware_profiles
        return out

    def corpora(self) -> dict[str, str]:
        """What the numbers are shares of, said once per answer rather than per row."""
        out: dict[str, str] = {}
        if self.benign_corpus:
            out["benign"] = self.benign_corpus
        if self.held_out_malware_corpus:
            out["held_out_malware"] = self.held_out_malware_corpus
        return out


def _measured(raw: Any) -> MeasuredRate | None:
    """One ``measured`` block, or ``None`` when it is absent or unreadable.

    Unreadable is treated as absent on purpose: an association whose rate
    cannot be parsed has not been measured as far as any reader is concerned,
    and printing a partial number would be worse than printing none.
    """
    if not isinstance(raw, dict):
        return None
    percent, files = raw.get("seen_on_benign_percent"), raw.get("seen_on_benign_files")
    if not isinstance(percent, int | float) or not isinstance(files, int):
        return None
    labels_benign_percent = raw.get("labels_benign_percent")
    labels_benign_files = raw.get("labels_benign_files")
    held = raw.get("held_out_malware_profiles")
    return MeasuredRate(
        seen_on_benign_percent=float(percent),
        seen_on_benign_files=int(files),
        benign_corpus=str(raw.get("benign_corpus") or ""),
        labels_benign_percent=(
            float(labels_benign_percent) if isinstance(labels_benign_percent, int | float) else None
        ),
        labels_benign_files=(
            int(labels_benign_files) if isinstance(labels_benign_files, int) else None
        ),
        held_out_malware_profiles=(int(held) if isinstance(held, int) else None),
        held_out_malware_corpus=str(raw.get("held_out_malware_corpus") or ""),
    )


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
    # alone; every category the catalogue still tiers above informational has
    # one, on both platforms.
    flag_gates: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # Per category, how much benign software it appears on. A category with no
    # entry here has not been measured, which is not the same as zero.
    measurements: dict[str, MeasuredRate] = field(default_factory=dict)

    def corroborated_by(self, category: str | None) -> tuple[str, ...]:
        """The APIs the catalogue names as corroboration for ``category``."""
        return self.corroborators.get(category or "", ())

    def flags_with(self, category: str | None) -> tuple[str, ...]:
        """The names a gated category needs beside it before it is labelled."""
        return self.flag_gates.get(category or "", ())

    def measured_for(self, category: str | None) -> MeasuredRate | None:
        """What ``category`` was measured at on benign software, or ``None``."""
        return self.measurements.get(category or "")

    def _gate_is_met(self, category: str | None, present: Iterable[str]) -> bool:
        """Whether a gated category's second name is in the set asked about.

        ``memfd_create`` on its own is ordinary in the graphics and service
        stacks; the same symbol beside a call that reaches into another process
        is not, and a label that cannot tell those apart is a label a reader
        learns to ignore.
        """
        gate = self.flag_gates.get(category or "")
        if not gate:
            return True
        wanted = {_canonical(name) for name in gate}
        return any(_canonical(name) in wanted for name in present)

    def classify(self, function: str, present: Iterable[str] = ()) -> tuple[str | None, bool]:
        """``(category, whether the catalogue labels it)`` for one API name.

        The label is decided here rather than by the caller, so a reader that
        asks about one name cannot label a gated category the catalogue would
        not have labelled. ``present`` is the whole set the name was seen in;
        with none given a gated category answers ``False``, because the second
        name that would open the gate is not there to be seen.
        """
        hit = self.by_name.get(function)
        if hit is None:
            for candidate in _variants(function):
                hit = self.by_name_lower.get(candidate)
                if hit is not None:
                    break
        if hit is None:
            return None, False
        category, tiered = hit
        return category, tiered and self._gate_is_met(category, present)

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
    # What software that is not a sample imports the same set for. A rule
    # states a mechanism and a mechanism has ordinary users; the row carries
    # the sentence so it cannot be read as an accusation on its own.
    ordinary_use: str
    # How much benign software this combination fires on, measured. ``None``
    # where it has not been measured, which the surfaces say rather than
    # printing a zero.
    measured: MeasuredRate | None
    apis: frozenset[str]
    apis_lower: frozenset[str]
    min_apis: int
    confidence_base: float
    confidence_max: float
    platforms: tuple[str, ...]


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
    measurements: dict[str, MeasuredRate] = {}

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
        rate = _measured(spec.get("measured"))
        if rate is not None:
            measurements[category] = rate
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
        measurements=measurements,
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
        conf_base = float(row.get("confidence_base", 0.40))
        conf_max = float(row.get("confidence_max", 0.60))
    except (TypeError, ValueError):
        logger.warning("api-attck: %s has non-numeric thresholds — skipped.", tid)
        return None

    # ``min_apis`` is what stands between "this binary imports one name the
    # catalogue knows" and "this binary performs the technique", so it is read
    # strictly rather than coerced. It used to be ``max(1, int(...))``, which
    # turned a hand-edited ``0``, a negative, ``true`` or ``1.4`` into 1 — and
    # 1 on a sixteen-name rule makes it fire on any one of them.
    # JSON has one number type, so a catalogue round-tripped through a
    # serialiser that emits ``2.0`` must not lose the rule. A float that is a
    # whole number is that number; a fractional one, a bool, a string or
    # anything below one is not a count of names and the rule is dropped.
    floor = row.get("min_apis", 2)
    if isinstance(floor, float) and floor.is_integer():
        floor = int(floor)
    if isinstance(floor, bool) or not isinstance(floor, int) or floor < 1:
        logger.warning("api-attck: %s has a min_apis of %r — skipped.", tid, floor)
        return None
    # A floor of one is allowed only where the single name *is* the act, which
    # a rule states by naming nothing else. Anything wider asking for one name
    # is the data file having drifted from what the tool documents.
    if floor == 1 and len(apis) > 1:
        logger.warning("api-attck: %s asks for one of %d names — skipped.", tid, len(apis))
        return None
    min_apis = floor

    # The authored numbers are kept as written. They used to be clamped under
    # a 0.65 ceiling here, which silently lowered a hand-edited value; nothing
    # reads them as a claim's confidence (a rule hit is reported by name and
    # the imports it matched), and the data file's builder states its own
    # bound where the numbers are written.

    platforms_raw = row.get("platforms")
    platforms = tuple(
        p for p in (platforms_raw if isinstance(platforms_raw, list) else []) if isinstance(p, str)
    ) or ("windows",)

    return TechniqueRule(
        technique_id=tid,
        name=str(row.get("name") or tid),
        rule=str(row.get("rule") or ""),
        ordinary_use=str(row.get("ordinary_use") or ""),
        measured=_measured(row.get("measured")),
        apis=frozenset(apis),
        apis_lower=frozenset(a.lower() for a in apis),
        min_apis=min_apis,
        confidence_base=conf_base,
        confidence_max=conf_max,
        platforms=platforms,
    )
