"""Function-hash attribution: aggregate and render code-reuse links.

Companion to :mod:`maljan.memory.function_hash_store`. The deterministic,
side-effect-free pieces: given the per-function matches the store returns
for a sample's hashes, :func:`aggregate_matches` groups them by family and
:func:`build_attribution_hint` / :func:`to_report_dicts` render the prompt hint
and the report rows. The hashes themselves are the static provider's
(``StaticProvider.function_hashes``): a provider that can hash a program's
functions declares ``provides_function_hashes`` and answers them its own way.

The same two sides of the system use these:

- The static analyst (query side) asks its provider for the sample's hashes,
  asks the store which known samples share them, aggregates, and injects the
  hint.
- The judge node (write side) asks for the sample's hashes and upserts them
  under the final family so the corpus grows.

Tiny functions (a handful of instructions: thunks, stubs, ``ret`` wrappers)
normalize to the same opcode hash across completely unrelated binaries, so a
provider leaves out anything below ``preprocessing.function_hash_min_instructions``
— matching those would manufacture false family links.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from maljan.memory.long_term_memory import family_key

# How many example function names to show per family in the hint.
_EXAMPLES_PER_FAMILY = 3


@dataclass
class FamilyHashAttribution:
    """An aggregated family link derived from shared function hashes."""

    family: str
    shared_functions: int = 0
    sample_ids: list[str] = field(default_factory=list)
    example_functions: list[str] = field(default_factory=list)
    # The shared functions for which this family filed more than half of the
    # distinct prior samples that filed the hash. A hash as many samples file
    # under other families (a library routine, a shared packer stub) says
    # nothing about this one; a stray sample filed under a wrong name does not
    # outweigh the family's own samples of that hash.
    distinctive_functions: int = 0

    @property
    def confidence(self) -> float:
        """A monotone, capped confidence from the count of distinctive shared functions.

        One distinctive shared function is a weak prior; the signal saturates
        as the count grows. A family that holds no shared function's majority
        stays at the floor. Capped below 1.0 because
        exact-match is strong evidence but still a *prior* that the
        analyst/judge must corroborate behaviorally.
        """
        return round(min(0.5 + 0.1 * self.distinctive_functions, 0.95), 2)


def aggregate_matches(
    matches: Iterable[Any],
    max_families: int = 8,
) -> list[FamilyHashAttribution]:
    """Group raw ``FunctionMatch`` rows by family.

    Each match exposes ``.family``, ``.sample_id``, ``.func_hash`` and
    ``.func_name`` (see :class:`maljan.memory.function_hash_store.FunctionMatch`).
    Families are grouped by one spelling (``family_key``) and shown by the
    spelling their prior samples used most. Counts DISTINCT shared function
    hashes per family (so the same hash stored by several past samples is not
    double-counted), the ones among them for which this family filed more
    than half of the distinct prior samples that filed the hash
    (``distinctive_functions``), tracks the distinct prior samples, and ranks
    families by distinctive, then shared, function count.
    """
    by_family: dict[str, dict[str, Any]] = {}
    # Per hash, the distinct prior samples each family filed it for.
    filed_by: dict[str, dict[str, set[str]]] = {}
    for m in matches:
        written = getattr(m, "family", None) or "UNKNOWN"
        key = getattr(m, "family_key", "") or family_key(written) or "unknown"
        fh = getattr(m, "func_hash", "") or ""
        sid = getattr(m, "sample_id", "") or ""
        name = getattr(m, "func_name", "") or ""
        if not fh:
            continue
        samples = filed_by.setdefault(fh, {}).setdefault(key, set())
        # A match with no sample id is one sample of its own.
        samples.add(sid or f"#{len(samples)}")
        rec = by_family.setdefault(
            key, {"hashes": set(), "samples": set(), "names": {}, "spellings": {}}
        )
        rec["hashes"].add(fh)
        if sid:
            rec["samples"].add(sid)
            rec["spellings"].setdefault(sid, written)
        else:
            rec["spellings"].setdefault(f"#{len(rec['spellings'])}", written)
        # Keep one representative name per hash for the examples list.
        if name and fh not in rec["names"]:
            rec["names"][fh] = name

    results = [
        FamilyHashAttribution(
            family=_spelling(rec["spellings"].values()),
            shared_functions=len(rec["hashes"]),
            sample_ids=sorted(rec["samples"]),
            example_functions=sorted(rec["names"].values())[:_EXAMPLES_PER_FAMILY],
            distinctive_functions=sum(1 for fh in rec["hashes"] if _holds_most(filed_by[fh], key)),
        )
        for key, rec in by_family.items()
    ]
    # Most distinctive functions first, then most shared, then more distinct
    # samples, then name.
    results.sort(
        key=lambda r: (
            -r.distinctive_functions,
            -r.shared_functions,
            -len(r.sample_ids),
            r.family,
        )
    )
    return results[:max_families]


def _holds_most(filed_by: dict[str, set[str]], key: str) -> bool:
    """Whether family ``key`` filed more than half of the distinct samples one hash was filed for.

    Counted per hash, so samples of a family that never filed this hash do not
    weigh on it: a library routine two families each filed once is neither's,
    and a tie is never distinctive.
    """
    total = sum(len(samples) for samples in filed_by.values())
    return 2 * len(filed_by.get(key, ())) > total


def _spelling(written: Iterable[str]) -> str:
    """The spelling most prior samples used, the first in order on a tie."""
    counts = Counter(written)
    return sorted(counts, key=lambda name: (-counts[name], name))[0]


def build_attribution_hint(results: list[FamilyHashAttribution]) -> str:
    """Render the prompt hint for the static analyst, or ``""`` if no matches."""
    if not results:
        return ""
    lines = [
        "ATTRIBUTION PRIOR (exact normalized-opcode-hash matches against known "
        "samples — strong CODE-REUSE signal, not proof):",
    ]
    for r in results:
        examples = ", ".join(r.example_functions)
        ex = f" [e.g. {examples}]" if examples else ""
        contested = r.shared_functions - r.distinctive_functions
        also = (
            f", {contested} of them filed for as many samples or more of other families"
            if contested
            else ""
        )
        lines.append(
            f"- family '{r.family}': {r.shared_functions} shared function(s){also} "
            f"across {len(r.sample_ids)} prior sample(s){ex} "
            f"(prior confidence ~{r.confidence})"
        )
    lines.append(
        "Treat the highest-overlap family as a prior to CONFIRM behaviorally "
        "(imports, call-sites, decompiled logic) before asserting attribution. "
        "If families disagree, prefer the one with the most shared functions "
        "no other family is filed with. "
        "Do NOT raise a family CLAIM above this prior confidence on the hash "
        "match alone.\n"
    )
    return "\n".join(lines)


def to_report_dicts(results: list[FamilyHashAttribution], source: str) -> list[dict[str, Any]]:
    """Convert aggregated results into FamilyAttribution.function_hash_matches rows.

    ``source`` is the id of the static provider whose hashes matched. Rows
    stored before it was recorded say ``ghidra-mcp``, the one provider that
    hashed functions then, and keep saying it.
    """
    return [
        {
            "family": r.family,
            "confidence": r.confidence,
            "shared_functions": r.shared_functions,
            "distinctive_functions": r.distinctive_functions,
            "sample_ids": r.sample_ids,
            "example_functions": r.example_functions,
            "match_method": "function-hash",
            "source": source,
        }
        for r in results
    ]
