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

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

# How many example function names to show per family in the hint.
_EXAMPLES_PER_FAMILY = 3


@dataclass
class FamilyHashAttribution:
    """An aggregated family link derived from shared function hashes."""

    family: str
    shared_functions: int = 0
    sample_ids: list[str] = field(default_factory=list)
    example_functions: list[str] = field(default_factory=list)

    @property
    def confidence(self) -> float:
        """A monotone, capped confidence from the count of shared functions.

        One shared function is a weak prior; the signal saturates as the count
        grows. Capped below 1.0 because exact-match is strong evidence but still
        a *prior* that the analyst/judge must corroborate behaviorally.
        """
        return round(min(0.5 + 0.1 * self.shared_functions, 0.95), 2)


def aggregate_matches(
    matches: Iterable[Any],
    max_families: int = 8,
) -> list[FamilyHashAttribution]:
    """Group raw ``FunctionMatch`` rows by family.

    Each match exposes ``.family``, ``.sample_id``, ``.func_hash`` and
    ``.func_name`` (see :class:`maljan.memory.function_hash_store.FunctionMatch`).
    Counts DISTINCT shared function hashes per family (so the same hash stored by
    several past samples is not double-counted), tracks the distinct prior
    samples, and ranks families by shared-function count.
    """
    by_family: dict[str, dict[str, Any]] = {}
    for m in matches:
        family = getattr(m, "family", None) or "UNKNOWN"
        fh = getattr(m, "func_hash", "") or ""
        sid = getattr(m, "sample_id", "") or ""
        name = getattr(m, "func_name", "") or ""
        if not fh:
            continue
        rec = by_family.setdefault(family, {"hashes": set(), "samples": set(), "names": {}})
        rec["hashes"].add(fh)
        if sid:
            rec["samples"].add(sid)
        # Keep one representative name per hash for the examples list.
        if name and fh not in rec["names"]:
            rec["names"][fh] = name

    results = [
        FamilyHashAttribution(
            family=family,
            shared_functions=len(rec["hashes"]),
            sample_ids=sorted(rec["samples"]),
            example_functions=sorted(rec["names"].values())[:_EXAMPLES_PER_FAMILY],
        )
        for family, rec in by_family.items()
    ]
    # Most shared functions first, then more distinct samples, then name.
    results.sort(key=lambda r: (-r.shared_functions, -len(r.sample_ids), r.family))
    return results[:max_families]


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
        lines.append(
            f"- family '{r.family}': {r.shared_functions} shared function(s) "
            f"across {len(r.sample_ids)} prior sample(s){ex} "
            f"(prior confidence ~{r.confidence})"
        )
    lines.append(
        "Treat the highest-overlap family as a prior to CONFIRM behaviorally "
        "(imports, call-sites, decompiled logic) before asserting attribution. "
        "If families disagree, prefer the one with the most shared functions. "
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
            "sample_ids": r.sample_ids,
            "example_functions": r.example_functions,
            "match_method": "function-hash",
            "source": source,
        }
        for r in results
    ]
