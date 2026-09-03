"""Function-hash attribution: fetch, aggregate, and render code-reuse links.

Companion to :mod:`maljan.memory.function_hash_store`. This module holds the
deterministic, side-effect-light pieces:

- :func:`fetch_bulk_function_hashes` drives the Ghidra MCP REST API to compute
  per-function normalized-opcode hashes for a loaded binary (the only part that
  touches the network; fail-safe).
- :func:`aggregate_matches` and :func:`build_attribution_hint` are pure: given
  the raw per-function matches returned by the store, they group them by family
  and render the prompt hint / report rows. These are unit-tested.

The same two sides of the system use these:

- The static analyst (query side) fetches the sample's hashes, asks the store
  which known samples share them, aggregates, and injects the hint.
- The judge node (write side) fetches the sample's hashes and upserts them under
  the final family so the corpus grows.

Tiny functions (a handful of instructions: thunks, stubs, ``ret`` wrappers)
normalize to the same opcode hash across completely unrelated binaries, so the
fetch drops anything below ``min_instructions`` — matching those would
manufacture false family links.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from maljan.core.logger import logger

# How many example function names to show per family in the hint.
_EXAMPLES_PER_FAMILY = 3


def _extract_functions(data: Any) -> list[dict[str, Any]]:
    """Pull the ``functions`` list out of a get_bulk_function_hashes payload.

    Defensive against transport wrapping: accepts the list at the top level or
    nested under ``result``/``data``. Returns ``[]`` for anything unexpected.
    """
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (json.JSONDecodeError, ValueError):
            return []
    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("functions", "result", "data"):
        val = data.get(key)
        if isinstance(val, list):
            return [f for f in val if isinstance(f, dict)]
        if isinstance(val, dict):  # nested wrapper -> recurse once
            inner = val.get("functions")
            if isinstance(inner, list):
                return [f for f in inner if isinstance(f, dict)]
    return []


def fetch_bulk_function_hashes(
    *,
    base_url: str,
    auth_token: str,
    file_path: str,
    min_instructions: int,
    page_limit: int = 2000,
    max_pages: int = 8,
    timeout: float = 120.0,
) -> list[tuple[str, str]]:
    """Return ``(func_name, func_hash)`` for the binary's meaningful functions.

    Best-effort ``load_program`` + ``run_analysis`` (tolerated if the program is
    already loaded by another pre-pass), then paginates ``get_bulk_function_hashes``
    and keeps only functions with at least ``min_instructions`` instructions.
    Fail-safe: any error yields an empty list.
    """
    try:
        import httpx
    except Exception as exc:  # pragma: no cover - httpx is a hard dep in practice
        logger.warning("function-hash fetch: httpx unavailable (%s).", exc)
        return []

    base = base_url.rstrip("/")
    headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    try:
        from maljan.analysis.ghidra_program import (
            SWITCH_PARAM,
            SWITCH_PATH,
            program_name_from_load,
        )

        with httpx.Client(timeout=timeout, headers=headers) as http:
            # Best-effort load + activate + analyse; another pre-pass may have
            # done this. The activate step is not optional cleanup: a load only
            # becomes Ghidra's *current* program when nothing is current yet, so
            # without it `get_bulk_function_hashes` below returns the hashes of
            # whichever binary the container looked at first — attributing this
            # sample to another sample's functions, silently and plausibly.
            try:
                loaded = http.post(f"{base}/load_program", json={"file": file_path})
                name = program_name_from_load(loaded.text)
            except Exception:  # noqa: BLE001 - a transport failure is the same as no load
                name = None
            if not name:
                # A refused load answers 200 with an `error` body. Hashing on
                # regardless would attribute this sample to whichever binary is
                # still current — the wrong family, stated confidently.
                logger.warning(
                    "function-hash fetch: load_program did not yield a program for %s; "
                    "skipping attribution rather than hashing the previously loaded binary.",
                    file_path,
                )
                return []
            try:
                http.post(f"{base}{SWITCH_PATH}", params={SWITCH_PARAM: name}, json={})
                http.post(f"{base}/run_analysis", json={})
            except Exception as exc:  # noqa: BLE001 - the current program is now unknown
                logger.warning(
                    "function-hash fetch: could not switch Ghidra to %s (%s); skipping "
                    "attribution rather than hashing whichever binary is current.",
                    name,
                    type(exc).__name__,
                )
                return []

            offset = 0
            for _ in range(max_pages):
                resp = http.get(
                    f"{base}/get_bulk_function_hashes",
                    params={"offset": offset, "limit": page_limit},
                )
                resp.raise_for_status()
                items = _extract_functions(resp.json() if resp.text.strip() else None)
                if not items:
                    break
                for it in items:
                    fh = it.get("hash")
                    name = it.get("name", "") or ""
                    ic = it.get("instruction_count", 0)
                    if not isinstance(fh, str) or not fh:
                        continue
                    if not isinstance(ic, int) or ic < min_instructions:
                        continue
                    if fh in seen:
                        continue
                    seen.add(fh)
                    out.append((name, fh))
                if len(items) < page_limit:
                    break
                offset += len(items)
        logger.info(
            "function-hash fetch: %d functions (>= %d instr) from '%s'.",
            len(out),
            min_instructions,
            file_path,
        )
        return out
    except Exception as exc:  # fail-safe
        logger.warning(
            "function-hash fetch failed (%s: %s); continuing without hashes.",
            type(exc).__name__,
            exc,
        )
        return []


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


def to_report_dicts(results: list[FamilyHashAttribution]) -> list[dict[str, Any]]:
    """Convert aggregated results into FamilyAttribution.function_hash_matches rows."""
    return [
        {
            "family": r.family,
            "confidence": r.confidence,
            "shared_functions": r.shared_functions,
            "sample_ids": r.sample_ids,
            "example_functions": r.example_functions,
            "match_method": "function-hash",
            "source": "ghidra-mcp",
        }
        for r in results
    ]
