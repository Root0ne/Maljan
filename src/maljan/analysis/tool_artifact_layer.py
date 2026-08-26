"""Offensive-tool and commodity-RAT byte markers (Layer 0).

Maljan could not name a malware family without a sandbox. ``FamilyAttribution``
draws its family from one place — CAPE's ``cti.family[]`` — so a static-only run
produced a report with a verdict, a technique list, and no idea what it was
looking at. With the sandbox unreachable, which is the normal case here, that is
every run.

A Cobalt Strike beacon, a Mimikatz build and an AsyncRAT client all carry
distinctive strings, and matching them is neither clever nor expensive. It is
simply something nobody had wired up.

Two design choices are load-bearing:

**``min_hits`` is 2, never 1.** Every single one of these markers can appear in
something benign — a detection signature, an EDR agent, a blue-team utility, a
malware-analysis tool. A one-hit rule flags the defenders' own tooling, and a
report that calls Sysinternals "Cobalt Strike" is worse than one that says
nothing.

**It emits on ``domain="yara"``, not a new domain.** This is byte-signature
matching over the sample, structurally identical to what ``YaraLayer`` does, so
it inherits the existing 0.90 weight with no change to ``LAYER_WEIGHTS`` — and,
more importantly, it *cannot* double-count against YARA, because the cascade's
corroboration multiplier counts distinct domains. A new domain here would have
manufactured cross-layer agreement out of one piece of evidence.

Confidence is capped at 0.75, under the real-YARA band, because an unanchored
string match is weaker evidence than a structural rule.

Mirrors the Sigma/YARA/LOLBin Layer-0 pattern: produces a deterministic
``AgentISR(domain="yara", revision_round=0)`` consumed by the TTP cascade.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

__all__ = [
    "ToolArtifact",
    "build_tool_artifact_isr",
    "load_tool_artifacts",
    "reset_cache",
]

# Below the real-YARA band (0.90-0.92). A string match is weaker than a rule.
_CONFIDENCE_CEILING = 0.75
_MAX_EVIDENCE = 4


@dataclass(frozen=True)
class ToolArtifact:
    name: str
    family: str
    kind: str
    technique_ids: tuple[str, ...]
    patterns: tuple[str, ...]
    min_hits: int
    confidence_base: float
    confidence_max: float

    def confidence_for(self, hits: int) -> float:
        extra = max(0, hits - self.min_hits)
        return round(min(self.confidence_max, self.confidence_base + 0.04 * extra), 4)


_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, tuple[ToolArtifact, ...] | None] = {}


def load_tool_artifacts(catalog_path: str) -> tuple[ToolArtifact, ...] | None:
    """Load (and cache) the artifact catalog, or ``None`` when unavailable."""
    key = str(catalog_path)
    with _CACHE_LOCK:
        if key in _CACHE:
            return _CACHE[key]
    result = _load_uncached(key)
    with _CACHE_LOCK:
        _CACHE[key] = result
    return result


def reset_cache() -> None:
    """Clear the catalog cache (test hook; not used at runtime)."""
    with _CACHE_LOCK:
        _CACHE.clear()


def _load_uncached(catalog_path: str) -> tuple[ToolArtifact, ...] | None:
    if not catalog_path or not Path(catalog_path).is_file():
        logger.info("tool-artifacts: catalog not found at '%s' — layer disabled.", catalog_path)
        return None
    try:
        doc = json.loads(Path(catalog_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("tool-artifacts: failed to read '%s' (%s) — disabled.", catalog_path, exc)
        return None
    rows = doc.get("artifacts") if isinstance(doc, dict) else None
    if not isinstance(rows, list) or not rows:
        logger.warning("tool-artifacts: '%s' has no 'artifacts' — disabled.", catalog_path)
        return None

    out: list[ToolArtifact] = []
    for row in rows:
        parsed = _parse(row)
        if parsed is not None:
            out.append(parsed)
    if not out:
        logger.warning("tool-artifacts: '%s' produced no usable entries.", catalog_path)
        return None
    logger.info("tool-artifacts: loaded %d artifact(s) from '%s'.", len(out), catalog_path)
    return tuple(out)


def _parse(row: Any) -> ToolArtifact | None:
    if not isinstance(row, dict):
        return None
    name = row.get("name")
    patterns_raw = row.get("patterns")
    if not isinstance(name, str) or not name or not isinstance(patterns_raw, list):
        return None
    patterns = tuple(p for p in patterns_raw if isinstance(p, str) and p)
    if not patterns:
        return None
    try:
        # Floor of 2 enforced here, not just in the data: a hand-edited
        # "min_hits": 1 would turn this layer into a false-attribution engine.
        min_hits = max(2, int(row.get("min_hits", 2)))
        conf_base = float(row.get("confidence_base", 0.55))
        conf_max = min(float(row.get("confidence_max", 0.72)), _CONFIDENCE_CEILING)
    except (TypeError, ValueError):
        logger.warning("tool-artifacts: %s has non-numeric thresholds — skipped.", name)
        return None

    tids_raw = row.get("technique_ids")
    tids = tuple(t for t in (tids_raw if isinstance(tids_raw, list) else []) if isinstance(t, str))

    return ToolArtifact(
        name=name,
        family=str(row.get("family") or name),
        kind=str(row.get("kind") or "tool"),
        technique_ids=tids,
        patterns=patterns,
        min_hits=min(min_hits, len(patterns)),
        confidence_base=min(conf_base, conf_max),
        confidence_max=conf_max,
    )


def match_artifacts(
    blob: bytes, artifacts: tuple[ToolArtifact, ...]
) -> list[tuple[ToolArtifact, list[str]]]:
    """Return ``[(artifact, matched_patterns)]`` for entries clearing ``min_hits``.

    Matching is case-insensitive over both the ASCII and the UTF-16LE view of
    the blob. The wide view matters more than it sounds: .NET tooling stores its
    type names as wide strings, so an AsyncRAT client scanned only as ASCII
    matches nothing at all.
    """
    if not blob or not artifacts:
        return []
    ascii_view = blob.lower()
    # Collapse the UTF-16LE view by dropping every second byte. Crude, and
    # exactly right for the ASCII-range identifiers these patterns are.
    wide_view = blob[::2].lower() + blob[1::2].lower()

    out: list[tuple[ToolArtifact, list[str]]] = []
    for artifact in artifacts:
        matched = [
            pattern
            for pattern in artifact.patterns
            if (needle := pattern.lower().encode("utf-8", errors="ignore")) in ascii_view
            or needle in wide_view
        ]
        if len(matched) >= artifact.min_hits:
            out.append((artifact, matched))
    return out


def build_tool_artifact_isr(
    blob: bytes | None, catalog_path: str
) -> tuple[AgentISR | None, list[dict[str, Any]]]:
    """Scan ``blob`` for offensive-tool markers.

    Returns ``(isr, matches)``. The second element carries the family names to
    the report, following the same judge-node → state → ``FamilyAttribution``
    route that ``function_hash_matches`` already uses; adding a ``family`` field
    to ``ClaimEvidence`` would have widened the shared inter-agent contract for
    the benefit of exactly one producer.
    """
    if not blob:
        return None, []
    artifacts = load_tool_artifacts(catalog_path)
    if not artifacts:
        return None, []

    hits = match_artifacts(blob, artifacts)
    if not hits:
        return None, []

    claims: list[ClaimEvidence] = []
    matches: list[dict[str, Any]] = []
    for artifact, matched in hits:
        confidence = artifact.confidence_for(len(matched))
        evidence = ", ".join(f"'{p}'" for p in matched[:_MAX_EVIDENCE])
        if len(matched) > _MAX_EVIDENCE:
            evidence += f", +{len(matched) - _MAX_EVIDENCE} more"
        matches.append(
            {
                "family": artifact.family,
                "tool": artifact.name,
                "kind": artifact.kind,
                "confidence": confidence,
                "markers": matched[:_MAX_EVIDENCE],
            }
        )
        for tid in artifact.technique_ids or (None,):
            claims.append(
                ClaimEvidence(
                    # The family name appears in the claim text on purpose:
                    # attribution's grounding guardrail scans claim text for it,
                    # so this is what lets the family reach the report at all.
                    claim=(
                        f"Offensive-tool artifact cluster matches {artifact.name} "
                        f"({len(matched)} distinct marker(s), {artifact.kind})."
                    ),
                    evidence_ref=f"tool_artifact: {evidence}",
                    confidence=confidence,
                    technique_id=tid,
                    rule_platforms=["windows"],
                )
            )

    logger.info(
        "Tool-artifact Layer 0: %d tool(s) matched -> cascade domain='yara'.",
        len(hits),
    )
    return (
        AgentISR(
            agent_id="tool_artifact",
            domain="yara",
            claims=claims,
            dissent_items=[],
            revision_round=0,
        ),
        matches,
    )
