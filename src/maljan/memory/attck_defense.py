"""ATT&CK's own defensive knowledge per technique, read from the cached bundles.

For a technique id this answers, from the STIX bundles the platform already
caches (``attck_loader.ATTCK_CACHE_FILES``) and from nothing else:

* the mitigations: ``course-of-action`` objects joined to the technique by a
  ``mitigates`` relationship, each with the relationship's own sentence on how
  it applies to that technique;
* the detection strategies (ATT&CK v18 and later): ``x-mitre-detection-strategy``
  objects joined by a ``detects`` relationship;
* the data components those strategies read: strategy -> its analytics ->
  each analytic's log-source references -> ``x-mitre-data-component``. A bundle
  from before v18 joins a data component to the technique by ``detects``
  directly, and that join is read too.

Each bundle is read once and indexed in one pass (linear in its size); only the
domains a caller asks about are read, and the index of a bundle file is kept
until the file changes. An object marked revoked or deprecated is skipped, and
so is a relationship marked so. A domain with no cached bundle answers with
nothing: this module never downloads (``attck_update`` is the update path).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.memory import attck_loader

_CITATION_RE = re.compile(r"\s*\(Citation:[^)]*\)")
_TAG_RE = re.compile(r"</?[a-zA-Z][^>]*>")
_LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")


@dataclass(frozen=True)
class AttckObject:
    """One ATT&CK object a technique links to: its id, its name, and the link's own words."""

    attck_id: str
    name: str
    text: str = ""


@dataclass
class TechniqueDefense:
    """What ATT&CK itself lists against one technique."""

    mitigations: list[AttckObject] = field(default_factory=list)
    detection_strategies: list[AttckObject] = field(default_factory=list)
    data_components: list[AttckObject] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.mitigations or self.detection_strategies or self.data_components)


def clean_text(value: Any) -> str:
    """A bundle's prose on one line: no citation markers, markup tags or link targets."""
    text = _LINK_RE.sub(r"\1", _TAG_RE.sub("", _CITATION_RE.sub("", str(value or ""))))
    return " ".join(text.split())


def _inactive(obj: dict[str, Any]) -> bool:
    return bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))


def _attck_id(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            return str(ref.get("external_id") or "")
    return ""


def _component_refs(analytic: dict[str, Any]) -> list[str]:
    refs = analytic.get("x_mitre_log_source_references") or []
    if isinstance(refs, str):
        # A bundle that carries the list as its repr, not as JSON, is read as
        # empty rather than parsed as code.
        return []
    return [
        str(ref["x_mitre_data_component_ref"])
        for ref in refs
        if isinstance(ref, dict) and ref.get("x_mitre_data_component_ref")
    ]


def index_bundle(bundle: dict[str, Any]) -> dict[str, TechniqueDefense]:
    """``{technique id: its defence}`` for every active technique of one bundle, in one pass."""
    techniques: dict[str, str] = {}
    mitigations: dict[str, AttckObject] = {}
    strategies: dict[str, tuple[AttckObject, list[str]]] = {}
    analytics: dict[str, list[str]] = {}
    components: dict[str, AttckObject] = {}
    relationships: list[dict[str, Any]] = []

    for obj in bundle.get("objects", []):
        kind = obj.get("type")
        if kind == "relationship":
            if obj.get("relationship_type") in ("mitigates", "detects") and not _inactive(obj):
                relationships.append(obj)
            continue
        if _inactive(obj):
            continue
        sid = str(obj.get("id") or "")
        if kind == "attack-pattern":
            tid = _attck_id(obj)
            if tid:
                techniques[sid] = tid
        elif kind == "course-of-action":
            mitigations[sid] = AttckObject(_attck_id(obj), str(obj.get("name") or ""))
        elif kind == "x-mitre-detection-strategy":
            strategies[sid] = (
                AttckObject(_attck_id(obj), str(obj.get("name") or "")),
                [str(r) for r in obj.get("x_mitre_analytic_refs") or []],
            )
        elif kind == "x-mitre-analytic":
            analytics[sid] = _component_refs(obj)
        elif kind == "x-mitre-data-component":
            components[sid] = AttckObject(_attck_id(obj), str(obj.get("name") or ""))

    found: dict[str, TechniqueDefense] = {}

    def entry(stix_id: str) -> TechniqueDefense | None:
        tid = techniques.get(stix_id)
        return found.setdefault(tid, TechniqueDefense()) if tid else None

    for rel in relationships:
        target = entry(str(rel.get("target_ref") or ""))
        if target is None:
            continue
        source = str(rel.get("source_ref") or "")
        if rel.get("relationship_type") == "mitigates" and source in mitigations:
            base = mitigations[source]
            target.mitigations.append(
                AttckObject(base.attck_id, base.name, clean_text(rel.get("description")))
            )
        elif source in strategies:
            strategy, analytic_refs = strategies[source]
            target.detection_strategies.append(strategy)
            for analytic in analytic_refs:
                for ref in analytics.get(analytic, ()):
                    if ref in components:
                        target.data_components.append(components[ref])
        elif source in components:
            target.data_components.append(components[source])

    for defense in found.values():
        defense.mitigations = _unique(defense.mitigations)
        defense.detection_strategies = _unique(defense.detection_strategies)
        defense.data_components = _unique(defense.data_components)
    return found


def _unique(items: Iterable[AttckObject]) -> list[AttckObject]:
    """One entry per ATT&CK id, in id order; the first text for an id is kept."""
    kept: dict[str, AttckObject] = {}
    for item in items:
        kept.setdefault(item.attck_id or item.name, item)
    return sorted(kept.values(), key=lambda o: (o.attck_id, o.name))


# domain -> ((path, mtime_ns, size), index, version): a bundle file is parsed once until it
# changes.
_INDEXES: dict[str, tuple[tuple[str, int, int], dict[str, TechniqueDefense], str]] = {}


def _domain_entry(domain: str) -> tuple[dict[str, TechniqueDefense], str]:
    path = Path(attck_loader.ATTCK_CACHE_FILES[domain])
    try:
        stat = path.stat()
    except OSError:
        return {}, ""
    stamp = (str(path), stat.st_mtime_ns, stat.st_size)
    cached = _INDEXES.get(domain)
    if cached is not None and cached[0] == stamp:
        return cached[1], cached[2]
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning(
            "ATT&CK %s bundle at %s is unreadable (%s); no defence data.", domain, path, exc
        )
        return {}, ""
    index = index_bundle(bundle)
    version = attck_loader._extract_version(bundle)  # noqa: SLF001 — the loader's own reader
    _INDEXES[domain] = (stamp, index, version)
    return index, version


def _domain_index(domain: str) -> dict[str, TechniqueDefense]:
    return _domain_entry(domain)[0]


def cached_version(domain: str = "enterprise") -> str:
    """The ATT&CK release of ``domain``'s cached bundle, without parsing the bundle.

    From the parsed index when one is held, else the facts ``attck_update`` keeps
    beside the bundle, else the vendored catalogue's release; ``""`` when none says.
    """
    path = Path(attck_loader.ATTCK_CACHE_FILES[domain])
    held = _INDEXES.get(domain)
    if held is not None:
        return held[2]
    try:
        facts = json.loads(attck_loader.meta_path(path).read_text(encoding="utf-8"))
        if isinstance(facts, dict) and facts.get("version"):
            return str(facts["version"])
    except (OSError, ValueError):
        pass
    try:
        table = json.loads(attck_loader.TECHNIQUES_FILE.read_text(encoding="utf-8"))
        return str((table.get("_meta") or {}).get("attck_version") or "")
    except (OSError, ValueError, AttributeError):
        return ""


def release_for(technique_ids: Iterable[str]) -> str:
    """The release(s) of the bundles that answered for ``technique_ids``, e.g. ``"20.0"``."""
    versions: list[str] = []
    for tid in technique_ids:
        domain = attck_loader.domain_of(str(tid or "").strip().upper())
        held = _INDEXES.get(domain or "")
        if held is not None and held[2] and held[2] not in versions:
            versions.append(held[2])
    return ", ".join(versions)


def defense_for(technique_ids: Iterable[str]) -> dict[str, TechniqueDefense]:
    """What ATT&CK lists against each given technique, only for those it lists anything for.

    The technique's domain is the vendored catalogue's answer
    (``attck_loader.domain_of``); an id no domain owns, and a domain with no
    cached bundle, answer nothing.
    """
    wanted: dict[str, str] = {}
    for raw in technique_ids:
        tid = str(raw or "").strip().upper()
        domain = attck_loader.domain_of(tid) if tid else None
        if domain:
            wanted[tid] = domain
    out: dict[str, TechniqueDefense] = {}
    for domain in dict.fromkeys(wanted.values()):
        index = _domain_index(domain)
        for tid, owner in wanted.items():
            if owner == domain and tid in index and index[tid]:
                out[tid] = index[tid]
    return out


def reset_caches() -> None:
    """Forget every parsed bundle (tests)."""
    _INDEXES.clear()
