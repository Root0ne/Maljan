"""Build a non-circular malware-category evaluation set from ATT&CK prose.

The static keyword classifier (``infer_malware_category``) and any dynamic
alternative both need an INDEPENDENT ground truth to be measured against.
ATT&CK ``malware`` SDO descriptions are ideal: they are human-written threat
intelligence, and their first sentence almost always *declares the family's
type* ("EKANS is ransomware variant ...", "cd00r is an open-source backdoor
...", "BLINDINGCAN is a remote access Trojan ...").

We exploit that to label WITHOUT circularity:

  * **label**   = the declared type extracted from sentence 1 by a targeted
                  copular-noun parser (a *different* mechanism than the
                  bag-of-keywords classifier under test).
  * **input**   = the *rest* of the description (sentences 2..N) — the
                  behavioral prose. Removing the self-declaring first sentence
                  stops the keyword classifier from trivially echoing the label
                  noun, forcing it to infer the category from behaviour. We
                  also keep the full description so the harness can report both
                  the easy (full) and hard (behavioral-only) regimes.

A family is included only when sentence 1 declares *exactly one* category
(ambiguous "ransomware worm" style declarations are dropped) and the behavioral
remainder carries enough text to score. This yields a few hundred
high-precision (category, text) pairs straight from the cached ATT&CK bundle —
fully reproducible, no hand-labeling, no LLM.

This is a data module, not a pytest test (filename intentionally not test_*).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from maljan.analysis.schema_pruner import MalwareCategory

# ---------------------------------------------------------------------------
# Declared-type -> category map. Order matters only for reporting; ambiguity
# (phrases resolving to >1 distinct category in sentence 1) -> the family is
# dropped, so overlapping single-category synonyms are safe.
# ---------------------------------------------------------------------------
_DECLARED_TYPE_PATTERNS: list[tuple[str, MalwareCategory]] = [
    (r"ransomware", MalwareCategory.RANSOMWARE),
    (r"wiper", MalwareCategory.RANSOMWARE),  # destructive-impact sibling
    (r"remote access (?:trojan|tool)", MalwareCategory.RAT),
    (r"remote-access (?:trojan|tool)", MalwareCategory.RAT),
    (r"\bbackdoor\b", MalwareCategory.RAT),
    (r"\brat\b", MalwareCategory.RAT),
    (r"\bdropper\b", MalwareCategory.DROPPER),
    (r"\bloader\b", MalwareCategory.DROPPER),
    (r"\bdownloader\b", MalwareCategory.DROPPER),
    (r"\bworm\b", MalwareCategory.WORM),
    (r"info(?:rmation)?[ -]?stealer", MalwareCategory.INFOSTEALER),
    (r"credential[ -]?stealer", MalwareCategory.INFOSTEALER),
    (r"\bstealer\b", MalwareCategory.INFOSTEALER),
    (r"keylogger", MalwareCategory.INFOSTEALER),
    (r"spyware", MalwareCategory.INFOSTEALER),
]

_MIN_BEHAVIORAL_CHARS = 120
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_CITATION = re.compile(r"\(Citation:[^)]*\)", re.IGNORECASE)
_WS = re.compile(r"\s+")
# Sentence boundary: period after a letter or ')' followed by whitespace + an
# uppercase letter. Avoids splitting decimals ("3.0") and version strings.
_SENT_SPLIT = re.compile(r"(?<=[a-zA-Z)])\.\s+(?=[A-Z])")


# How many leading sentences to scan for the family's self-declared type.
# The declaration is almost always early ("X is a backdoor ...", or after a
# one-line provenance preamble "X was first seen in 2019. It is a loader ...").
_DECLARE_SCAN_SENTENCES = 4


@dataclass(frozen=True)
class CategorySample:
    """One labelled ATT&CK family for category-inference evaluation."""

    sample_id: str  # ATT&CK software ID (e.g. S0266) or slugged name
    name: str
    category: MalwareCategory  # ground-truth label from the declaring sentence
    full_text: str  # whole cleaned description (easy regime)
    behavioral_text: str  # description minus the declaring sentence (hard regime)


def _clean(text: str) -> str:
    """Strip ATT&CK markdown links and citations, collapse whitespace."""
    text = _MD_LINK.sub(r"\1", text)
    text = _CITATION.sub("", text)
    return _WS.sub(" ", text).strip()


def _split_sentences(text: str) -> list[str]:
    parts = _SENT_SPLIT.split(text)
    return [p.strip() for p in parts if p.strip()]


def _declared_category(sentence: str) -> MalwareCategory | None:
    """Return the single category declared in ``sentence``, else None.

    None when no declared type is found OR when the sentence declares more
    than one distinct category (ambiguous → excluded from the eval set).
    """
    low = sentence.lower()
    found: set[MalwareCategory] = set()
    for pattern, cat in _DECLARED_TYPE_PATTERNS:
        if re.search(pattern, low):
            found.add(cat)
    if len(found) == 1:
        return next(iter(found))
    return None


def _attck_cache_path() -> Path:
    from maljan.memory.attck_loader import ATTCK_CACHE_FILE

    return ATTCK_CACHE_FILE


def build_category_samples(bundle_path: Path | None = None) -> list[CategorySample]:
    """Extract labelled (category, text) samples from the ATT&CK malware corpus.

    Returns an empty list if the cached bundle is missing — callers (harness /
    tests) decide whether to skip. Deterministic: same bundle -> same samples,
    ordered by ATT&CK ID for stable k-fold slicing.
    """
    path = bundle_path or _attck_cache_path()
    if not path.exists():
        return []

    bundle = json.loads(path.read_text(encoding="utf-8"))
    samples: list[CategorySample] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "malware" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        raw_desc = (obj.get("description") or "").strip()
        if not raw_desc:
            continue
        desc = _clean(raw_desc)
        sentences = _split_sentences(desc)
        if len(sentences) < 2:
            continue  # need a declaring sentence AND behavioral remainder

        # Find the first leading sentence that declares exactly one category.
        declare_idx = -1
        label: MalwareCategory | None = None
        for idx in range(min(_DECLARE_SCAN_SENTENCES, len(sentences))):
            cat = _declared_category(sentences[idx])
            if cat is not None:
                declare_idx, label = idx, cat
                break
        if label is None:
            continue

        # Behavioral input = every sentence except the declaring one. This
        # removes the self-declared type noun so the classifier must infer
        # the category from behaviour, not echo the label.
        behavioral = " ".join(s for i, s in enumerate(sentences) if i != declare_idx).strip()
        if len(behavioral) < _MIN_BEHAVIORAL_CHARS:
            continue

        attck_id = _extract_attck_id(obj)
        samples.append(
            CategorySample(
                sample_id=attck_id or _slug(obj.get("name", "?")),
                name=obj.get("name", "?"),
                category=label,
                full_text=desc,
                behavioral_text=behavioral,
            )
        )

    samples.sort(key=lambda s: s.sample_id)
    return samples


def _extract_attck_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            ext_id = ref.get("external_id")
            if isinstance(ext_id, str) and ext_id:
                return ext_id
    return None


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def category_distribution(samples: list[CategorySample]) -> dict[str, int]:
    dist: dict[str, int] = {}
    for s in samples:
        dist[s.category.value] = dist.get(s.category.value, 0) + 1
    return dict(sorted(dist.items(), key=lambda kv: (-kv[1], kv[0])))


if __name__ == "__main__":
    rows = build_category_samples()
    print(f"Built {len(rows)} labelled category samples from ATT&CK malware prose.")
    print(f"Distribution: {category_distribution(rows)}")
    if rows:
        ex = rows[0]
        print("\nExample:")
        print(f"  id={ex.sample_id} name={ex.name} label={ex.category.value}")
        print(f"  full[:120]={ex.full_text[:120]!r}")
        print(f"  behavioral[:120]={ex.behavioral_text[:120]!r}")
