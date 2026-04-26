"""prepare_tram_dataset.py — Build Maljan ground truth fixtures from TRAM2.

Downloads the TRAM2 single_label.json dataset from the MITRE Center for
Threat-Informed Defense repository, groups entries by threat report document,
and writes one GroundTruth-compatible JSON fixture per unique document to:

    tests/evaluation/ground_truth/tram/

Usage:
    uv run python scripts/prepare_tram_dataset.py
    uv run python scripts/prepare_tram_dataset.py --min-techniques 3
    uv run python scripts/prepare_tram_dataset.py --out tests/evaluation/ground_truth/tram/

Dataset source:
    https://github.com/center-for-threat-informed-defense/tram
    License: Apache-2.0
    Each entry: {"text": "...", "label": "T1055", "doc_title": "..."}
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

TRAM2_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense"
    "/tram/main/data/tram2-data/single_label.json"
)

DEFAULT_OUT_DIR = (
    Path(__file__).resolve().parent.parent / "tests" / "evaluation" / "ground_truth" / "tram"
)

# Minimum unique techniques required for a document to be included.
DEFAULT_MIN_TECHNIQUES = 3


def _slugify(title: str) -> str:
    """Convert a document title to a safe filesystem/fixture identifier."""
    slug = title.lower()
    slug = re.sub(r"[^a-z0-9]+", "_", slug)
    slug = slug.strip("_")
    return slug[:72]


def _fetch_tram2(url: str) -> list[dict[str, str]]:
    """Download and parse the TRAM2 single_label.json file."""
    print(f"Fetching TRAM2 dataset from:\n  {url}", flush=True)
    try:
        with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
            raw = response.read().decode("utf-8")
    except Exception as exc:
        print(f"[ERROR] Download failed: {exc}", file=sys.stderr)
        sys.exit(1)
    try:
        data: list[dict[str, str]] = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"[ERROR] JSON parse failed: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"  Loaded {len(data):,} labeled sentences.", flush=True)
    return data


def _group_by_document(
    entries: list[dict[str, str]],
) -> dict[str, dict[str, object]]:
    """Group TRAM2 entries by doc_title.

    Returns:
        Mapping of doc_title -> {"technique_ids": set[str], "texts": list[str]}
    """
    groups: dict[str, dict[str, object]] = defaultdict(
        lambda: {"technique_ids": set(), "texts": []}
    )
    for entry in entries:
        title = entry.get("doc_title", "").strip()
        label = entry.get("label", "").strip().upper()
        text = entry.get("text", "").strip()
        if not title or not label:
            continue
        groups[title]["technique_ids"].add(label)  # type: ignore[union-attr]
        groups[title]["texts"].append(text)  # type: ignore[union-attr]
    return dict(groups)


def _build_fixture(
    sample_id: str,
    doc_title: str,
    technique_ids: set[str],
    attck_valid_ids: set[str],
) -> dict[str, object]:
    """Build a GroundTruth-compatible fixture dict."""
    return {
        "sample_id": sample_id,
        "notes": (
            f"TRAM2 ground truth — threat report: '{doc_title}'. "
            f"Source: center-for-threat-informed-defense/tram (Apache-2.0)."
        ),
        "technique_ids": sorted(technique_ids),
        "attck_valid_ids": sorted(attck_valid_ids),
        "expected_stix_types": ["malware", "attack-pattern", "relationship"],
        "expected_rel_types": ["uses"],
    }


def prepare(
    out_dir: Path = DEFAULT_OUT_DIR,
    min_techniques: int = DEFAULT_MIN_TECHNIQUES,
    url: str = TRAM2_URL,
) -> int:
    """Download TRAM2 and write per-document fixture files.

    Returns:
        Number of fixture files written.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    entries = _fetch_tram2(url)
    groups = _group_by_document(entries)

    # Collect all technique IDs from the dataset for hallucination rate baseline.
    all_technique_ids: set[str] = set()
    for group in groups.values():
        all_technique_ids.update(group["technique_ids"])  # type: ignore[arg-type]

    print(
        f"\nDataset summary:\n"
        f"  Unique documents : {len(groups)}\n"
        f"  Unique techniques: {len(all_technique_ids)}\n",
        flush=True,
    )

    written = 0
    skipped = 0

    for doc_title, group in sorted(groups.items()):
        tech_ids: set[str] = group["technique_ids"]  # type: ignore[assignment]
        if len(tech_ids) < min_techniques:
            skipped += 1
            continue

        sample_id = _slugify(doc_title)
        fixture = _build_fixture(
            sample_id=sample_id,
            doc_title=doc_title,
            technique_ids=tech_ids,
            attck_valid_ids=all_technique_ids,
        )
        out_path = out_dir / f"{sample_id}.json"
        out_path.write_text(json.dumps(fixture, indent=2, ensure_ascii=False), encoding="utf-8")
        written += 1
        print(f"  [{written:>3}] {sample_id} ({len(tech_ids)} techniques)", flush=True)

    print(
        f"\nDone.\n"
        f"  Written : {written} fixtures  ->  {out_dir}\n"
        f"  Skipped : {skipped} documents (< {min_techniques} unique techniques)\n",
        flush=True,
    )
    return written


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build Maljan ground truth fixtures from the TRAM2 dataset.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT_DIR,
        help="Output directory for fixture JSON files.",
    )
    parser.add_argument(
        "--min-techniques",
        type=int,
        default=DEFAULT_MIN_TECHNIQUES,
        help="Minimum unique techniques required to include a document.",
    )
    parser.add_argument(
        "--url",
        default=TRAM2_URL,
        help="URL of the TRAM2 single_label.json file.",
    )
    args = parser.parse_args()

    count = prepare(out_dir=args.out, min_techniques=args.min_techniques, url=args.url)
    if count == 0:
        print(
            "[WARNING] No fixtures were written. Check --min-techniques threshold.", file=sys.stderr
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
