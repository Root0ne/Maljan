"""Offline builder for the family-feature RAG fingerprint catalog (§4 U3).

Produces the vendored ``data/family_fingerprints_v1.json`` that
``maljan.memory.family_fingerprint_index`` loads at runtime. This is an OPERATOR /
OFFLINE script — never imported by the pipeline. It needs NO heavy ML deps: it
reuses Maljan's own static-feature extractor and profile renderer so the family
fingerprints are written in the exact vocabulary the runtime query uses (the index
embeds the text at load, guaranteeing one embedding space).

Inputs (combinable):
  * ``--samples-dir DIR``   a folder-per-family tree of RAW binaries (e.g. the
                            Ultimate-RAT-Collection ingested for §U1). Each binary
                            is profiled with ``pe_extractor.build_static_analysis``
                            + ``family_feature_rag.build_sample_profile_text`` — the
                            SAME path the runtime query uses (perfect parity).
                            RECOMMENDED.
  * ``--csv FILE``          a per-sample feature CSV (e.g. MABEL re-exported). With
                            ``--family-col`` and ``--text-cols a,b,c`` the named
                            columns are concatenated into each row's profile text.
                            Use when only features (not binaries) are available.

Per family the per-sample profiles are aggregated into one discriminative
fingerprint description (``build_family_fingerprint_text``). Output JSON stores
TEXT only (no vectors); the runtime index embeds it on load.

Run:
    uv run python scripts/build_family_feature_kb.py --samples-dir ./rats \
        --out data/family_fingerprints_v1.json --min-per-family 3
"""

# Bootstraps sys.path before first-party imports (E402 is intentional here).
# ruff: noqa: E402

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from maljan.analysis.family_feature_rag import (
    build_family_fingerprint_text,
    build_sample_profile_text,
)
from maljan.extractors.pe_extractor import build_static_analysis

_CATALOG_SCHEMA = "maljan-family-fingerprints/v1"
_EMBED_MODEL = "BAAI/bge-small-en-v1.5"  # what the runtime index embeds the text with


def _profiles_from_samples_dir(root: Path) -> dict[str, list[str]]:
    """{family: [per-sample profile text]} from a folder-per-family raw-binary tree."""
    out: dict[str, list[str]] = defaultdict(list)
    for fam_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        family = fam_dir.name
        for f in sorted(fam_dir.rglob("*")):
            if not f.is_file():
                continue
            try:
                static = build_static_analysis(sample_path=str(f))
            except Exception as exc:  # noqa: BLE001 - skip unparseable members
                print(f"  skip {f.name}: {exc}", flush=True)
                continue
            if static is None:
                continue
            profile = build_sample_profile_text(static)
            if profile:
                out[family].append(profile)
    return out


def _profiles_from_csv(path: Path, family_col: str, text_cols: list[str]) -> dict[str, list[str]]:
    """{family: [row text]} from a generic per-sample feature CSV (e.g. MABEL)."""
    out: dict[str, list[str]] = defaultdict(list)
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        cols = reader.fieldnames or []
        if family_col not in cols:
            raise SystemExit(f"ERROR: --family-col '{family_col}' not in CSV columns {cols}")
        use_cols = [c for c in text_cols if c in cols] or [c for c in cols if c != family_col]
        for row in reader:
            fam = (row.get(family_col) or "").strip()
            if not fam:
                continue
            text = "; ".join(
                f"{c}: {row[c].strip()}" for c in use_cols if (row.get(c) or "").strip()
            )
            if text:
                out[fam].append(text)
    return out


def _profiles_from_manifest(manifest_path: Path, flat_dir: Path) -> dict[str, list[str]]:
    """{family: [profile]} from a flat ``<sha256>.<ext>`` dir + a temporal manifest.

    Reuses an existing local corpus (e.g. the n=210 MalwareBazaar samples in
    data/samples/) without re-arranging it into folder-per-family: the manifest's
    ``cohorts[*][].signature`` provides the family for each sha256.
    """
    out: dict[str, list[str]] = defaultdict(list)
    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    samples = [s for recs in doc.get("cohorts", {}).values() for s in recs]
    for s in samples:
        sha = s.get("sha256", "")
        family = (s.get("signature") or "").strip()
        ext = s.get("file_type", "bin") or "bin"
        if not sha or not family or family.lower() == "unknown":
            continue
        binary = flat_dir / f"{sha}.{ext}"
        if not binary.is_file():
            continue
        try:
            static = build_static_analysis(sample_path=str(binary))
        except Exception as exc:  # noqa: BLE001 - skip unparseable members
            print(f"  skip {sha[:12]}: {exc}", flush=True)
            continue
        if static is None:
            continue
        profile = build_sample_profile_text(static)
        if profile:
            out[family].append(profile)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the family-feature RAG fingerprint catalog.")
    ap.add_argument("--samples-dir", type=str, help="Folder-per-family raw-binary tree.")
    ap.add_argument("--manifest", type=str, help="Temporal manifest (sha256->signature map).")
    ap.add_argument("--flat-dir", type=str, help="Flat <sha256>.<ext> dir (with --manifest).")
    ap.add_argument("--csv", type=str, help="Per-sample feature CSV (e.g. MABEL).")
    ap.add_argument("--family-col", type=str, default="family", help="CSV family column.")
    ap.add_argument("--text-cols", type=str, default="", help="Comma CSV feature columns to use.")
    ap.add_argument("--out", type=str, default="data/family_fingerprints_v1.json")
    ap.add_argument("--min-per-family", type=int, default=3, help="Drop families with fewer.")
    args = ap.parse_args()

    profiles: dict[str, list[str]] = defaultdict(list)
    if args.samples_dir:
        root = Path(args.samples_dir)
        if not root.is_dir():
            print(f"ERROR: --samples-dir not found: {root}", file=sys.stderr)
            return 2
        for fam, ps in _profiles_from_samples_dir(root).items():
            profiles[fam].extend(ps)
    if args.manifest:
        if not args.flat_dir:
            print("ERROR: --manifest requires --flat-dir <sha256-dir>.", file=sys.stderr)
            return 2
        man, flat = Path(args.manifest), Path(args.flat_dir)
        if not man.is_file() or not flat.is_dir():
            print(f"ERROR: bad --manifest/--flat-dir ({man}, {flat}).", file=sys.stderr)
            return 2
        for fam, ps in _profiles_from_manifest(man, flat).items():
            profiles[fam].extend(ps)
    if args.csv:
        text_cols = [c.strip() for c in args.text_cols.split(",") if c.strip()]
        for fam, ps in _profiles_from_csv(Path(args.csv), args.family_col, text_cols).items():
            profiles[fam].extend(ps)
    if not profiles:
        print(
            "ERROR: no profiles — pass --samples-dir, --manifest+--flat-dir, and/or --csv.",
            file=sys.stderr,
        )
        return 2

    families: list[dict] = []
    for fam in sorted(profiles):
        ps = profiles[fam]
        if len(ps) < args.min_per_family:
            continue
        description = build_family_fingerprint_text(ps)
        if not description:
            continue
        families.append(
            {
                "family_id": fam,
                "description": description,
                "malware_category": "",
                "sample_count": len(ps),
            }
        )
    if len(families) < 1:
        print(f"ERROR: no family met --min-per-family={args.min_per_family}.", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(
            {
                "schema": _CATALOG_SCHEMA,
                "embed_model": _EMBED_MODEL,
                "families": families,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Wrote {out_path}: {len(families)} family fingerprints.", flush=True)
    print(
        "Enable at runtime with PREPROCESSING__USE_FAMILY_FEATURE_RAG=true and "
        f"PREPROCESSING__FAMILY_FINGERPRINT_CATALOG_PATH={out_path}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
