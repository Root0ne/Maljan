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
  * ``--manifest FILE --flat-dir DIR --cohorts a,b``
                            a temporal manifest over a flat ``<sha256>.<ext>`` dir,
                            read for the named training cohorts only.
  * ``--csv FILE``          a per-sample feature CSV (e.g. MABEL re-exported). With
                            ``--family-col``, ``--id-cols`` and ``--text-cols a,b,c``
                            (both required) the text columns are concatenated into
                            each row's profile text; a text column that is the
                            family column or an id column, or one the CSV lacks, is
                            refused.
                            Use when only features (not binaries) are available.

Held out: ``--held-out c`` names the manifest cohorts an evaluation scores. Their
sha256 set is built once and applied to every input: such a cohort is refused as
a training cohort, a sample file whose SHA-256 is in the set is skipped, and a
CSV row whose ``--sha-col`` value is in it is skipped (``--sha-col`` is then
required with ``--csv``). ``--cohorts`` requires ``--held-out``.

Per family the per-sample profiles are aggregated into one discriminative
fingerprint description (``build_family_fingerprint_text``). Output JSON stores
TEXT only (no vectors); the runtime index embeds it on load.

Run:
    uv run python scripts/knowledge/build_family_feature_kb.py --samples-dir ./rats \
        --out data/family_fingerprints_v1.json --min-per-family 3
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from maljan.analysis.family_feature_rag import (
    build_family_fingerprint_text,
    build_sample_profile_text,
)
from maljan.extractors.pe_extractor import build_static_analysis

_CATALOG_SCHEMA = "maljan-family-fingerprints/v1"
_EMBED_MODEL = "BAAI/bge-small-en-v1.5"  # what the runtime index embeds the text with


def _sha256_of(path: Path) -> str:
    """The SHA-256 of a file's bytes, read in blocks (the file is never run)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _profiles_from_samples_dir(
    root: Path, held: frozenset[str] = frozenset()
) -> dict[str, list[str]]:
    """{family: [per-sample profile text]} from a folder-per-family raw-binary tree.

    A file whose SHA-256 is in ``held`` (a held-out cohort's) is skipped.
    """
    out: dict[str, list[str]] = defaultdict(list)
    skipped = 0
    for fam_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        family = fam_dir.name
        for f in sorted(fam_dir.rglob("*")):
            if not f.is_file():
                continue
            if held and _sha256_of(f) in held:
                skipped += 1
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
    if skipped:
        print(f"  left out {skipped} held-out sample(s) of {root}", flush=True)
    return out


def _profiles_from_csv(
    path: Path,
    family_col: str,
    text_cols: list[str],
    id_cols: list[str],
    *,
    sha_col: str = "",
    held: frozenset[str] = frozenset(),
) -> dict[str, list[str]]:
    """{family: [row text]} from a generic per-sample feature CSV (e.g. MABEL).

    Only the named text columns are read. A text column that is the family
    column or one of the id columns is refused (a fingerprint holding the
    label or the sample's id answers the question it is asked), and a named
    column the CSV lacks is refused rather than replaced by every column. A
    row whose ``sha_col`` value is in ``held`` is skipped; ``held`` needs a
    ``sha_col``.
    """
    if not text_cols:
        raise SystemExit("ERROR: --text-cols names no feature column")
    if not id_cols:
        raise SystemExit("ERROR: --id-cols names no id column")
    overlap = sorted(set(text_cols) & {family_col, *id_cols})
    if overlap:
        raise SystemExit(
            f"ERROR: --text-cols {overlap} overlap the family column '{family_col}' or the "
            f"id columns {id_cols}: a label or an id is not a feature"
        )
    if held and not sha_col:
        raise SystemExit("ERROR: --held-out with --csv requires --sha-col")
    csv.field_size_limit(10**8)  # MABEL packs large multi-value cells (imports, capa)
    out: dict[str, list[str]] = defaultdict(list)
    skipped = 0
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        cols = reader.fieldnames or []
        if family_col not in cols:
            raise SystemExit(f"ERROR: --family-col '{family_col}' not in CSV columns {cols}")
        missing = [c for c in [*text_cols, *id_cols, *([sha_col] if sha_col else [])]
                   if c not in cols]  # fmt: skip
        if missing:
            raise SystemExit(f"ERROR: columns {missing} not in the CSV {path} (columns {cols})")
        for row in reader:
            if held and (row.get(sha_col) or "").strip().lower() in held:
                skipped += 1
                continue
            fam = (row.get(family_col) or "").strip()
            if not fam:
                continue
            text = "; ".join(
                f"{c}: {row[c].strip()}" for c in text_cols if (row.get(c) or "").strip()
            )
            if text:
                out[fam].append(text)
    if skipped:
        print(f"  left out {skipped} held-out row(s) of {path}", flush=True)
    return out


def _cohorts_of(manifest_path: Path) -> dict[str, Any]:
    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    found = doc.get("cohorts") if isinstance(doc, dict) else None
    if not isinstance(found, dict):
        raise SystemExit(f"ERROR: {manifest_path} holds no cohorts map")
    return found


def held_out_shas(manifest_path: Path, held_out: list[str]) -> frozenset[str]:
    """The SHA-256 of every sample of the manifest's held-out cohorts, built once."""
    if not held_out:
        raise SystemExit("ERROR: --held-out names no held-out cohort")
    found = _cohorts_of(manifest_path)
    unknown = sorted(set(held_out) - set(found))
    if unknown:
        raise SystemExit(f"ERROR: cohort(s) {unknown} not in the manifest {sorted(found)}")
    return frozenset(
        str(s.get("sha256") or "").strip().lower()
        for name in held_out
        for s in found.get(name) or []
        if isinstance(s, dict) and s.get("sha256")
    )


def _manifest_samples(
    manifest_path: Path, cohorts: list[str], held_out: list[str]
) -> list[dict[str, Any]]:
    """The manifest's samples of the named training cohorts, none of a held-out cohort.

    A cohort the evaluation holds out is refused as a training cohort, a
    cohort the manifest does not name is refused, and a sample that is in a
    held-out cohort as well is left out: the catalogue never holds a
    fingerprint of a sample the evaluation scores.
    """
    if not cohorts:
        raise SystemExit("ERROR: --cohorts names no training cohort")
    held = held_out_shas(manifest_path, held_out)
    found = _cohorts_of(manifest_path)
    unknown = sorted(set(cohorts) - set(found))
    if unknown:
        raise SystemExit(f"ERROR: cohort(s) {unknown} not in the manifest {sorted(found)}")
    overlap = sorted(set(cohorts) & set(held_out))
    if overlap:
        raise SystemExit(f"ERROR: cohort(s) {overlap} are held out and cannot be trained on")
    return [
        s
        for name in cohorts
        for s in found.get(name) or []
        if isinstance(s, dict) and str(s.get("sha256") or "").strip().lower() not in held
    ]


def _profiles_from_manifest(
    manifest_path: Path, flat_dir: Path, cohorts: list[str], held_out: list[str]
) -> dict[str, list[str]]:
    """{family: [profile]} from a flat ``<sha256>.<ext>`` dir + a temporal manifest.

    Reuses an existing local corpus (e.g. the n=210 MalwareBazaar samples in
    data/samples/) without re-arranging it into folder-per-family: the manifest's
    ``cohorts[<name>][].signature`` provides the family for each sha256, read
    for the named training cohorts only (:func:`_manifest_samples`).
    """
    out: dict[str, list[str]] = defaultdict(list)
    for s in _manifest_samples(manifest_path, cohorts, held_out):
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


def _names(raw: str) -> list[str]:
    return [c.strip() for c in raw.split(",") if c.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the family-feature RAG fingerprint catalog.")
    ap.add_argument("--samples-dir", type=str, help="Folder-per-family raw-binary tree.")
    ap.add_argument("--manifest", type=str, help="Temporal manifest (sha256->signature map).")
    ap.add_argument("--flat-dir", type=str, help="Flat <sha256>.<ext> dir (with --cohorts).")
    ap.add_argument(
        "--csv", nargs="+", help="Per-sample feature CSV segment(s) (e.g. MABEL, multi-part)."
    )
    ap.add_argument("--family-col", type=str, default="family", help="CSV family column.")
    ap.add_argument(
        "--text-cols",
        type=str,
        default="",
        help="Comma CSV feature columns to use (required with --csv; never a label or id column).",
    )
    ap.add_argument(
        "--id-cols",
        type=str,
        default="",
        help="Comma CSV id columns (required with --csv; refused as --text-cols).",
    )
    ap.add_argument(
        "--sha-col",
        type=str,
        default="",
        help="CSV column holding each row's sha256 (required with --csv and --held-out).",
    )
    ap.add_argument(
        "--cohorts",
        type=str,
        default="",
        help="Comma manifest cohorts to build from (with --manifest, --flat-dir, --held-out).",
    )
    ap.add_argument(
        "--held-out",
        type=str,
        default="",
        help="Comma manifest cohorts the evaluation scores: refused as --cohorts, and their "
        "samples left out of every input.",
    )
    ap.add_argument("--out", type=str, default="data/family_fingerprints_v1.json")
    ap.add_argument("--min-per-family", type=int, default=3, help="Drop families with fewer.")
    args = ap.parse_args()

    cohorts, held_out = _names(args.cohorts), _names(args.held_out)
    man = Path(args.manifest) if args.manifest else None
    if (cohorts or held_out) and man is None:
        print("ERROR: --cohorts and --held-out name cohorts of a --manifest.", file=sys.stderr)
        return 2
    if man is not None and not man.is_file():
        print(f"ERROR: --manifest not found: {man}", file=sys.stderr)
        return 2
    if man is not None and not held_out:
        print(
            "ERROR: --manifest requires --held-out <the cohorts the evaluation scores>.",
            file=sys.stderr,
        )
        return 2
    held = held_out_shas(man, held_out) if man is not None else frozenset()

    profiles: dict[str, list[str]] = defaultdict(list)
    if args.samples_dir:
        root = Path(args.samples_dir)
        if not root.is_dir():
            print(f"ERROR: --samples-dir not found: {root}", file=sys.stderr)
            return 2
        for fam, ps in _profiles_from_samples_dir(root, held).items():
            profiles[fam].extend(ps)
    if man is not None and (cohorts or args.flat_dir):
        if not cohorts or not args.flat_dir:
            print(
                "ERROR: building from --manifest requires --cohorts <training cohorts> and "
                "--flat-dir <sha256-dir>.",
                file=sys.stderr,
            )
            return 2
        flat = Path(args.flat_dir)
        if not flat.is_dir():
            print(f"ERROR: bad --flat-dir ({flat}).", file=sys.stderr)
            return 2
        for fam, ps in _profiles_from_manifest(man, flat, cohorts, held_out).items():
            profiles[fam].extend(ps)
    if args.csv:
        text_cols, id_cols = _names(args.text_cols), _names(args.id_cols)
        if not text_cols or not id_cols:
            print(
                "ERROR: --csv requires --text-cols <feature columns> and --id-cols <id "
                "columns>: a text column is never the family, a label or an id column.",
                file=sys.stderr,
            )
            return 2
        if held and not args.sha_col:
            print("ERROR: --held-out with --csv requires --sha-col.", file=sys.stderr)
            return 2
        for csv_path in args.csv:
            p = Path(csv_path)
            if not p.is_file():
                print(f"ERROR: --csv file not found: {p}", file=sys.stderr)
                return 2
            found = _profiles_from_csv(
                p, args.family_col, text_cols, id_cols, sha_col=args.sha_col, held=held
            )
            for fam, ps in found.items():
                profiles[fam].extend(ps)
    if not profiles:
        print(
            "ERROR: no profiles — pass --samples-dir, --manifest+--flat-dir+--cohorts, "
            "and/or --csv.",
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
