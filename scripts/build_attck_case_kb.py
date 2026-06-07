"""Offline builder for the ATT&CK case-prior RAG corpus (§4 U2).

Mines our OWN long-term memory (the Qdrant ``StoredCase`` history: a behavioural
``summary_text`` plus the ``technique_ids`` the pipeline ultimately attributed) into
the vendored ``data/attck_case_corpus_v1.json`` that
``maljan.memory.attck_case_index`` loads at runtime. This is an OPERATOR / OFFLINE
script — never imported by the pipeline. It needs NO heavy ML deps: the corpus stores
case TEXT only and the runtime index embeds it at load (one embedding space).

Inputs (pick one):
  * ``--qdrant-url URL [--collection NAME]``  scroll every point out of the live LTM
                            collection. This is the "mine our analysed history" path.
                            Requires ``qdrant-client`` and a reachable Qdrant.
  * ``--cases-jsonl FILE``  a JSON-Lines export with one case per line
                            (``{sample_id, summary_text, technique_ids,
                            malware_category}``). Test/operator-friendly; needs no infra.

Each case becomes one corpus row. Cases with fewer than ``--min-techniques`` attributed
techniques are dropped (nothing useful to recommend), and duplicate ``sample_id``s keep
the last seen. Output JSON stores TEXT only; the runtime index embeds it on load.

Run:
    uv run python scripts/build_attck_case_kb.py --qdrant-url http://localhost:6333 \
        --out data/attck_case_corpus_v1.json --min-techniques 1
"""

# Bootstraps sys.path before first-party imports (E402 is intentional here).
# ruff: noqa: E402

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

_CORPUS_SCHEMA = "maljan-attck-case-corpus/v1"
_EMBED_MODEL = "BAAI/bge-small-en-v1.5"  # what the runtime index embeds the text with

# MABEL feature-CSV mining (a features-only, no-binary dataset whose condensed
# v2.10 release carries per-sample capa-derived ATT&CK ids — see findings-log §4).
_MABEL_TID = re.compile(r"T\d{4}(?:\.\d{3})?")
_MABEL_MAX_IMPORTS = 12
_MABEL_MAX_CAPA = 8
_MABEL_MAX_YARA = 8


def _row_from_payload(p: dict) -> dict | None:
    """Normalise a raw case dict (Qdrant payload or JSONL line) into a corpus row."""
    sample_id = str(p.get("sample_id", "")).strip()
    summary = str(p.get("summary_text", "")).strip()
    if not summary:
        return None
    techs = [str(t).strip() for t in (p.get("technique_ids") or []) if str(t).strip()]
    return {
        "sample_id": sample_id,
        "summary_text": summary,
        "technique_ids": techs,
        "malware_category": str(p.get("malware_category", "") or "UNKNOWN"),
    }


def _cases_from_qdrant(url: str, collection: str) -> list[dict]:
    """Scroll every point out of the live LTM collection into corpus rows."""
    from qdrant_client import QdrantClient

    client = QdrantClient(url=url)
    rows: list[dict] = []
    offset = None
    while True:
        points, offset = client.scroll(
            collection_name=collection,
            limit=256,
            offset=offset,
            with_payload=True,
            with_vectors=False,
        )
        for pt in points:
            row = _row_from_payload(pt.payload or {})
            if row is not None:
                rows.append(row)
        if offset is None:
            break
    return rows


def _cases_from_jsonl(path: Path) -> list[dict]:
    """Read one case per line from a JSON-Lines export into corpus rows."""
    rows: list[dict] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                print(f"  skip malformed JSONL line: {line[:60]}...", flush=True)
                continue
            if isinstance(obj, dict):
                row = _row_from_payload(obj)
                if row is not None:
                    rows.append(row)
    return rows


def _mabel_val(row: dict, col: str) -> str:
    """MABEL cell value with its '-' null placeholder normalised to ''."""
    v = (row.get(col) or "").strip()
    return "" if v == "-" else v


def _mabel_category(row: dict) -> str:
    """Derive a coarse malware category from MABEL's yara family-class columns."""
    for col, cat in (
        ("yara_ransomware", "RANSOMWARE"),
        ("yara_rat", "RAT"),
        ("yara_stealer", "STEALER"),
        ("yara_miners", "MINER"),
    ):
        if _mabel_val(row, col):
            return cat
    return "UNKNOWN"


def _mabel_summary(row: dict) -> str:
    """Render a MABEL row's behaviour as the retrieval key.

    Uses the import list + capa capability names + yara capability tags — a vocabulary
    that overlaps the runtime static-feature profile (build_sample_profile_text emits
    'suspicious imports: ...'), so the query and the corpus partially share an
    embedding space.
    """
    parts: list[str] = []
    imps = _mabel_val(row, "standardized_import_functions_sorted")
    if imps:
        names = [t for t in imps.split() if t][:_MABEL_MAX_IMPORTS]
        if names:
            parts.append("suspicious imports: " + ", ".join(names))
    capa = _mabel_val(row, "capa_capability_name")
    if capa:
        caps = [c.strip() for c in capa.split(";") if c.strip()][:_MABEL_MAX_CAPA]
        if caps:
            parts.append("capabilities: " + "; ".join(caps))
    yara = _mabel_val(row, "yara_capabilities")
    if yara:
        tags = [t.strip() for t in yara.split(";") if t.strip()][:_MABEL_MAX_YARA]
        if tags:
            parts.append("yara: " + ", ".join(tags))
    return "; ".join(parts)


def _cases_from_mabel(paths: list[str], max_per_family: int) -> list[dict]:
    """Transform MABEL feature-CSV rows into ATT&CK case-corpus rows.

    Each row -> one case: sample_id = sha256, summary_text from imports + capa +
    yara tags, technique_ids parsed from the capa-derived ``mitre_attack_id`` column,
    category from the yara_* family-class columns. ``max_per_family`` bounds the corpus
    so the runtime index does not embed all ~74k labelled rows at load.
    """
    csv.field_size_limit(10**8)  # MABEL packs large multi-value cells
    rows: list[dict] = []
    per_family: dict[str, int] = {}
    for p in paths:
        with open(p, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            if "mitre_attack_id" not in (reader.fieldnames or []):
                print(f"  skip {p}: no 'mitre_attack_id' column.", flush=True)
                continue
            for row in reader:
                fam = (row.get("family_name") or "").strip()
                if max_per_family > 0 and per_family.get(fam, 0) >= max_per_family:
                    continue
                techs = list(dict.fromkeys(_MABEL_TID.findall(row.get("mitre_attack_id") or "")))
                if not techs:
                    continue
                summary = _mabel_summary(row)
                if not summary:
                    continue
                rows.append(
                    {
                        "sample_id": (row.get("sha256_hash") or "").strip(),
                        "summary_text": summary,
                        "technique_ids": techs,
                        "malware_category": _mabel_category(row),
                    }
                )
                per_family[fam] = per_family.get(fam, 0) + 1
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the ATT&CK case-prior RAG corpus.")
    ap.add_argument("--qdrant-url", type=str, help="Live Qdrant URL to scroll the LTM from.")
    ap.add_argument("--collection", type=str, default="maljan_cases_v2", help="LTM collection.")
    ap.add_argument("--cases-jsonl", type=str, help="JSONL export (one StoredCase per line).")
    ap.add_argument(
        "--mabel-csv", nargs="+", help="MABEL feature CSV segment(s) to mine (capa->ATT&CK)."
    )
    ap.add_argument(
        "--max-per-family", type=int, default=12, help="Cap cases per family (MABEL mode)."
    )
    ap.add_argument("--out", type=str, default="data/attck_case_corpus_v1.json")
    ap.add_argument("--min-techniques", type=int, default=1, help="Drop cases with fewer.")
    args = ap.parse_args()

    if not args.qdrant_url and not args.cases_jsonl and not args.mabel_csv:
        print("ERROR: pass --qdrant-url, --cases-jsonl, or --mabel-csv.", file=sys.stderr)
        return 2

    rows: list[dict] = []
    if args.qdrant_url:
        try:
            rows.extend(_cases_from_qdrant(args.qdrant_url, args.collection))
        except Exception as exc:  # noqa: BLE001 - operator-facing, report and bail
            print(f"ERROR: Qdrant scroll failed ({exc}).", file=sys.stderr)
            return 1
    if args.cases_jsonl:
        path = Path(args.cases_jsonl)
        if not path.is_file():
            print(f"ERROR: --cases-jsonl not found: {path}", file=sys.stderr)
            return 2
        rows.extend(_cases_from_jsonl(path))
    if args.mabel_csv:
        missing = [p for p in args.mabel_csv if not Path(p).is_file()]
        if missing:
            print(f"ERROR: --mabel-csv file(s) not found: {missing}", file=sys.stderr)
            return 2
        rows.extend(_cases_from_mabel(args.mabel_csv, args.max_per_family))

    # De-duplicate by sample_id (keep last) and apply the technique floor.
    by_id: dict[str, dict] = {}
    anonymous: list[dict] = []
    for r in rows:
        if len(r["technique_ids"]) < args.min_techniques:
            continue
        sid = r["sample_id"]
        if sid:
            by_id[sid] = r
        else:
            anonymous.append(r)
    cases = list(by_id.values()) + anonymous
    if not cases:
        print(
            f"ERROR: no case met --min-techniques={args.min_techniques} "
            "(empty LTM or all cases below the floor).",
            file=sys.stderr,
        )
        return 1

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(
            {
                "schema": _CORPUS_SCHEMA,
                "embed_model": _EMBED_MODEL,
                "cases": cases,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Wrote {out_path}: {len(cases)} case behaviours.", flush=True)
    print(
        "Enable at runtime with PREPROCESSING__USE_ATTCK_CASE_RAG=true and "
        f"PREPROCESSING__ATTCK_CASE_CORPUS_PATH={out_path}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
