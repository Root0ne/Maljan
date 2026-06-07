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
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

_CORPUS_SCHEMA = "maljan-attck-case-corpus/v1"
_EMBED_MODEL = "BAAI/bge-small-en-v1.5"  # what the runtime index embeds the text with


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


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the ATT&CK case-prior RAG corpus.")
    ap.add_argument("--qdrant-url", type=str, help="Live Qdrant URL to scroll the LTM from.")
    ap.add_argument("--collection", type=str, default="maljan_cases_v2", help="LTM collection.")
    ap.add_argument("--cases-jsonl", type=str, help="JSONL export (one StoredCase per line).")
    ap.add_argument("--out", type=str, default="data/attck_case_corpus_v1.json")
    ap.add_argument("--min-techniques", type=int, default=1, help="Drop cases with fewer.")
    args = ap.parse_args()

    if not args.qdrant_url and not args.cases_jsonl:
        print("ERROR: pass --qdrant-url or --cases-jsonl.", file=sys.stderr)
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
