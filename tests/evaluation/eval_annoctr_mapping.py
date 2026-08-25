"""Does the rank-vs-gate result replicate on a second, independent corpus?

§1.5.1 measured three ATT&CK index backends on TRAM2 (N=4,913) and concluded that
*ranking* quality and *gate* quality are separate axes: semantic embeddings rank better
but their scores barely separate a correct pick from a wrong one, TF-IDF ranks worse but
gates cleanly, and a hybrid takes both. That conclusion is one of the few claims the
2026-08-08 literature review left standing as ours — and it rests on a single corpus.

It also has a specific vulnerability. TRAM2 sentences are short and were annotated for
a technique-classification task, so a lexical gate has an easy job: the sentence often
names the behaviour in ATT&CK's own words. If the gate separation is an artifact of that
register rather than a property of the method, the claim does not survive contact with
real report prose.

**AnnoCTR** (Lange et al., LREC-COLING 2024, CC-BY-SA 4.0) is the test. It is expert-
annotated *entity linking* over whole threat reports, not sentence classification: a
mention in running prose is linked to an ATT&CK entity, so the evidence text is whatever
the analyst actually wrote around it. Different annotators, different documents,
different task — an honest generalisation test rather than a second sample of the same
thing.

Non-circularity holds for the same reason it held on TRAM2: the *text* comes from real
threat reports written independently of the ATT&CK catalogue, and the *label* is a human
judgement. The index is built from ATT&CK descriptions, which is what makes scoring
against those descriptions circular and scoring against this corpus not.

Deliberately reuses ``eval_technique_mapping._evaluate`` rather than reimplementing the
metrics. A replication that quietly redefines its measure is not a replication.

No LLM, no sandbox. Needs the corpus:

    git clone --depth 1 https://github.com/boschresearch/anno-ctr-lrec-coling-2024 \
        data/external/annoctr

Run:
    uv run python tests/evaluation/eval_annoctr_mapping.py \
        --out tests/evaluation/annoctr_mapping.json
"""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (_REPO_ROOT, _REPO_ROOT / "src", Path(__file__).resolve().parent):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from eval_technique_mapping import _embedding_backend_note, _evaluate

from maljan.memory.attck_index import ATTCKIndex
from maljan.memory.hybrid_attck_index import HybridATTCKIndex
from maljan.memory.semantic_attck_index import SemanticATTCKIndex

_TECHNIQUE_URL = re.compile(r"attack\.mitre\.org/techniques/(T\d{4})(?:/(\d{3}))?")

_DEFAULT_CORPUS = "data/external/annoctr/AnnoCTR/linking_mitre_only"


def _iter_json_objects(raw: str):
    """AnnoCTR's ``.jsonl`` files are pretty-printed objects, not one per line.

    Decoding them line-by-line fails on the second line. Streaming with
    ``raw_decode`` reads them regardless of how they are wrapped, and keeps working
    if a future release switches to true JSON Lines.
    """
    decoder = json.JSONDecoder()
    i, n = 0, len(raw)
    while i < n:
        while i < n and raw[i] in " \r\n\t":
            i += 1
        if i >= n:
            break
        obj, i = decoder.raw_decode(raw, i)
        yield obj


def _technique_id(link: str | None) -> str | None:
    """``…/techniques/T1574/002`` → ``T1574.002``; sub-technique form is preserved."""
    if not link:
        return None
    m = _TECHNIQUE_URL.search(link)
    if not m:
        return None
    return f"{m.group(1)}.{m.group(2)}" if m.group(2) else m.group(1)


def load_pairs(corpus_dir: Path, splits: tuple[str, ...]) -> list[tuple[str, str]]:
    """``(evidence_text, technique_id)`` for every technique-linked mention.

    The evidence text is the mention **in its written context** — left context, the
    mention, right context — because that is what a production claim looks like and
    what the index would actually be handed. Using the mention alone would measure
    something easier than the task.
    """
    pairs: list[tuple[str, str]] = []
    for split in splits:
        path = corpus_dir / f"{split}.jsonl"
        if not path.is_file():
            continue
        for obj in _iter_json_objects(path.read_text(encoding="utf-8")):
            tid = _technique_id(obj.get("label_link"))
            if not tid:
                continue
            text = " ".join(
                part.strip()
                for part in (
                    (obj.get("context_left") or "")[-400:],
                    obj.get("mention") or "",
                    (obj.get("context_right") or "")[:400],
                )
                if part and part.strip()
            )
            if text.strip():
                pairs.append((text, tid))
    return pairs


def restrict_to_index(
    pairs: list[tuple[str, str]], index: ATTCKIndex
) -> tuple[list[tuple[str, str]], int]:
    """Drop pairs whose label the index cannot possibly return.

    AnnoCTR links to whatever ATT&CK version its annotators used; a label that is
    revoked, or absent from our bundle, is unreachable for *every* backend. Scoring
    those would depress all three equally and add nothing — but silently dropping
    them would misreport coverage, so the count is returned and published.
    """
    known = {t.upper() for t in index.techniques}
    kept = [(t, lab) for t, lab in pairs if lab.upper() in known]
    return kept, len(pairs) - len(kept)


def _sep(m: dict[str, float]) -> float:
    return m["mean_correct_score"] - m["mean_wrong_top1_score"]


def main() -> int:
    ap = argparse.ArgumentParser(description="External replication of §1.5.1 on AnnoCTR.")
    ap.add_argument("--corpus-dir", type=str, default=_DEFAULT_CORPUS)
    ap.add_argument(
        "--splits",
        type=str,
        default="train,dev,test",
        help="AnnoCTR is used purely as an evaluation corpus — nothing is trained, so "
        "every split is legitimate test data for us.",
    )
    ap.add_argument("--limit", type=int, default=0, help="even-stride sample (0 = all)")
    ap.add_argument("--out", type=str, default="tests/evaluation/annoctr_mapping.json")
    args = ap.parse_args()

    corpus_dir = Path(args.corpus_dir)
    if not corpus_dir.is_dir():
        print(f"ERROR: corpus not found at {corpus_dir}", file=sys.stderr)
        print("Clone it — see the module docstring.", file=sys.stderr)
        return 2

    splits = tuple(s.strip() for s in args.splits.split(",") if s.strip())
    pairs = load_pairs(corpus_dir, splits)
    print(f"AnnoCTR: {len(pairs)} technique-linked mentions from {splits}", flush=True)
    if not pairs:
        print("ERROR: no technique-linked pairs parsed", file=sys.stderr)
        return 2

    print("building TF-IDF index ...", flush=True)
    tfidf = ATTCKIndex.from_loader()
    pairs, dropped = restrict_to_index(pairs, tfidf)
    print(f"  {len(pairs)} scoreable ({dropped} labels not in our ATT&CK bundle)", flush=True)

    if args.limit and args.limit < len(pairs):
        stride = len(pairs) / args.limit
        pairs = [pairs[int(i * stride)] for i in range(args.limit)]
        print(f"  sampled to {len(pairs)} at even stride", flush=True)

    note = _embedding_backend_note()
    print(note, flush=True)

    print("building semantic index ...", flush=True)
    semantic = SemanticATTCKIndex.from_loader()
    print("building hybrid index ...", flush=True)
    hybrid = HybridATTCKIndex.from_loader()

    print("scoring tfidf ...", flush=True)
    tf = _evaluate(tfidf, tfidf, pairs)
    print("scoring semantic ...", flush=True)
    se = _evaluate(semantic, semantic, pairs)
    print("scoring hybrid ...", flush=True)
    hy = _evaluate(hybrid, hybrid, pairs)

    # §1.5.1's TRAM2 numbers, for the only comparison that matters: does the ordering
    # hold on a corpus with a different register and different annotators?
    # Read, not transcribed. These three rows were a literal in this file, and
    # the paper printed them as TRAM2's result: a re-run of that corpus would
    # have moved the record and left this copy standing.
    tram2_artefact = Path(__file__).resolve().parent / "technique_mapping.json"
    if not tram2_artefact.exists():
        print(
            f"ERROR: {tram2_artefact.name} not found; run eval_technique_mapping.py first",
            file=sys.stderr,
        )
        return 2
    tram2 = {
        backend: {k: v for k, v in row.items() if not k.startswith("gate_scores_")}
        for backend, row in json.loads(tram2_artefact.read_text(encoding="utf-8"))["tram2"].items()
    }

    result = {
        "schema": "maljan-annoctr-mapping/v1",
        "corpus": {
            "name": "AnnoCTR (Lange et al., LREC-COLING 2024), CC-BY-SA 4.0",
            "splits": list(splits),
            "pairs_scored": len(pairs),
            "labels_outside_our_attck_bundle": dropped,
        },
        "embedding_backend": note,
        "annoctr": {
            "tfidf": {**tf, "gate_separation": _sep(tf)},
            "semantic": {**se, "gate_separation": _sep(se)},
            "hybrid": {**hy, "gate_separation": _sep(hy)},
        },
        "tram2_reference": tram2,
        "replication": {
            "ranking_order_holds": (se["top3"] > tf["top3"]) and (hy["top3"] >= se["top3"]),
            "gate_order_holds": _sep(hy) > _sep(tf) > _sep(se),
            "hybrid_wins_both_axes": (hy["top3"] >= se["top3"]) and (_sep(hy) > _sep(tf)),
        },
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print()
    print("| backend | top-1 | top-3 | MRR | gate sep | TRAM2 gate sep |")
    print("|---|---|---|---|---|---|")
    for name, m in (("TF-IDF", tf), ("semantic", se), ("hybrid", hy)):
        key = name.lower().replace("-", "").replace("tfidf", "tfidf")
        ref = tram2.get("tfidf" if name == "TF-IDF" else key, {})
        print(
            f"| {name} | {m['top1']:.3f} | {m['top3']:.3f} | {m['mrr']:.3f} | "
            f"{_sep(m):+.3f} | {ref.get('gate_separation', float('nan')):+.3f} |"
        )
    print()
    print("replication:", json.dumps(result["replication"]))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
