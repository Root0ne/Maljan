"""Function-RAG retrieval quality A/B (findings-log §4 Item 2, TraceRAG).

Measures whether behavior-query retrieval over a sample's function chunks selects
the *malicious* functions while discarding benign filler — and how much input
token volume that saves vs feeding every chunk (the linear baseline).

This harness is **offline** (no LLM): it builds a synthetic corpus of one
malicious function per behavior cluster plus ``--filler`` benign functions, runs
the production ``select_relevant_chunks`` retrieval, and reports:
  * **recall** — fraction of seeded malicious functions retrieved,
  * **precision** — fraction of retrieved chunks that are malicious,
  * **token reduction** — 1 - (fed tokens / all tokens).
The retrieval core is the same code the static analyst uses in production; the
LLM-in-the-loop claim-quality comparison is the natural follow-up once this shows
retrieval keeps the malicious core.

Run:  uv run python tests/evaluation/eval_function_rag.py [--filler N] [--top-k K] [--smoke]
"""

# Bootstraps sys.path before first-party imports (E402 is intentional here).
# ruff: noqa: E402

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk
from maljan.memory.function_index import BEHAVIOR_QUERIES, select_relevant_chunks

_OUT_FILE = Path("D:/tmp/function_rag.md")

# One malicious function per behavior cluster (the seeded "core").
_MALICIOUS: list[tuple[str, str]] = [
    ("inject", "WriteProcessMemory CreateRemoteThread VirtualAllocEx into a remote process"),
    ("persist", "RegSetValueEx CurrentVersion Run autostart registry persistence key"),
    ("beacon", "WinHttpConnect periodic callback to a remote command-and-control server"),
    ("steal", "read stored browser credentials and exfiltrate saved passwords"),
    ("evade", "IsDebuggerPresent anti-VM timing check sandbox detection evasion"),
    ("encrypt", "CryptEncrypt AES ransomware loop encrypting files across directories"),
]

# Benign filler function templates (string utils, getters, math — no malicious intent).
_FILLER_TEMPLATES: list[str] = [
    "strlen helper computing the length of a null-terminated buffer",
    "getter returning a cached configuration integer field",
    "memcpy wrapper copying bytes between two local stack buffers",
    "format a timestamp into a human-readable date string",
    "compare two version structs and return an ordering integer",
    "allocate and zero a small fixed-size lookup table",
]


def _chunk(index: int, name: str, body: str, total: int) -> TextChunk:
    content = f"/// Function: {name}\n{body}"
    return TextChunk(
        index=index,
        total=total,
        strategy=ChunkStrategy.FUNCTION_BOUNDARY,
        content=content,
        char_count=len(content),
        token_estimate=max(1, len(content) // 4),
        domain="static",
    )


def _build_corpus(filler: int) -> tuple[list[TextChunk], set[int]]:
    """Return (chunks, indices_of_malicious_chunks)."""
    chunks: list[TextChunk] = []
    malicious_idx: set[int] = set()
    total = len(_MALICIOUS) + filler
    i = 0
    for name, body in _MALICIOUS:
        chunks.append(_chunk(i, name, body, total))
        malicious_idx.add(i)
        i += 1
    for f in range(filler):
        body = _FILLER_TEMPLATES[f % len(_FILLER_TEMPLATES)]
        chunks.append(_chunk(i, f"util_{f}", body, total))
        i += 1
    return chunks, malicious_idx


def main() -> None:
    ap = argparse.ArgumentParser(description="Function-RAG retrieval quality A/B (offline).")
    ap.add_argument("--filler", type=int, default=30, help="Benign filler functions.")
    ap.add_argument("--top-k", type=int, default=2, help="Top-k chunks per behavior query.")
    ap.add_argument("--smoke", action="store_true", help="Tiny corpus sanity run.")
    args = ap.parse_args()

    filler = 4 if args.smoke else args.filler
    top_k = args.top_k

    chunks, malicious_idx = _build_corpus(filler)
    selected = select_relevant_chunks(chunks, top_k)
    sel_idx = {c.index for c in selected}

    hit = len(sel_idx & malicious_idx)
    recall = hit / len(malicious_idx) if malicious_idx else 0.0
    precision = hit / len(sel_idx) if sel_idx else 0.0
    all_tokens = sum(c.token_estimate for c in chunks)
    fed_tokens = sum(c.token_estimate for c in selected)
    reduction = 1.0 - (fed_tokens / all_tokens) if all_tokens else 0.0

    lines = [
        "# Function-RAG retrieval quality (offline, §4 Item 2)",
        "",
        f"- Corpus: {len(_MALICIOUS)} malicious + {filler} benign = {len(chunks)} function chunks.",
        f"- Retrieval: top-{top_k} per behavior query ({len(BEHAVIOR_QUERIES)} queries), union.",
        "",
        "| metric | value |",
        "|---|---|",
        f"| malicious functions seeded | {len(malicious_idx)} |",
        f"| chunks selected (fed to analyst) | {len(sel_idx)} / {len(chunks)} |",
        f"| malicious recall | {recall:.3f} |",
        f"| selection precision | {precision:.3f} |",
        f"| token reduction | {reduction:.1%} |",
        "",
        "Interpretation: high recall + high token reduction = retrieval keeps the",
        "malicious core while dropping benign filler. Low recall warns that behavior",
        "queries miss a capability cluster (add/adjust BEHAVIOR_QUERIES).",
    ]
    report = "\n".join(lines)
    print("\n" + report, flush=True)
    try:
        _OUT_FILE.write_text(report + "\n", encoding="utf-8")
        print(f"\nWrote {_OUT_FILE}", flush=True)
    except OSError:
        pass


if __name__ == "__main__":
    main()
