"""Semantic embeddings for long-term memory retrieval.

Both ``InMemoryStore`` and ``QdrantStore`` previously used a bag-of-words /
MD5-hash projection that captures surface lexical overlap but no semantic
similarity ("ransomware encrypts files" and "crypto-locker scrambles disk"
score near zero). This module replaces that with a real sentence-embedding
model from `fastembed` (Qdrant's ONNX-Runtime helper).

Design goals:

- **Cheap default**: ``BAAI/bge-small-en-v1.5`` is ~30 MB on disk, 384-dim,
  runs on CPU at ~50 docs/sec on a modern laptop. No GPU required.
- **Single shared instance**: model loading is the expensive part (200 ms).
  Both memory backends call ``encode()`` which lazily builds one instance
  on first use and reuses it across the process.
- **Graceful degradation**: if `fastembed` is not installed, ``encode()``
  falls back to the legacy BoW projection so the pipeline still runs.
  A loud warning is emitted once so operators notice.
- **Stable dimension**: the embedding dimension is exposed as
  ``EMBED_DIM`` so ``QdrantStore`` can validate the collection schema
  without re-importing fastembed.

Upgrade path: swap the ``_MODEL_NAME`` constant for a larger model
(``BAAI/bge-base-en-v1.5`` or a finetuned malware-classification embedder)
or wire a remote `/v1/embeddings` endpoint here — only this file changes.
"""

from __future__ import annotations

import hashlib
import math
import os
import threading
from collections import Counter

from maljan.core.logger import logger

# 384-dim small English embedder. fastembed downloads the ONNX weights on
# first ``TextEmbedding(...)`` construction and caches them under the user
# cache dir.
_MODEL_NAME = "BAAI/bge-small-en-v1.5"
_FASTEMBED_DIM = 384
_FALLBACK_DIM = 384  # match fastembed so the Qdrant collection schema stays stable

EMBED_DIM: int = _FASTEMBED_DIM

# onnxruntime intra-op threads and the batch handed to the model.
#
# These two numbers were the whole of the worker's "memory leak" (2026-07-27).
# The symptom was an arq process climbing from ~3.4 GB to ~8.5 GB during a
# single analysis and never releasing it; on a 30 GB host also running a 15 GB
# llama-server that froze the machine, and once a container limit existed it
# became a cgroup OOM kill mid-job. It is not a leak at all. onnxruntime sizes
# its CPU arena from the *core count* — 32 here — and pre-allocates per thread
# and per batch element, so the default configuration reserves multiple GB up
# front and keeps them for the process lifetime.
#
# Measured on this host, embedding the 697 ATT&CK technique texts (~1.4 KB
# each) in one process:
#
#   threads=default(32), batch=default(256)  ->  8.3 GB, OOM-killed
#   threads=2,           batch=32            ->  1.33 GB, 103 s
#   threads=1,           batch=8             ->  0.51 GB, 153 s
#
# It is a ceiling, not a leak: a second pass over the same corpus added 21 MB
# and a third added 1 MB. So the fix is to pick the ceiling deliberately rather
# than let it be a function of the machine's core count. Two threads keeps the
# once-per-process index build near 100 s while staying an order of magnitude
# below the old peak. Raise ``MALJAN_EMBED_THREADS`` on a host with memory to
# spare.
_EMBED_THREADS = max(1, int(os.environ.get("MALJAN_EMBED_THREADS", "2")))
_EMBED_BATCH = max(1, int(os.environ.get("MALJAN_EMBED_BATCH", "32")))

_lock = threading.Lock()
_model: object | None = None
_fallback_warned = False


def _try_load_fastembed() -> object | None:
    """Return a cached fastembed TextEmbedding instance, or None when unavailable."""
    global _model, _fallback_warned
    if _model is not None:
        return _model
    with _lock:
        if _model is not None:
            return _model
        try:
            from fastembed import TextEmbedding  # type: ignore[import-not-found]

            _model = TextEmbedding(model_name=_MODEL_NAME, threads=_EMBED_THREADS)
            logger.info(
                "Embeddings: loaded fastembed model '%s' (%d-dim, threads=%d, batch=%d).",
                _MODEL_NAME,
                _FASTEMBED_DIM,
                _EMBED_THREADS,
                _EMBED_BATCH,
            )
        except Exception as exc:  # noqa: BLE001
            if not _fallback_warned:
                logger.warning(
                    "Embeddings: fastembed unavailable (%s). Falling back to BoW "
                    "projection — semantic similarity will be poor. Install with "
                    "`uv add fastembed` for real embeddings.",
                    exc,
                )
                _fallback_warned = True
            _model = False  # sentinel: tried and failed
        return _model


def _bow_projection(text: str, dim: int = _FALLBACK_DIM) -> list[float]:
    """Term-frequency vector projected to ``dim`` dimensions via MD5 hashing.

    Kept as a graceful fallback so the pipeline still produces verdicts even
    when fastembed cannot be imported (air-gapped install, missing wheel,
    sandbox without ONNX runtime, etc.).
    """
    tokens = text.lower().split()
    if not tokens:
        return [0.0] * dim
    tf = Counter(tokens)
    vec = [0.0] * dim
    for token, freq in tf.items():
        digest = hashlib.md5(token.encode(), usedforsecurity=False).digest()
        idx = int.from_bytes(digest[:4], "little") % dim
        vec[idx] += float(freq)
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0.0:
        vec = [v / norm for v in vec]
    return vec


def encode(text: str) -> list[float]:
    """Return a ``EMBED_DIM``-dimensional unit vector for the input text.

    Uses fastembed when available, falls back to BoW projection otherwise.
    Always returns a list (never None) so callers can index it directly.
    """
    if not text or not text.strip():
        return [0.0] * EMBED_DIM

    model = _try_load_fastembed()
    if model and model is not False:
        # fastembed.embed() is a generator over numpy arrays — take first item.
        try:
            vectors = list(model.embed([text]))  # type: ignore[attr-defined]
            if vectors:
                # numpy.ndarray.tolist() is typed as Any in stubs we ignore for
                # fastembed; coerce to list[float] explicitly so mypy is happy.
                vec: list[float] = [float(v) for v in vectors[0].tolist()]
                # fastembed already L2-normalizes BGE embeddings; re-normalize
                # defensively if a future model changes the contract.
                norm = math.sqrt(sum(v * v for v in vec))
                if norm == 0.0:
                    return vec
                if abs(norm - 1.0) > 1e-3:
                    vec = [v / norm for v in vec]
                return vec
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Embeddings: fastembed.embed() failed (%s). Falling back to BoW for this call.",
                exc,
            )

    return _bow_projection(text, dim=EMBED_DIM)


def encode_batch(texts: list[str]) -> list[list[float]]:
    """Embed many texts at once, returning one unit vector per input.

    Uses fastembed's native batch path (`model.embed(list)`) which is ~10x
    faster than calling :func:`encode` per string — important when embedding a
    whole corpus (e.g. ~700 ATT&CK techniques) at index-build time. Falls back
    to the per-item path (BoW when fastembed is unavailable). Empty strings map
    to zero vectors. Output order matches input order.
    """
    if not texts:
        return []

    model = _try_load_fastembed()
    if model and model is not False:
        try:
            # fastembed.embed() preserves order and yields one ndarray per input.
            raw = list(model.embed(texts, batch_size=_EMBED_BATCH))  # type: ignore[attr-defined]
            if len(raw) == len(texts):
                out: list[list[float]] = []
                for arr in raw:
                    vec: list[float] = [float(v) for v in arr.tolist()]
                    norm = math.sqrt(sum(v * v for v in vec))
                    if norm and abs(norm - 1.0) > 1e-3:
                        vec = [v / norm for v in vec]
                    out.append(vec)
                return out
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Embeddings: fastembed batch embed failed (%s). Falling back to per-item.",
                exc,
            )

    return [encode(t) for t in texts]


def cosine(a: list[float], b: list[float]) -> float:
    """Return cosine similarity between two equal-length unit vectors.

    Both ``a`` and ``b`` are assumed to be L2-normalized (which ``encode()``
    guarantees) so this reduces to a plain dot product. Handles zero vectors
    by returning 0.0.
    """
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    # Guard against non-normalized fallback paths.
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def reset_cache() -> None:
    """Drop the cached fastembed model. Test helper only."""
    global _model, _fallback_warned
    with _lock:
        _model = None
        _fallback_warned = False
