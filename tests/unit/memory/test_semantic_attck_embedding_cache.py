"""Embedding the ATT&CK corpus is recomputation, and it was not cheap.

Measured in the worker container on 2026-07-28: building the hybrid index
embeds 697 technique descriptions, costs **+1317 MB** of resident memory and
**105 seconds**, and never gives the memory back — fastembed's onnxruntime
arena grows to fit the largest inference it has seen and does not shrink, so
``malloc_trim`` reclaimed 2 MB of it. The judge node holds the index as a
process-wide singleton, so every worker paid it once and kept it for life. It
was the single largest term in that node's ~1.4 GB footprint.

The corpus is static between ATT&CK releases and the vectors are a pure
function of it, so this file pins the properties that make caching them safe.
The dangerous failure is not a slow cache miss — it is a cache *hit* that
serves vectors for a corpus that has since changed, because nothing downstream
would notice: search would keep returning plausible techniques, scored against
the wrong text.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from maljan.memory import semantic_attck_index as sai
from maljan.memory.attck_loader import ATTCKTechnique
from maljan.memory.semantic_attck_index import SemanticATTCKIndex


def _tech(
    tid: str, name: str = "Process Injection", desc: str = "Adversaries inject code."
) -> ATTCKTechnique:
    return ATTCKTechnique(
        technique_id=tid,
        name=name,
        description=desc,
        tactic_phases=["defense-evasion"],
        is_subtechnique="." in tid,
    )


def _fake_vectors(n: int) -> list[list[float]]:
    """Deterministic unit-ish vectors of the real width, so a cached round-trip
    is comparable byte for byte without loading a 190 MB model in a unit test."""
    dim = sai.embeddings.EMBED_DIM
    return [[float((i + j) % 7) / 10.0 for j in range(dim)] for i in range(n)]


class TestTheCacheRoundTripsExactly:
    def test_a_second_build_reuses_the_vectors_and_does_not_embed(self, tmp_path: Path) -> None:
        techs = [_tech("T1055"), _tech("T1056.001", "Keylogging", "Log keystrokes.")]
        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path):
            with patch.object(
                sai.embeddings, "encode_batch", return_value=_fake_vectors(2)
            ) as first:
                a = SemanticATTCKIndex.from_techniques(techs)
            assert first.call_count == 1, "the cold build must embed"

            with patch.object(sai.embeddings, "encode_batch") as second:
                b = SemanticATTCKIndex.from_techniques(techs)
            second.assert_not_called()

        assert a._emb == b._emb, "a cached vector must be identical, not merely close"
        assert set(b._emb) == {"T1055", "T1056.001"}


class TestTheCacheCannotOutliveItsCorpus:
    """The ATT&CK bundle auto-refreshes every 30 days. A cache keyed on
    anything looser than the corpus itself would silently serve the previous
    release's vectors, and search would keep answering — wrongly."""

    def test_changed_technique_text_misses_the_cache(self, tmp_path: Path) -> None:
        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path):
            with patch.object(sai.embeddings, "encode_batch", return_value=_fake_vectors(1)):
                SemanticATTCKIndex.from_techniques([_tech("T1055", desc="old text")])
            with patch.object(
                sai.embeddings, "encode_batch", return_value=_fake_vectors(1)
            ) as again:
                SemanticATTCKIndex.from_techniques([_tech("T1055", desc="NEW text")])
            again.assert_called_once()

    def test_an_added_technique_misses_the_cache(self, tmp_path: Path) -> None:
        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path):
            with patch.object(sai.embeddings, "encode_batch", return_value=_fake_vectors(1)):
                SemanticATTCKIndex.from_techniques([_tech("T1055")])
            with patch.object(
                sai.embeddings, "encode_batch", return_value=_fake_vectors(2)
            ) as again:
                SemanticATTCKIndex.from_techniques([_tech("T1055"), _tech("T1059")])
            again.assert_called_once()

    def test_a_different_embedding_width_misses_the_cache(self, tmp_path: Path) -> None:
        """A model swap changes the vector space. Reusing the old vectors would
        score every technique against a different geometry."""
        techs = [_tech("T1055")]
        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path):
            with patch.object(sai.embeddings, "encode_batch", return_value=_fake_vectors(1)):
                SemanticATTCKIndex.from_techniques(techs)
            key_before = sai._corpus_key(["T1055"], [techs[0].searchable_text])
            with patch.object(sai.embeddings, "EMBED_DIM", 768):
                key_after = sai._corpus_key(["T1055"], [techs[0].searchable_text])
        assert key_before != key_after

    def test_stale_keys_are_swept_so_the_dir_does_not_grow_per_release(
        self, tmp_path: Path
    ) -> None:
        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path):
            with patch.object(sai.embeddings, "encode_batch", return_value=_fake_vectors(1)):
                SemanticATTCKIndex.from_techniques([_tech("T1055", desc="v1")])
            with patch.object(sai.embeddings, "encode_batch", return_value=_fake_vectors(1)):
                SemanticATTCKIndex.from_techniques([_tech("T1055", desc="v2")])
        assert len(list(tmp_path.glob("embeddings-*.json"))) == 1


class TestABrokenCacheDegradesInsteadOfFailing:
    """A cache that can break an analysis is worse than no cache. Every failure
    path here must fall back to embedding, which is exactly what the code did
    before the cache existed."""

    def test_corrupt_json_falls_back_to_embedding(self, tmp_path: Path) -> None:
        techs = [_tech("T1055")]
        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path):
            with patch.object(sai.embeddings, "encode_batch", return_value=_fake_vectors(1)):
                SemanticATTCKIndex.from_techniques(techs)
            for f in tmp_path.glob("embeddings-*.json"):
                f.write_text("{not json", encoding="utf-8")
            with patch.object(
                sai.embeddings, "encode_batch", return_value=_fake_vectors(1)
            ) as again:
                idx = SemanticATTCKIndex.from_techniques(techs)
            again.assert_called_once()
        assert idx._emb

    def test_a_cache_missing_one_technique_is_rejected_whole(self, tmp_path: Path) -> None:
        """Not partially usable: search would score the absent technique as
        missing and quietly stop being able to correct an id to it."""
        techs = [_tech("T1055"), _tech("T1059")]
        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path):
            with patch.object(sai.embeddings, "encode_batch", return_value=_fake_vectors(2)):
                SemanticATTCKIndex.from_techniques(techs)
            path = next(tmp_path.glob("embeddings-*.json"))
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw["vectors"].pop("T1059")
            path.write_text(json.dumps(raw), encoding="utf-8")
            with patch.object(
                sai.embeddings, "encode_batch", return_value=_fake_vectors(2)
            ) as again:
                SemanticATTCKIndex.from_techniques(techs)
            again.assert_called_once()

    def test_a_wrong_width_vector_is_rejected(self, tmp_path: Path) -> None:
        techs = [_tech("T1055")]
        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path):
            with patch.object(sai.embeddings, "encode_batch", return_value=_fake_vectors(1)):
                SemanticATTCKIndex.from_techniques(techs)
            path = next(tmp_path.glob("embeddings-*.json"))
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw["vectors"]["T1055"] = [0.1, 0.2]
            path.write_text(json.dumps(raw), encoding="utf-8")
            with patch.object(
                sai.embeddings, "encode_batch", return_value=_fake_vectors(1)
            ) as again:
                SemanticATTCKIndex.from_techniques(techs)
            again.assert_called_once()

    def test_an_unwritable_cache_dir_does_not_fail_the_build(self, tmp_path: Path) -> None:
        blocked = tmp_path / "nope"
        blocked.write_text("I am a file, not a directory", encoding="utf-8")
        with patch.object(sai, "_EMB_CACHE_DIR", blocked):
            with patch.object(sai.embeddings, "encode_batch", return_value=_fake_vectors(1)):
                idx = SemanticATTCKIndex.from_techniques([_tech("T1055")])
        assert idx._emb, "the index must still build when the cache cannot be written"
