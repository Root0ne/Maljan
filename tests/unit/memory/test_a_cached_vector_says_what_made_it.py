"""Two backends, the same 384 numbers, and nothing on disk telling them apart.

``embeddings`` ships a bag-of-words projection for the case where the model
cannot be loaded, and it projects into the model's own dimension so the vector
store's schema stays stable. The embedding cache keyed on version, dimension
and corpus, and the file it wrote recorded version and dimension — so a process
that could not load the model wrote a bag-of-words corpus into
``~/.cache/maljan/attck``, deleted every other file there as stale, and the
next process logged "reused cached embeddings" and ranked techniques with it.
It is durable, it is shared, and nothing about it looks wrong.

What produced a vector is part of what the vector is. Three consequences, all
from the one fact ``embeddings.active_backend`` answers: it is in the key, it
is in the stored header, and a run on the fallback neither stores nor sweeps.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maljan.memory import embeddings
from maljan.memory import semantic_attck_index as sai
from maljan.memory.attck_loader import ATTCKTechnique
from maljan.memory.semantic_attck_index import SemanticATTCKIndex

MODEL = embeddings.model_backend_id()
FALLBACK = embeddings.FALLBACK_BACKEND


def _tech(tid: str = "T1055") -> ATTCKTechnique:
    return ATTCKTechnique(
        technique_id=tid,
        name="Process Injection",
        description="Adversaries inject code.",
        tactic_phases=["defense-evasion"],
        is_subtechnique="." in tid,
    )


def _vectors(n: int) -> list[list[float]]:
    dim = embeddings.EMBED_DIM
    return [[float((i + j) % 7) / 10.0 for j in range(dim)] for i in range(n)]


@contextmanager
def _embedding_with(backend: str, vectors: list[list[float]]) -> Iterator[MagicMock]:
    """Run the block as though ``backend`` produced ``vectors``."""
    with (
        patch.object(sai.embeddings, "active_backend", return_value=backend),
        patch.object(
            sai.embeddings, "encode_batch_with_backend", return_value=(vectors, backend)
        ) as embedded,
    ):
        yield embedded


def _files(where: Path) -> list[Path]:
    return sorted(where.glob("embeddings-*.json"))


def _header(path: Path) -> dict[str, object]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in raw.items() if k != "vectors"}


class TestWhatTheKeyAndTheHeaderCarry:
    def test_the_two_backends_do_not_share_a_key(self) -> None:
        with patch.object(sai.embeddings, "active_backend", return_value=MODEL):
            from_model = sai._corpus_key(["T1055"], ["text"])
        with patch.object(sai.embeddings, "active_backend", return_value=FALLBACK):
            from_fallback = sai._corpus_key(["T1055"], ["text"])

        assert from_model != from_fallback

    def test_a_stored_file_says_what_made_it(self, tmp_path: Path) -> None:
        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path), _embedding_with(MODEL, _vectors(1)):
            SemanticATTCKIndex.from_techniques([_tech()])

        assert _header(_files(tmp_path)[0]) == {
            "version": sai._EMB_CACHE_VERSION,
            "dim": embeddings.EMBED_DIM,
            "backend": MODEL,
        }


class TestAFallbackRunLeavesNoTrace:
    def test_its_vectors_are_never_written(self, tmp_path: Path) -> None:
        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path), _embedding_with(FALLBACK, _vectors(1)):
            index = SemanticATTCKIndex.from_techniques([_tech()])

        assert index._emb, "the run still gets its vectors"
        assert _files(tmp_path) == []

    def test_it_does_not_reuse_the_model_s_cache(self, tmp_path: Path) -> None:
        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path), _embedding_with(MODEL, _vectors(1)):
            SemanticATTCKIndex.from_techniques([_tech()])
        written = _files(tmp_path)[0]

        with (
            patch.object(sai, "_EMB_CACHE_DIR", tmp_path),
            _embedding_with(FALLBACK, _vectors(1)) as embedded,
        ):
            SemanticATTCKIndex.from_techniques([_tech()])

        embedded.assert_called_once()
        assert _files(tmp_path) == [written]

    def test_it_does_not_delete_the_model_s_cache(self, tmp_path: Path) -> None:
        """The sweep is the dangerous half: a fallback run used to clear the lot."""
        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path), _embedding_with(MODEL, _vectors(1)):
            SemanticATTCKIndex.from_techniques([_tech()])
        before = {p.name: p.read_bytes() for p in _files(tmp_path)}

        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path), _embedding_with(FALLBACK, _vectors(1)):
            SemanticATTCKIndex.from_techniques([_tech("T1059")])

        assert {p.name: p.read_bytes() for p in _files(tmp_path)} == before


class TestAFileThatDoesNotSayIsNotTrusted:
    """Every file written before the field existed, including the poisoned one."""

    @staticmethod
    def _unlabelled(where: Path, key: str, tids: list[str]) -> Path:
        path = where / f"embeddings-{key[:32]}.json"
        path.write_text(
            json.dumps(
                {
                    "version": sai._EMB_CACHE_VERSION,
                    "dim": embeddings.EMBED_DIM,
                    "vectors": dict(zip(tids, _vectors(len(tids)), strict=True)),
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_it_is_re_embedded_rather_than_reused(self, tmp_path: Path) -> None:
        with patch.object(sai.embeddings, "active_backend", return_value=MODEL):
            key = sai._corpus_key(["T1055"], [_tech().searchable_text])
        self._unlabelled(tmp_path, key, ["T1055"])

        with (
            patch.object(sai, "_EMB_CACHE_DIR", tmp_path),
            _embedding_with(MODEL, _vectors(1)) as embedded,
        ):
            SemanticATTCKIndex.from_techniques([_tech()])

        embedded.assert_called_once()

    def test_a_real_backend_write_may_replace_it(self, tmp_path: Path) -> None:
        with patch.object(sai.embeddings, "active_backend", return_value=MODEL):
            key = sai._corpus_key(["T9999"], ["something else"])
        stale = self._unlabelled(tmp_path, key, ["T9999"])

        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path), _embedding_with(MODEL, _vectors(1)):
            SemanticATTCKIndex.from_techniques([_tech()])

        assert not stale.exists()
        assert len(_files(tmp_path)) == 1

    def test_a_fallback_run_may_not(self, tmp_path: Path) -> None:
        with patch.object(sai.embeddings, "active_backend", return_value=MODEL):
            key = sai._corpus_key(["T9999"], ["something else"])
        stale = self._unlabelled(tmp_path, key, ["T9999"])

        with patch.object(sai, "_EMB_CACHE_DIR", tmp_path), _embedding_with(FALLBACK, _vectors(1)):
            SemanticATTCKIndex.from_techniques([_tech()])

        assert stale.exists()


class TestTheHeaderIsAskedEvenOnTheSameKey:
    def test_a_file_whose_backend_differs_is_ignored_and_said_so(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The key carries the backend, so this is belt and braces — and it is
        what answers a file copied between machines or written by a version of
        this code that keyed it differently."""
        with patch.object(sai.embeddings, "active_backend", return_value=FALLBACK):
            key = sai._corpus_key(["T1055"], [_tech().searchable_text])
        path = tmp_path / f"embeddings-{key[:32]}.json"
        path.write_text(
            json.dumps(
                {
                    "version": sai._EMB_CACHE_VERSION,
                    "dim": embeddings.EMBED_DIM,
                    "backend": MODEL,
                    "vectors": {"T1055": _vectors(1)[0]},
                }
            ),
            encoding="utf-8",
        )

        with (
            patch.object(sai, "_EMB_CACHE_DIR", tmp_path),
            _embedding_with(FALLBACK, _vectors(1)) as embedded,
        ):
            SemanticATTCKIndex.from_techniques([_tech()])

        embedded.assert_called_once()
        assert any("ignoring the cached embeddings" in m for m in caplog.messages)
