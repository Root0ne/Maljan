"""The doors the unit tree holds, and the proof that they are held.

A guard that is installed but never fires is indistinguishable from one that
was never installed, and this one can only fire on the day somebody adds the
test it exists for. So it is asked here directly: the index build refuses and
says which stand-in to use, the embedding model is not reachable at all, the
cache both would write to is somewhere else, and the opt-in opens the first
two for the one test that asks.

The refusal sits at the build rather than at the network fetch because a
machine with a warm bundle cache reaches the same code for the same reason —
a hundred megabytes of JSON and a second of parsing per build — and a guard
that only fires on a cold runner leaves the developer's own suite quietly
paying for it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from maljan.memory import attck_index, attck_loader, embeddings, semantic_attck_index


class TestTheDoorsAreHeld:
    def test_the_index_build_refuses_and_says_what_to_use(self) -> None:
        with pytest.raises(pytest.fail.Exception) as refused:
            attck_loader.load_all_domains()

        assert "built the ATT&CK index" in str(refused.value)
        assert "_Attck" in str(refused.value)

    def test_the_name_the_index_module_bound_at_import_refuses_too(self) -> None:
        """``attck_index`` imported the loader's name, so it holds a second reference."""
        with pytest.raises(pytest.fail.Exception):
            attck_index.load_all_domains()

    def test_the_embedding_model_is_not_reachable(self) -> None:
        """No model is the module's own signal to project bags of words.

        The fallback is what ``embeddings`` ships for an air-gapped install,
        it is deterministic, and it is what the memory layer's tests were
        always about — they compare sentences that share no words.
        """
        assert embeddings._try_load_fastembed() is None
        assert embeddings.encode_batch(["a b c"])[0] != [0.0] * embeddings.EMBED_DIM

    def test_the_refusal_is_not_something_the_pipeline_can_swallow(self) -> None:
        """``knowledge._hybrid_index`` catches ``Exception`` and degrades.

        A guard raising anything it catches would be turned back into the
        silent slow path this exists to make loud.
        """
        with pytest.raises(BaseException) as refused:  # noqa: B017, PT011
            attck_loader.load_all_domains()

        assert not isinstance(refused.value, Exception)


class TestTheCacheIsSomewhereElse:
    """A unit run must not be able to write into the cache the worker reads."""

    @staticmethod
    def _real_dir() -> Path:
        return Path.home() / ".cache" / "maljan" / "attck"

    def test_both_caches_point_away_from_the_home_directory(self) -> None:
        real = self._real_dir()

        for redirected in (
            attck_loader.ATTCK_CACHE_DIR,
            semantic_attck_index._EMB_CACHE_DIR,
            *attck_loader.ATTCK_CACHE_FILES.values(),
            attck_loader.ATTCK_CACHE_FILE,
        ):
            assert real not in Path(redirected).parents
            assert Path(redirected) != real

    def test_building_an_index_leaves_the_real_directory_exactly_as_it_was(self) -> None:
        """The whole point, stated as the thing a reader would check by hand.

        A bag-of-words corpus written into that directory is read back by the
        next live run as though the model had produced it, and the export
        ranks techniques with it.
        """
        real = self._real_dir()
        if not real.is_dir():
            pytest.skip("this machine has no ATT&CK cache to leave alone")

        def listing() -> list[tuple[str, int, int]]:
            return sorted((f.name, f.stat().st_size, f.stat().st_mtime_ns) for f in real.iterdir())

        before = listing()
        index = semantic_attck_index.SemanticATTCKIndex.from_techniques(
            [
                attck_loader.ATTCKTechnique(
                    technique_id="T1055",
                    name="Process Injection",
                    description="Adversaries inject code.",
                    tactic_phases=["defense-evasion"],
                    is_subtechnique=False,
                )
            ]
        )

        assert index._emb, "the index must have built, or this test proves nothing"
        assert listing() == before


class TestTheOptInOpensTheDoors:
    def test_a_test_that_asks_gets_the_real_loader_back(self, real_attck_index: None) -> None:
        """Asked for, and then not used: nothing below reaches the network.

        What is checked is that the guard is out of the way. The loader's own
        error path answers first, because the scheme check runs before any
        socket is opened.
        """
        with pytest.raises(RuntimeError) as refused:
            attck_loader._fetch_bundle("file:///etc/hosts")

        assert "Refusing non-HTTP(S)" in str(refused.value)

    def test_the_cache_stays_this_session_s_own_even_then(self, real_attck_index: None) -> None:
        assert self_dir_is_temporary(attck_loader.ATTCK_CACHE_DIR)
        assert self_dir_is_temporary(semantic_attck_index._EMB_CACHE_DIR)


def self_dir_is_temporary(path: Path) -> bool:
    """Whether this path is somewhere a test session may write."""
    return Path.home() / ".cache" / "maljan" / "attck" != Path(path)
