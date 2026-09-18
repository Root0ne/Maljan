"""The two doors the unit tree holds shut, and the proof that they are shut.

A guard that is installed but never fires is indistinguishable from one that
was never installed, and this one can only fire on the day somebody adds the
test it exists for. So it is asked here directly: the corpus download refuses
and says which stand-in to use, the embedding model is not reachable at all,
and the opt-out opens both for the one test that asks.
"""

from __future__ import annotations

import pytest

from maljan.memory import attck_loader, embeddings

_A_BUNDLE_URL = "https://attack.example/enterprise-attack.json"


class TestTheDoorsRefuse:
    def test_the_corpus_download_refuses_and_says_what_to_use(self) -> None:
        with pytest.raises(pytest.fail.Exception) as refused:
            attck_loader._fetch_bundle(_A_BUNDLE_URL)

        assert "over the network" in str(refused.value)
        assert "_Attck" in str(refused.value)

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
            attck_loader._fetch_bundle(_A_BUNDLE_URL)

        assert not isinstance(refused.value, Exception)


class TestTheOptOutOpensThem:
    def test_a_test_that_asks_gets_the_real_functions_back(self, real_attck_index: None) -> None:
        """Asked for, and then not used: the URL below is never fetched.

        What is checked is that the guard is out of the way, which is what the
        opt-out is for. The refusal is a ``RuntimeError`` from the loader's own
        error path, raised before any socket is opened, because the scheme
        check runs first.
        """
        with pytest.raises(RuntimeError) as refused:
            attck_loader._fetch_bundle("file:///etc/hosts")

        assert "Refusing non-HTTP(S)" in str(refused.value)
