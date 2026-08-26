"""The embedder's memory ceiling must be chosen, not inherited from the host.

This is the regression guard for the worker's "memory leak" — which was not a
leak. onnxruntime sizes its CPU arena from the machine's **core count** and
pre-allocates per thread and per batch element, so on a 32-core host the
default configuration reserved multiple GB the moment the ATT&CK hybrid index
embedded its 697 technique texts, and kept them for the life of the process.

Measured on that host, same corpus, same model:

===========================  ==========  =======
configuration                peak RSS    time
===========================  ==========  =======
threads=default, batch=256   8.3 GB      OOM
threads=2, batch=32          1.33 GB     103 s
threads=1, batch=8           0.51 GB     153 s
===========================  ==========  =======

A ceiling, not a leak: a second pass over the corpus added 21 MB and a third
added 1 MB. The symptom looked like a leak only because the ceiling was reached
inside a single job and never released.

These tests do not measure memory — that needs a real model, a real corpus and
several minutes. They pin the two decisions that keep the ceiling bounded, so
that "clean up these magic numbers" cannot silently restore an 8 GB allocation
on a machine with a lot of cores.
"""

from __future__ import annotations

import importlib

import pytest


class TestTheCeilingIsExplicit:
    def test_threads_and_batch_are_bounded_by_default(self) -> None:
        from maljan.memory import embeddings

        assert 1 <= embeddings._EMBED_THREADS <= 4, (
            "onnxruntime allocates per thread; the default must not follow the "
            "host's core count (32 here = 8.3 GB and an OOM kill)"
        )
        assert 1 <= embeddings._EMBED_BATCH <= 64, (
            "the default batch of 256 is what turns a 1 MB corpus into GBs"
        )

    def test_both_are_tunable_from_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A host with memory to spare should not need a patch to go faster."""
        from maljan.memory import embeddings

        monkeypatch.setenv("MALJAN_EMBED_THREADS", "8")
        monkeypatch.setenv("MALJAN_EMBED_BATCH", "128")
        reloaded = importlib.reload(embeddings)
        try:
            assert reloaded._EMBED_THREADS == 8
            assert reloaded._EMBED_BATCH == 128
        finally:
            monkeypatch.delenv("MALJAN_EMBED_THREADS", raising=False)
            monkeypatch.delenv("MALJAN_EMBED_BATCH", raising=False)
            importlib.reload(embeddings)

    def test_a_nonsense_value_cannot_disable_the_bound(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.memory import embeddings

        monkeypatch.setenv("MALJAN_EMBED_THREADS", "0")
        monkeypatch.setenv("MALJAN_EMBED_BATCH", "-5")
        reloaded = importlib.reload(embeddings)
        try:
            assert reloaded._EMBED_THREADS >= 1
            assert reloaded._EMBED_BATCH >= 1
        finally:
            monkeypatch.delenv("MALJAN_EMBED_THREADS", raising=False)
            monkeypatch.delenv("MALJAN_EMBED_BATCH", raising=False)
            importlib.reload(embeddings)


class TestTheLimitsReachTheModel:
    """Setting the constants and not passing them is the obvious way to
    "fix" this and have it keep happening."""

    def test_the_thread_limit_is_passed_to_the_model_constructor(self) -> None:
        import inspect

        from maljan.memory import embeddings

        source = inspect.getsource(embeddings._try_load_fastembed)
        assert "threads=_EMBED_THREADS" in source

    def test_the_batch_size_is_passed_to_embed(self) -> None:
        import inspect

        from maljan.memory import embeddings

        source = inspect.getsource(embeddings.encode_batch)
        assert "batch_size=_EMBED_BATCH" in source
