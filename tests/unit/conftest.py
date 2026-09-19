"""A unit test builds no ATT&CK index, loads no embedding model, and writes
nothing into the cache the worker reads.

The knowledge module degrades rather than raises, so a unit test that reaches
the real index does not fail — it waits. On a machine with a warm bundle cache
that is under two seconds and invisible; on a runner without one it is three
HTTP fetches from a third party plus an ONNX model download. One test acquired
that dependency for the whole suite and the only symptom was a second test
failing three hundred files later.

Three doors, each held in the way that fits what is behind it.

**The index build fails.** ``load_all_domains`` is the single entry — the
knowledge catalogue calls it directly and ``ATTCKIndex.from_loader`` calls it
too — and it refuses. The refusal is at the build rather than at the network
fetch on purpose: a machine with a warm cache reaches the same code for the
same reason and pays a second and a hundred megabytes for it, so a test that
gets there should be red there too, not only on a runner.

**The embedding model falls back.** ``embeddings`` ships a deterministic
bag-of-words projection for the case where the model cannot be loaded, and it
is the supported answer rather than a failure. The memory layer's tests embed
text as a side effect of storing, purging or indexing a case; none is about
embedding quality, and each was loading a 190 MB model to compare two sentences
that share no words.

**The cache directory is somewhere else.** Both caches — the STIX bundles and
the embedding vectors — point at a per-session temporary directory, so no unit
run can write into ``~/.cache/maljan/attck``. A bag-of-words corpus written
there is read back by the next live run as though the model had produced it,
and the export ranks techniques with it. The bundles are copied in when the
real cache already has them, so the tests that legitimately want the catalogue
do not re-download 50 MB per session; nothing is copied back out.

A test that means to go through the first two doors asks for
``real_attck_index``. It still cannot reach the real cache directory.

This is a floor, not a substitute for the stand-ins. A test that wants a
catalogue's answers uses the package's own ``_Attck``.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from maljan.memory import attck_index, attck_loader, embeddings, semantic_attck_index

_STAND_IN = (
    "Use the package's stand-in catalogue (``_Attck`` in "
    "tests/unit/pipeline/test_validation.py or test_technique_check.py), or ask for the "
    "``real_attck_index`` fixture."
)

_BUNDLES = ("enterprise-attack.json", "mobile-attack.json", "ics-attack.json")


def _refuse_build(*_args: Any, **_kwargs: Any) -> Any:
    pytest.fail(
        f"a unit test built the ATT&CK index from the corpus. {_STAND_IN}",
        pytrace=False,
    )


def _bag_of_words(*_args: Any, **_kwargs: Any) -> None:
    """No model, which is the module's own signal to project bags of words."""
    return None


@pytest.fixture(scope="session")
def _attck_doors() -> dict[str, Any]:
    """The functions as they were before any test ran."""
    return {
        "loader": attck_loader.load_all_domains,
        "index": attck_index.load_all_domains,
        "model": embeddings._try_load_fastembed,
    }


@pytest.fixture(scope="session")
def _attck_cache_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A cache of this session's own, seeded from the real one when it exists.

    Seeding is a copy rather than a link: the loader refreshes a bundle older
    than thirty days by writing to the same path, and a link would put that
    write through to the file the worker reads.
    """
    session_cache = tmp_path_factory.mktemp("attck-cache")
    for name in _BUNDLES:
        source = attck_loader.ATTCK_CACHE_DIR / name
        if source.is_file():
            shutil.copy2(source, session_cache / name)
    return session_cache


@pytest.fixture(autouse=True)
def _no_attck_downloads(
    _attck_doors: dict[str, Any],
    _attck_cache_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """Hold all three doors, before every test rather than once for the session.

    Once for the session is not enough: a test that calls ``importlib.reload``
    on either module puts the real function back on it, and a session-wide
    patch stays off for every test collected after that one.

    The build refusal goes on two modules because ``attck_index`` binds the
    loader's name at import. ``pytest.fail`` raises a ``BaseException``, which
    is what makes it a guard: ``knowledge._hybrid_index`` catches ``Exception``
    and would turn an ordinary error back into the silent slow path.

    ``embeddings._model`` is cleared with the function that caches it, so a
    model loaded before this fixture first ran cannot be handed to a later
    test. ``ATTCK_CACHE_FILES`` is redirected beside the directory it was
    computed from at import time, which is the value the loader actually reads.
    """
    monkeypatch.setattr(attck_loader, "load_all_domains", _refuse_build)
    monkeypatch.setattr(attck_index, "load_all_domains", _refuse_build)
    monkeypatch.setattr(embeddings, "_try_load_fastembed", _bag_of_words)
    monkeypatch.setattr(embeddings, "_model", None)
    monkeypatch.setattr(attck_loader, "ATTCK_CACHE_DIR", _attck_cache_dir)
    monkeypatch.setattr(
        attck_loader,
        "ATTCK_CACHE_FILES",
        {domain: _attck_cache_dir / f"{domain}-attack.json" for domain in attck_loader.DOMAINS},
    )
    monkeypatch.setattr(
        attck_loader, "ATTCK_CACHE_FILE", _attck_cache_dir / "enterprise-attack.json"
    )
    monkeypatch.setattr(semantic_attck_index, "_EMB_CACHE_DIR", _attck_cache_dir)
    yield


@pytest.fixture
def real_attck_index(
    _no_attck_downloads: None, _attck_doors: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Let one test build the real index and load the real model.

    The cache directory stays this session's own, so what the test builds is
    read from and written to a temporary copy and the worker's cache is not
    touched either way.
    """
    monkeypatch.setattr(attck_loader, "load_all_domains", _attck_doors["loader"])
    monkeypatch.setattr(attck_index, "load_all_domains", _attck_doors["loader"])
    monkeypatch.setattr(embeddings, "_try_load_fastembed", _attck_doors["model"])
    yield
