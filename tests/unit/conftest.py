"""A unit test does not download the ATT&CK corpus or an embedding model.

The knowledge module degrades rather than raises, so a unit test that reaches
the real index does not fail — it waits. On this box, with a warm 57.8 MB
bundle cache, that is under two seconds and invisible. On a runner with no
cache it is three HTTP fetches from a third party plus an ONNX model download,
or, with no network, three sixty-second timeouts before the same degraded
answer; and the test that caused it passes either way, so nothing points at it.
One test acquired that dependency for the whole suite and the only symptom was
a second test failing three hundred files later.

So the two doors are held shut for the whole unit tree, each in the way that
fits what is behind it.

The corpus download **fails**. Nothing in a unit test has any business
fetching three STIX bundles from a third party, and a test that tries is
pointed at the stand-in it should be using.

The embedding model **falls back**. ``embeddings`` ships a deterministic
bag-of-words projection for exactly the case where the model cannot be
loaded — an air-gapped install, a missing wheel, a sandbox without the ONNX
runtime — and it is the supported answer rather than a failure. Forty-two
tests across seven files in the memory layer embed text as a side effect of
storing, purging or indexing a case; none of them is about embedding quality,
and on a machine where fastembed imports they were each loading a 190 MB model
to compare two sentences that share no words. They take the fallback now, and
the model is unreachable from a unit test rather than merely discouraged.

A test that means to go through either door asks for ``real_attck_index``.

This is a floor, not a substitute for the stand-ins. A test that wants a
catalogue's answers uses the package's own ``_Attck``; this only makes the
expensive path impossible to take by accident.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from maljan.memory import attck_loader, embeddings

_STAND_IN = (
    "Use the package's stand-in catalogue (``_Attck`` in "
    "tests/unit/pipeline/test_validation.py or test_technique_check.py), or ask for the "
    "``real_attck_index`` fixture and point the loader at local fixture data."
)


def _refuse_fetch(*_args: Any, **_kwargs: Any) -> Any:
    pytest.fail(
        f"a unit test asked for the ATT&CK bundles over the network. {_STAND_IN}",
        pytrace=False,
    )


def _bag_of_words(*_args: Any, **_kwargs: Any) -> None:
    """No model, which is the module's own signal to project bags of words."""
    return None


@pytest.fixture(scope="session")
def _attck_doors() -> dict[str, Any]:
    """The two functions as they were before any test ran."""
    return {
        "_fetch_bundle": attck_loader._fetch_bundle,
        "_try_load_fastembed": embeddings._try_load_fastembed,
    }


@pytest.fixture(autouse=True)
def _no_attck_downloads(
    _attck_doors: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Shut both doors, before every test rather than once for the session.

    Once for the session is not enough: a test that calls
    ``importlib.reload`` on either module puts the real function back on it,
    and a session-wide patch stays off for every test collected after that
    one. Two ``setattr`` calls per test is the whole cost.

    ``pytest.fail`` raises a ``BaseException``, which is what makes the fetch
    refusal a guard: ``knowledge._hybrid_index`` catches ``Exception`` and
    would turn an ordinary error into the same silent degradation this exists
    to stop.

    ``embeddings._model`` is cleared with the function it caches, so a model
    loaded before this fixture first ran cannot be handed to a later test.
    """
    monkeypatch.setattr(attck_loader, "_fetch_bundle", _refuse_fetch)
    monkeypatch.setattr(embeddings, "_try_load_fastembed", _bag_of_words)
    monkeypatch.setattr(embeddings, "_model", None)
    yield


@pytest.fixture
def real_attck_index(
    _no_attck_downloads: None, _attck_doors: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Open both doors for one test, which then owns what it downloads.

    A test asking for this is saying it has local fixture data for the loader
    to read, or that it accepts the loader's own cache and what filling that
    cache costs on a machine without one.
    """
    monkeypatch.setattr(attck_loader, "_fetch_bundle", _attck_doors["_fetch_bundle"])
    monkeypatch.setattr(embeddings, "_try_load_fastembed", _attck_doors["_try_load_fastembed"])
    yield
