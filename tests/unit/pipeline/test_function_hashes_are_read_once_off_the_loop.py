"""The program's function hashes are read once, off the event loop, and a store's error is masked.

The judge's function-hash attribution asked the static provider to hash the
program again (a Ghidra REST walk of up to 120 s) on the event loop, after the
triage pack had already hashed the same program; the family-feature RAG parsed
the host binary on the loop too. Both now run in a thread, and the judge reads
the pack's whole read rather than walking the program a second time.

The pack's step fell through to a second store read when the store could not
be built and no function was hashed, and that read's error reached the run's
ledger with a credential in it. A store that could not be built is now said
with its redacted reason whatever was hashed, and the read's own error is
redacted the same way.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from maljan.pipeline import nodes
from maljan.providers.errors import ProviderError
from maljan.schemas.evidence import EvidenceCounter
from tests.credential_shapes import password

# Built at runtime, so no credential-shaped literal is committed.
SECRET = password()
STORE_URL_ERROR = f"could not connect to postgresql://maljan:{SECRET}@db.internal:5432/mem"


class _Hashes(list):
    cut = ""
    unavailable = ""


def _provider(hashes: Any) -> SimpleNamespace:
    asked: list[Any] = []

    def _function_hashes(job: Any) -> Any:
        asked.append(job)
        return hashes

    return SimpleNamespace(
        capabilities=SimpleNamespace(provides_function_hashes=True),
        function_hashes=_function_hashes,
        asked=asked,
        preprocessing=lambda: SimpleNamespace(
            use_function_hash_attribution=True, function_hash_max_matches=8
        ),
    )


class TestThePacksReadIsKeptForTheJudge:
    def test_a_whole_read_is_kept_and_handed_back(self) -> None:
        container = SimpleNamespace(function_hashes_read=None)
        hashes = _Hashes([("f1", "h1")])

        nodes.remember_hashes_read(container, "/mirror/s.bin", hashes)

        assert nodes.hashes_read(container, "/mirror/s.bin") is hashes
        assert nodes.hashes_read(container, "/mirror/other.bin") is None

    def test_a_cut_read_is_not_kept(self) -> None:
        container = SimpleNamespace(function_hashes_read=None)
        hashes = _Hashes([("f1", "h1")])
        hashes.cut = "the walk stopped at the stage's deadline"

        nodes.remember_hashes_read(container, "/mirror/s.bin", hashes)

        assert nodes.hashes_read(container, "/mirror/s.bin") is None

    def test_the_judge_reads_the_kept_hashes_rather_than_walking_again(self) -> None:
        kept = _Hashes([("f1", "h1"), ("f2", "h2")])
        provider = _provider(_Hashes())
        container = SimpleNamespace(
            function_hashes_read=("/mirror/s.bin", kept),
            get_static_provider=lambda: provider,
        )
        matched: list[list[str]] = []

        def _match(_store: Any, hashes: list[str], **_kw: Any) -> list[Any]:
            matched.append(list(hashes))
            return []

        with (
            patch("maljan.memory.store_factory.acquire_function_hash_store", return_value=object()),
            patch("maljan.memory.store_factory.release_function_hash_store"),
            patch("maljan.memory.long_term_memory.match_functions", side_effect=_match),
            patch("maljan.memory.long_term_memory.memory_owner_of", return_value=""),
        ):
            nodes._function_hash_attribution(  # type: ignore[arg-type]
                container, {"static_sample_path": "/mirror/s.bin", "file_hash": "x"}, None
            )

        assert provider.asked == []
        assert matched == [["h1", "h2"]]


class TestTheJudgeReadsTheSampleOffTheLoop:
    def test_attribution_and_family_rag_run_in_a_thread(self) -> None:
        from maljan.agents.judge_agent import JudgeVerdict
        from maljan.schemas.stix_models import Bundle
        from tests.unit.pipeline.test_a_fallback_verdict_assesses_nothing import (
            _Container,
            _state,
        )

        container = _Container(EvidenceCounter())
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(
                bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={}
            )
        )
        threads: dict[str, bool] = {}

        def _attribution(*_args: Any) -> list[dict[str, Any]]:
            threads["attribution"] = threading.current_thread() is threading.main_thread()
            return []

        def _rag(_state: Any) -> list[dict[str, Any]]:
            threads["rag"] = threading.current_thread() is threading.main_thread()
            return []

        with (
            patch.object(nodes, "_function_hash_attribution", side_effect=_attribution),
            patch.object(nodes, "_family_rag_candidates", side_effect=_rag),
        ):
            asyncio.run(nodes.make_judge_node(container)(_state()))

        assert threads == {"attribution": False, "rag": False}


def _step(provider: Any, *, build: Any) -> Any:
    container = SimpleNamespace(
        config=SimpleNamespace(triage=SimpleNamespace(budget_seconds=0)),
        get_static_provider=lambda: provider,
        function_hashes_read=None,
    )
    with (
        patch("maljan.memory.store_factory.build_function_hash_store", side_effect=build),
        patch("maljan.memory.store_factory.configured_backend", return_value="postgres"),
    ):
        return nodes._function_matches_step(  # type: ignore[arg-type]
            container, {"static_sample_path": "/mirror/s.bin", "file_hash": "a" * 64}
        )


class TestAStoreErrorIsMasked:
    def test_no_hash_read_and_no_store_is_said_redacted_without_a_second_read(self) -> None:
        step = _step(_provider(_Hashes()), build=RuntimeError(STORE_URL_ERROR))

        with patch(
            "maljan.memory.store_factory.leased_function_hash_store",
            side_effect=AssertionError("a store that could not be built is asked again"),
        ):
            args, value = step()

        assert args["func_hashes"] == []
        assert value["matches"] == []
        assert SECRET not in value["reason"]
        assert "the function-hash store is unavailable" in value["reason"]

    def test_the_read_s_own_error_is_redacted(self) -> None:
        step = _step(_provider(_Hashes([("f1", "h1")])), build=lambda _cfg: object())

        with (
            patch(
                "maljan.memory.store_factory.leased_function_hash_store",
                side_effect=RuntimeError(STORE_URL_ERROR),
            ),
            pytest.raises(ProviderError) as raised,
        ):
            step()

        assert SECRET not in str(raised.value)
        assert "could not be read" in str(raised.value)
