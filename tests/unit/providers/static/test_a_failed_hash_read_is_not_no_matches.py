"""PS-M6/PS-M7: a Ghidra step that failed is said as failed, never as success or "nothing".

* A load whose make-current step Ghidra refused (no ``sample_open`` declared)
  is the open failing, with the switch's words, not the load's success.
* A function-hash read that could not be made is no hashes with the reason,
  never an empty read that the attribution reads as "no matches"; and every
  function is read, to the server's last page, with no fixed page count.

No Ghidra runs here: each request is answered in-process with Ghidra's shapes.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from maljan.providers.sample_open import SELECT_REFUSED_AFTER_OPEN, SampleNotes
from maljan.providers.static.ghidra import function_hashes as hashes
from maljan.providers.static.ghidra.provider import not_made_current, open_ghidra_sample

URL = "http://ghidra.invalid"
HELD = "/data/samples/.work/s.exe"
LOADED = json.dumps({"success": True, "program": "s.exe"})


def _mock(monkeypatch: Any, handler: Any) -> None:
    real = httpx.Client

    def client(**kwargs: Any) -> httpx.Client:
        return real(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "Client", client)


class TestAnUndeclaredLoad:
    def test_a_switch_refused_after_the_load_is_the_open_failing(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/load_program":
                return httpx.Response(200, text=LOADED)
            return httpx.Response(200, text=json.dumps({"error": "Program not found"}))

        with httpx.Client(transport=httpx.MockTransport(handler)) as http:
            said = open_ghidra_sample(http, URL, HELD, None, SampleNotes(), key="k")
        assert json.loads(said)["tool_error"] == SELECT_REFUSED_AFTER_OPEN
        stop = not_made_current(said)
        assert stop is not None and "Program not found" in str(stop)

    def test_a_switch_that_answered_keeps_the_load_s_answer(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/load_program":
                return httpx.Response(200, text=LOADED)
            return httpx.Response(200, text=json.dumps({"success": True}))

        with httpx.Client(transport=httpx.MockTransport(handler)) as http:
            assert open_ghidra_sample(http, URL, HELD, None, SampleNotes(), key="k") == LOADED


def _fetch(**over: Any) -> Any:
    common: dict[str, Any] = {
        "base_url": URL,
        "auth_token": "",
        "file_path": HELD,
        "min_instructions": 1,
        "note_key": "remote http://ghidra.invalid:80",
        "shared": False,
    }
    return hashes.fetch_bulk_function_hashes(**{**common, **over})


def _ghidra(total: int, *, repeat: bool = False) -> tuple[Any, list[int]]:
    """A Ghidra holding ``total`` functions; ``repeat`` answers the first page again for
    every offset past the second page (a page read before, but not the one just read)."""
    offsets: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/load_program":
            return httpx.Response(200, text=LOADED)
        if path == "/get_bulk_function_hashes":
            offset = int(request.url.params["offset"])
            limit = int(request.url.params["limit"])
            if repeat and offset >= 2 * limit:
                offset = 0
            offsets.append(offset)
            items = [
                {"name": f"f{i}", "hash": f"h{i}", "instruction_count": 5}
                for i in range(offset, min(total, offset + limit))
            ]
            return httpx.Response(200, json={"functions": items})
        return httpx.Response(200, json={"success": True})

    return handler, offsets


class TestTheHashRead:
    def test_a_read_that_could_not_be_made_says_why(self, monkeypatch: Any) -> None:
        handler, _offsets = _ghidra(10)
        _mock(monkeypatch, handler)
        got = _fetch(shared=True)
        assert got == []
        assert "sample_open" in got.unavailable

    def test_a_server_error_is_a_failed_read_not_no_functions(self, monkeypatch: Any) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/get_bulk_function_hashes":
                return httpx.Response(500, text="boom")
            if request.url.path == "/load_program":
                return httpx.Response(200, text=LOADED)
            return httpx.Response(200, json={"success": True})

        _mock(monkeypatch, handler)
        got = _fetch()
        assert got == [] and "HTTPStatusError" in got.unavailable

    def test_a_program_with_no_function_is_a_read_with_nothing_unread(
        self, monkeypatch: Any
    ) -> None:
        handler, _offsets = _ghidra(0)
        _mock(monkeypatch, handler)
        got = _fetch()
        assert got == [] and got.unavailable == ""

    def test_every_function_is_read_past_the_old_sixteen_thousand(self, monkeypatch: Any) -> None:
        handler, offsets = _ghidra(20_001)
        _mock(monkeypatch, handler)
        got = _fetch()
        assert len(got) == 20_001 and got.unavailable == "" and got.cut == ""
        # The short page at 20,000 is not taken as the last; the empty one is.
        assert offsets[-2:] == [20_000, 20_001]

    def test_a_server_repeating_a_full_page_ends_the_read_as_a_stated_cut(
        self, monkeypatch: Any
    ) -> None:
        handler, offsets = _ghidra(5_000, repeat=True)
        _mock(monkeypatch, handler)
        got = _fetch()
        assert len(got) == 4_000
        assert offsets == [0, 2_000, 0]
        # Not a complete answer: the walk ended on a repeat, not a last page.
        assert "repeats entries already read" in got.cut and "offset 4000" in got.cut
        assert got.unavailable == ""

    def test_a_server_clamping_an_offset_past_its_end_is_a_complete_read(
        self, monkeypatch: Any
    ) -> None:
        offsets: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/load_program":
                return httpx.Response(200, text=LOADED)
            if request.url.path == "/get_bulk_function_hashes":
                asked = int(request.url.params["offset"])
                offsets.append(asked)
                # An offset past the last page is clamped to the last page's start.
                start = min(asked, 200)
                items = [
                    {"address": f"0x{i:x}", "hash": f"h{i}", "instruction_count": 9}
                    for i in range(start, min(250, start + 100))
                ]
                return httpx.Response(200, json={"functions": items})
            return httpx.Response(200, json={"success": True})

        _mock(monkeypatch, handler)
        got = _fetch(page_limit=100)
        assert len(got) == 250
        assert offsets == [0, 100, 200, 250]
        assert got.cut == "" and got.unavailable == ""

    def test_a_server_ignoring_the_offset_is_a_stated_cut_not_a_complete_read(
        self, monkeypatch: Any
    ) -> None:
        offsets: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/load_program":
                return httpx.Response(200, text=LOADED)
            if request.url.path == "/get_bulk_function_hashes":
                offsets.append(int(request.url.params["offset"]))
                # The first full page, whatever offset is asked for.
                items = [
                    {"address": f"0x{i:x}", "hash": f"h{i}", "instruction_count": 9}
                    for i in range(100)
                ]
                return httpx.Response(200, json={"functions": items})
            return httpx.Response(200, json={"success": True})

        _mock(monkeypatch, handler)
        got = _fetch(page_limit=100)
        assert len(got) == 100 and offsets == [0, 100]
        assert "same full page" in got.cut and "may ignore the offset" in got.cut

    def test_a_later_page_that_fails_keeps_what_was_read_as_a_stated_cut(
        self, monkeypatch: Any
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/load_program":
                return httpx.Response(200, text=LOADED)
            if request.url.path == "/get_bulk_function_hashes":
                offset = int(request.url.params["offset"])
                if offset >= 350:
                    return httpx.Response(400, text="offset out of range")
                items = [
                    {"address": f"0x{i:x}", "hash": f"h{i}", "instruction_count": 9}
                    for i in range(offset, min(350, offset + 100))
                ]
                return httpx.Response(200, json={"functions": items})
            return httpx.Response(200, json={"success": True})

        _mock(monkeypatch, handler)
        got = _fetch(page_limit=100, walk_budget=0.0)
        assert len(got) == 350 and got.unavailable == ""
        assert "offset 350 failed" in got.cut and "HTTPStatusError" in got.cut

    def test_a_short_last_page_is_a_complete_read_with_no_cut(self, monkeypatch: Any) -> None:
        handler, _offsets = _ghidra(2_500)
        _mock(monkeypatch, handler)
        got = _fetch()
        assert len(got) == 2_500 and got.cut == ""

    def test_an_entry_is_known_by_its_address_and_hash_alone(self) -> None:
        one = {"address": "0x401000", "hash": "h1", "name": "f", "instruction_count": 9}
        assert hashes._entry_key(one) == ("0x401000", "h1")
        # The same function read again with other fields is the same entry.
        again = {**one, "instruction_count": 10, "extra": "x" * 1000}
        assert hashes._entry_key(again) == hashes._entry_key(one)
        # Another function with the same code is another entry.
        assert hashes._entry_key({**one, "address": "0x402000"}) != hashes._entry_key(one)
        # With no address, the name stands for where the function is.
        assert hashes._entry_key({"name": "f", "hash": "h1"}) == ("f", "h1")

    def test_a_page_repeating_the_same_functions_in_other_words_ends_the_walk(
        self, monkeypatch: Any
    ) -> None:
        pages: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/load_program":
                return httpx.Response(200, text=LOADED)
            if request.url.path == "/get_bulk_function_hashes":
                pages.append(int(request.url.params["offset"]))
                limit = int(request.url.params["limit"])
                # The same functions every time, their other fields changing.
                items = [
                    {
                        "address": f"0x{i:x}",
                        "hash": f"h{i}",
                        "name": f"f{i}",
                        "instruction_count": 5 + len(pages),
                    }
                    for i in range(limit)
                ]
                return httpx.Response(200, json={"functions": items})
            return httpx.Response(200, json={"success": True})

        _mock(monkeypatch, handler)
        got = _fetch(page_limit=10)
        assert len(got) == 10 and len(pages) == 2
        assert got.cut

    def test_a_caller_s_own_page_count_is_a_stated_cut(self, monkeypatch: Any, caplog: Any) -> None:
        import logging

        handler, _offsets = _ghidra(5_000)
        _mock(monkeypatch, handler)
        with caplog.at_level(logging.WARNING):
            got = _fetch(max_pages=1)
        assert len(got) == 2_000
        assert "were not read" in got.cut
        assert any("were not read" in r.getMessage() for r in caplog.records)


class TestThePackStep:
    def test_a_failed_read_fails_the_step_with_its_reason(self, monkeypatch: Any) -> None:
        from maljan.core.config import Settings
        from maljan.memory import store_factory
        from maljan.pipeline import nodes

        class _Provider:
            class capabilities:  # noqa: N801 - read as an attribute
                provides_function_hashes = True

            def function_hashes(self, job: Any) -> Any:
                return hashes.FunctionHashes(unavailable="Ghidra did not answer")

        class _Container:
            config = Settings(_env_file=None)

            def get_static_provider(self) -> Any:
                return _Provider()

        monkeypatch.setattr(store_factory, "build_function_hash_store", lambda cfg: object())
        step = nodes._function_matches_step(
            _Container(),  # type: ignore[arg-type]
            {"static_sample_path": HELD, "file_hash": "ab"},  # type: ignore[arg-type]
        )
        assert step is not None
        with pytest.raises(Exception, match="Ghidra did not answer"):
            step()

    def test_a_cut_read_is_said_with_the_step_s_answer(self, monkeypatch: Any) -> None:
        from maljan.core.config import Settings
        from maljan.memory import store_factory
        from maljan.pipeline import nodes
        from maljan.tools import knowledge

        class _Provider:
            class capabilities:  # noqa: N801 - read as an attribute
                provides_function_hashes = True

            def function_hashes(self, job: Any) -> Any:
                return hashes.FunctionHashes([("f", "h")], cut="the page at offset 2 repeats")

        class _Container:
            config = Settings(_env_file=None)

            def get_static_provider(self) -> Any:
                return _Provider()

        class _Lease:
            def __enter__(self) -> Any:
                return object()

            def __exit__(self, *exc: Any) -> None:
                return None

        monkeypatch.setattr(store_factory, "build_function_hash_store", lambda cfg: object())
        monkeypatch.setattr(store_factory, "leased_function_hash_store", lambda cfg: _Lease())
        monkeypatch.setattr(knowledge, "function_matches", lambda *a, **k: {"matches": []})
        step = nodes._function_matches_step(
            _Container(),  # type: ignore[arg-type]
            {"static_sample_path": HELD, "file_hash": "ab"},  # type: ignore[arg-type]
        )
        _args, value = step()
        assert value == {"matches": [], "cut": "the page at offset 2 repeats"}

    def test_the_step_s_walk_carries_the_pack_s_deadline(self, monkeypatch: Any) -> None:
        import time

        from maljan.core.config import Settings
        from maljan.memory import store_factory
        from maljan.pipeline import nodes

        jobs: list[Any] = []

        class _Provider:
            class capabilities:  # noqa: N801 - read as an attribute
                provides_function_hashes = True

            def function_hashes(self, job: Any) -> Any:
                jobs.append(job)
                return hashes.FunctionHashes(unavailable="stop here")

        class _Container:
            config = Settings(_env_file=None)

            def get_static_provider(self) -> Any:
                return _Provider()

        monkeypatch.setattr(store_factory, "build_function_hash_store", lambda cfg: object())
        step = nodes._function_matches_step(
            _Container(),  # type: ignore[arg-type]
            {"static_sample_path": HELD, "file_hash": "ab"},  # type: ignore[arg-type]
        )
        before = time.monotonic()
        with pytest.raises(Exception, match="stop here"):
            step()
        budget = _Container.config.triage.budget_seconds
        assert jobs[0].deadline is not None
        assert before + budget <= jobs[0].deadline <= time.monotonic() + budget


class TestTheWalkIsBoundedOnlyByWhatBoundsTheJob:
    def test_a_server_answering_fresh_pages_forever_ends_at_the_call_budget(
        self, monkeypatch: Any
    ) -> None:
        pages: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/load_program":
                return httpx.Response(200, text=LOADED)
            if request.url.path == "/get_bulk_function_hashes":
                k = len(pages)
                pages.append(k)
                if k > 100:
                    raise AssertionError("the walk outlived the call budget")
                items = [
                    {"address": f"{k}-{i}", "hash": f"h{k}-{i}", "instruction_count": 9}
                    for i in range(10)
                ]
                return httpx.Response(200, json={"functions": items})
            return httpx.Response(200, json={"success": True})

        _mock(monkeypatch, handler)
        clock = iter(float(t) for t in range(10_000))
        monkeypatch.setattr(hashes.time, "monotonic", lambda: next(clock))
        got = _fetch(page_limit=10, walk_budget=5.0)
        assert got and got.unavailable == ""
        assert "call_timeout_seconds" in got.cut and "5s" in got.cut
        assert len(pages) < 10

    def test_with_no_budget_the_walk_reads_to_the_empty_page(self, monkeypatch: Any) -> None:
        handler, offsets = _ghidra(35)
        _mock(monkeypatch, handler)
        got = _fetch(page_limit=10, walk_budget=0.0)
        assert len(got) == 35 and got.cut == ""
        assert offsets == [0, 10, 20, 30, 35]
        # Nothing bounded it, and the result says so.
        assert "no call budget" in got.unbounded

    def test_with_no_call_budget_the_stage_deadline_ends_the_walk(self, monkeypatch: Any) -> None:
        pages: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/load_program":
                return httpx.Response(200, text=LOADED)
            if request.url.path == "/get_bulk_function_hashes":
                k = len(pages)
                pages.append(k)
                if k > 100:
                    raise AssertionError("the walk outlived the stage deadline")
                items = [
                    {"address": f"{k}-{i}", "hash": f"h{k}-{i}", "instruction_count": 9}
                    for i in range(10)
                ]
                return httpx.Response(200, json={"functions": items})
            return httpx.Response(200, json={"success": True})

        _mock(monkeypatch, handler)
        clock = iter(float(t) for t in range(10_000))
        monkeypatch.setattr(hashes.time, "monotonic", lambda: next(clock))
        got = _fetch(page_limit=10, walk_budget=0.0, deadline=4.0)
        assert got and got.unbounded == ""
        assert "deadline of the stage" in got.cut
        assert len(pages) < 10

    def test_the_provider_passes_the_stage_deadline_on(self, monkeypatch: Any) -> None:
        from maljan.core.config import MCPServerConfig, PreprocessingConfig
        from maljan.providers.base import StaticJobContext
        from maljan.providers.static.ghidra import GhidraStaticProvider

        cfg = MCPServerConfig(enabled=True, transport="http", url=URL, call_timeout_seconds=0.0)
        provider = GhidraStaticProvider(cfg, None, None)  # type: ignore[arg-type]
        provider._pre = PreprocessingConfig()
        seen: dict[str, Any] = {}

        def fetch(**kw: Any) -> list[Any]:
            seen.update(kw)
            return []

        monkeypatch.setattr(hashes, "fetch_bulk_function_hashes", fetch)
        provider.function_hashes(StaticJobContext(mirror_sample_path=HELD, deadline=123.0))
        assert seen["walk_budget"] == 0.0 and seen["deadline"] == 123.0

    def test_the_provider_walks_under_its_call_budget(self, monkeypatch: Any) -> None:
        from maljan.core.config import MCPServerConfig, PreprocessingConfig
        from maljan.providers.base import StaticJobContext
        from maljan.providers.static.ghidra import GhidraStaticProvider

        cfg = MCPServerConfig(enabled=True, transport="http", url=URL, call_timeout_seconds=77.0)
        provider = GhidraStaticProvider(cfg, None, None)  # type: ignore[arg-type]
        provider._pre = PreprocessingConfig()
        seen: dict[str, Any] = {}

        def fetch(**kw: Any) -> list[Any]:
            seen.update(kw)
            return []

        monkeypatch.setattr(hashes, "fetch_bulk_function_hashes", fetch)
        provider.function_hashes(StaticJobContext(mirror_sample_path=HELD))
        assert seen["walk_budget"] == provider.call_budget(None) > 0


class TestARefusedStepHashesNothing:
    @pytest.mark.parametrize(
        ("step", "status", "body"),
        [
            ("/switch_program", 200, json.dumps({"error": "no program"})),
            ("/switch_program", 404, "not here"),
            ("/run_analysis", 200, json.dumps({"error": "busy"})),
            ("/run_analysis", 409, "locked"),
        ],
    )
    def test_a_refused_switch_or_analysis_is_no_hashes_with_the_reason(
        self, monkeypatch: Any, step: str, status: int, body: str
    ) -> None:
        asked: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            asked.append(request.url.path)
            if request.url.path == "/load_program":
                return httpx.Response(200, text=LOADED)
            if request.url.path == step:
                return httpx.Response(status, text=body)
            return httpx.Response(200, json={"success": True, "functions": []})

        _mock(monkeypatch, handler)
        got = _fetch()
        assert got == [] and "refused" in got.unavailable
        assert "/get_bulk_function_hashes" not in asked


class TestRepeatsAndShortPages:
    def test_entries_with_no_identity_but_new_hashes_keep_the_walk_going(
        self, monkeypatch: Any
    ) -> None:
        pages: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/load_program":
                return httpx.Response(200, text=LOADED)
            if request.url.path == "/get_bulk_function_hashes":
                offset = int(request.url.params["offset"])
                pages.append(offset)
                if offset >= 30:
                    return httpx.Response(200, json={"functions": []})
                # No identity, but hashes not read before: not a repeat.
                items = [{"hash": f"h{offset + i}", "instruction_count": 9} for i in range(10)]
                return httpx.Response(200, json={"functions": items})
            return httpx.Response(200, json={"success": True})

        _mock(monkeypatch, handler)
        got = _fetch(page_limit=10)
        assert pages == [0, 10, 20, 30]
        assert got.cut == "" and len(got) == 30

    def test_identity_less_pages_repeating_their_hashes_forever_end_as_a_stated_cut(
        self, monkeypatch: Any
    ) -> None:
        pages: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/load_program":
                return httpx.Response(200, text=LOADED)
            if request.url.path == "/get_bulk_function_hashes":
                pages.append(int(request.url.params["offset"]))
                if len(pages) > 50:
                    raise AssertionError("the walk never ended")
                # The same anonymous hashes on every page, forever.
                # Never the page just sent (the order turns), so no clamped offset.
                k = len(pages)
                items = [{"hash": f"h{(i + k) % 2}", "instruction_count": 9} for i in range(10)]
                return httpx.Response(200, json={"functions": items})
            return httpx.Response(200, json={"success": True})

        _mock(monkeypatch, handler)
        got = _fetch(page_limit=10)
        assert pages == [0, 10]
        assert "repeats entries already read" in got.cut
        assert sorted(h for _n, h in got) == ["h0", "h1"]

    def test_a_server_whose_pages_are_shorter_than_asked_is_read_whole(
        self, monkeypatch: Any
    ) -> None:
        offsets: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/load_program":
                return httpx.Response(200, text=LOADED)
            if request.url.path == "/get_bulk_function_hashes":
                offset = int(request.url.params["offset"])
                offsets.append(offset)
                # The server caps every page at 100, whatever is asked for.
                items = [
                    {"address": f"0x{i:x}", "hash": f"h{i}", "instruction_count": 9}
                    for i in range(offset, min(250, offset + 100))
                ]
                return httpx.Response(200, json={"functions": items})
            return httpx.Response(200, json={"success": True})

        _mock(monkeypatch, handler)
        got = _fetch()
        assert len(got) == 250 and got.cut == ""
        assert offsets == [0, 100, 200, 250]
