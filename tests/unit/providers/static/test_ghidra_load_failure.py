"""A load that failed must produce no hint, and no loop either.

`load_program` answers **HTTP 200** with `{"error": "Failed to load program
from: ..."}` when it cannot open a file, so `raise_for_status()` sees nothing
wrong. The pre-pass then carried on and built its priority hint from whichever
program was still current — a hint about a completely different sample, handed
to the analyst as guidance for this one.

Observed while measuring hint frequency: the Ghidra server started refusing
loads after roughly thirty in one container lifetime (JVM at 5.15 GB), and
every subsequent sample produced a call graph of exactly 75,426 characters —
the last binary that had loaded successfully.

The load is now the precondition of the agent's loop: a load that opens
nothing raises ``SampleNotOpened`` with the server's words, and nothing after
it runs — no analysis, no graph, no model turn.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import SecretStr

from maljan.core.config import GHIDRA_SAMPLE_OPEN
from maljan.core.exceptions import SampleNotOpened
from maljan.providers.static.ghidra.program import program_name_from_load


class TestALoadErrorIsNotASuccess:
    def test_the_real_failure_body_yields_no_program(self) -> None:
        """Verbatim from the live server, returned with status 200."""
        body = json.dumps({"error": "Failed to load program from: /data/samples/x.exe"})
        assert program_name_from_load(body) is None

    def test_a_success_still_yields_its_program(self) -> None:
        body = json.dumps({"success": True, "program": "x.exe"})
        assert program_name_from_load(body) == "x.exe"


class _Resp:
    def __init__(self, text: str) -> None:
        self.text = text
        self.status_code = 200

    def raise_for_status(self) -> None:
        return None  # the point: a failed load is a 200


class _Client:
    """Stands in for httpx.Client, recording the paths the pre-pass calls."""

    def __init__(self, load_body: str) -> None:
        self.load_body = load_body
        self.paths: list[str] = []

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(self, url: str, json: Any = None, params: Any = None, **_kw: Any) -> _Resp:  # noqa: A002
        self.paths.append(url.rsplit("/", 1)[-1].split("?")[0])
        return _Resp(self.load_body if url.endswith("/load_program") else "{}")

    def get(self, url: str, params: Any = None) -> _Resp:
        self.paths.append(url.rsplit("/", 1)[-1].split("?")[0])
        return _Resp("edges")


@pytest.fixture
def analyst(monkeypatch: pytest.MonkeyPatch) -> Any:
    from maljan.agents.static_analyst import StaticAnalyst

    a = StaticAnalyst.__new__(StaticAnalyst)
    import logging

    a.logger = logging.getLogger("test.ghidra_load_failure")
    return a


def _patch_settings(monkeypatch: pytest.MonkeyPatch, analyst: Any) -> None:
    """The analyst's own provider: Ghidra over http, with the sink pre-pass on."""
    from maljan.providers.static.ghidra import GhidraStaticProvider

    class _G:
        enabled = True
        transport = "http"
        url = "http://ghidra.invalid"
        auth_token = SecretStr("")
        # Declared, as Ghidra ships: on a Ghidra other jobs share (http), the
        # graph is read only for the program the job opened.
        sample_open = GHIDRA_SAMPLE_OPEN

    class _P:
        use_sink_reachability = True
        sink_reachability_max_funcs = 12

    provider = GhidraStaticProvider(_G(), _P(), None)  # type: ignore[arg-type]
    monkeypatch.setattr(analyst, "_provider", lambda: provider, raising=False)


def _shipped_provider(monkeypatch: pytest.MonkeyPatch, analyst: Any, provider_id: str) -> None:
    """The analyst's own provider: ``provider_id`` as it ships."""
    from maljan.core.config import Settings
    from maljan.providers.registry import static_provider_class

    provider = static_provider_class(provider_id).from_settings(Settings())
    monkeypatch.setattr(analyst, "_provider", lambda: provider, raising=False)


class TestThePrePassStopsOnAFailedLoad:
    def test_a_failed_load_stops_the_agent_with_the_servers_words(
        self, analyst: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_settings(monkeypatch, analyst)
        client = _Client(json.dumps({"error": "Failed to load program from: /data/samples/x.exe"}))
        monkeypatch.setattr("httpx.Client", lambda **kw: client)

        with pytest.raises(SampleNotOpened) as stopped:
            analyst._compute_sink_priority_hint("/data/samples/x.exe")
        assert "Failed to load program from: /data/samples/x.exe" in str(stopped.value)

    def test_a_failed_load_does_not_analyse_or_fetch_a_graph(
        self, analyst: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The wasted work is the least of it — `run_analysis` on a failed load
        analyses the *previous* program, and the graph fetched afterwards is
        that program's."""
        _patch_settings(monkeypatch, analyst)
        client = _Client(json.dumps({"error": "Failed to load program from: /data/samples/x.exe"}))
        monkeypatch.setattr("httpx.Client", lambda **kw: client)

        with pytest.raises(SampleNotOpened):
            analyst._compute_sink_priority_hint("/data/samples/x.exe")
        assert client.paths == ["load_program"], client.paths


class TestThePrePassIsTheProvidersOwn:
    """L3 (live-run finding): the pre-pass used to drive Ghidra's headless REST
    API whichever static provider was selected, logging a "load_program did
    not yield a program" warning for a provider that offers no such tool at
    all. The open and the call graph are now each provider's own answer, so a
    provider that has neither calls nothing."""

    def test_an_r2_provider_never_calls_load_program_and_logs_nothing(
        self, analyst: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _shipped_provider(monkeypatch, analyst, "r2")
        client = _Client("{}")
        monkeypatch.setattr("httpx.Client", lambda **kw: client)

        with caplog.at_level("WARNING"):
            assert analyst._compute_sink_priority_hint("/data/samples/x.exe") == ""
        assert client.paths == [], client.paths
        assert not any("load_program" in r.getMessage() for r in caplog.records)

    def test_a_generic_mcp_provider_is_skipped_the_same_way(
        self, analyst: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _shipped_provider(monkeypatch, analyst, "generic_mcp")
        client = _Client("{}")
        monkeypatch.setattr("httpx.Client", lambda **kw: client)

        assert analyst._compute_sink_priority_hint("/data/samples/x.exe") == ""
        assert client.paths == [], client.paths

    def test_the_ghidra_path_is_unchanged(
        self, analyst: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same fixture as TestThePrePassStopsOnAFailedLoad, spelled out here
        to pin that Ghidra's own behaviour did not change: it still reaches
        ``load_program``, then reads the call graph."""
        _patch_settings(monkeypatch, analyst)
        client = _Client(json.dumps({"success": True, "program": "x.exe"}))
        monkeypatch.setattr("httpx.Client", lambda **kw: client)

        analyst._compute_sink_priority_hint("/data/samples/x.exe")
        assert client.paths[0] == "load_program", client.paths
        assert client.paths[-1] == "get_full_call_graph", client.paths
