"""A load that failed must produce no hint, not a hint about another binary.

`load_program` answers **HTTP 200** with `{"error": "Failed to load program
from: ..."}` when it cannot open a file, so `raise_for_status()` sees nothing
wrong. The pre-pass then carried on and built its priority hint from whichever
program was still current — a hint about a completely different sample, handed
to the analyst as guidance for this one.

Observed 2026-08-10 while measuring hint frequency: the Ghidra server started
refusing loads after roughly thirty in one container lifetime (JVM at 5.15 GB),
and every subsequent sample produced a call graph of exactly 75,426 characters
— the last binary that had loaded successfully. Sixty-six samples of identical
"data", none of it about the sample named in the result.

No hint is better than a wrong hint: the analyst falls back to its normal
behaviour, which is the documented fail-safe, instead of being pointed at
functions that do not exist in the binary it is looking at.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from maljan.analysis.ghidra_program import program_name_from_load


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

    def post(self, url: str, json: Any = None, params: Any = None) -> _Resp:  # noqa: A002
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


def _patch_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    class _G:
        transport = "http"
        url = "http://ghidra.invalid"
        auth_token = ""

    class _P:
        use_sink_reachability = True
        sink_reachability_max_funcs = 12

    class _S:
        class mcp:  # noqa: N801
            ghidra = _G()

        preprocessing = _P()

    monkeypatch.setattr("maljan.core.config.get_settings", lambda: _S())


class TestThePrePassStopsOnAFailedLoad:
    def test_a_failed_load_yields_no_hint(
        self, analyst: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_settings(monkeypatch)
        client = _Client(json.dumps({"error": "Failed to load program from: /data/samples/x.exe"}))
        monkeypatch.setattr("httpx.Client", lambda **kw: client)

        assert analyst._compute_sink_priority_hint("/data/samples/x.exe") == ""

    def test_a_failed_load_does_not_analyse_or_fetch_a_graph(
        self, analyst: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The wasted work is the least of it — `run_analysis` on a failed load
        analyses the *previous* program, and the graph fetched afterwards is
        that program's."""
        _patch_settings(monkeypatch)
        client = _Client(json.dumps({"error": "Failed to load program from: /data/samples/x.exe"}))
        monkeypatch.setattr("httpx.Client", lambda **kw: client)

        analyst._compute_sink_priority_hint("/data/samples/x.exe")
        assert client.paths == ["load_program"], client.paths
