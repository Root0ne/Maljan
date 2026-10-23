"""Ghidra opens a job's sample once, through the general opener and its declared tools.

Every ``load_program`` imports the file afresh, in the place of an analysed
program of the same name, and an import holds no call or code reference. The
Ghidra block declares as data that ``load_program`` opens, ``switch_program``
selects and ``run_analysis`` analyses (``GHIDRA_SAMPLE_OPEN``); the general
opener (``providers.sample_open``) does the rest, for the model's own load, the
load before the loop, the triage pass and the function-hash pass, all under one
note of the job.

No Ghidra runs here: each request is answered in-process with Ghidra's shapes.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
from pydantic import SecretStr

from maljan.core.config import GHIDRA_SAMPLE_OPEN, MCPServerConfig
from maljan.providers.sample_open import SampleNotes
from maljan.providers.static.ghidra import GhidraStaticProvider
from maljan.providers.static.ghidra.http_client import GhidraHTTPClient

HELD = "/data/samples/.work/s.exe"
# Ghidra in the job's note: its address (``sample_open.server_note_key``).
KEY = "remote http://ghidra.invalid:80"
LOADED = json.dumps({"success": True, "program": "s.exe"})
SWITCHED = json.dumps({"success": True, "switched_to": "s.exe"})
ANALYSED = json.dumps({"success": True, "total_functions": 150, "program": "s.exe"})
SCHEMA = [
    {
        "path": "/load_program",
        "method": "POST",
        "params": [{"name": "file", "type": "string", "required": True, "source": "body"}],
    },
    {
        "path": "/switch_program",
        "method": "POST",
        "params": [{"name": "program", "type": "string", "source": "query"}],
    },
    {
        "path": "/run_analysis",
        "method": "POST",
        "params": [{"name": "program", "type": "string", "source": "body"}],
    },
]


class _Ghidra:
    def __init__(self, **over: str) -> None:
        self.answers = {
            "/load_program": LOADED,
            "/switch_program": SWITCHED,
            "/run_analysis": ANALYSED,
            "/get_current_program_info": json.dumps({"image_base": "140000000"}),
        }
        self.answers.update({f"/{k}": v for k, v in over.items()})
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, text=self.answers.get(request.url.path, "{}"))

    def paths(self) -> list[str]:
        return [r.url.path for r in self.requests]


def _provider(ghidra: _Ghidra, notes: SampleNotes | None = None) -> tuple[Any, Any]:
    cfg = MCPServerConfig(
        enabled=True,
        transport="http",
        url="http://ghidra.invalid",
        auth_token=SecretStr(""),
        sample_open=GHIDRA_SAMPLE_OPEN,
    )
    provider = GhidraStaticProvider(cfg, None, None)  # type: ignore[arg-type]
    if notes is not None:
        provider.sample_notes = notes
    client = GhidraHTTPClient(
        base_url="http://ghidra.invalid",
        long_running_tools=frozenset({"load_program", "run_analysis"}),
    )
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(ghidra.handler))
    tools = [client._create_langchain_tool(entry) for entry in SCHEMA]
    provider._toolkit = client
    provider.pin_sample(HELD)
    (load,) = [t for t in provider._pin_load_program_path(tools) if t.name == "load_program"]
    return provider, load


def _loads(load: Any, times: int) -> list[str]:
    async def go() -> list[str]:
        return [str(await load.ainvoke({"file": "/invented.exe"})) for _ in range(times)]

    return asyncio.run(go())


class TestTheClientKeepsTheGuardsRule:
    """The declared open and analysis tools wait as long as Ghidra takes, as on every server."""

    def _timeouts(self, explicit: float) -> dict[str, Any]:
        from maljan.providers.sample_open import long_running_tools

        ghidra = _Ghidra()
        client = GhidraHTTPClient(
            base_url="http://ghidra.invalid",
            long_running_tools=long_running_tools(GHIDRA_SAMPLE_OPEN),
            explicit_call_timeout=explicit,
        )
        client._http = httpx.AsyncClient(
            transport=httpx.MockTransport(ghidra.handler), timeout=60.0
        )
        for entry in SCHEMA:
            asyncio.run(
                client._call_endpoint(entry["path"], "POST", entry["params"], {"program": "s"})
            )
        return {r.url.path: r.extensions["timeout"]["read"] for r in ghidra.requests}

    def test_no_deadline_for_the_declared_tools_and_the_client_s_own_for_the_rest(self) -> None:
        read = self._timeouts(0.0)
        assert read["/load_program"] is None and read["/run_analysis"] is None
        assert read["/switch_program"] == 60.0

    def test_an_operator_s_budget_bounds_the_declared_tools(self) -> None:
        read = self._timeouts(900.0)
        assert read["/run_analysis"] == 900.0


class TestTheModelsLoad:
    def test_the_first_load_is_made_current_analysed_and_noted(self) -> None:
        ghidra = _Ghidra()
        provider, load = _provider(ghidra)
        (said,) = _loads(load, 1)
        # The client's own switch after a load, then the opener's select and analysis.
        assert ghidra.paths() == [
            "/load_program",
            "/switch_program",
            "/switch_program",
            "/run_analysis",
        ]
        assert json.loads(ghidra.requests[0].content) == {"file": HELD}
        assert json.loads(ghidra.requests[3].content) == {"program": "s.exe"}
        assert said == LOADED
        assert provider.sample_notes.get(KEY, HELD).name == "s.exe"

    def test_every_later_load_is_a_switch_answered_with_the_load_s_answer(self) -> None:
        ghidra = _Ghidra()
        _provider_, load = _provider(ghidra)
        said = _loads(load, 5)
        assert ghidra.paths()[4:] == ["/switch_program"] * 4
        assert ghidra.paths().count("/load_program") == 1
        assert said == [LOADED] * 5

    def test_an_analysis_ghidra_did_not_confirm_stops_unremembered_and_is_not_noted(
        self,
    ) -> None:
        """PS-M6: a refused analysis is the load failing, never its success."""
        import pytest

        from maljan.core.exceptions import SampleNotOpened

        ghidra = _Ghidra(run_analysis=json.dumps({"error": "Analysis failed: x"}))
        provider, load = _provider(ghidra)
        for _ in range(2):
            with pytest.raises(SampleNotOpened) as stopped:
                _loads(load, 1)
            said = str(stopped.value)
            assert "refused to analyse it" in said and "Analysis failed: x" in said
        # Each loop loads again: nothing about the file is remembered.
        assert ghidra.paths().count("/load_program") == 2
        assert provider.sample_failure(HELD) is None
        assert provider.sample_notes.get(KEY, HELD) is None

    def test_a_switch_refused_after_the_load_stops_with_its_own_sentence_unremembered(
        self,
    ) -> None:
        import pytest

        from maljan.core.exceptions import SampleNotOpened

        ghidra = _Ghidra(switch_program=json.dumps({"error": "Program not found: s.exe"}))
        provider, load = _provider(ghidra)
        with pytest.raises(SampleNotOpened) as stopped:
            _loads(load, 1)
        said = str(stopped.value)
        assert "refused to make it the current program" in said
        assert "Program not found: s.exe" in said
        assert "sample_mount" not in said
        assert provider.sample_failure(HELD) is None
        assert provider.sample_notes.get(KEY, HELD) is None

    def test_an_odd_held_path_opens_and_is_noted(self) -> None:
        odd = "/data/samples/.work/s.e%78e"
        ghidra = _Ghidra()
        provider, load = _provider(ghidra)
        provider.pin_sample(odd)
        assert _loads(load, 2) == [LOADED] * 2
        assert json.loads(ghidra.requests[0].content) == {"file": odd}
        assert ghidra.paths().count("/load_program") == 1
        assert provider.sample_notes.get(KEY, odd) is not None


class TestOneNoteForEveryPath:
    def test_the_triage_pass_s_open_answers_the_model_s_load(self) -> None:
        from maljan.providers.static.ghidra.passes import GhidraPasses

        notes = SampleNotes()
        pass_ghidra = _Ghidra()
        passes = GhidraPasses(
            base_url="http://ghidra.invalid",
            sample_path=HELD,
            transport=httpx.MockTransport(pass_ghidra.handler),
            sample_open=GHIDRA_SAMPLE_OPEN,
            sample_notes=notes,
            note_key=KEY,
        )
        assert passes.open() == "s.exe"
        assert pass_ghidra.paths()[:3] == ["/load_program", "/switch_program", "/run_analysis"]

        agent_ghidra = _Ghidra()
        _provider_, load = _provider(agent_ghidra, notes)
        assert _loads(load, 1) == [json.dumps({"success": True, "program": "s.exe"})]
        assert agent_ghidra.paths() == ["/switch_program"]

    def test_an_analysis_the_pass_did_not_get_stops_the_pass(self) -> None:
        import pytest

        from maljan.providers.static.ghidra.passes import GhidraPasses, GhidraPassFailed

        ghidra = _Ghidra(run_analysis=json.dumps({"error": "Analysis failed: x"}))
        passes = GhidraPasses(
            base_url="http://ghidra.invalid",
            sample_path=HELD,
            transport=httpx.MockTransport(ghidra.handler),
            sample_open=GHIDRA_SAMPLE_OPEN,
            sample_notes=SampleNotes(),
            note_key=KEY,
        )
        with pytest.raises(GhidraPassFailed):
            passes.open()

    def test_the_function_hash_pass_selects_a_noted_sample(self, monkeypatch: Any) -> None:
        from maljan.providers.static.ghidra import function_hashes as hashes

        notes = SampleNotes()
        notes.note(KEY, HELD, "s.exe", LOADED)
        ghidra = _Ghidra(get_bulk_function_hashes=json.dumps({"functions": []}))
        real = httpx.Client

        def client(**kwargs: Any) -> httpx.Client:
            return real(transport=httpx.MockTransport(ghidra.handler), **kwargs)

        monkeypatch.setattr(httpx, "Client", client)
        hashes.fetch_bulk_function_hashes(
            base_url="http://ghidra.invalid",
            auth_token="",
            file_path=HELD,
            min_instructions=1,
            sample_open=GHIDRA_SAMPLE_OPEN,
            sample_notes=notes,
            note_key=KEY,
        )
        assert "/load_program" not in ghidra.paths()
        assert ghidra.paths()[0] == "/switch_program"

    def test_a_hash_pass_that_cannot_select_the_sample_hashes_nothing(
        self, monkeypatch: Any
    ) -> None:
        from maljan.providers.static.ghidra import function_hashes as hashes

        ghidra = _Ghidra(switch_program=json.dumps({"error": "Program not found"}))
        real = httpx.Client

        def client(**kwargs: Any) -> httpx.Client:
            return real(transport=httpx.MockTransport(ghidra.handler), **kwargs)

        monkeypatch.setattr(httpx, "Client", client)
        got = hashes.fetch_bulk_function_hashes(
            base_url="http://ghidra.invalid",
            auth_token="",
            file_path=HELD,
            min_instructions=1,
            sample_open=GHIDRA_SAMPLE_OPEN,
            sample_notes=SampleNotes(),
            note_key=KEY,
        )
        assert got == []
        assert "/get_bulk_function_hashes" not in ghidra.paths()
