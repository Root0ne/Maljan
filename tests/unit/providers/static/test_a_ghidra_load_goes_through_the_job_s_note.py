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

from maljan.agents.ghidra_http_client import GhidraHTTPClient
from maljan.core.config import GHIDRA_SAMPLE_OPEN, MCPServerConfig
from maljan.providers.sample_open import SampleNotes
from maljan.providers.static.ghidra import GhidraStaticProvider

HELD = "/data/samples/.work/s.exe"
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
        base_url="http://ghidra.invalid", unbounded_tools=frozenset({"run_analysis"})
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
        assert provider.sample_notes.get("ghidra", HELD).name == "s.exe"

    def test_every_later_load_is_a_switch_answered_with_the_load_s_answer(self) -> None:
        ghidra = _Ghidra()
        _provider_, load = _provider(ghidra)
        said = _loads(load, 5)
        assert ghidra.paths()[4:] == ["/switch_program"] * 4
        assert ghidra.paths().count("/load_program") == 1
        assert said == [LOADED] * 5

    def test_an_analysis_ghidra_did_not_confirm_is_not_noted(self) -> None:
        ghidra = _Ghidra(run_analysis=json.dumps({"error": "Analysis failed: x"}))
        provider, load = _provider(ghidra)
        _loads(load, 2)
        assert ghidra.paths().count("/load_program") == 2
        assert provider.sample_notes.get("ghidra", HELD) is None


class TestOneNoteForEveryPath:
    def test_the_triage_pass_s_open_answers_the_model_s_load(self) -> None:
        from maljan.analysis.ghidra_passes import GhidraPasses

        notes = SampleNotes()
        pass_ghidra = _Ghidra()
        passes = GhidraPasses(
            base_url="http://ghidra.invalid",
            sample_path=HELD,
            transport=httpx.MockTransport(pass_ghidra.handler),
            sample_open=GHIDRA_SAMPLE_OPEN,
            sample_notes=notes,
        )
        assert passes.open() == "s.exe"
        assert pass_ghidra.paths()[:3] == ["/load_program", "/switch_program", "/run_analysis"]

        agent_ghidra = _Ghidra()
        _provider_, load = _provider(agent_ghidra, notes)
        assert _loads(load, 1) == [json.dumps({"success": True, "program": "s.exe"})]
        assert agent_ghidra.paths() == ["/switch_program"]

    def test_an_analysis_the_pass_did_not_get_stops_the_pass(self) -> None:
        import pytest

        from maljan.analysis.ghidra_passes import GhidraPasses, GhidraPassFailed

        ghidra = _Ghidra(run_analysis=json.dumps({"error": "Analysis failed: x"}))
        passes = GhidraPasses(
            base_url="http://ghidra.invalid",
            sample_path=HELD,
            transport=httpx.MockTransport(ghidra.handler),
            sample_open=GHIDRA_SAMPLE_OPEN,
            sample_notes=SampleNotes(),
        )
        with pytest.raises(GhidraPassFailed):
            passes.open()

    def test_the_function_hash_pass_selects_a_noted_sample(self, monkeypatch: Any) -> None:
        from maljan.analysis import function_hash_attribution as hashes

        notes = SampleNotes()
        notes.note("ghidra", HELD, "s.exe", LOADED)
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
        )
        assert "/load_program" not in ghidra.paths()
        assert ghidra.paths()[0] == "/switch_program"

    def test_a_hash_pass_that_cannot_select_the_sample_hashes_nothing(
        self, monkeypatch: Any
    ) -> None:
        from maljan.analysis import function_hash_attribution as hashes

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
        )
        assert got == []
        assert "/get_bulk_function_hashes" not in ghidra.paths()
