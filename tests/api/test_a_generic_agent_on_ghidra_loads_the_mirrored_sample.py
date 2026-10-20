"""A generic agent on Ghidra loads the sample from the path the Ghidra container reads.

The reverser a team puts on Ghidra opens the provider when it is resolved,
before any sample path exists, so the ``load_program`` override had no path
to hold a model to: a model that sent the host path, or a directory it made
up, got "file not found" from the container and spent paid steps on it. The
analyst node now pins the agent's container path on its provider before the
loop, and its head chunk names only that path.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from maljan.agents.base_agent import run_coro_blocking
from maljan.agents.composition import ResolvedAgent, pin_provider_sample
from maljan.agents.prompt_fragments import PROVIDER_FAMILY, stamp_source
from maljan.core.config import Settings
from maljan.providers.base import StaticJobContext
from maljan.providers.static.ghidra import GhidraStaticProvider

MIRROR = "/data/samples/.work/" + "ab" * 32 + ".exe"
HOST = "/home/someone/Maljan/data/samples/.work/" + "ab" * 32 + ".exe"

SCHEMA = {
    "tools": [
        {
            "path": "/load_program",
            "method": "POST",
            "params": [{"name": "file", "type": "string", "required": True, "source": "body"}],
        }
    ]
}


class _Ghidra(BaseHTTPRequestHandler):
    loaded: list[str] = []

    def _answer(self, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802 - the stdlib's name
        self._answer(SCHEMA)

    def do_POST(self) -> None:  # noqa: N802 - the stdlib's name
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        query = parse_qs(urlsplit(self.path).query)
        if urlsplit(self.path).path == "/load_program":
            # The client follows a load with its switch to the program; only
            # the load names a file.
            type(self).loaded.append(body.get("file") or (query.get("file") or [""])[0])
        self._answer({"success": True, "program": "x.exe"})

    def log_message(self, *args: Any) -> None:
        return None


@pytest.fixture
def ghidra() -> Iterator[tuple[str, type[_Ghidra]]]:
    handler = type("Handler", (_Ghidra,), {"loaded": []})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _provider(url: str) -> GhidraStaticProvider:
    settings = Settings(
        _env_file=None,
        static={"ghidra": {"enabled": True, "transport": "http", "url": url}},
    )
    provider = GhidraStaticProvider.from_settings(settings)
    # As resolution opens it for a generic agent: no sample path yet.
    provider.open(StaticJobContext(job_key="job"))
    return provider


def _load(provider: GhidraStaticProvider, file: str) -> str:
    tool = next(t for t in provider.get_tools() if t.name == "load_program")
    return str(run_coro_blocking(tool.coroutine(file=file), hard_timeout=20.0, label="test-load"))


def _refused_as_foreign(answer: str) -> bool:
    """Whether ``answer`` is the refusal of a path that is not the job's own sample."""
    error = (json.loads(answer) or {}).get("error") or {}
    return error.get("code") == "foreign_program"


class _Registry:
    def __init__(self) -> None:
        self.degradation_reasons: list[str] = []


class _Container:
    def __init__(self, provider: Any) -> None:
        self.provider = provider
        self.registry = _Registry()

    def get_server_registry(self) -> Any:
        return self.registry

    def get_static_provider(self, provider_id: str | None = None) -> Any:
        return self.provider


def _reverser(provider: GhidraStaticProvider) -> Any:
    class _Agent:
        pass

    agent = _Agent()
    agent._container = _Container(provider)
    agent._resolved = ResolvedAgent(
        key="all_tools_reverser_ghidra",
        role="generic",
        prompt="p",
        tools=[],
        static_provider_id="ghidra",
        llm=None,
    )
    agent.tools = stamp_source(provider.get_tools(), PROVIDER_FAMILY)
    agent._analysis_file_path = MIRROR
    return agent


@pytest.mark.parametrize("sent", [HOST, "/tmp/invented/sample.exe"], ids=["host-path", "invented"])
def test_the_container_path_is_what_ghidra_is_asked_to_load(ghidra, sent: str) -> None:
    url, handler = ghidra
    provider = _provider(url)
    try:
        pin_provider_sample(_reverser(provider), {"ghidra": MIRROR})
        _load(provider, sent)
    finally:
        provider.close()
    assert handler.loaded == [MIRROR]


def test_without_the_pin_the_model_s_path_is_not_sent(ghidra) -> None:
    """The state the pin fixes: resolution's attach knew no path. The model's
    path used to go through; on a Ghidra other jobs share (http) a path that is
    not the job's own sample is refused before it is sent, and said."""
    url, handler = ghidra
    provider = _provider(url)
    try:
        answer = _load(provider, HOST)
    finally:
        provider.close()
    assert handler.loaded == []
    assert _refused_as_foreign(answer)


def test_an_agent_without_the_provider_s_tools_pins_nothing(ghidra) -> None:
    url, handler = ghidra
    provider = _provider(url)
    try:
        agent = _reverser(provider)
        agent.tools = []
        pin_provider_sample(agent, {"ghidra": MIRROR})
        answer = _load(provider, HOST)
    finally:
        provider.close()
    # Nothing pinned: the model's path is not the job's held sample, so it is
    # refused rather than sent to a Ghidra other jobs share.
    assert handler.loaded == []
    assert _refused_as_foreign(answer)


def test_the_analyst_node_pins_it_with_the_agent_s_own_mirror(ghidra) -> None:
    from maljan.pipeline.nodes import _pin_sample_path

    url, handler = ghidra
    provider = _provider(url)
    try:
        agent = _reverser(provider)
        agent._analysis_file_path = None
        _pin_sample_path(
            agent,
            {"static_sample_paths": {"ghidra": MIRROR, "none": HOST}, "sample_path": HOST},
        )
        assert agent._analysis_file_path == MIRROR
        _load(provider, HOST)
    finally:
        provider.close()
    assert handler.loaded == [MIRROR]


def test_a_generic_agent_s_head_chunk_names_only_the_path_its_tools_read() -> None:
    from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk
    from maljan.pipeline.nodes import _augment_static_chunks_with_path

    state = {
        "static_sample_paths": {"ghidra": MIRROR},
        "sample_path": HOST,
        "file_hash": "ab" * 32,
    }
    content = json.dumps({"sha256": "ab" * 32})
    chunks = [
        TextChunk(
            index=0,
            total=1,
            strategy=ChunkStrategy.SLIDING_WINDOW,
            content=content,
            char_count=len(content),
            token_estimate=len(content) // 4,
            domain="static",
        )
    ]
    head = json.loads(
        _augment_static_chunks_with_path(chunks, state, provider_id="ghidra")[0].content
    )
    assert head["analysis_file_path"] == MIRROR
    # No role's chunk carries the worker's path: the static role's family
    # classifier reads it from the agent (``_pin_sample_path``).
    assert "host_sample_path" not in head
    assert HOST not in json.dumps(head)


def test_only_the_provider_s_own_mirror_is_pinned(ghidra) -> None:
    """With no Ghidra mirror, a fallback path is one Ghidra cannot read: nothing
    is pinned, a pin from before is cleared, and the run says why."""
    url, handler = ghidra
    provider = _provider(url)
    try:
        agent = _reverser(provider)
        agent.degradation_reasons = []
        pin_provider_sample(agent, {"ghidra": MIRROR})
        pin_provider_sample(agent, {"none": HOST})
        answer = _load(provider, "/tmp/invented/sample.exe")
        registry = agent._container.registry
    finally:
        provider.close()
    # The pin from before is cleared, so no path is the job's own on this
    # shared Ghidra: the invented one is refused, never sent.
    assert handler.loaded == []
    assert _refused_as_foreign(answer)
    assert agent.degradation_reasons == ["sample not mirrored for ghidra"]
    assert registry.degradation_reasons == ["sample not mirrored for ghidra"]


def test_a_delegation_pins_the_callee_s_own_mirror(ghidra) -> None:
    """A lead asking the reverser on Ghidra hands it Ghidra's mirror, not the
    caller's own path."""
    from maljan.agents.delegation import _brief_callee

    url, handler = ghidra
    provider = _provider(url)
    try:
        callee = _reverser(provider)
        callee._analysis_file_path = None

        class _Caller:
            name = "lead"
            _analysis_file_path = HOST
            sample_path_choices = {
                "by_provider": {"ghidra": MIRROR, "none": HOST},
                "static": None,
                "host": HOST,
            }

        _brief_callee(_Caller(), callee, stage="lead", round_index=0)
        assert callee._analysis_file_path == MIRROR
        _load(provider, HOST)
    finally:
        provider.close()
    assert handler.loaded == [MIRROR]


def test_on_a_ghidra_no_other_job_shares_the_model_s_path_goes_through(ghidra) -> None:
    """Unshared, as on stdio: with no pin, the model's own load runs as it was
    made, the behaviour before the shared-server rules (one Ghidra per job holds
    only that job's programs)."""
    url, handler = ghidra
    provider = _provider(url)
    try:
        # The same client and fake Ghidra, the block declared a local process:
        # what decides "shared" is the transport the block names.
        provider._cfg = provider._cfg.model_copy(update={"transport": "stdio"})
        provider._all_tools = provider._pin_load_program_path(
            provider._reading_errors(provider._toolkit.get_tools())
        )
        _load(provider, HOST)
    finally:
        provider.close()
    assert handler.loaded == [HOST]
