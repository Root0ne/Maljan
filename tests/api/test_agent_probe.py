"""The agent probe answers "what would this agent get" without spending a token.

An operator clicking Resolve wants the prompt size, the tool names and the
model id. A probe that ran the agent would be a job, so the LLM registry this
builds refuses to hand out a model at all, and the test fails loudly if
anything reaches for one.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx
import pytest

from app.services import settings_probes  # noqa: E402
from app.services.settings_probes import PROBES, probe_agent, run_agent_probe  # noqa: E402


class _Exploding:
    """Any attempt to build or call a model fails the test."""

    def build_model(self, *a: Any, **k: Any) -> Any:
        raise AssertionError("the agent probe must never build an LLM")

    def build_model_for_agent(self, *a: Any, **k: Any) -> Any:
        raise AssertionError("the agent probe must never build an LLM")


@pytest.fixture(autouse=True)
def _no_llm(monkeypatch):
    monkeypatch.setattr(
        "maljan.llm.registry.LLMProviderRegistry",
        lambda *a, **k: _Exploding(),
        raising=False,
    )


@pytest.fixture(autouse=True)
def _the_model_answers(monkeypatch):
    """The probe's one-turn completion, answered without touching a network.

    The probe ends by calling the model, which is the whole point of it — but
    a suite that reached an endpoint would be testing the endpoint. Every test
    here is about what the probe resolves and reports; the completion itself
    is driven against a mocked client in ``TestTheProbeMakesTheCallTheJobWillMake``.
    """

    async def _answered(provider: str, *, endpoint: str, model: str, api_key: str = ""):
        return (bool(model.strip()), f"{model!r} answered" if model.strip() else "no model named")

    monkeypatch.setattr(settings_probes, "complete_one_turn", _answered)


@pytest.fixture(autouse=True)
def _no_servers(monkeypatch):
    """Every server attaches instantly and offers two tools."""

    async def _atools_for(self, role, job_id, *, exclude="", **ctx):  # type: ignore[no-untyped-def]
        from langchain_core.tools import StructuredTool

        if role != "network":
            return [], []
        return [
            StructuredTool.from_function(func=lambda: "x", name=n, description=n)
            for n in ("extract_dns", "read_pcap_summary")
        ], []

    async def _atools_for_ref(self, ref, job_id, **ctx):  # type: ignore[no-untyped-def]
        return [], []

    monkeypatch.setattr("maljan.providers.servers.ServerRegistry.atools_for", _atools_for)
    monkeypatch.setattr("maljan.providers.servers.ServerRegistry.atools_for_ref", _atools_for_ref)


@pytest.mark.asyncio
async def test_a_built_in_agent_resolves_to_its_prompt_and_its_tools():
    result = await probe_agent({"name": "network", "settings": {}})
    assert result.ok is True
    assert result.tools == ["extract_dns", "read_pcap_summary"]
    assert result.details["prompt_chars"] > 0
    assert len(result.details["prompt"]) == result.details["prompt_chars"]
    assert len(result.details["prompt_sha256"]) == 64
    assert result.details["static_provider"] == "ghidra"
    assert result.details["llm"]["provider"] == "openai"
    # The role-bound half first, then the definition's own references: the
    # network analyst is bound to ``network`` by role and names ``knowledge``
    # by reference.
    assert [s["key"] for s in result.details["servers"]] == [
        "network",
        "knowledge",
        "virustotal",
    ]
    assert {s["status"] for s in result.details["servers"]} == {"ok"}


@pytest.mark.asyncio
async def test_the_detail_line_says_what_an_operator_wanted_to_know():
    result = await probe_agent({"name": "network", "settings": {}})
    assert "2 tools" in result.detail and "extract_dns" in result.detail


@pytest.mark.asyncio
async def test_a_generic_agent_resolves_to_the_prompt_the_operator_typed():
    import hashlib

    staged = {
        "agents.definitions": {"strings": {"role": "generic", "prompt": "read strings"}},
        "agents.profiles": {"one": {"analysts": ["strings"]}},
        "agents.profile": "one",
    }
    result = await probe_agent({"name": "strings", "settings": staged})
    assert result.ok is True
    assert result.details["prompt_chars"] == len("read strings")
    assert result.details["prompt_sha256"] == hashlib.sha256(b"read strings").hexdigest()
    assert result.tools == []


@pytest.mark.asyncio
async def test_an_unknown_agent_is_a_legible_failure_not_a_stack_trace():
    result = await probe_agent({"name": "ghost", "settings": {}})
    assert result.ok is False and "ghost" in result.detail


@pytest.mark.asyncio
async def test_a_degraded_server_is_reported_per_server_rather_than_failing_the_probe(monkeypatch):
    async def _atools_for(self, role, job_id, *, exclude="", **ctx):  # type: ignore[no-untyped-def]
        return [], ["mcp server 'network' unavailable"]

    monkeypatch.setattr("maljan.providers.servers.ServerRegistry.atools_for", _atools_for)
    result = await probe_agent({"name": "network", "settings": {}})
    assert result.ok is True
    statuses = {s["key"]: s["status"] for s in result.details["servers"]}
    assert statuses["network"] == "mcp server 'network' unavailable"


@pytest.mark.asyncio
async def test_a_wedged_server_open_is_bounded_by_the_probe_budget_not_by_its_own_cleanup(
    monkeypatch,
):
    """F9's own lesson, reused: the probe never waits for a wedged cleanup.

    A server whose ``atools_for`` never returns, and whose cancellation is
    itself slow to unwind — exactly the shape ``handshake_tools``' own
    docstring describes for ``aopen`` — must still bound the probe's *visible*
    latency to the budget, not to however long the server eventually takes to
    actually stop. The container's own close is picked up in the background
    once the wedged call finally gives up.
    """
    monkeypatch.setattr(settings_probes, "PROBE_BUDGET_SECONDS", 0.05)

    async def _wedged(self, role, job_id, *, exclude="", **ctx):  # type: ignore[no-untyped-def]
        try:
            await asyncio.sleep(999)
        except asyncio.CancelledError:
            # Cancellation itself is slow to unwind — the wedge F9 describes.
            await asyncio.sleep(0.2)
            raise

    cleaned_up = asyncio.Event()

    async def _closed(self) -> None:  # type: ignore[no-untyped-def]
        cleaned_up.set()

    monkeypatch.setattr("maljan.providers.servers.ServerRegistry.atools_for", _wedged)
    monkeypatch.setattr("maljan.core.container.ServiceContainer.aclose", _closed)

    t0 = time.perf_counter()
    result = await probe_agent({"name": "network", "settings": {}})
    elapsed = time.perf_counter() - t0

    assert result.ok is False
    assert "did not answer within" in result.detail
    # Bounded by the (monkeypatched) budget plus the fixed cancellation grace,
    # nowhere near the 999s + 0.2s the wedged server actually takes to unwind.
    assert elapsed < 1.0

    # The container's close is still scheduled and eventually runs, in the
    # background, once the wedged cancellation finally gives up.
    await asyncio.wait_for(cleaned_up.wait(), timeout=2.0)


@pytest.mark.asyncio
async def test_each_bound_server_reports_only_its_own_tools(monkeypatch):
    staged = {
        "mcp.servers": {
            "serverA": {"enabled": True, "agents": []},
            "serverB": {"enabled": True, "agents": []},
        },
        "agents.definitions": {
            "multi": {
                "role": "generic",
                "prompt": "multi",
                "tools": [
                    {"kind": "mcp", "server": "serverA"},
                    {"kind": "mcp", "server": "serverB"},
                ],
            }
        },
        "agents.profiles": {"multi_profile": {"analysts": ["multi"]}},
        "agents.profile": "multi_profile",
    }

    async def _atools_for_ref(self, ref, job_id, **ctx):  # type: ignore[no-untyped-def]
        from langchain_core.tools import StructuredTool

        name = f"{ref.server}_tool"
        return [StructuredTool.from_function(func=lambda: "x", name=name, description=name)], []

    monkeypatch.setattr("maljan.providers.servers.ServerRegistry.atools_for_ref", _atools_for_ref)
    result = await probe_agent({"name": "multi", "settings": staged})

    assert result.ok is True
    by_key = {s["key"]: s["tools"] for s in result.details["servers"]}
    assert by_key["serverA"] == ["serverA_tool"]
    assert by_key["serverB"] == ["serverB_tool"]


@pytest.mark.asyncio
async def test_a_server_that_blows_up_while_listed_degrades_only_its_own_entry(monkeypatch):
    """A per-server listing failure is that server's problem, not the probe's.

    Neither of the two servers here is the one the resolve itself opened —
    both are only asked about afterwards, for the per-server ``tools`` list —
    so a ``RuntimeError`` from one of them must not escape ``probe_agent`` as
    a 500, must not blank out the other server's already-fetched tools, and
    must not skip closing the container the successful resolve opened.
    """
    from maljan.core.container import ServiceContainer

    # Bound via ``agents`` (role-bound), not an explicit ``ToolRef`` — the
    # initial resolve then reads them through ``atools_for`` (already stubbed
    # empty by ``_no_servers`` for a role other than "network"), so the only
    # caller of ``atools_for_ref`` in this test is the post-resolve per-server
    # listing this finding is about.
    staged = {
        "mcp.servers": {
            "serverA": {"enabled": True, "agents": ["multi"]},
            "serverB": {"enabled": True, "agents": ["multi"]},
        },
        "agents.definitions": {"multi": {"role": "generic", "prompt": "multi"}},
        "agents.profiles": {"multi_profile": {"analysts": ["multi"]}},
        "agents.profile": "multi_profile",
    }

    async def _atools_for_ref(self, ref, job_id, **ctx):  # type: ignore[no-untyped-def]
        from langchain_core.tools import StructuredTool

        if str(ref.server) == "serverA":
            raise RuntimeError("serverA blew up")
        name = f"{ref.server}_tool"
        return [StructuredTool.from_function(func=lambda: "x", name=name, description=name)], []

    close_calls: list[None] = []
    original_aclose = ServiceContainer.aclose

    async def _counted_aclose(self):  # type: ignore[no-untyped-def]
        close_calls.append(None)
        await original_aclose(self)

    monkeypatch.setattr("maljan.providers.servers.ServerRegistry.atools_for_ref", _atools_for_ref)
    monkeypatch.setattr(ServiceContainer, "aclose", _counted_aclose)

    result = await probe_agent({"name": "multi", "settings": staged})

    assert result.ok is True
    by_key = {s["key"]: s for s in result.details["servers"]}
    assert by_key["serverA"]["tools"] == []
    assert "serverA blew up" in by_key["serverA"]["status"]
    assert by_key["serverB"]["tools"] == ["serverB_tool"]
    assert by_key["serverB"]["status"] == "ok"
    assert len(close_calls) == 1


@pytest.mark.asyncio
async def test_staged_values_win_over_stored_ones():
    stored = {"core.agents.definitions": {"strings": {"role": "generic", "prompt": "stored"}}}
    staged = {"core.agents.definitions": {"strings": {"role": "generic", "prompt": "staged"}}}
    result = await run_agent_probe("strings", staged, stored)
    assert result.details["prompt_chars"] == len("staged")


@pytest.mark.asyncio
async def test_a_stored_definition_alone_is_enough():
    stored = {"core.agents.definitions": {"strings": {"role": "generic", "prompt": "stored"}}}
    result = await run_agent_probe("strings", {}, stored)
    assert result.ok is True and result.details["prompt_chars"] == len("stored")


def test_the_probe_is_registered_under_its_own_name():
    assert "agent" in PROBES


def test_the_route_is_admin_only_and_passes_the_name_through(monkeypatch):
    from unittest.mock import AsyncMock, MagicMock, patch

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin
    from app.services.settings_probes import ProbeResult

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id="1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    client = TestClient(app)

    seen: list[str] = []

    async def _fake(name, values, stored):  # type: ignore[no-untyped-def]
        seen.append(name)
        return ProbeResult(True, 1, "ok", None, ["a"], {"prompt_chars": 3})

    with (
        patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})),
        patch("app.api.v1.settings.run_agent_probe", _fake),
    ):
        response = client.post("/api/v1/settings/test/agent?name=strings", json={"values": {}})
    assert response.status_code == 200
    assert seen == ["strings"]
    assert response.json()["details"] == {"prompt_chars": 3}


@pytest.mark.asyncio
async def test_a_rejected_definition_reports_why_not_only_which_field():
    """A generic agent with no prompt is a legible sentence, not "agents".

    ``build_settings`` raises a ValidationError whose ``loc`` is the useless
    part ("agents") and whose ``msg`` is the whole diagnosis. Reporting only
    the field left the operator with nothing to act on.
    """
    staged = {
        "agents.definitions": {"nameless": {"role": "generic"}},
        "agents.profiles": {"one": {"analysts": ["nameless"]}},
        "agents.profile": "one",
    }
    result = await probe_agent({"name": "nameless", "settings": staged})
    assert result.ok is False
    assert "needs a prompt" in result.detail
    assert "nameless" in result.detail


@pytest.mark.asyncio
async def test_an_inheriting_agent_reports_the_resolved_global_expert_model(monkeypatch):
    """An agent with no per-agent override still names the model it would get."""
    _tags(monkeypatch, ["qwen3.5:9b"])
    staged = {"llm.provider": "ollama", "llm.ollama.expert_model": "qwen3.5:9b"}
    result = await probe_agent({"name": "network", "settings": staged})
    assert result.ok is True
    assert result.details["llm"] == {
        "provider": "ollama",
        "model": "qwen3.5:9b",
        "endpoint": "http://localhost:11434",
    }


# ---------------------------------------------------------------------------
# BUG 8: an Ollama tag that is not on the server is the operator's typo, and
# the probe is the last place to catch it before a job spends 10 minutes
# reaching that agent.
# ---------------------------------------------------------------------------


def _tags(monkeypatch, names, *, reachable=True):
    """An Ollama server that lists ``names`` and will generate with those only.

    Both halves, because the probe asks for both: the tag list says the
    endpoint is up, and the one-turn completion says the server will actually
    load the model. A tag it does not have is refused the way Ollama refuses
    it, with a 404.
    """
    import httpx

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if not reachable:
            raise httpx.ConnectError("connection refused", request=request)
        if request.url.path.endswith("/api/generate"):
            import json as _json

            asked = _json.loads(request.content or b"{}").get("model", "")
            if asked not in names:
                return httpx.Response(404, json={"error": f"model {asked!r} not found"})
            return httpx.Response(200, json={"response": "OK"})
        return httpx.Response(200, json={"models": [{"name": n} for n in names]})

    monkeypatch.setattr(
        settings_probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=10),
    )
    return calls


@pytest.mark.asyncio
async def test_a_per_agent_ollama_model_the_server_lacks_is_reported(monkeypatch):
    """The server will not load it, and the probe finds that out by asking."""
    monkeypatch.undo()
    calls = _tags(monkeypatch, ["qwen3:8b"])
    staged = {
        "llm.provider": "ollama",
        "llm.ollama.expert_model": "qwen3:8b",
        "llm.agents": {"network": {"provider": "ollama", "model": "qwen3:nope"}},
    }
    result = await probe_agent({"name": "network", "settings": staged})
    assert result.ok is False
    assert "qwen3:nope" in result.detail and "404" in result.detail
    assert [c for c in calls if c.endswith("/api/generate")], "the model was asked, not listed"


@pytest.mark.asyncio
async def test_a_per_agent_ollama_model_the_server_has_still_resolves(monkeypatch):
    _tags(monkeypatch, ["qwen3:8b", "qwen3:4b"])
    staged = {
        "llm.provider": "ollama",
        "llm.ollama.expert_model": "qwen3:8b",
        "llm.agents": {"network": {"provider": "ollama", "model": "qwen3:4b"}},
    }
    result = await probe_agent({"name": "network", "settings": staged})
    assert result.ok is True
    assert result.details["llm"] == {
        "provider": "ollama",
        "model": "qwen3:4b",
        # Where the answer is filed: the endpoint this agent would call.
        "endpoint": "http://localhost:11434",
    }


@pytest.mark.asyncio
async def test_an_unreachable_ollama_server_does_not_fail_the_agent_probe(monkeypatch):
    _tags(monkeypatch, [], reachable=False)
    staged = {
        "llm.provider": "ollama",
        "llm.ollama.expert_model": "qwen3:8b",
        "llm.agents": {"network": {"provider": "ollama", "model": "qwen3:4b"}},
    }
    result = await probe_agent({"name": "network", "settings": staged})
    assert result.ok is True, "reachability is the LLM probe's job, not this one"


@pytest.mark.asyncio
async def test_a_non_ollama_agent_model_is_not_checked_against_any_tag_list(monkeypatch):
    calls = _tags(monkeypatch, ["qwen3:8b"])
    staged = {
        "llm.provider": "openai",
        "llm.agents": {"network": {"provider": "openai", "model": "gpt-4o"}},
    }
    result = await probe_agent({"name": "network", "settings": staged})
    assert result.ok is True
    assert calls == []


class TestTheProbeMakesTheCallTheJobWillMake:
    """A gate that refuses a job has to rest on a probe that reached the model.

    Listing a catalogue says the endpoint is up and that a name appears in it.
    It does not say the server will load that model, that the key may use it,
    or that a misspelling has not landed on a name the catalogue happens to
    hold — and those are the failures the gate exists to catch before a sample
    is uploaded and a queue slot spent.
    """

    @pytest.mark.parametrize(
        ("provider", "endpoint", "fragment"),
        [
            ("openai", "http://127.0.0.1:8080/v1", "/chat/completions"),
            ("ollama", "http://box:11434", "/api/generate"),
            ("anthropic", "", "api.anthropic.com/v1/messages"),
            ("gemini", "", ":generateContent"),
        ],
    )
    def test_every_provider_is_asked_for_one_short_answer(
        self, provider: str, endpoint: str, fragment: str
    ) -> None:
        from app.services.settings_probes import COMPLETION_MAX_TOKENS, _completion_request

        url, _headers, body = _completion_request(provider, endpoint, "a-model", "k")

        assert url is not None and fragment in url
        assert "a-model" in (url + json.dumps(body))
        assert str(COMPLETION_MAX_TOKENS) in json.dumps(body)

    @pytest.mark.asyncio
    async def test_a_completion_that_was_refused_is_not_a_pass(self, monkeypatch) -> None:
        monkeypatch.undo()

        class _Client:
            async def __aenter__(self) -> Any:
                return self

            async def __aexit__(self, *_: Any) -> None:
                return None

            async def post(self, *_: Any, **__: Any) -> Any:
                return httpx.Response(404, request=httpx.Request("POST", "http://x"))

        monkeypatch.setattr(settings_probes, "_client", lambda *_a, **_k: _Client())

        ok, said = await settings_probes.complete_one_turn(
            "openai", endpoint="http://127.0.0.1:8080/v1", model="ghost"
        )

        assert ok is False and "ghost" in said and "404" in said

    @pytest.mark.asyncio
    async def test_a_completion_that_answered_is_a_pass(self, monkeypatch) -> None:
        monkeypatch.undo()

        class _Client:
            async def __aenter__(self) -> Any:
                return self

            async def __aexit__(self, *_: Any) -> None:
                return None

            async def post(self, *_: Any, **__: Any) -> Any:
                return httpx.Response(
                    200,
                    request=httpx.Request("POST", "http://x"),
                    json={"choices": [{"message": {"content": "OK"}}]},
                )

        monkeypatch.setattr(settings_probes, "_client", lambda *_a, **_k: _Client())

        ok, said = await settings_probes.complete_one_turn(
            "openai", endpoint="http://127.0.0.1:8080/v1", model="qwen"
        )

        assert ok is True and "qwen" in said

    @pytest.mark.asyncio
    async def test_a_two_hundred_with_nothing_in_it_is_not_a_pass(self, monkeypatch) -> None:
        """A proxy that answers politely for a model it cannot serve."""
        monkeypatch.undo()
        from app.services import settings_probes

        class _Client:
            async def __aenter__(self) -> Any:
                return self

            async def __aexit__(self, *_: Any) -> None:
                return None

            async def post(self, *_: Any, **__: Any) -> Any:
                return httpx.Response(200, request=httpx.Request("POST", "http://x"), json={})

        monkeypatch.setattr(settings_probes, "_client", lambda *_a, **_k: _Client())

        ok, said = await settings_probes.complete_one_turn(
            "openai", endpoint="http://127.0.0.1:8080/v1", model="qwen"
        )

        assert ok is False and "answered nothing" in said

    @pytest.mark.asyncio
    async def test_a_completion_that_timed_out_files_nothing(self, monkeypatch) -> None:
        """A cold model is not a missing one, and a row would lock the operator out."""
        monkeypatch.undo()
        from app.services import settings_probes

        class _Client:
            async def __aenter__(self) -> Any:
                return self

            async def __aexit__(self, *_: Any) -> None:
                return None

            async def post(self, *_: Any, **__: Any) -> Any:
                raise httpx.ReadTimeout("slow", request=httpx.Request("POST", "http://x"))

        monkeypatch.setattr(settings_probes, "_client", lambda *_a, **_k: _Client())

        verdict, said = await settings_probes.complete_one_turn(
            "openai", endpoint="http://127.0.0.1:8080/v1", model="qwen"
        )

        assert verdict is None, "neither a pass nor a failure"
        assert "still be loading" in said and "Nothing was written down" in said
        assert str(int(settings_probes.COMPLETION_TIMEOUT)) in said

    @pytest.mark.asyncio
    async def test_the_completion_gets_its_own_budget(self) -> None:
        from app.services.settings_probes import COMPLETION_TIMEOUT, TIMEOUT

        assert COMPLETION_TIMEOUT > TIMEOUT, "a cold local model is not a listing"

    @pytest.mark.asyncio
    async def test_an_agent_that_names_no_model_is_not_a_pass(self, monkeypatch) -> None:
        monkeypatch.undo()
        from app.services.settings_probes import complete_one_turn

        ok, said = await complete_one_turn("openai", endpoint="http://x/v1", model="  ")

        assert ok is False and said == "no model named"

    @pytest.mark.asyncio
    async def test_the_llm_probe_files_only_what_it_completed(self, monkeypatch) -> None:
        """Every filed pair was asked, at its own endpoint, and no other pair is filed."""
        monkeypatch.undo()
        import httpx as _httpx

        from app.services import settings_probes

        asked: list[tuple[str, str]] = []

        def handler(request: _httpx.Request) -> _httpx.Response:
            if request.url.path.endswith("/api/generate"):
                import json as _json

                model = _json.loads(request.content or b"{}").get("model", "")
                asked.append((f"{request.url.scheme}://{request.url.netloc.decode()}", model))
                return _httpx.Response(200, json={"response": "OK"})
            return _httpx.Response(
                200, json={"models": [{"name": "qwen3:8b"}, {"name": "qwen3:70b"}]}
            )

        monkeypatch.setattr(
            settings_probes,
            "_client",
            lambda *_a, **_k: _httpx.AsyncClient(
                transport=_httpx.MockTransport(handler), timeout=10
            ),
        )

        result = await settings_probes.probe_llm(
            {
                "provider": "ollama",
                "ollama_base_url": "http://ollama:11434",
                "ollama_expert_model": "qwen3:8b",
                "ollama_judge_model": "qwen3:70b",
                "agents": {
                    "network": {
                        "provider": "ollama",
                        "model": "qwen3:4b",
                        "base_url": "http://gpu-box:11434",
                    }
                },
            }
        )

        filed = {(p["endpoint"], p["model"]) for p in (result.details or {})["completions"]}
        assert filed == {
            ("http://ollama:11434", "qwen3:8b"),
            ("http://gpu-box:11434", "qwen3:4b"),
        }
        assert set(asked) == filed, "every filed pair was the pair that was called"
        assert not any(model == "qwen3:70b" for _endpoint, model in asked), "the judge was listed"
