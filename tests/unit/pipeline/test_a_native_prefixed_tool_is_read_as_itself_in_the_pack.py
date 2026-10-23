"""The pack reads a server's tool by the name its step declares, never with a prefix off.

A step (or a configured lookup) names the tool as the server declares it, so
the pack's readers look it up exactly: a tool a server natively spells
``<its key>__x`` is read as itself, never as the server's tool ``x``, and the
entry its step writes is stored under that name as the declared one.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.core.config import Settings
from maljan.core.declared_reading import FACTS_VERSION
from maljan.core.pack_steps import PackStep
from maljan.core.tool_declarations import ToolDeclarations
from maljan.pipeline import nodes, triage_pack
from maljan.pipeline.triage_pack import PIPELINE, ServerAnswer
from maljan.schemas.evidence import EvidenceCounter

HASH = "b" * 64


def _settings() -> Settings:
    # Only ``x`` is declared: a native ``mine__x`` is undeclared and must stay so.
    facts: dict[str, Any] = {
        "x": {
            "kind": "reputation",
            "read_only": True,
            "arguments": {"path": "p", "hash": "h"},
            "timeout_seconds": 99,
        },
    }
    return Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    "mine": {
                        "command": "x",
                        "tool_facts": facts,
                    }
                }
            }
        }
    )


@pytest.fixture
def held(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, bool]]:
    """The declarations in force, and every read of them as ``(tool name, exact)``."""
    declared = ToolDeclarations.from_settings(_settings())
    monkeypatch.setattr("maljan.core.declared_reading.declarations", lambda *_a, **_k: declared)
    seen: list[tuple[str, bool]] = []
    real = ToolDeclarations.declaration_for

    def spy(self: ToolDeclarations, entry: Any, *, exact: bool = False) -> Any:
        seen.append((entry[1], exact))
        return real(self, entry, exact=exact)

    monkeypatch.setattr(ToolDeclarations, "declaration_for", spy)
    return seen


def _container(withheld: list[str]) -> Any:
    return SimpleNamespace(
        config=_settings(),
        active_profile=lambda: SimpleNamespace(exclude_servers=withheld),
        job_key=lambda: "job",
    )


def _recorder() -> EvidenceRecorder:
    return EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")


def test_the_server_step_reads_a_native_prefixed_tool_as_itself(
    held: list[tuple[str, bool]],
) -> None:
    step = PackStep(id="s", tool="mine__x", server="mine")
    call = nodes._server_step_call(_container(["mine"]))
    answer = call(step, {"sample_path": "/s", "sha256": HASH}, None)
    # ``x`` declares a path argument; the native tool declares none, so none is built.
    assert answer.args == {}
    assert held == [("mine__x", True)]


def test_the_scheduling_read_is_exact(held: list[tuple[str, bool]]) -> None:
    step = PackStep(id="s", tool="mine__x", server="mine")
    assert triage_pack._server_facts(step) is None
    assert held == [("mine__x", True)]


def test_the_lookup_reads_its_declared_timeout_exactly(held: list[tuple[str, bool]]) -> None:
    container = _container([])
    for key, server in container.config.mcp.servers.items():
        server.enabled = key == "mine"
    container.get_server_registry = lambda: SimpleNamespace(
        tools_for_ref=lambda *_a, **_k: ([], ["offered nothing"])
    )
    container.get_truncation_ledger = lambda: None
    entry = nodes._reputation_lookup(container, HASH)(_recorder())
    assert entry.tool == "x"
    assert ("x", True) in held
    # The entry it writes is stored under that name too: no read takes a prefix off.
    assert all(exact for _name, exact in held)


def test_the_pack_stores_a_server_step_under_its_declared_name(
    held: list[tuple[str, bool]],
) -> None:
    step = PackStep(id="s", tool="mine__x", server="mine")
    inputs = SimpleNamespace(
        steps=(step,), budget_s=0, sample_path="/s", sha256=HASH, file_type="pe"
    )
    recorder = _recorder()
    pack = triage_pack._Pack(
        recorder,
        inputs,  # type: ignore[arg-type]
        reputation=None,
        function_matches=None,
        server_step=lambda s, _values, _left: ServerAnswer(
            tool=s.called, args={}, server=s.server, output="{}"
        ),
    )
    pack._server(step)
    (entry,) = recorder.entries
    # Read as ``mine__x`` itself, which nothing declares; not as the server's ``x``.
    assert entry.tool == "mine__x"
    assert entry.facts == {"v": FACTS_VERSION}
