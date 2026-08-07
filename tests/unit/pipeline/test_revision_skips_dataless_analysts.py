"""An analyst with no data must not be revised — it manufactures corroboration.

The analyst node already refuses to run an agent whose loader returned nothing
but its "No <layer> data available for sample <sha>." sentence
(``nodes.py`` / ``_is_placeholder_only``, locked in by
``test_placeholder_skip.py``). The revision node never got the same guard: it
iterates ``agent_registry.list_agents()`` unconditionally, so every negotiation
round re-runs every analyst — including the ones that were just skipped for
having nothing to analyse.

Observed live on 2026-07-29, CAPE unreachable, one round:

    14:32:18  static  ISR revision (round 1)     6m38s
    14:38:56  dynamic ISR revision (round 1)     8m39s   <- no sandbox data at all
    14:47:35  network ISR revision (round 1)     8m03s   <- no PCAP at all
    14:55:38  WARNING Sycophancy detected between 'static' and 'dynamic' (sim=1.000)

The cost is not the wasted quarter hour. ``_revise_one`` hands each agent its
*peers'* reports, so an analyst with no evidence of its own has nothing to write
but what static already said — and it comes back tagged ``domain="dynamic"``.
``CascadeResult.is_corroborated`` is ``len(contributing_layers) >= 2``, so a
single-layer static finding is promoted to CORROBORATED by an analyst that
never saw a byte of dynamic data, and enters at ``LAYER_WEIGHTS["dynamic"]``
= 0.45 — *above* static's own 0.35. sim=1.000 is that echo, measured.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

from maljan.pipeline.nodes import make_revision_node


@dataclass
class _Chunk:
    content: str
    index: int = 0
    total: int = 1

    def to_prompt_header(self) -> str:
        return f"[chunk {self.index + 1}/{self.total}]"


def _agent(name: str) -> MagicMock:
    """An agent whose ``safe_revise_isr`` records that it was called."""
    agent = MagicMock()
    isr = MagicMock()
    isr.claims = [MagicMock()]
    isr.dissent_items = []
    agent.safe_revise_isr.return_value = (f"{name} revised text", isr)
    return agent


def _container(chunks_by_agent: dict[str, list[_Chunk]]) -> MagicMock:
    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = list(chunks_by_agent)
    container.config.llm.parallel_analysts = False
    agents = {name: _agent(name) for name in chunks_by_agent}
    container.get_agent.side_effect = lambda n: agents[n]
    container.load_chunked.side_effect = lambda _h, n: chunks_by_agent[n]
    container.load_data.side_effect = lambda _h, n: chunks_by_agent[n][0].content
    container._agents = agents  # test handle
    return container


def _state() -> dict[str, Any]:
    return {
        "file_hash": "abc123",
        "iteration_count": 1,
        "discussion_history": [],
        "reports": {
            "static": "PE32 with VirtualAllocEx, WriteProcessMemory, CreateRemoteThread.",
            "dynamic": "",
            "network": "",
        },
        "isr_reports": {},
    }


_REAL_DATA = [_Chunk(content="PE32 executable, 9 sections, imports VirtualAllocEx.")]


def _placeholder(layer: str) -> list[_Chunk]:
    return [_Chunk(content=f"No {layer} data available for sample abc123.")]


def _run(container: MagicMock) -> dict[str, Any]:
    node = make_revision_node(container)
    return asyncio.run(node(_state()))


class TestADatalessAnalystIsNotRevised:
    def test_the_analyst_with_only_a_placeholder_is_skipped(self) -> None:
        c = _container(
            {"static": _REAL_DATA, "dynamic": _placeholder("dynamic"), "network": _REAL_DATA}
        )
        _run(c)

        assert c._agents["static"].safe_revise_isr.called
        assert c._agents["network"].safe_revise_isr.called
        assert not c._agents["dynamic"].safe_revise_isr.called, (
            "dynamic has no sandbox data; revising it can only echo its peers"
        )

    def test_every_dataless_analyst_is_skipped(self) -> None:
        c = _container(
            {
                "static": _REAL_DATA,
                "dynamic": _placeholder("dynamic"),
                "network": _placeholder("network"),
            }
        )
        _run(c)

        assert c._agents["static"].safe_revise_isr.called
        assert not c._agents["dynamic"].safe_revise_isr.called
        assert not c._agents["network"].safe_revise_isr.called

    def test_an_analyst_with_no_chunks_at_all_is_skipped(self) -> None:
        c = _container({"static": _REAL_DATA, "dynamic": []})
        _run(c)

        assert not c._agents["dynamic"].safe_revise_isr.called


class TestTheSkipDoesNotFabricateOrDestroyContent:
    def test_the_skipped_analyst_keeps_its_original_report(self) -> None:
        """Skipping must not blank a report the rest of the pipeline reads."""
        c = _container({"static": _REAL_DATA, "dynamic": _placeholder("dynamic")})
        out = _run(c)

        assert out["revised_reports"]["dynamic"] == _state()["reports"]["dynamic"]

    def test_the_skipped_analyst_emits_an_empty_isr_not_a_missing_key(self) -> None:
        """``zip(..., strict=True)`` downstream means every agent must be present."""
        c = _container({"static": _REAL_DATA, "dynamic": _placeholder("dynamic")})
        out = _run(c)

        assert set(out["isr_reports"]) == {"static", "dynamic"}
        assert not out["isr_reports"]["dynamic"].claims, (
            "a skipped analyst must contribute no claims — claims are what "
            "reach the cascade as a contributing layer"
        )


class TestStaticIsNeverSkipped:
    """Mirrors ``_is_placeholder_only``'s static carve-out.

    When a sample cannot be mirrored for the Ghidra container the loader
    returns the placeholder for static too, and static is *meant* to fall back
    to a metadata-only prompt. Skipping it here would delete the primary
    analyst on exactly the runs that most need whatever it can still say.
    """

    def test_static_is_revised_even_on_a_placeholder(self) -> None:
        c = _container({"static": _placeholder("static"), "dynamic": _REAL_DATA})
        _run(c)

        assert c._agents["static"].safe_revise_isr.called


class TestTheGuardSurvivesALoaderFailure:
    def test_a_raising_loader_does_not_skip_the_analyst(self) -> None:
        """Unknown data is not absent data — fail open, revise anyway."""
        c = _container({"static": _REAL_DATA, "dynamic": _REAL_DATA})
        c.load_chunked.side_effect = RuntimeError("qdrant down")
        _run(c)

        assert c._agents["dynamic"].safe_revise_isr.called
