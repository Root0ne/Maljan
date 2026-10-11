"""A static provider registered at runtime gets the sink pre-pass and the pack's scan.

Nothing in the analysts, the triage node or the pack names a provider: an
invented disassembler that answers ``call_graph`` gets the priority-functions
hint in its agents' prompts, and one that answers ``anti_analysis_scan`` gets
the pack's anti-analysis entry, its line naming the provider by its display
name. radare2, which answers neither, runs without either and without errors.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

import pytest
from langchain_core.tools import StructuredTool

from maljan.agents.composition import ResolvedAgent
from maljan.agents.configurable_analyst import ConfigurableAnalyst
from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.agents.prompt_fragments import PROVIDER_FAMILY, stamp_source
from maljan.analysis.anti_analysis import SCAN_TOOL
from maljan.analysis.sink_reachability import CallGraph
from maljan.core.config import Settings
from maljan.pipeline.nodes import _anti_analysis_step
from maljan.pipeline.triage_pack import (
    PIPELINE,
    CapaSettings,
    PackInputs,
    pack_block,
    pack_entries,
    run_pack,
)
from maljan.providers import registry
from maljan.providers.base import (
    StaticCapabilities,
    StaticJobContext,
    StaticProvider,
    prepare_sample,
)
from maljan.schemas.evidence import EvidenceCounter
from maljan.tools import rules
from tests.unit.tools.synthetic_pe import TEXT_RVA, SyntheticPE

INVENTED = "acme_disassembler"
FOLLOW_UP = "Open these first with acme_decompile.\n"


@dataclass
class _AcmeScan:
    provider: str
    sample_path: str
    unavailable: str = ""
    formats: frozenset[str] = frozenset({"pe"})
    closed: bool = False

    def anti_analysis(self, host_path: str = "", function_starts: Sequence[Any] = ()) -> dict:
        return {
            "server": self.provider,
            "total_findings": 1,
            "returned": 1,
            "stated": [{"category": "suspicious_instruction", "what": "RDTSC", "offset": "0x1010"}],
            "not_stated": 0,
        }

    def close(self) -> None:
        self.closed = True


class _Acme(StaticProvider):
    choice_label: ClassVar[str] = "Acme Disassembler"
    title: ClassVar[str] = "Acme Disassembler MCP"
    priority_follow_up: ClassVar[str] = FOLLOW_UP
    scan_checks_short: ClassVar[str] = "listed instructions"

    def __init__(self) -> None:
        self.opened: list[str | None] = []

    @classmethod
    def from_settings(cls, cfg: Settings) -> _Acme:
        return cls()

    @property
    def capabilities(self) -> StaticCapabilities:
        return StaticCapabilities(provides_tools=True, needs_sample_mirror=True)

    def open_sample(self, path: str | None = None) -> bool:
        self.opened.append(path)
        return True

    def preprocessing(self) -> Any:
        return Settings(_env_file=None).preprocessing

    def call_graph(self, path: str) -> CallGraph:
        return CallGraph.of_edges(
            [("start", "decode"), ("decode", "VirtualAllocEx"), ("start", "connect")],
            {"start": "0x401000", "decode": "0x401200"},
        )

    def anti_analysis_scan(
        self, job: StaticJobContext, *, notes: Any = None, call_budget: float = 0.0
    ) -> _AcmeScan:
        return _AcmeScan(provider=self.id, sample_path=str(job.mirror_sample_path or ""))


@pytest.fixture
def acme() -> Iterator[type[_Acme]]:
    registry.register_static_provider(INVENTED)(_Acme)
    try:
        yield _Acme
    finally:
        registry._STATIC_REGISTRY.pop(INVENTED, None)


@pytest.fixture(autouse=True)
def _capa(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        rules,
        "capa",
        lambda path, **_: {"capabilities": [], "function_starts": [hex(TEXT_RVA)], "meta": {}},
    )


def _shipped(provider_id: str) -> StaticProvider:
    return registry.static_provider_class(provider_id).from_settings(Settings(_env_file=None))


class _Container:
    def __init__(self, configured: str, providers: dict[str, Any]) -> None:
        settings = Settings(_env_file=None)
        self.config = settings.model_copy(deep=True)
        object.__setattr__(self.config.static, "provider", configured)
        self.providers = providers
        self.sample_notes = None

    def get_static_provider(self, provider_id: str | None = None) -> Any:
        return self.providers[str(provider_id or self.config.static.provider)]


def _pack(tmp_path: Path, scan: Any) -> Any:
    target = tmp_path / "s.exe"
    target.write_bytes(SyntheticPE(functions=[(TEXT_RVA, TEXT_RVA + 0x100)]).build())
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    inputs = PackInputs(
        sample_path=str(target),
        sha256="a" * 64,
        file_type="pe",
        strings_head=10,
        capa=CapaSettings(rules_dir="", signatures_dir="", timeout_s=1),
    )
    return run_pack(recorder, inputs, anti_analysis=scan)


class TestThePrePass:
    def test_the_invented_provider_opens_the_sample_and_gives_its_hint(
        self, acme: type[_Acme]
    ) -> None:
        provider = acme()
        hint = prepare_sample(provider, "/data/samples/.work/x.exe")
        assert provider.opened == ["/data/samples/.work/x.exe"]
        assert hint.startswith("PRIORITY FUNCTIONS")
        assert "- start (@ 0x401000) [injection, network] -> reaches:" in hint
        assert hint.endswith(FOLLOW_UP)

    def test_its_reverser_reads_the_hint_in_its_human_turn(
        self, acme: type[_Acme], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = acme()
        tool = StructuredTool.from_function(
            func=lambda: "x", name="acme_decompile", description="d"
        )
        resolved = ResolvedAgent(
            key="reverser_acme",
            role="generic",
            prompt="reverse it",
            tools=stamp_source([tool], PROVIDER_FAMILY),
            static_provider_id=INVENTED,
            llm=None,
        )
        agent = ConfigurableAnalyst("reverser_acme", resolved, llm=None)  # type: ignore[arg-type]
        agent._analysis_file_path = "/data/samples/.work/x.exe"
        agent._container = _Container(INVENTED, {INVENTED: provider})
        sent: list[Any] = []
        monkeypatch.setattr(agent, "execute_tool_loop", lambda messages: sent.append(messages))

        agent.analyze_isr(json.dumps({"analysis_file_path": "/data/samples/.work/x.exe"}))

        human = sent[0][1][1]
        assert "PRIORITY FUNCTIONS" in human and FOLLOW_UP.strip() in human

    def test_radare2_runs_without_it_and_without_errors(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            assert prepare_sample(_shipped("r2"), "/data/samples/r2-work/x.exe") == ""
        assert caplog.records == []


class TestTheScan:
    def test_the_node_asks_the_configured_invented_provider(self, acme: type[_Acme]) -> None:
        container = _Container(INVENTED, {INVENTED: acme()})
        scan = _anti_analysis_step(container, {"static_sample_path": "/s/x.exe"})  # type: ignore[arg-type]
        assert isinstance(scan, _AcmeScan)
        assert (scan.provider, scan.sample_path) == (INVENTED, "/s/x.exe")

    def test_the_pack_records_it_and_names_the_provider(
        self, acme: type[_Acme], tmp_path: Path
    ) -> None:
        scan = _AcmeScan(provider=INVENTED, sample_path="/s/x.exe")
        result = _pack(tmp_path, scan)
        entry = next(e for e in result.entries if e.tool == SCAN_TOOL)
        assert entry.ok and entry.args == {"program": "/s/x.exe", "provider": INVENTED}
        line = next(
            line
            for line in pack_block(pack_entries(result.entries), 0).splitlines()
            if line.startswith(f"[{entry.id}]")
        )
        assert line == (
            f"[{entry.id}] anti-analysis (Acme Disassembler): Acme Disassembler's scan (listed "
            "instructions) matched, each as Acme Disassembler's category: what @ offsets (in "
            "function): suspicious_instruction: RDTSC @ 0x1010"
        )
        assert scan.closed

    def test_an_unavailable_scan_is_one_no_line_naming_the_provider(
        self, acme: type[_Acme], tmp_path: Path
    ) -> None:
        scan = _AcmeScan(provider=INVENTED, sample_path="", unavailable="Acme is switched off")
        result = _pack(tmp_path, scan)
        entry = next(e for e in result.entries if e.tool == SCAN_TOOL)
        line = next(
            line
            for line in pack_block(pack_entries(result.entries), 0).splitlines()
            if line.startswith(f"[{entry.id}]")
        )
        assert line.endswith("anti-analysis (Acme Disassembler): no: Acme is switched off")
        assert result.failed == []

    def test_radare2_has_no_scan_and_the_pack_makes_no_entry(self, tmp_path: Path) -> None:
        r2 = _shipped("r2")
        assert r2.anti_analysis_scan(StaticJobContext(mirror_sample_path="/s/x.exe")) is None
        container = _Container("r2", {"r2": r2})
        state = {"static_sample_path": "/s/x.exe", "static_sample_paths": {"r2": "/s/x.exe"}}
        assert _anti_analysis_step(container, state) is None  # type: ignore[arg-type]
        result = _pack(tmp_path, None)
        assert SCAN_TOOL not in [e.tool for e in result.entries]
        assert result.failed == []
