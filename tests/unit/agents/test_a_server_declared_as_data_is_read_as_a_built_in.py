"""A server declared only as data is read as a built-in is; a run with no Ghidra hears none of it.

The invented server ``acmescan`` declares, in its settings block alone, the
workflow text its agents are shown, the budget each of its calls gets, a
signature-rule tool whose rows are the rules that matched, and a sample
lookup its report links to. Each reaches the agent, the guard, a stage
condition and the report the way a built-in server's does. A run on radare2
carries no Ghidra text in any prompt; the Ghidra prompt is dev's but for the
one line that pointed at another server's tool; every static provider gets
the verification discipline.
"""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.core.config import Settings

ACME = "acmescan"
WORKFLOW = (
    "=== ACMESCAN WORKFLOW ===\n"
    "Call `match_rules` on the path you are given once; each row it returns is a rule "
    "that matched, and its name is what a claim cites."
)
LOOKUP = "https://intel.example/lookup/{sha256}"
SHA256 = "a" * 64


class _Args(BaseModel):
    path: str = ""


def _tool(name: str) -> Any:
    async def _run(**_: object) -> str:
        return ""

    return StructuredTool.from_function(
        func=None, coroutine=_run, name=name, description=f"Runs {name}.", args_schema=_Args
    )


def _settings() -> Settings:
    return Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    ACME: {
                        "enabled": True,
                        "command": "acme",
                        "agents": ["static"],
                        "label": "Acme Scan",
                        "prompt_fragment": WORKFLOW,
                        "call_timeout_seconds": 45,
                        "reference_urls": [LOOKUP],
                        "tool_facts": {
                            "match_rules": {
                                "kind": "signature_rules",
                                "rows": "/hits/*",
                                "values": {"rule": "/name"},
                                "arguments": {"path": "path"},
                            }
                        },
                    }
                }
            }
        }
    )


def _entry(settings: Settings, rows: int = 2) -> Any:
    from maljan.core import declared_reading
    from maljan.core.config import get_settings, install_settings
    from maljan.schemas.evidence import build_entry

    previous = get_settings()
    install_settings(settings)
    declared_reading.forget()
    try:
        return build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="static",
            tool="match_rules",
            args={"path": "/samples/x.bin"},
            server=ACME,
            output=json.dumps({"hits": [{"name": f"rule_{i}"} for i in range(rows)]}),
            source=f"mcp:{ACME}",
        )
    finally:
        install_settings(previous)
        declared_reading.forget()


class TestItsWorkflowText:
    def _attached(self, settings: Settings) -> list[Any]:
        from maljan.providers.servers import ServerRegistry

        registry = ServerRegistry(settings)
        handle = registry._handles[ACME]
        handle.tools = lambda: [_tool("match_rules")]  # type: ignore[method-assign]
        handle.withheld_reasons = lambda: []  # type: ignore[method-assign]
        tools: list[Any] = []
        registry._merge(handle, tools, {})
        return tools

    def test_it_reaches_the_agent_with_the_servers_tools(self) -> None:
        from maljan.agents.prompt_fragments import format_fragment, tools_statement
        from maljan.agents.static_analyst import assemble_static_prompt
        from maljan.providers.static.null import NullStaticProvider

        tools = self._attached(_settings())
        assert WORKFLOW in tools_statement(tools)
        prompt = assemble_static_prompt(
            NullStaticProvider(), format_fragment("pe", "windows"), tools
        )
        assert prompt.count(WORKFLOW) == 1

    def test_a_request_without_its_tools_shows_none_of_it(self) -> None:
        from maljan.agents.prompt_fragments import tools_statement

        other = _tool("something_else").model_copy(
            update={"metadata": {"maljan_server": "knowledge"}}
        )
        assert WORKFLOW not in tools_statement([other])
        assert WORKFLOW not in tools_statement([])

    def test_a_server_that_declares_none_adds_nothing(self) -> None:
        from maljan.agents.prompt_fragments import server_fragments

        settings = _settings()
        settings.mcp.servers[ACME].prompt_fragment = ""
        assert server_fragments(self._attached(settings)) == []


class TestItsCallBudget:
    def test_each_call_gets_the_budget_its_block_declares(self) -> None:
        from maljan.providers.server_guard import guard_from_settings

        settings = _settings()
        assert guard_from_settings(ACME, settings).call_timeout("match_rules") == 75.0
        # The operator's breaker budget, where set, applies to every server.
        settings.mcp.breaker.call_timeout_seconds = 20
        assert guard_from_settings(ACME, settings).call_timeout("match_rules") == 50.0


class TestItsRuleHits:
    def test_a_stage_condition_reads_them_by_server_and_by_kind(self) -> None:
        from maljan.pipeline.conditions import evaluate, validate_condition
        from maljan.pipeline.nodes import stage_context

        entry = _entry(_settings())
        state = {"evidence_ledger": [entry.model_dump()], "triage_facts": {"capa_hits": 3}}
        ctx = stage_context(state)  # type: ignore[arg-type]
        assert ctx.triage.hits[ACME] == 2
        assert ctx.triage.hits["signature_rules"] == 2
        assert ctx.triage.rule_hits == 2
        assert evaluate(f'triage.hits["{ACME}"] > 1 and triage.rule_hits == 2', ctx)
        assert evaluate('triage.hits["no_such_server"] == 0', ctx)
        # The legacy fields stay the pack's own counts, as stored teams read them.
        assert ctx.triage.capa_hits == 3 and ctx.triage.yara_hits == 0
        assert validate_condition(f'triage.hits["{ACME}"] > 0') == []
        (problem,) = validate_condition("triage.hits[triage.yara_hits] > 0")
        assert "literal key" in problem

    def test_a_built_in_rule_answer_counts_the_same_way(self) -> None:
        from maljan.pipeline.conditions import rule_match_hits

        row = {
            "id": "ev_0002",
            "tool": "yara_scan",
            "server": "analysis",
            "ok": True,
            "structured": {"matches": [{"rule": "a"}, {"rule": "b"}, {"rule": "c"}]},
        }
        counted, total = rule_match_hits([row])
        assert total == 3
        assert counted["signature_rules"] == 3 and counted["yara"] == 3

    def test_facts_stored_before_the_counts_read_their_two_fields(self) -> None:
        from maljan.pipeline.conditions import TriageFacts

        facts = TriageFacts.from_dict({"yara_hits": 2, "capa_hits": 1})
        assert facts.rule_hits == 3
        assert dict(facts.hits) == {"signature_rules": 2, "capability_rules": 1}

    def test_the_count_is_linear_in_the_ledger(self) -> None:
        import time

        from maljan.pipeline.conditions import rule_match_hits

        def rows(n: int) -> list[dict[str, Any]]:
            return [
                {
                    "id": f"ev_{i:04d}",
                    "tool": "yara_scan",
                    "server": "analysis",
                    "ok": True,
                    "structured": {"matches": [{"rule": "a"}] * 5},
                }
                for i in range(n)
            ]

        def best(n: int) -> float:
            held = rows(n)
            times = []
            for _ in range(3):
                start = time.perf_counter()
                rule_match_hits(held)
                times.append(time.perf_counter() - start)
            return min(times)

        small, large = best(400), best(4000)
        assert large <= small * 10 * 2.5 + 0.05


class TestItsSampleLookup:
    def test_a_run_that_asked_it_links_it_and_the_report_keeps_the_link(self) -> None:
        from maljan.core import declared_reading
        from maljan.core.config import get_settings, install_settings
        from maljan.reporting.renderers.markdown import MarkdownRenderer
        from tests.unit.reporting.test_builder import _build

        settings = _settings()
        entry = _entry(settings)
        previous = get_settings()
        install_settings(settings)
        declared_reading.forget()
        try:
            report = _build(ledger=[entry])
        finally:
            install_settings(previous)
            declared_reading.forget()
        url = LOOKUP.replace("{sha256}", SHA256)
        # After the shipped lookups every report links.
        assert [(ref.source, ref.url) for ref in report.references] == [
            ("VirusTotal", f"https://www.virustotal.com/gui/file/{SHA256}"),
            ("MalwareBazaar", f"https://bazaar.abuse.ch/sample/{SHA256}/"),
            ("Acme Scan", url),
        ]
        markdown = MarkdownRenderer().render(report)
        for ref in report.references:
            assert f"]({ref.url})" in markdown

    def test_a_run_that_never_asked_a_service_links_none(self) -> None:
        from maljan.core.tool_declarations import ToolDeclarations
        from maljan.reporting.references import declared_references

        declared = ToolDeclarations.from_settings(_settings())
        hashes = SimpleNamespace(sha256=SHA256, md5=None, sha1=None)
        assert declared_references([], hashes, declared=declared) == []
        asked_other = [{"source": "mcp:knowledge", "server": "knowledge", "tool": "x"}]
        assert declared_references(asked_other, hashes, declared=declared) == []

    def test_the_operators_own_lookups_are_linked_on_every_report(self) -> None:
        from maljan.core.tool_declarations import ToolDeclarations
        from maljan.reporting.references import declared_references

        declared = ToolDeclarations.from_settings(_settings())
        hashes = SimpleNamespace(sha256=SHA256, md5="b" * 32, sha1=None)
        linked = declared_references(
            [],
            hashes,
            declared=declared,
            operator=["https://samples.example/{md5}", "https://other.example/{sha1}"],
        )
        assert [(ref.source, ref.url) for ref in linked] == [
            ("samples.example", f"https://samples.example/{'b' * 32}")
        ]

    def test_under_default_settings_a_new_report_links_what_dev_linked(self) -> None:
        from tests.unit.reporting.test_builder import _build

        report = _build()
        assert [(r.source, r.url, r.note) for r in report.references] == [
            ("VirusTotal", f"https://www.virustotal.com/gui/file/{SHA256}", "VT detection summary"),
            ("MalwareBazaar", f"https://bazaar.abuse.ch/sample/{SHA256}/", "Sample lookup"),
        ]

    def test_a_run_that_asked_virustotal_links_it_once(self) -> None:
        from maljan.core.config import Settings as _Settings
        from maljan.core.tool_declarations import ToolDeclarations
        from maljan.reporting.references import declared_references

        settings = _Settings()
        declared = ToolDeclarations.from_settings(settings)
        hashes = SimpleNamespace(sha256=SHA256, md5=None, sha1=None)
        asked = [{"source": "mcp:virustotal", "server": "virustotal", "tool": "get_file_report"}]
        linked = declared_references(
            asked, hashes, declared=declared, operator=settings.reporting.reference_urls
        )
        assert [ref.source for ref in linked] == ["VirusTotal", "MalwareBazaar"]
        removed = declared_references(asked, hashes, declared=declared, operator=[])
        assert [ref.url for ref in removed] == [f"https://www.virustotal.com/gui/file/{SHA256}"]

    def test_a_link_of_a_service_the_report_does_not_hold_is_defanged(self) -> None:
        from maljan.reporting.renderers.markdown import _KEPT_LINKS, _defanged_text, _Kept

        token = _KEPT_LINKS.set(_Kept(frozenset({"https://intel.example/lookup/x"}), False))
        try:
            assert _defanged_text("https://intel.example/lookup/x") == (
                "https://intel.example/lookup/x"
            )
            assert "hxxps" in _defanged_text("https://intel.example/other/x")
            # A newer report does not keep the legacy services' shapes.
            assert "hxxps" in _defanged_text(f"https://bazaar.abuse.ch/sample/{SHA256}/")
        finally:
            _KEPT_LINKS.reset(token)


class TestARunWithNoGhidra:
    @pytest.fixture
    def container(self) -> Any:
        from maljan.core.container import ServiceContainer

        settings = Settings(_env_file=None)
        settings.static.provider = "r2"
        return ServiceContainer(settings, mock=True)

    def test_no_prompt_names_ghidra(self, container: Any) -> None:
        from maljan.agents.composition import builtin_prompt

        prompts = [
            builtin_prompt(role, container, "r2", [], provider_expected=expected)
            for role in ("static", "dynamic", "network", "judge")
            for expected in (False, True)
        ]
        for prompt in prompts:
            assert "ghidra" not in prompt.lower()
        static = builtin_prompt("static", container, "r2", [], provider_expected=True)
        assert "radare2" in static and "=== VERIFICATION DISCIPLINE" in static


class TestTheGhidraPrompt:
    def test_it_is_devs_but_for_the_line_that_named_another_servers_tool(self) -> None:
        from maljan.providers.static.ghidra import GHIDRA_PROMPT_FRAGMENT

        reworded = (
            "  published constants and where they stand; a crypto-constant tool, where one\n"
            "  is attached, gives its whole answer (Ghidra's `detect_crypto_constants`\n"
        )
        before = (
            "  published constants and where they stand; `find_crypto_constants` on the\n"
            "  analysis server gives its whole answer (Ghidra's `detect_crypto_constants`\n"
        )
        assert GHIDRA_PROMPT_FRAGMENT.count(reworded) == 1
        dev = GHIDRA_PROMPT_FRAGMENT.replace(reworded, before)
        assert hashlib.sha256(dev.encode()).hexdigest()[:16] == "9be4fea6d9b8c95f"

    def test_its_guidance_is_the_shared_discipline_byte_for_byte(self) -> None:
        from maljan.providers.base import CLAIM_GUIDANCE
        from maljan.providers.static.ghidra import GHIDRA_GUIDANCE

        assert GHIDRA_GUIDANCE == CLAIM_GUIDANCE
        assert hashlib.sha256(GHIDRA_GUIDANCE.encode()).hexdigest()[:16] == "97db82324dec815f"


class TestEveryStaticProviderCarriesTheDiscipline:
    @pytest.mark.parametrize("provider_id", ["ghidra", "r2", "generic_mcp", "none", "capa_yara"])
    def test_attached_absent_and_tool_free(self, provider_id: str) -> None:
        from maljan.agents.static_analyst import static_provider_parts
        from maljan.providers.base import VERIFICATION_DISCIPLINE
        from maljan.providers.registry import get_static_provider

        settings = Settings(_env_file=None)
        settings.static.provider = provider_id
        provider = get_static_provider(settings)
        for expected in (False, True):
            body, _statement = static_provider_parts(provider, [], provider_expected=expected)
            assert body.count(VERIFICATION_DISCIPLINE) == 1, (provider_id, expected)

    def test_a_provider_writing_its_own_fragment_still_gets_it(self) -> None:
        from maljan.agents.static_analyst import static_provider_parts
        from maljan.providers.base import VERIFICATION_DISCIPLINE

        provider = SimpleNamespace(
            label="Acme",
            capabilities=SimpleNamespace(provides_tools=False),
            prompt_fragment=lambda: "ACME WORKFLOW",
        )
        body, _statement = static_provider_parts(provider, [])
        assert body == "ACME WORKFLOW\n\n" + VERIFICATION_DISCIPLINE
