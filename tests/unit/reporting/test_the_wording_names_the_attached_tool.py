"""Model-facing and published wording names a tool by its declared display name, or neutrally.

* The function map counts decoded strings under the display name the placing
  tool declares (the shipped decoder's, as before), and neutrally where no one
  name covers them.
* The run state's function-index line calls its rule cells by the shipped
  matcher only where the rows hold them under its name.
* The Markdown capability tables and the ATT&CK table's note name the tool the
  capability table's title names, the shipped one as before.
* The narrative's rule pointer is read from the rule tables the report holds,
  "sigma/yara" for a built-in run as before, a swapped tool as itself.
* The function check names the attached string emulators by their declared
  display names ("FLOSS" for a built-in run, as before), neutrally when none is
  attached.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from maljan.agents.function_map import build_function_map, function_artefacts, function_map_block
from maljan.core.declared_reading import shipped_by_name, stored_record
from maljan.pipeline.run_state import index_sentence
from maljan.reporting.models import EvidenceSection, FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import _capability_owner, _capability_table
from maljan.schemas.evidence import LedgerEntry

_DECODED = json.dumps({"strings": [{"kind": "decoded", "string": "a", "function_rva": "0x2000"}]})


def _map(entry: LedgerEntry) -> str:
    own = [LedgerEntry(id="ev_0009", tool="disassemble_function", args={"address": "0x2000"})]
    claim = SimpleNamespace(claim="0x2000 reads a value.", evidence_ref="ev_0009")
    return function_map_block(build_function_map(own, function_artefacts([entry]), [claim]))


def test_the_shipped_decoder_is_named_as_before() -> None:
    block = _map(LedgerEntry(id="ev_0001", tool="floss", output=_DECODED))
    assert "1 string FLOSS decoded" in block


def test_another_decoder_is_named_by_its_declared_display_name_or_neutrally() -> None:
    shipped = shipped_by_name()["floss"]
    for display, said in (("Unwinder", "1 string Unwinder decoded"), ("", "decoded by emulation")):
        facts = shipped.model_copy(update={"display_name": display})
        entry = LedgerEntry(id="ev_0001", tool="unwind", output=_DECODED).model_copy(
            update={"source": "mcp:emu", "facts": stored_record(facts)}
        )
        block = _map(entry)
        assert said in block and "FLOSS" not in block


def test_the_index_line_names_the_shipped_matcher_only_for_its_cells() -> None:
    from maljan.tools.artefact_index import RULES_FIELD_NEUTRAL, rules_field

    shipped = rules_field(shipped=True)
    assert f"{shipped} rules" in index_sentence("ev_0001", {"rows": [{shipped: []}]})
    assert f"{shipped} rules" in index_sentence("ev_0001", {"rows": [{"function": "0x1"}]})
    neutral = index_sentence("ev_0001", {"rows": [{RULES_FIELD_NEUTRAL: []}]})
    assert f"{shipped} rules" not in neutral and "strings, rules, callers" in neutral


def _report(title: str) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        sections=[
            EvidenceSection(
                key="capa_capabilities",
                title=title,
                kind="table",
                columns=["Namespace", "Rule", "ATT&CK", "MBC"],
                rows=[["anti-analysis", "check for debugger", "", ""]],
            )
        ],
    )


def test_the_capability_tables_name_the_tool_their_title_names() -> None:
    rule = ({"namespace": "anti-analysis", "rule": "r", "attck": "", "mbc": ""}, ["ev_0001"])
    assert "_Measured:_ capa rules" in "\n".join(_capability_table([rule], lambda _: True, "capa"))
    swapped = "\n".join(_capability_table([rule], lambda _: True, "RuleBench"))
    assert "RuleBench rules" in swapped and "capa" not in swapped
    assert "capability rules" in "\n".join(_capability_table([rule], lambda _: True))
    assert _capability_owner(_report("capa capabilities")) == "capa's"
    assert _capability_owner(_report("RuleBench capabilities")) == "RuleBench's"
    assert _capability_owner(_report("Capabilities")) == "a capability rule tool's"


def _rule_report(**titles: str) -> SimpleNamespace:
    return SimpleNamespace(
        sections=[SimpleNamespace(key=key, title=title) for key, title in titles.items()]
    )


def test_the_narrative_rule_pointer_is_read_from_the_reports_rule_tables() -> None:
    from maljan.reporting import narrative_agent

    assert narrative_agent.rule_pointer() == "a sigma/yara pointer"
    assert narrative_agent.system_prompt() == narrative_agent._SYSTEM_PROMPT
    assert "or a sigma/yara pointer. Do NOT " in narrative_agent._SYSTEM_PROMPT
    shipped = _rule_report(sigma_matches="Sigma rule matches", yara_matches="YARA rule matches")
    assert narrative_agent.system_prompt(shipped) == narrative_agent._SYSTEM_PROMPT
    swapped = _rule_report(sigma_matches="Hayabusa rule matches")
    assert narrative_agent.rule_pointer(swapped) == "a hayabusa/yara pointer"
    assert "or a hayabusa/yara pointer. Do NOT " in narrative_agent.system_prompt(swapped)


def test_the_function_check_names_the_attached_emulator(monkeypatch: pytest.MonkeyPatch) -> None:
    from maljan.core import declared_reading
    from maljan.pipeline import function_claims as fc

    assert fc.attached_emulators() == "FLOSS"
    built_in = fc.NOT_A_SAMPLE_STRING.format(value="v", emulators=fc.attached_emulators())
    assert built_in == (
        'no: "v" is no string a strings tool, FLOSS, the blob decoder or the function index holds'
    )
    for held, said in (
        ([("mcp:emu", "unwind", SimpleNamespace(display_name="Unwinder"))], "Unwinder"),
        ([], fc.NO_EMULATOR_NAMED),
        ([("mcp:emu", "unwind", SimpleNamespace(display_name=""))], fc.NO_EMULATOR_NAMED),
    ):
        fake = SimpleNamespace(tools_of_kind=lambda kind, enabled_only=False, h=held: h)
        monkeypatch.setattr(declared_reading, "declarations", lambda settings=None, f=fake: f)
        assert fc.attached_emulators() == said
