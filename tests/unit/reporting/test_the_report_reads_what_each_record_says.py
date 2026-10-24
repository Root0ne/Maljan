"""Each reporting reader takes a record for what it says (AUD-43).

* A section fact that is ``False`` or ``0`` is a fact, shown to the composer.
* A claim is cited by its whole label: "static claim 12" does not cite claim 1.
* A Suricata draft's comment stays on its line whatever the family is called.
* A Sigma persistence image is the payload that runs, never the registry key.
* An autostart key is read at its components, to the value that starts a program.
* A sandbox signature keeps the techniques the sandbox tagged it with.
* An Android package's permissions are permissions, not exports.
* An analyst's listing is read by its headings, and merged tables keep each
  artifact's cells under their own headings.
* With no sandbox observation the narrative's prompt asserts no absence.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from maljan.reporting.models import (
    ConsolidatedIOC,
    DynamicBehavior,
    EvidenceSection,
    FamilyAttribution,
    FileHashes,
    MalwareReport,
    PersistenceMechanism,
    SampleIdentity,
    StaticAnalysis,
)
from maljan.schemas.evidence import EvidenceCounter, LedgerEntry, build_entry
from maljan.schemas.isr_models import AgentISR, Artifact
from tests.unit._ledger_helpers import entry


def _report(**fields: Any) -> MalwareReport:
    return MalwareReport(
        verdict="Malware",
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32)),
        **fields,
    )


# --- RC-3: a falsy fact ------------------------------------------------------


def test_a_false_or_zero_fact_is_shown_and_an_empty_one_is_not() -> None:
    from maljan.reporting.composer import _bundle_text

    text = _bundle_text(
        "packing_obfuscation",
        {
            "facts": {
                "packer_detected": False,
                "crypto_api_count": 0,
                "obfuscation_indicators": [],
                "packer_hint": None,
                "note": "",
            }
        },
    )
    assert "- packer_detected: False" in text
    assert "- crypto_api_count: 0" in text
    for empty in ("obfuscation_indicators", "packer_hint", "note"):
        assert empty not in text


# --- RC-4: a claim's label ---------------------------------------------------


def test_a_claim_is_cited_by_its_whole_label() -> None:
    from maljan.reporting.claim_coverage import ClaimInForce, _Body, coverage_of

    claim = ClaimInForce(
        agent="static", number=1, claim="It hashes API names", evidence_ref="", confidence=None
    )
    assert coverage_of(claim, _Body.of("As static claim 12 says, it beacons.")) is not None
    assert coverage_of(claim, _Body.of("As nonstatic claim 1 says.")) is not None
    for cited in ("Static claim 1 says so.", "(static claim 1)", "static claim 1, and 2"):
        assert coverage_of(claim, _Body.of(cited)) is None


# --- RC-5: a Suricata comment ------------------------------------------------


def test_a_family_with_a_line_break_writes_no_rule_of_its_own() -> None:
    from maljan.reporting import detection_signatures as ds

    family = 'Foo\npass ip any any -> any any (msg:"x"; sid:1; rev:1;)\r\u2028drop'
    report = _report(
        attribution=FamilyAttribution(family=family, family_grounded=True),
        consolidated_iocs=[
            ConsolidatedIOC(type="Domain", kind="domain", value="evil.example", published="yes: t")
        ],
    )
    rule = ds._build_suricata(report)
    assert rule is not None
    assert rule.compile_error is None
    lines = rule.body.split("\n")
    assert not any(line.lstrip().startswith(("pass", "drop")) for line in lines)
    assert all(line.startswith(("#", "alert")) for line in lines if line.strip())
    assert len(rule.body.splitlines()) == len(lines)


def test_a_plain_family_comment_is_as_it_was() -> None:
    from maljan.reporting import detection_signatures as ds

    report = _report(
        attribution=FamilyAttribution(family="Latrodectus", family_grounded=True),
        consolidated_iocs=[
            ConsolidatedIOC(type="Domain", kind="domain", value="evil.example", published="yes: t")
        ],
    )
    rule = ds._build_suricata(report)
    assert rule is not None
    assert rule.body.split("\n")[1].startswith("# Family: Latrodectus; verdict: Malware; ")


# --- RC-11: a Sigma persistence image ----------------------------------------

_RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd"


def _sigma(payload_published: bool) -> str:
    from maljan.reporting import detection_signatures as ds

    iocs = [
        ConsolidatedIOC(
            type="Registry key",
            kind="registry",
            value=_RUN_KEY,
            source="persistence",
            published="yes: x",
        )
    ]
    if payload_published:
        iocs.append(
            ConsolidatedIOC(
                type="File path",
                kind="path",
                value="C:\\Users\\a\\evil.exe",
                source="persistence",
                published="yes: x",
            )
        )
    report = _report(
        attribution=FamilyAttribution(family="Foo", family_grounded=True),
        persistence=[
            PersistenceMechanism(
                kind="registry_run", target=_RUN_KEY, payload="C:\\Users\\a\\evil.exe"
            )
        ],
        consolidated_iocs=iocs,
    )
    rule = ds._build_sigma(report)
    assert rule is not None
    return rule.body


def test_the_sigma_image_is_the_payload_that_runs() -> None:
    import yaml

    detection = yaml.safe_load(_sigma(payload_published=True))["detection"]
    assert detection["selection_persistence"] == {"Image|endswith": ["\\evil.exe"]}


def test_a_registry_target_is_never_an_image() -> None:
    body = _sigma(payload_published=False)
    assert "selection_persistence" not in body
    assert "TargetObject|contains" in body


# --- RC-6: autostart keys ----------------------------------------------------


@pytest.mark.parametrize(
    ("key", "kind"),
    [
        ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd", "registry_run"),
        ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "registry_run"),
        ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001", "registry_run"),
        ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\evilsvc", "service"),
        ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\evilsvc\\ImagePath", "service"),
        ("HKLM\\SYSTEM\\ControlSet001\\Services\\evilsvc\\Parameters\\ServiceDll", "service"),
        (
            "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
            "winlogon_helper",
        ),
        ("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "winlogon_helper"),
        (
            "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\x",
            "winlogon_helper",
        ),
        (
            "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution "
            "Options\\sethc.exe\\Debugger",
            "image_hijack",
        ),
        (
            "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
            "appinit_dll",
        ),
        ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil\\", "service"),
        ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil\\\\", "service"),
        ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil\\Parameters", "service"),
        ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil\\ServiceDll", "service"),
        ("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\e\\ImagePath", "service"),
        ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\", "winlogon_helper"),
        (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GinaDLL",
            "winlogon_helper",
        ),
        (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\System",
            "winlogon_helper",
        ),
        (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit ",
            "winlogon_helper",
        ),
        ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\", "registry_run"),
        ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices\\x", "registry_run"),
        ("HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load", "registry_run"),
        (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
            "image_hijack",
        ),
        (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs\\",
            "appinit_dll",
        ),
    ],
)
def test_an_autostart_key_is_its_mechanism(key: str, kind: str) -> None:
    from maljan.reporting.ledger_projection import _autostart_kind

    assert _autostart_kind(key) == kind


@pytest.mark.parametrize(
    "key",
    [
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"
        "\\StandardProfile\\EnableFirewall",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\\Start",
        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AutoAdminLogon",
        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\DefaultPassword",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Runtime\\x",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil\\Type",
        "HKLM\\System\\CurrentControlSet\\Services\\evil\\Security",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil\\Description",
    ],
)
def test_a_configuration_write_is_no_persistence(key: str) -> None:
    from maljan.reporting.ledger_projection import _autostart_kind, persistence_from_ledger

    assert _autostart_kind(key) is None
    ledger = [
        build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="a",
            tool="sandbox_registry_ops",
            args={},
            server=None,
            output=json.dumps({"registry": [{"key": key, "operation": "modify", "value": "0"}]}),
            source=None,
        )
    ]
    assert persistence_from_ledger(ledger) == []


# --- RC-7: a sandbox signature's techniques ----------------------------------


def _signatures(*rows: dict[str, Any]) -> list[LedgerEntry]:
    return [
        entry(
            "sandbox_signatures",
            {"signatures": list(rows), "total": len(rows)},
            EvidenceCounter(),
            agent="dynamic",
        )
    ]


def test_a_sandbox_signature_keeps_the_techniques_the_sandbox_tagged() -> None:
    from maljan.reporting.ledger_projection import dynamic_from_ledger
    from maljan.reporting.ledger_report import build_sections

    ledger = _signatures(
        {"name": "Active Setup", "severity": 8, "technique_ids": ["T1547.014", "t1112"]},
        {"name": "Untagged", "severity": 1},
    )
    dynamic = dynamic_from_ledger(ledger)
    assert dynamic is not None
    assert [s.technique_ids for s in dynamic.sandbox_signatures] == [["T1547.014", "T1112"], []]
    table = next(s for s in build_sections(ledger) if s.key == "sandbox_signatures")
    assert table.columns == ["Name", "Severity", "Description", "Techniques"]
    assert [row[-1] for row in table.rows] == ["T1547.014, T1112", "-"]


def test_an_untagged_signature_table_is_as_it_was() -> None:
    from maljan.reporting.ledger_report import build_sections

    ledger = _signatures({"name": "Untagged", "severity": 1, "description": "d"})
    table = next(s for s in build_sections(ledger) if s.key == "sandbox_signatures")
    assert table.columns == ["Name", "Severity", "Description"]
    assert table.rows == [["Untagged", "1", "d"]]


def test_a_later_tagged_answer_gives_the_earlier_rows_a_dash() -> None:
    from maljan.reporting.ledger_report import build_sections

    counter = EvidenceCounter()
    ledger = [
        entry("sandbox_signatures", {"signatures": [{"name": "A", "severity": 1}]}, counter),
        entry(
            "sandbox_signatures",
            {"signatures": [{"name": "B", "severity": 2, "technique_ids": ["T1055"]}]},
            counter,
        ),
    ]
    table = next(s for s in build_sections(ledger) if s.key == "sandbox_signatures")
    assert table.rows == [["A", "1", "", "-"], ["B", "2", "", "T1055"]]


# --- RC-8: an APK's permissions ----------------------------------------------


def test_permissions_are_printed_as_permissions_and_never_as_exports() -> None:
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    report = _report(static=StaticAnalysis(permissions=["android.permission.INTERNET"]))
    markdown = MarkdownRenderer().render(report)
    assert "Declared permissions" in markdown
    assert "- `android.permission.INTERNET`" in markdown
    assert "Exports" not in markdown.split("Declared permissions")[0].split("## 7.")[-1]
    assert "permissions" not in StaticAnalysis().model_dump()


# --- RC-9: an analyst's listing by its headings ------------------------------


def _persistence_section(columns: list[str], rows: list[list[str]]) -> EvidenceSection:
    return EvidenceSection(
        key="artifact_persistence",
        title="Persistence",
        kind="table",
        columns=columns,
        rows=rows,
        source="artifact:static",
    )


def test_a_persistence_listing_is_read_by_its_headings() -> None:
    from maljan.reporting.ledger_report import analyst_persistence

    reordered = _persistence_section(
        ["Target", "Payload", "Kind"], [["HKCU\\...\\Run\\upd", "C:\\x.exe", "registry_run"]]
    )
    row = analyst_persistence([reordered])[0]
    assert (row["kind"], row["target"], row["payload"]) == (
        "registry_run",
        "HKCU\\...\\Run\\upd",
        "C:\\x.exe",
    )
    offset = _persistence_section(["Type", "Value", "Offset"], [["task", "LogonTrigger", "0x10"]])
    row = analyst_persistence([offset])[0]
    assert (row["kind"], row["target"], row["payload"]) == ("task", "LogonTrigger", "")
    unnamed = _persistence_section(["a", "b", "c"], [["task", "LogonTrigger", "cmd"]])
    row = analyst_persistence([unnamed])[0]
    assert (row["kind"], row["target"], row["payload"]) == ("task", "LogonTrigger", "cmd")


def test_an_ioc_listing_is_read_by_its_headings() -> None:
    from maljan.reporting.ledger_projection import listed_non_network_values

    rows = [["Global\\m1", "mutex"], ["C:\\x.exe", "path"]]
    assert listed_non_network_values("iocs", rows, ["Value", "Type"]) == [
        ("mutex", "Global\\m1", ""),
        ("path", "C:\\x.exe", ""),
    ]
    assert listed_non_network_values("persistence", [["service", "evilsvc", "x"]]) == [
        ("service", "evilsvc", "x")
    ]


def _merged(
    kind: str, one: tuple[list[str], list[list[str]]], two: tuple[list[str], list[list[str]]]
) -> Any:
    from maljan.reporting.ledger_report import build_sections

    isrs = {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            artifacts=[Artifact(kind=kind, columns=one[0], rows=one[1], evidence_ids=["ev_1"])],
        ),
        "dynamic": AgentISR(
            agent_id="dynamic",
            domain="dynamic",
            artifacts=[Artifact(kind=kind, columns=two[0], rows=two[1], evidence_ids=["ev_2"])],
        ),
    }
    return [s for s in build_sections([], isrs) if s.key == f"artifact_{kind}"]


def test_a_merged_table_reads_each_artifact_by_its_own_headings() -> None:
    from maljan.reporting.ledger_report import analyst_persistence

    sections = _merged(
        "persistence",
        (["Type", "Value"], [["registry_run", "HKCU\\...\\Run\\x"]]),
        (["Target", "Kind", "Payload"], [["Updater", "scheduled_task", "C:\\x.exe"]]),
    )
    table = sections[0]
    # The payload the table names no place for is headed as a reader takes it.
    assert table.columns == ["Listed by", "Evidence", "Type", "Value", "Payload"]
    assert table.rows == [
        ["static", "ev_1", "registry_run", "HKCU\\...\\Run\\x"],
        ["dynamic", "ev_2", "scheduled_task", "Updater", "C:\\x.exe"],
    ]
    assert [(r["kind"], r["target"], r["payload"]) for r in analyst_persistence(sections)] == [
        ("registry_run", "HKCU\\...\\Run\\x", ""),
        ("scheduled_task", "Updater", "C:\\x.exe"),
    ]


def test_a_merged_ioc_list_keeps_every_row_the_positional_read_kept() -> None:
    from maljan.reporting.ledger_projection import listed_non_network_values
    from maljan.reporting.ledger_report import listed_headings, listed_rows

    sections = _merged(
        "iocs",
        (["Type", "Value"], [["mutex", "runnung"]]),
        (["Indicator type", "Indicator"], [["mutex", "Global\\abc"]]),
    )
    table = sections[0]
    values = [
        listed_non_network_values("iocs", [cells], listed_headings(table))
        for _who, _ids, cells in listed_rows(table)
    ]
    assert values == [[("mutex", "runnung", "")], [("mutex", "Global\\abc", "")]]


def test_a_duplicate_value_heading_is_the_payload() -> None:
    from maljan.reporting.ledger_report import analyst_persistence

    sections = _merged(
        "persistence",
        (["Type", "Value", "Value"], [["registry_run", "HKCU\\Run\\x", "c:\\a.exe"]]),
        (["Type", "Value", "Value"], [["service", "svc", "c:\\b.exe"]]),
    )
    assert [r["payload"] for r in analyst_persistence(sections)] == ["c:\\a.exe", "c:\\b.exe"]


def test_a_merged_table_of_alike_headings_is_as_it_was() -> None:
    from maljan.reporting.ledger_report import build_sections

    one = Artifact(kind="mutex", columns=["Label", "Value"], rows=[["m", "a"]])
    two = Artifact(kind="mutex", columns=["label", "value"], rows=[["n", "b", "extra"]])
    isrs = {
        "static": AgentISR(agent_id="static", domain="static", artifacts=[one]),
        "dynamic": AgentISR(agent_id="dynamic", domain="dynamic", artifacts=[two]),
    }
    table = next(s for s in build_sections([], isrs) if s.key == "artifact_mutex")
    assert table.columns == ["Listed by", "Evidence", "Label", "Value", "Payload"]
    assert table.rows == [["static", "", "m", "a"], ["dynamic", "", "n", "b", "extra"]]


# --- RC-10: the narrative with no sandbox ------------------------------------


def test_the_narrative_asserts_no_absence_without_a_sandbox() -> None:
    from maljan.reporting.narrative_agent import NO_SANDBOX_OBSERVATION, build_prompt_text

    static_only = build_prompt_text(_report())
    assert static_only.count(f"  ({NO_SANDBOX_OBSERVATION})") == 2
    assert "(none detected)" not in static_only
    watched = build_prompt_text(_report(dynamic=DynamicBehavior()))
    assert NO_SANDBOX_OBSERVATION not in watched
    assert "Sandbox signatures:\n  (none)" in watched
    assert "Persistence:\n  (none detected)" in watched


# --- RC-3: a count is stated only where the profile was measured -------------


@pytest.mark.parametrize(
    ("section", "facts"),
    [
        ("encryption_scheme", ("crypto_api_count",)),
        ("discovery", ("discovery_api_count",)),
        ("evasion_antiforensics", ("anti_debug_api_count", "evasion_api_count")),
        ("persistence_detail", ("persistence_api_count", "registry_api_count")),
    ],
)
def test_a_profile_count_is_stated_only_when_measured(section: str, facts: tuple[str, ...]) -> None:
    from maljan.reporting.evidence_bundles import bundle_for

    unmeasured = bundle_for(section, _report(static=StaticAnalysis()), {}, None)["facts"]
    assert not set(facts) & set(unmeasured)
    measured = _report(
        static=StaticAnalysis(
            api_capabilities={"network": 3}, api_capabilities_evidence_ids=["ev_1"]
        )
    )
    stated = bundle_for(section, measured, {}, None)["facts"]
    assert {fact: stated[fact] for fact in facts} == dict.fromkeys(facts, 0)
