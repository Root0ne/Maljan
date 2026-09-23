"""What changed between two stored analyses, read off their records alone.

The records here are the recorded Windows PE run (``_report_shapes.rich_report``)
dumped the way the report column stores it, with its export bundle rendered by
the real STIX renderer, and a second record made by editing a copy of it the
way a re-run or a new build would differ.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.reporting.run_diff import (
    ADDED,
    CHANGED,
    MATCH_KEYS,
    ONLY_IN_A,
    ONLY_IN_B,
    REMOVED,
    REPEATED_KEY_NOTE,
    STATUSES,
    UNCHANGED,
    RunRecord,
    diff_runs,
    sample_statement,
)
from tests.unit.reporting._report_shapes import rich_report, stored_old_shape

SHA = "a" * 64


@pytest.fixture(scope="module")
def stored() -> dict[str, Any]:
    """The recorded run as the store holds it: report document, summary and bundle."""
    report = rich_report()
    document = report.model_dump(mode="json")
    document["run_summary"] = {
        **document["run_summary"],
        "verdict_reading": "stated",
        "profile": {"name": "default", "analysts": ["static", "dynamic", "network"]},
        "models": {"judge": {"turns": {"qwen3:8b": 3}, "fallbacks": []}},
        "tokens": {
            "input_tokens": 1000,
            "output_tokens": 200,
            "total_tokens": 1200,
            "llm_calls": 4,
        },
        "evidence": {"entries": 17, "by_tool": {"pe_info": 1, "capa": 1}},
    }
    return {
        "document": document,
        "bundle": ExtendedSTIXRenderer().render(report).model_dump(mode="json"),
        "second_bundle": ExtendedSTIXRenderer().render(rich_report()).model_dump(mode="json"),
    }


def _record(
    document: dict[str, Any],
    bundle: dict[str, Any] | None,
    *,
    rid: str = "1",
    sha: str | None = SHA,
    findings: list[dict[str, Any]] | None = None,
) -> RunRecord:
    return RunRecord(
        report_id=f"report-{rid}",
        job_id=f"job-{rid}",
        created_at="2026-09-20T10:00:00+00:00",
        verdict=document.get("verdict"),
        overall_confidence=document.get("overall_confidence"),
        malware_category=document.get("malware_category"),
        malware_report=document,
        run_summary=document.get("run_summary"),
        stix_bundle=bundle,
        agent_findings=findings or [],
        sample_sha256=sha,
        sample_file_name="invoice.exe",
        duration_seconds=412.0,
    )


def _pair(stored: dict[str, Any], edit=None, *, edit_bundle=None, **kwargs: Any):
    doc_b = copy.deepcopy(stored["document"])
    bundle_b = copy.deepcopy(stored["second_bundle"])
    if edit is not None:
        edit(doc_b)
    if edit_bundle is not None:
        edit_bundle(bundle_b)
    a = _record(stored["document"], stored["bundle"], rid="1")
    b = _record(doc_b, bundle_b, rid="2", **kwargs)
    return diff_runs(a, b)


def _section(diff: dict[str, Any], key: str) -> dict[str, Any]:
    (found,) = [s for s in diff["sections"] if s["key"] == key]
    return found


def _rows(diff: dict[str, Any], key: str, status: str) -> list[dict[str, Any]]:
    return [r for r in _section(diff, key)["rows"] if r["status"] == status]


def _row(diff: dict[str, Any], section: str, key: str) -> dict[str, Any]:
    (found,) = [r for r in _section(diff, section)["rows"] if r["key"] == key]
    return found


class TestTwoRecordsOfTheSameRun:
    def test_nothing_is_added_removed_or_changed(self, stored) -> None:
        diff = _pair(stored)

        assert diff["totals"][ADDED] == 0
        assert diff["totals"][REMOVED] == 0
        assert diff["totals"][CHANGED] == 0
        assert diff["totals"][UNCHANGED] > 0

    def test_the_header_says_the_file_is_the_same(self, stored) -> None:
        diff = _pair(stored)

        assert diff["same_sample"] is True
        assert "same file" in diff["sample_statement"]
        assert diff["a"]["job_id"] == "job-1" and diff["b"]["job_id"] == "job-2"

    def test_every_section_names_its_key_and_counts_every_status(self, stored) -> None:
        diff = _pair(stored)

        for section in diff["sections"]:
            assert section["match_key"] == MATCH_KEYS[section["key"]]
            assert set(section["counts"]) == set(STATUSES)
            assert sum(section["counts"].values()) == len(section["rows"])

    def test_neither_record_is_changed_by_the_comparison(self, stored) -> None:
        before = copy.deepcopy(stored)
        _pair(stored)

        assert stored == before


class TestVerdict:
    def test_a_changed_verdict_carries_both_values_and_how_each_was_read(self, stored) -> None:
        def edit(doc: dict[str, Any]) -> None:
            doc["verdict"] = "Suspicious"
            doc["overall_confidence"] = None
            doc["run_summary"]["verdict_reading"] = "fallback"

        diff = _pair(stored, edit)

        verdict = _row(diff, "verdict", "verdict")
        assert verdict["status"] == CHANGED
        assert verdict["a"] == {"value": "Malware", "reading": "stated"}
        assert verdict["b"] == {"value": "Suspicious", "reading": "fallback"}
        confidence = _row(diff, "verdict", "confidence")
        assert confidence["a"] == {"value": 0.86, "stated_by": "judge"}
        assert confidence["b"] == {"value": None, "stated_by": None}

    def test_a_family_names_who_stated_it_and_cites_both_runs(self, stored) -> None:
        def edit(doc: dict[str, Any]) -> None:
            doc["attribution"]["family"] = "OtherLoader"
            doc["attribution"]["family_source"] = "sandbox"
            doc["attribution"]["family_evidence_ids"] = ["ev_0099"]

        diff = _pair(stored, edit)

        family = _row(diff, "verdict", "family")
        assert family["status"] == CHANGED
        assert family["a"]["value"] == "ExampleLoader"
        assert family["b"]["value"] == "OtherLoader"
        assert family["b"]["stated_by"] == "sandbox"
        assert family["evidence"]["a"] and family["evidence"]["b"] == ["ev_0099"]


class TestAttack:
    def test_techniques_added_removed_and_a_confidence_changed(self, stored) -> None:
        def edit(doc: dict[str, Any]) -> None:
            mappings = doc["ttp_mappings"]
            doc["ttp_mappings"] = [m for m in mappings if m["technique_id"] != "T1055"]
            doc["ttp_mappings"][0]["confidence"] = 0.5
            doc["ttp_mappings"].append(
                {
                    **mappings[0],
                    "technique_id": "T1082",
                    "technique_name": "System Information Discovery",
                }
            )

        diff = _pair(stored, edit)

        assert [r["key"] for r in _rows(diff, "attack", REMOVED)] == ["T1055"]
        assert [r["key"] for r in _rows(diff, "attack", ADDED)] == ["T1082"]
        changed = _row(diff, "attack", "T1547.001")
        assert changed["status"] == CHANGED
        assert changed["changes"] == [{"field": "confidence", "a": 0.92, "b": 0.5}]
        # The capability cell's own record of who stated the number.
        assert changed["a"]["confidence_source"] == "the judge"
        # The quotes hold ids in their prose; prose is not an id field.
        assert changed["evidence"] == {"a": [], "b": []}

    def test_the_technique_id_is_the_key_whatever_its_case(self, stored) -> None:
        def edit(doc: dict[str, Any]) -> None:
            for mapping in doc["ttp_mappings"]:
                mapping["technique_id"] = mapping["technique_id"].lower()

        diff = _pair(stored, edit)

        assert _section(diff, "attack")["counts"][UNCHANGED] == 2


class TestIndicators:
    def test_an_indicator_added_and_a_publish_decision_changed(self, stored) -> None:
        def edit(doc: dict[str, Any]) -> None:
            rows = doc["consolidated_iocs"]
            rows.append({**rows[0], "kind": "domain", "type": "Domain", "value": "new.example.tld"})
            rows[0]["published"] = "no: a name only the file's bytes know"

        diff = _pair(stored, edit)

        added = _rows(diff, "indicators", ADDED)
        assert [r["key"] for r in added] == ["domain|new.example.tld"]
        (changed,) = _rows(diff, "indicators", CHANGED)
        assert [c["field"] for c in changed["changes"]] == ["published"]

    def test_a_domain_is_the_same_domain_in_another_case(self, stored) -> None:
        def edit(doc: dict[str, Any]) -> None:
            for row in doc["consolidated_iocs"]:
                if row.get("kind") == "domain":
                    row["value"] = row["value"].upper()

        diff = _pair(stored, edit)

        assert _section(diff, "indicators")["counts"][ADDED] == 0

    def test_a_report_without_the_table_is_read_from_its_network_block_and_says_so(
        self, stored
    ) -> None:
        def edit(doc: dict[str, Any]) -> None:
            doc["consolidated_iocs"] = []

        diff = _pair(stored, edit)

        section = _section(diff, "indicators")
        assert any(
            "network block" in note and note.startswith("Run B") for note in section["notes"]
        )


class TestFindings:
    def test_a_reworded_key_finding_is_listed_by_run_and_never_paired(self, stored) -> None:
        def edit(doc: dict[str, Any]) -> None:
            doc["key_findings"][0]["text"] = doc["key_findings"][0]["text"] + " Reworded."

        diff = _pair(stored, edit)

        section = _section(diff, "key_findings")
        assert section["keyed"] is False
        assert len(_rows(diff, "key_findings", ONLY_IN_A)) == 1
        assert len(_rows(diff, "key_findings", ONLY_IN_B)) == 1
        assert section["counts"][ADDED] == section["counts"][REMOVED] == 0

    def test_analyst_findings_are_paired_by_agent_name(self, stored) -> None:
        a = _record(
            stored["document"],
            None,
            findings=[
                {
                    "agent_name": "static",
                    "status": "complete",
                    "final_confidence": 0.8,
                    "claims": [{"claim": "x", "evidence_ref": "ev_0003"}],
                }
            ],
        )
        b = _record(
            stored["document"],
            None,
            rid="2",
            findings=[
                {"agent_name": "static", "status": "timeout", "final_confidence": 0.0, "claims": []}
            ],
        )

        row = _row(diff_runs(a, b), "analysts", "static")
        assert row["status"] == CHANGED
        assert {c["field"] for c in row["changes"]} == {"status", "confidence", "claims"}
        assert row["evidence"] == {"a": ["ev_0003"], "b": []}

    def test_a_key_repeated_more_times_in_one_run_is_a_surplus_that_says_so(self, stored) -> None:
        def edit(doc: dict[str, Any]) -> None:
            doc["persistence"].append(copy.deepcopy(doc["persistence"][0]))

        diff = _pair(stored, edit)

        (repeated,) = _rows(diff, "persistence", ADDED)
        assert repeated["note"] == REPEATED_KEY_NOTE
        assert _section(diff, "persistence")["counts"][UNCHANGED] == 4


class TestDetection:
    def test_a_rule_match_gone_and_a_level_changed(self, stored) -> None:
        sigma = next(s for s in stored["document"]["sections"] if s["key"] == "sigma_matches")
        rule = sigma["rows"][0][0]

        def edit(doc: dict[str, Any]) -> None:
            section = next(s for s in doc["sections"] if s["key"] == "sigma_matches")
            section["rows"][0][1] = "critical"
            yara = next(s for s in doc["sections"] if s["key"] == "yara_matches")
            yara["rows"] = yara["rows"][1:]

        diff = _pair(stored, edit)

        changed = _row(diff, "detection", f"sigma|{rule}")
        assert changed["changes"][0]["field"] == "level"
        assert changed["changes"][0]["b"] == "critical"
        # A rule section cites its entries as a whole: on the section, not the row.
        assert changed["evidence"] == {"a": [], "b": []}
        assert _section(diff, "detection")["section_evidence"]["a"]
        assert [r["key"].split("|")[0] for r in _rows(diff, "detection", REMOVED)] == ["yara"]


class TestStix:
    def test_two_renders_with_different_ids_pair_by_key_not_by_id(self, stored) -> None:
        ids_a = {o["id"] for o in stored["bundle"]["objects"]}
        ids_b = {o["id"] for o in stored["second_bundle"]["objects"]}
        assert ids_a != ids_b  # the renderer mints fresh ids for some objects

        diff = _pair(stored)

        section = _section(diff, "stix")
        assert section["counts"][ADDED] == section["counts"][REMOVED] == 0
        types = {r["a"]["type"] for r in _rows(diff, "stix", UNCHANGED)}
        assert {"attack-pattern", "relationship", "file"} <= types

    def test_an_object_with_no_identifying_property_is_listed_by_run(self, stored) -> None:
        diff = _pair(stored)

        only_a = {r["a"]["type"] for r in _rows(diff, "stix", ONLY_IN_A)}
        assert "report" in only_a or "note" in only_a or "process" in only_a
        assert len(_rows(diff, "stix", ONLY_IN_A)) == len(_rows(diff, "stix", ONLY_IN_B))

    def test_a_changed_indicator_pattern_is_one_removed_and_one_added(self, stored) -> None:
        def edit_bundle(bundle: dict[str, Any]) -> None:
            for obj in bundle["objects"]:
                if obj["type"] == "indicator":
                    obj["pattern"] = "[domain-name:value = 'other.example.tld']"
                    break

        if not any(o["type"] == "indicator" for o in stored["bundle"]["objects"]):
            pytest.skip("the recorded run's export carries no indicator")
        diff = _pair(stored, edit_bundle=edit_bundle)

        assert any(r["a"]["type"] == "indicator" for r in _rows(diff, "stix", REMOVED))
        assert any(r["b"]["type"] == "indicator" for r in _rows(diff, "stix", ADDED))

    def test_a_confidence_change_on_a_paired_object_is_named(self, stored) -> None:
        def edit_bundle(bundle: dict[str, Any]) -> None:
            for obj in bundle["objects"]:
                if obj["type"] == "attack-pattern":
                    obj["confidence"] = 12
                    break

        diff = _pair(stored, edit_bundle=edit_bundle)

        (changed,) = _rows(diff, "stix", CHANGED)
        assert changed["a"]["type"] == "attack-pattern"
        assert changed["changes"][0]["field"] == "confidence"
        assert changed["changes"][0]["b"] == 12

    def test_a_run_with_no_bundle_says_so(self, stored) -> None:
        a = _record(stored["document"], stored["bundle"])
        b = _record(stored["document"], None, rid="2")

        section = _section(diff_runs(a, b), "stix")
        assert section["recorded"] == {"a": True, "b": False}
        assert section["notes"]


class TestRunFacts:
    def test_models_tokens_and_tools_are_compared(self, stored) -> None:
        def edit(doc: dict[str, Any]) -> None:
            doc["run_summary"]["models"] = {"judge": {"turns": {"gpt-oss:20b": 3}, "fallbacks": []}}
            doc["run_summary"]["tokens"]["input_tokens"] = 5000
            doc["run_summary"]["evidence"]["by_tool"] = {"pe_info": 2, "floss": 1}

        diff = _pair(stored, edit)

        models = _row(diff, "run", "models:judge")
        assert models["changes"][0] == {"field": "value", "a": ["qwen3:8b"], "b": ["gpt-oss:20b"]}
        assert _row(diff, "run", "tokens:input_tokens")["status"] == CHANGED
        assert _row(diff, "tools", "pe_info")["changes"] == [{"field": "calls", "a": 1, "b": 2}]
        assert _row(diff, "tools", "floss")["status"] == ADDED
        assert _row(diff, "tools", "capa")["status"] == REMOVED

    def test_a_summary_with_estimated_tokens_shows_no_count(self, stored) -> None:
        def edit(doc: dict[str, Any]) -> None:
            doc["run_summary"]["tokens"]["estimated_calls"] = 2

        diff = _pair(stored, edit)

        assert _row(diff, "run", "tokens:input_tokens")["b"] == {"value": None}

    def test_degradation_reasons_are_matched_by_exact_text(self, stored) -> None:
        def edit(doc: dict[str, Any]) -> None:
            doc["degradation_reasons"] = ["the sandbox was unreachable"]

        diff = _pair(stored, edit)

        assert [r["key"] for r in _rows(diff, "degradation", ONLY_IN_B)] == [
            "the sandbox was unreachable"
        ]


class TestSamples:
    def test_different_files_are_allowed_and_said_plainly(self, stored) -> None:
        diff = _pair(stored, sha="b" * 64)

        assert diff["same_sample"] is False
        assert "different files" in diff["sample_statement"]

    def test_a_missing_digest_is_not_guessed(self) -> None:
        same, sentence = sample_statement(SHA, None)

        assert same is None
        assert "run B" in sentence

    def test_the_report_identity_stands_in_for_the_sample_row(self, stored) -> None:
        a = _record(stored["document"], None, sha=None)
        b = _record(stored["document"], None, rid="2", sha=None)

        assert diff_runs(a, b)["same_sample"] is True


def test_a_report_stored_in_the_old_shape_is_compared_without_error(stored) -> None:
    old = stored_old_shape()
    document = old.model_dump(mode="json") if hasattr(old, "model_dump") else old
    a = _record(document, None)
    b = _record(stored["document"], stored["bundle"], rid="2")

    diff = diff_runs(a, b)

    assert diff["sections"]
    assert _section(diff, "stix")["recorded"] == {"a": False, "b": True}


def test_a_run_with_no_report_document_is_compared_from_its_columns() -> None:
    a = RunRecord(report_id="r1", job_id="j1", verdict="Malware", overall_confidence=0.9)
    b = RunRecord(report_id="r2", job_id="j2", verdict="Benign", overall_confidence=0.7)

    diff = diff_runs(a, b)

    assert _row(diff, "verdict", "verdict")["status"] == CHANGED
    assert _section(diff, "attack")["recorded"] == {"a": False, "b": False}
    assert diff["same_sample"] is None


def _self(stored: dict[str, Any], document: dict[str, Any] | None = None) -> dict[str, Any]:
    """One record compared with itself."""
    record = _record(document or stored["document"], stored["bundle"])
    return diff_runs(record, record)


class TestARecordComparedWithItself:
    def test_every_row_of_every_section_is_unchanged(self, stored) -> None:
        diff = _self(stored)

        for section in diff["sections"]:
            statuses = {row["status"] for row in section["rows"]}
            assert statuses <= {UNCHANGED}, (section["key"], statuses)
        assert diff["totals"][UNCHANGED] == sum(diff["totals"].values())

    def test_a_rule_that_matched_twice_is_unchanged_against_itself(self, stored) -> None:
        document = copy.deepcopy(stored["document"])
        yara = next(s for s in document["sections"] if s["key"] == "yara_matches")
        yara["rows"].append(list(yara["rows"][0]))

        diff = _self(stored, document)

        assert {r["status"] for r in _section(diff, "detection")["rows"]} == {UNCHANGED}

    def test_a_second_match_of_one_rule_in_one_run_only_is_added_as_a_repeat(self, stored) -> None:
        def edit(doc: dict[str, Any]) -> None:
            yara = next(s for s in doc["sections"] if s["key"] == "yara_matches")
            yara["rows"].append(list(yara["rows"][0]))

        diff = _pair(stored, edit)

        (surplus,) = _rows(diff, "detection", ADDED)
        assert surplus["note"] == REPEATED_KEY_NOTE
        assert _section(diff, "detection")["counts"][ONLY_IN_B] == 0


class TestEvidenceComesOnlyFromIdFields:
    def test_an_id_inside_a_quote_or_a_sample_string_yields_no_chip(self, stored) -> None:
        def edit(doc: dict[str, Any]) -> None:
            doc["ttp_mappings"][0]["evidence_quotes"] = ["Unlike ev_0004 this shows no injection"]
            doc["capability_matrix"][0]["evidence"] = ["Unlike ev_0004 this shows no injection"]
            doc["consolidated_iocs"].append(
                {
                    "type": "Scheduled task",
                    "kind": "scheduled_task",
                    "value": "Updater",
                    "description": "schtasks /tn ev_20231",
                    "context": "schtasks /create /tn ev_20231 /tr evil.exe",
                    "published": "yes",
                    "source": "persistence",
                }
            )

        diff = _pair(stored, edit)

        for key in ("attack", "indicators"):
            for row in _section(diff, key)["rows"]:
                assert row["evidence"] == {"a": [], "b": []}, (key, row["key"])
        task = _row(diff, "indicators", "scheduled_task|Updater")
        assert task["status"] == ADDED
        assert "ev_20231" not in str(task["evidence"])

    def test_a_citation_field_holding_prose_cites_nothing(self, stored) -> None:
        def finding(ref: str) -> list[dict[str, Any]]:
            return [
                {
                    "agent_name": "static",
                    "status": "complete",
                    "final_confidence": 0.5,
                    "claims": [{"claim": "x", "evidence_ref": ref}],
                }
            ]

        a = _record(stored["document"], None, findings=finding("see ev_0002 for the header"))
        b = _record(stored["document"], None, rid="2", findings=finding("[ev_0002, ev_0005]"))

        row = _row(diff_runs(a, b), "analysts", "static")
        assert row["evidence"] == {"a": [], "b": ["ev_0002", "ev_0005"]}


class TestSeverityAttribution:
    def test_a_report_that_carries_the_reading_names_the_judge(self, stored) -> None:
        diff = _self(stored)

        assert _row(diff, "verdict", "severity")["a"] == {"value": "High", "stated_by": "judge"}

    def test_a_report_stored_before_the_judge_owned_severity_names_no_one(self, stored) -> None:
        old = stored_old_shape().model_dump(mode="json")
        a = _record(old, None)
        b = _record(stored["document"], None, rid="2")

        severity = _row(diff_runs(a, b), "verdict", "severity")
        assert severity["a"] == {"value": "High"}
        assert "stated_by" not in severity["a"]
        assert severity["b"]["stated_by"] == "judge"


class TestIndicatorShapes:
    def test_rows_stored_without_a_kind_are_never_paired_with_rows_that_have_one(
        self, stored
    ) -> None:
        old = stored_old_shape().model_dump(mode="json")
        new = copy.deepcopy(stored["document"])
        new["consolidated_iocs"].append(
            {"type": "Domain", "kind": "domain", "value": "old-c2.example.org", "published": "yes"}
        )
        a = _record(old, None)
        b = _record(new, None, rid="2")

        section = _section(diff_runs(a, b), "indicators")

        assert section["counts"][ADDED] == section["counts"][REMOVED] == 0
        assert section["counts"][UNCHANGED] == section["counts"][CHANGED] == 0
        assert section["counts"][ONLY_IN_A] == 2
        assert any("store indicators differently" in n and "run A" in n for n in section["notes"])

    def test_two_old_shaped_tables_pair_by_type_and_stored_value(self) -> None:
        old = stored_old_shape().model_dump(mode="json")
        record = _record(old, None)

        section = _section(diff_runs(record, _record(old, None, rid="2")), "indicators")

        assert section["counts"][UNCHANGED] == 2
        assert not section["notes"]


class TestCaseRule:
    def _indicators(self, *rows: dict[str, Any]) -> RunRecord:
        return RunRecord(
            report_id="r", job_id="j", malware_report={"consolidated_iocs": list(rows)}
        )

    def test_case_is_ignored_only_where_the_value_is_caseless_by_definition(self) -> None:
        a = self._indicators(
            {"kind": "registry", "type": "Registry Key", "value": r"HKCU\\Software\\Run"},
            {"kind": "mutex", "type": "Mutex", "value": "Global\\Lock"},
            {"kind": "email", "type": "E-mail", "value": "Ops@Example.COM"},
            {"kind": "url", "type": "URL", "value": "http://h.tld/Path"},
        )
        b = self._indicators(
            {"kind": "registry", "type": "Registry Key", "value": r"hkcu\\software\\run"},
            {"kind": "mutex", "type": "Mutex", "value": "global\\lock"},
            {"kind": "email", "type": "E-mail", "value": "Ops@example.com"},
            {"kind": "url", "type": "URL", "value": "http://h.tld/path"},
        )

        section = _section(diff_runs(a, b), "indicators")

        unchanged = {r["key"].split("|")[0] for r in section["rows"] if r["status"] == UNCHANGED}
        assert unchanged == {"registry", "email"}
        assert section["counts"][ADDED] == section["counts"][REMOVED] == 2

    def test_a_registry_key_follows_the_same_rule_in_the_stix_section(self) -> None:
        def bundle(key: str) -> dict[str, Any]:
            return {"objects": [{"type": "windows-registry-key", "id": "k--1", "key": key}]}

        a = RunRecord(report_id="r", job_id="j", stix_bundle=bundle(r"HKCU\\Run"))
        b = RunRecord(report_id="r", job_id="j", stix_bundle=bundle(r"hkcu\\run"))

        assert _section(diff_runs(a, b), "stix")["counts"][UNCHANGED] == 1

    def test_a_change_of_case_in_a_stix_name_is_a_difference(self) -> None:
        def bundle(name: str) -> dict[str, Any]:
            return {"objects": [{"type": "malware", "id": "m--1", "name": name, "is_family": True}]}

        a = RunRecord(report_id="r", job_id="j", stix_bundle=bundle("Emotet"))
        b = RunRecord(report_id="r", job_id="j", stix_bundle=bundle("EMOTET"))

        section = _section(diff_runs(a, b), "stix")
        assert section["counts"][UNCHANGED] == 0
        assert section["counts"][REMOVED] == section["counts"][ADDED] == 1
