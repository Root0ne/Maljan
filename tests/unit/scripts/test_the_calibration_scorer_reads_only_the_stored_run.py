"""The calibration scorer: verdicts from a stored run's structure and publications alone.

Each stored run here is written by the test in the benchmark's layout (a
``report.json`` the platform's model reads, an ``evidence.json``, a
``job.json`` naming the sample), so what the scorer reads and what it may not
read are both known. The held-out half is refused in tuning mode, never
printed in held-out mode, and is the only half a gate reads.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.calibration import cases, run
from scripts.calibration import score as scoring
from scripts.calibration.run import HeldOut, gate, main, score_run
from scripts.replay.stored import digests

from maljan.reporting.models import MalwareReport
from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import _benchmark

TUNING_CASE = next(c for c in cases.build_all() if c.split == "tuning" and c.format == "pe64")
HELDOUT_CASE = next(c for c in cases.build_all() if c.split == "heldout" and c.format == "pe64")
# A technique no case's manifest speaks of.
UNRELATED_TECHNIQUE = "T1497"


def _facts(case: cases.Case) -> dict[str, dict[str, Any]]:
    return {f["id"]: f for f in case.manifest()["facts"]}


def _traps(case: cases.Case) -> dict[str, dict[str, Any]]:
    return {t["kind"]: t for t in case.manifest()["traps"]}


def _table(key: str, source: str, *cells: str) -> dict[str, Any]:
    return {"key": key, "title": key, "kind": "table", "source": source, "columns": ["Value"],
            "rows": [[c] for c in cells]}  # fmt: skip


def _write_run(root: Path, case: cases.Case, *, with_evidence: bool = True) -> Path:
    """A stored run of ``case``: some facts in its tables, a trap published, others held back.

    - F1 in the import table, F3 in a strings table, F4 a flagged section: found;
    - F2 named only in the narrative: mentioned; F5 only in the ledger: partial;
    - one of F6's three names in a hash resolver's table: partial; F7's id only in a
      bookkeeping field: missed;
    - the dead import's technique (a sub-technique of it) and the decoy host
      published: false; the comment API denied in the narrative: mentioned;
    - the first absence a capability cell the judge dropped, the second a claim
      in force the report does not publish: withheld;
    - an unrelated published technique: beyond.
    """
    facts = _facts(case)
    traps = _traps(case)
    absent = case.manifest()["absent"]
    term = {fid: f["terms"][0][0] for fid, f in facts.items()}
    decoy_host = traps["decoy_url"]["claims"]["indicators"][1]
    dead_technique = traps["dead_import"]["claims"]["techniques"][0]
    comment_api = traps["comment_api"]["subject"]
    report = MalwareReport.model_validate(
        {
            "identity": {"hashes": {"sha256": "0" * 64}},
            "verdict": "Malware",
            "executive_summary": (
                f"The code also calls {term['F2']}. {comment_api} appears only in a comment"
                f" string and is never called, so it is no capability. It reaches"
                f" {decoy_host.replace('.', '[.]')}."
            ),
            "static": {
                "imports": [{"dll": "KERNEL32.dll", "function": term["F1"]}],
                "sections": [
                    {
                        "name": ".text",
                        "virtual_address": "0x1000",
                        "characteristics": "EXECUTE|READ|CODE",
                    },
                    {
                        "name": term["F4"],
                        "virtual_address": "0x5000",
                        "characteristics": "EXECUTE|READ|WRITE",
                    },
                ],
            },
            "sections": [
                _table("strings", "tool:strings", f"0x10 {term['F3']}", term["F3"]),
                _table("tool_resolve_api_hashes_hits", "tool:resolve_api_hashes", term["F6"]),
            ],
            "consolidated_iocs": [
                {
                    "type": "Domain",
                    "kind": "domain",
                    "value": decoy_host,
                    "source": "sandbox",
                    "published": "yes: the sandbox recorded it",
                }
            ],
            "ttp_mappings": [
                {"technique_id": f"{dead_technique}.001", "technique_name": "claimed"},
                {"technique_id": UNRELATED_TECHNIQUE, "technique_name": "unrelated"},
            ],
            "capability_matrix": [
                {
                    "tactic": "TA0001",
                    "tactic_name": "t",
                    "technique_id": absent[0]["claims"]["techniques"][0],
                    "technique_name": "dropped",
                    "not_published": "the judge dropped it (no call reaches it)",
                }
            ],
            # Bookkeeping holding the config's id: a tool saw it, the report never states it.
            "tool_sightings": {term["F7"]: [["ev_0002", "strings"]]},
        }
    )
    directory = root / case.case_id
    directory.mkdir()
    (directory / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    (directory / "job.json").write_text(
        json.dumps({"sample_sha256": case.manifest()["sha256"]}), encoding="utf-8"
    )
    claim = {"claim": "it would do this", "technique_id": absent[1]["claims"]["techniques"][0]}
    (directory / "report-byjob.json").write_text(
        json.dumps({"agent_findings": [{"agent_name": "static", "claims": [claim]}]}),
        encoding="utf-8",
    )
    if with_evidence:
        items = [{"entry_id": "ev_0001", "tool": "decode_string_blobs", "output": term["F5"]}]
        (directory / "evidence.json").write_text(json.dumps({"items": items}), encoding="utf-8")
    return directory


class TestTheVerdicts:
    def test_each_fact_trap_and_absence_gets_its_verdict(self, tmp_path: Path) -> None:
        result = score_run(_write_run(tmp_path, TUNING_CASE))
        facts = {f["id"]: (f["status"], f["why"]) for f in result["facts"]}
        assert facts == {
            "F1": ("found", "a tool or pack row holds every term"),
            "F2": ("mentioned", "only free text names it"),
            "F3": ("found", "a tool or pack row holds every term"),
            "F4": ("found", "a tool or pack row holds every term"),
            "F5": ("partial", "only the evidence holds it"),
            "F6": ("partial", "the tool rows hold 1 of 3 terms"),
            "F7": ("missed", ""),
        }
        traps = {t["kind"]: t for t in result["traps"]}
        dead = _traps(TUNING_CASE)["dead_import"]["claims"]["techniques"][0]
        assert traps["dead_import"]["status"] == "false"
        assert traps["dead_import"]["published"] == [f"{dead}.001"]
        assert traps["decoy_url"]["status"] == "false"
        absent = result["absent"]
        assert [a["status"] for a in absent[:2]] == ["withheld", "withheld"]
        assert all(a["status"] == "clear" for a in absent[2:])
        assert result["beyond"] == {"techniques": [UNRELATED_TECHNIQUE], "indicators": []}
        assert {k: v for k, v in result["totals"].items() if k != "by_difficulty"} == {
            "found": 3,
            "partial": 2,
            "mentioned": 1,
            "missed": 1,
            "false": 2,
            "withheld": 2,
            "not recorded": 0,
            "beyond": 1,
        }

    def test_a_denial_in_the_narrative_is_not_false(self, tmp_path: Path) -> None:
        result = score_run(_write_run(tmp_path, TUNING_CASE))
        comment = next(t for t in result["traps"] if t["kind"] == "comment_api")
        assert comment["status"] == "mentioned"
        assert comment["published"] == []

    def test_a_trap_published_as_a_technique_or_an_indicator_is_false(self, tmp_path: Path) -> None:
        result = score_run(_write_run(tmp_path, TUNING_CASE))
        traps = {t["kind"]: t for t in result["traps"]}
        host = _traps(TUNING_CASE)["decoy_url"]["claims"]["indicators"][1]
        assert traps["decoy_url"]["published"] == [host]
        assert traps["dead_import"]["status"] == traps["decoy_url"]["status"] == "false"

    def test_a_withdrawn_or_unpublished_claim_is_not_false(self, tmp_path: Path) -> None:
        result = score_run(_write_run(tmp_path, TUNING_CASE))
        absent = TUNING_CASE.manifest()["absent"]
        dropped, unpublished = result["absent"][0], result["absent"][1]
        assert dropped["withheld"] == [absent[0]["claims"]["techniques"][0]]
        assert unpublished["withheld"] == [absent[1]["claims"]["techniques"][0]]
        assert dropped["published"] == unpublished["published"] == []

    def test_an_analyst_s_table_is_model_text_and_never_finds_a_fact(self, tmp_path: Path) -> None:
        stored = _write_run(tmp_path, TUNING_CASE)
        data = json.loads((stored / "report.json").read_text())
        names = [t[0] for t in _facts(TUNING_CASE)["F6"]["terms"]]
        data["sections"] = [_table("artifact_resolved_apis", "artifact:static", *names)]
        (stored / "report.json").write_text(json.dumps(data))
        facts = {f["id"]: f["status"] for f in score_run(stored)["facts"]}
        assert facts["F6"] == "mentioned"

    def test_a_kept_claim_finds_a_fact_only_when_its_cited_entries_hold_it(
        self, tmp_path: Path
    ) -> None:
        stored = _write_run(tmp_path, TUNING_CASE)
        name = _facts(TUNING_CASE)["F2"]["terms"][0][0]

        def status(reference: str) -> str:
            claim = {"claim": f"The code calls {name.upper()}.", "evidence_ref": reference}
            (stored / "report-byjob.json").write_text(
                json.dumps({"agent_findings": [{"agent_name": "static", "claims": [claim]}]})
            )
            return {f["id"]: f["status"] for f in score_run(stored)["facts"]}["F2"]

        assert status("[ev_0999] an entry the run lacks") == "mentioned"
        assert status("[ev_0001] an entry without the name") == "mentioned"
        items = json.loads((stored / "evidence.json").read_text())["items"]
        items.append({"entry_id": "ev_0002", "tool": "pe_info", "output": f"imports {name}"})
        (stored / "evidence.json").write_text(json.dumps({"items": items}))
        assert status("[ev_0001] an entry without the name") == "partial", "evidence only"
        assert status("[ev_0002] the import table") == "found"

    def test_a_published_technique_alone_makes_a_fact_partial(self) -> None:
        manifest = {
            "case": "x",
            "split": "tuning",
            "facts": [
                {"id": "F1", "kind": "import", "difficulty": "easy",
                 "terms": [["GetUserNameW"]], "techniques": ["T1033"], "indicators": []},
                {"id": "F2", "kind": "config", "difficulty": "hard",
                 "terms": [["zz-1"], ["host-1.invalid"]], "techniques": [],
                 "indicators": ["host-1.invalid"]},
            ],
            "traps": [],
            "absent": [],
        }  # fmt: skip
        surfaces = scoring.Surfaces(
            name="r", sample_sha256="", tool_text="", tool_tokens=set(), flagged_sections=set(),
            kept_claims=[], free_text="", free_tokens=set(), evidence_text="",
            techniques=["T1033"], indicators=[("domain", "host-1.invalid")],
        )  # fmt: skip
        facts = {
            f["id"]: (f["status"], f["why"]) for f in scoring.score(manifest, surfaces)["facts"]
        }
        assert facts["F1"] == (
            "partial",
            "the report publishes its technique; nothing names the fact itself",
        )
        assert facts["F2"] == ("found", "the report publishes the fact's own indicator")

    def test_an_absence_the_analyst_asserts_is_not_withheld(self, tmp_path: Path) -> None:
        stored = _write_run(tmp_path, TUNING_CASE)
        technique = TUNING_CASE.manifest()["absent"][1]["claims"]["techniques"][0]
        claim = {"claim": "none of it", "technique_id": technique,
                 "kept_after_absence_question": True}  # fmt: skip
        (stored / "report-byjob.json").write_text(
            json.dumps({"agent_findings": [{"agent_name": "static", "claims": [claim]}]})
        )
        assert score_run(stored)["absent"][1]["status"] != "withheld"

    def test_publications_are_read_as_stored_and_absent_ones_are_not_recorded(
        self, tmp_path: Path
    ) -> None:
        stored = _write_run(tmp_path, TUNING_CASE)
        data = json.loads((stored / "report.json").read_text())
        for row in data["consolidated_iocs"]:
            row.pop("published")
        (stored / "report.json").write_text(json.dumps(data))
        result = score_run(stored)
        traps = {t["kind"]: t["status"] for t in result["traps"]}
        assert traps["decoy_url"] == "not recorded"
        assert "indicators" in result["not_read"]
        assert result["totals"]["not recorded"] == 1

    def test_one_published_item_counts_once(self) -> None:
        manifest = {
            "case": "x",
            "split": "tuning",
            "facts": [],
            "traps": [
                {"id": "T1", "kind": "dead_import", "claims": {"techniques": ["T1055"]}},
                {"id": "T2", "kind": "comment_api", "claims": {"techniques": ["T1055"]}},
            ],
            "absent": [],
        }
        surfaces = scoring.Surfaces(
            name="r", sample_sha256="", tool_text="", tool_tokens=set(), flagged_sections=set(),
            kept_claims=[], free_text="", free_tokens=set(), evidence_text="",
            techniques=["T1055.001"], indicators=[],
        )  # fmt: skip
        result = scoring.score(manifest, surfaces)
        assert [t["status"] for t in result["traps"]] == ["false", "false"]
        assert result["totals"]["false"] == 1

    def test_a_section_listed_but_not_flagged_is_partial(self, tmp_path: Path) -> None:
        stored = _write_run(tmp_path, TUNING_CASE)
        data = json.loads((stored / "report.json").read_text())
        data["static"]["sections"][1]["characteristics"] = "READ|INITIALIZED_DATA"
        (stored / "report.json").write_text(json.dumps(data))
        facts = {f["id"]: (f["status"], f["why"]) for f in score_run(stored)["facts"]}
        assert facts["F4"] == ("partial", "the section is listed and not flagged")

    def test_free_text_alone_never_finds_a_fact(self, tmp_path: Path) -> None:
        stored = _write_run(tmp_path, TUNING_CASE)
        data = json.loads((stored / "report.json").read_text())
        data["executive_summary"] = " ".join(t for c in TUNING_CASE.leak_terms for t in [c])
        data["static"] = {}
        data["sections"] = []
        (stored / "report.json").write_text(json.dumps(data))
        statuses = {f["id"]: f["status"] for f in score_run(stored)["facts"]}
        assert "found" not in statuses.values()
        assert statuses["F3"] == statuses["F4"] == "mentioned"

    def test_the_score_is_the_same_every_time_and_the_run_is_not_written(
        self, tmp_path: Path
    ) -> None:
        stored = _write_run(tmp_path, TUNING_CASE)
        before = digests(stored)
        assert score_run(stored) == score_run(stored)
        assert digests(stored) == before

    def test_a_run_without_evidence_says_so(self, tmp_path: Path) -> None:
        result = score_run(_write_run(tmp_path, TUNING_CASE, with_evidence=False))
        assert result["not_read"] == {
            "evidence": "evidence.json is absent: no claim's citation could be checked"
        }
        assert {f["id"]: f["status"] for f in result["facts"]}["F5"] == "missed"

    def test_a_run_without_its_report_row_says_no_claim_was_read(self, tmp_path: Path) -> None:
        stored = _write_run(tmp_path, TUNING_CASE)
        (stored / "report-byjob.json").unlink()
        result = score_run(stored)
        assert "claims" in result["not_read"]
        assert result["absent"][1]["status"] == "clear"

    def test_a_run_without_a_report_is_refused(self, tmp_path: Path) -> None:
        stored = _write_run(tmp_path, TUNING_CASE)
        (stored / "report.json").unlink()
        with pytest.raises(scoring.ScoreError, match="no report to score"):
            score_run(stored)

    def test_a_run_of_another_sample_is_no_case(self, tmp_path: Path) -> None:
        stored = _write_run(tmp_path, TUNING_CASE)
        (stored / "job.json").write_text(json.dumps({"sample_sha256": "f" * 64}))
        with pytest.raises(cases.CaseError, match="no calibration case"):
            score_run(stored)
        with pytest.raises(cases.CaseError, match="not cal-"):
            score_run(stored, case_id=TUNING_CASE.case_id)

    def test_a_stored_benchmark_run_is_read_and_left_as_it_was(self) -> None:
        root = _benchmark()
        if root is None or not (root / "haiku4" / "report.json").is_file():
            pytest.skip("the stored benchmark runs are not on this machine")
        before = digests(root / "haiku4")
        with pytest.raises(cases.CaseError, match="no calibration case"):
            score_run(root / "haiku4")
        assert digests(root / "haiku4") == before


class TestTheHeldOutHalf:
    def test_tuning_mode_refuses_a_held_out_case(self, tmp_path: Path) -> None:
        stored = _write_run(tmp_path, HELDOUT_CASE)
        with pytest.raises(HeldOut):
            score_run(stored)
        with pytest.raises(HeldOut):
            run.manifest(HELDOUT_CASE.case_id)
        assert run.manifest(TUNING_CASE.case_id)["case"] == TUNING_CASE.case_id

    def test_the_command_line_refuses_it_with_status_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        stored = _write_run(tmp_path, HELDOUT_CASE)
        assert main(["score", str(stored)]) == 2
        assert main(["manifest", HELDOUT_CASE.case_id]) == 2
        printed = capsys.readouterr()
        assert "held-out" in printed.err
        for term in HELDOUT_CASE.leak_terms:
            assert term not in printed.out + printed.err

    def test_held_out_mode_scores_it_and_prints_no_term(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        stored = _write_run(tmp_path, HELDOUT_CASE)
        out = tmp_path / "score.json"
        assert main(["score", str(stored), "--mode", "heldout", "--json", str(out)]) == 0
        printed = capsys.readouterr().out + out.read_text()
        assert "found 3" in printed
        for term in [*HELDOUT_CASE.leak_terms, UNRELATED_TECHNIQUE]:
            assert term not in printed

    def test_a_gate_reads_the_held_out_half_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built: list[cases.Entry] = []
        real = cases.build
        monkeypatch.setattr(cases, "build", lambda e, s: built.append(e) or real(e, s))
        tuning_run = _write_run(tmp_path, TUNING_CASE)
        heldout_run = _write_run(tmp_path, HELDOUT_CASE)
        result = gate([tuning_run, heldout_run])
        assert built and all(e.split == "heldout" for e in built)
        assert [s["case"] for s in result["scores"]] == [HELDOUT_CASE.case_id]
        assert result["not_scored"] == {str(tuning_run): "its sample is no held-out case"}
        assert HELDOUT_CASE.case_id not in result["heldout_cases_without_a_run"]
        assert result["totals"] == {
            "found": 3,
            "partial": 2,
            "mentioned": 1,
            "missed": 1,
            "false": 2,
            "withheld": 2,
            "not recorded": 0,
            "beyond": 1,
        }
        text = json.dumps(result)
        for term in HELDOUT_CASE.leak_terms:
            assert term not in text

    def test_the_build_writes_no_held_out_manifest_in_tuning_mode(self, tmp_path: Path) -> None:
        index = run.build(tmp_path / "set")
        written = {row["case"] for row in index if row["manifest"]}
        assert written == {c.case_id for c in cases.build_all() if c.split == "tuning"}
        assert sorted(p.name for p in (tmp_path / "set" / "manifests").iterdir()) == sorted(
            f"{c}.json" for c in written
        )
        assert len(list((tmp_path / "set").glob("*.bin"))) == len(index)
        index_text = (tmp_path / "set" / "index.json").read_text()
        for case in cases.build_all():
            if case.split == "heldout":
                for term in case.leak_terms:
                    assert term not in index_text
        with pytest.raises(cases.CaseError, match="not empty"):
            run.build(tmp_path / "set")
