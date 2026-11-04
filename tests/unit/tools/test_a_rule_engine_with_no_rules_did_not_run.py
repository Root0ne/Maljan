"""A rule engine that loaded no rule did not run; it never answers "0 hits" (T-556).

haiku8, haiku9 and haiku10 ran the Sigma pass over the sandbox report with no
corpus: the directory is fetched rather than tracked and the run's worktree
had none. The worker logged a warning, the entry held ``rule_count 0``, the
report said "Sigma (0 hits)", the run was not degraded, and the check before
the job named nothing, because the pass runs in the worker by a direct call
that no reading stands in for, and only readings and servers were checked.

Every rule engine now answers an empty corpus as a failure with the code a
missing library has and its declared data path's remedy, the same path capa's
missing rules take: the pack records the step failed, the run is degraded,
the report's scope says what the run went without and why, and the check
before a job looks at the corpus of every in-process step a sidecar declares.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

from app.services.tool_availability import as_rows, unavailable_tools
from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.core.config import Settings
from maljan.pipeline.triage_pack import PIPELINE, run_is_degraded, run_pack
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers import MarkdownRenderer
from maljan.reporting.renderers.layout import ANALYST
from maljan.schemas.evidence import EvidenceCounter
from maljan.tools import capabilities, emulated_strings, rules, sidecar_needs
from maljan.tools.errors import BAD_ARGUMENT, MISSING_DEPENDENCY, error_parts
from tests.unit.pipeline.test_triage_pack import SANDBOX_REPORT, _inputs, _write
from tests.unit.tools.test_binary import _pe
from tests.unit.tools.test_rules import SIGMA_RULE

YARA_RULES = """
rules:
  - id: marker_rule
    technique_id: T1059
    patterns: ["MARKER"]
"""


@pytest.fixture(autouse=True)
def fresh_caches() -> Any:
    rules.reset_rule_caches()
    yield
    rules.reset_rule_caches()


@pytest.fixture
def no_sigma(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """The Sigma corpus named by its override, and not there."""
    absent = tmp_path / "sigma_rules"
    monkeypatch.setenv(rules.SIGMA_RULES_ENV, str(absent))
    return absent


def _failure(answer: dict[str, Any]) -> tuple[str, str, str | None]:
    parts = error_parts(answer)
    assert parts is not None, answer
    return parts


class TestTheEngineAnswer:
    def test_sigma_over_a_sandbox_report_with_no_corpus_did_not_run(self, no_sigma: Path) -> None:
        answer = rules.sigma_match_sandbox(SANDBOX_REPORT)
        code, message, remedy = _failure(answer)
        assert code == MISSING_DEPENDENCY
        assert message.startswith("no rule was loaded from ")
        assert message.endswith("which is missing or holds none, so no rule was run")
        assert remedy == sidecar_needs.SIGMA_RULES.remedy
        assert answer["tool"] == "sigma_match_sandbox"
        assert answer["event_count"] == 1
        assert "matches" not in answer and "rule_count" not in answer

    def test_a_directory_holding_no_rule_file_did_not_run(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        (tmp_path / "empty").mkdir()
        (tmp_path / "empty" / "README.md").write_text("fetched later\n", encoding="utf-8")
        monkeypatch.setenv(rules.SIGMA_RULES_ENV, str(tmp_path / "empty"))
        assert _failure(rules.sigma_match([{"Image": "x"}]))[0] == MISSING_DEPENDENCY

    def test_a_ruleset_the_caller_named_is_its_own_argument_to_change(self, tmp_path: Path) -> None:
        code, _message, remedy = _failure(rules.sigma_match([], ruleset=str(tmp_path / "none")))
        assert code == BAD_ARGUMENT
        assert remedy is not None and "'default'" in remedy

    def test_an_empty_corpus_is_not_kept_so_one_put_in_place_later_is_read(
        self, no_sigma: Path
    ) -> None:
        assert "error" in rules.sigma_match_sandbox(SANDBOX_REPORT)
        no_sigma.mkdir()
        (no_sigma / "rundll32.yml").write_text(SIGMA_RULE, encoding="utf-8")
        answer = rules.sigma_match_sandbox(SANDBOX_REPORT)
        assert answer["rule_count"] == 1 and "error" not in answer

    def test_yara_with_no_corpus_did_not_run_and_a_directory_corpus_is_read(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"xx MARKER yy")
        monkeypatch.setenv(rules.YARA_RULES_ENV, str(tmp_path / "yara"))
        code, _message, remedy = _failure(rules.yara_scan(path=str(sample)))
        assert code == MISSING_DEPENDENCY
        assert remedy == sidecar_needs.YARA_RULES.remedy
        assert remedy.startswith("restore data/yara_ttp_rules.yaml from version control")
        (tmp_path / "yara").mkdir()
        (tmp_path / "yara" / "marker.yaml").write_text(YARA_RULES, encoding="utf-8")
        answer = rules.yara_scan(path=str(sample))
        assert answer["rule_count"] == 1
        assert [row["rule"] for row in answer["matches"]] == ["marker_rule"]

    def test_capa_with_no_rules_did_not_run_with_its_declared_remedy(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")
        code, message, remedy = _failure(rules.capa(str(sample), rules_dir=str(tmp_path / "x")))
        assert code == MISSING_DEPENDENCY
        assert "no rule was loaded from" in message
        assert remedy == sidecar_needs.CAPA_RULES.remedy


class TestTheRunIsDegraded:
    def test_the_pack_records_the_step_failed_and_the_run_is_degraded(
        self, no_sigma: Path, tmp_path: Path
    ) -> None:
        recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
        path = _write(tmp_path, "s.exe", _pe())
        result = run_pack(recorder, _inputs(path, "pe", sandbox_report=SANDBOX_REPORT))
        (sigma,) = [entry for entry in result.entries if entry.tool == "sigma_match_sandbox"]
        assert sigma.ok is False
        assert "no rule was loaded from" in str(sigma.error)
        assert sigma.remediation == sidecar_needs.SIGMA_RULES.remedy
        assert "triage.sigma_match_sandbox_failed" in result.degradation_reasons
        assert "triage.sigma_match_sandbox_failed" in result.to_state()["degradation_reasons"]
        assert run_is_degraded(["triage.sigma_match_sandbox_failed"])


def _degraded_report() -> MalwareReport:
    error = (
        "no rule was loaded from data/sigma_rules, which is missing or holds none, "
        "so no rule was run"
    )
    return MalwareReport.model_validate(
        {
            "verdict": "Malware",
            "overall_confidence": 0.8,
            "degraded_mode": True,
            "identity": {"hashes": {"sha256": "e" * 64}, "file_type": "pe"},
            "degradation_reasons": ["triage.sigma_match_sandbox_failed"],
            "run_summary": {
                "evidence": {
                    "failures": [
                        {
                            "tool": "sigma_match_sandbox",
                            "count": 1,
                            "error": error,
                            "server": "pipeline",
                            "entry_id": "ev_0009",
                        }
                    ]
                }
            },
        }
    )


class TestTheReportSaysItDidNotRun:
    def test_the_scope_says_what_the_run_went_without_and_why(self) -> None:
        markdown = MarkdownRenderer(layout=ANALYST).render(_degraded_report())
        scope = markdown.split("## 2. Introduction and scope", 1)[1].split("\n## ", 1)[0]
        assert (
            "The run went without sigma_match_sandbox (no rule was loaded from data/sigma_rules, "
            "which is missing or holds none, so no rule was run)."
        ) in scope
        assert "**[DEGRADED RUN]** The run went without sigma_match_sandbox" in markdown

    def test_a_run_that_is_not_degraded_says_nothing_of_it(self) -> None:
        report = _degraded_report()
        report.degraded_mode = False
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        assert "went without" not in markdown

    def test_an_unavailable_servers_tool_is_said_with_its_reason(self) -> None:
        report = _degraded_report()
        report.run_summary = {}
        report.degradation_reasons = [
            "server.analysis.sigma_match_unavailable(data/sigma_rules is missing or empty "
            "(named by the default)); put the data in data/sigma_rules"
        ]
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        assert (
            "The run went without sigma_match (data/sigma_rules is missing or empty "
            "(named by the default))."
        ) in markdown


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Every library and FLOSS present, and every corpus but Sigma's, under a root of its own."""
    monkeypatch.setattr(capabilities, "_data_root", lambda: tmp_path)
    monkeypatch.setattr(importlib.util, "find_spec", lambda name, *a, **k: object())
    monkeypatch.setattr(emulated_strings, "find_floss", lambda environ=None: ("floss", ""))
    monkeypatch.delenv(rules.SIGMA_RULES_ENV, raising=False)
    (tmp_path / "data" / "capa-rules").mkdir(parents=True)
    (tmp_path / "data" / "capa-rules" / "r.yml").write_text("rule:\n", encoding="utf-8")
    (tmp_path / "data" / "yara_ttp_rules.yaml").write_text(YARA_RULES, encoding="utf-8")
    return tmp_path


def _named(settings: Settings) -> list[tuple[str, str]]:
    return [(row["server"], row["tool"]) for row in as_rows(unavailable_tools(settings))]


class TestTheCheckBeforeAJobNamesIt:
    """With the real ``Settings()``: the step runs in the worker whatever the block says."""

    def test_the_in_process_pass_is_named_with_the_server_switched_off(self, host: Path) -> None:
        settings = Settings()
        settings.mcp.servers["analysis"].enabled = False
        rows = as_rows(unavailable_tools(settings))
        assert [(r["server"], r["tool"]) for r in rows] == [("analysis", "sigma_match_sandbox")]
        (row,) = rows
        assert row["reason"] == "data/sigma_rules is missing or empty (named by the default)"
        assert row["remediation"] == sidecar_needs.SIGMA_RULES.remedy
        assert row["manifest_code"] == MISSING_DEPENDENCY
        assert row["still_answers"] == ""

    def test_it_is_named_beside_a_server_with_its_own_import_path(self, host: Path) -> None:
        settings = Settings()
        settings.mcp.servers["analysis"].env = {"PYTHONPATH": "/opt/libs"}
        assert _named(settings) == [("analysis", "sigma_match_sandbox")]

    def test_the_servers_rows_and_the_workers_are_one_row_per_tool(self, host: Path) -> None:
        assert _named(Settings()) == [
            ("analysis", "sigma_match"),
            ("analysis", "sigma_match_sandbox"),
        ]

    def test_a_corpus_in_place_names_nothing(self, host: Path) -> None:
        (host / "data" / "sigma_rules").mkdir()
        (host / "data" / "sigma_rules" / "r.yml").write_text(SIGMA_RULE, encoding="utf-8")
        settings = Settings()
        settings.mcp.servers["analysis"].enabled = False
        assert _named(settings) == []
        assert _named(Settings()) == []

    def test_the_step_switched_off_is_not_named(self, host: Path) -> None:
        settings = Settings()
        settings.mcp.servers["analysis"].enabled = False
        settings.triage.steps = [{"id": "sigma_match_sandbox", "enabled": False}]
        assert _named(settings) == []

    def test_a_yara_override_naming_nothing_is_named_and_says_nothing_still_answers(
        self, host: Path
    ) -> None:
        settings = Settings()
        settings.mcp.servers["analysis"].env = {rules.YARA_RULES_ENV: "data/none"}
        (host / "data" / "sigma_rules").mkdir()
        (host / "data" / "sigma_rules" / "r.yml").write_text(SIGMA_RULE, encoding="utf-8")
        (row,) = as_rows(unavailable_tools(settings))
        assert (row["server"], row["tool"]) == ("analysis", "yara_scan")
        assert row["reason"] == "data/none is missing or empty (named by MALJAN_YARA_RULES_DIR)"
        assert row["still_answers"] == ""
