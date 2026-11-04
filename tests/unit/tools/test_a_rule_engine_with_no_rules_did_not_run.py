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
import json
import re
from pathlib import Path
from typing import Any

import pytest

from app.services.tool_availability import WORKER, as_rows, unavailable_tools
from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.core.config import Settings
from maljan.core.paths import OUTSIDE_PROJECT, get_project_root, host_paths_masked
from maljan.pipeline.operator_choice import SampleFacts, lost_tool_rows
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

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "reporting"
SIGMA_REASON = (
    "no rule was loaded from data/sigma_rules, which is missing or holds none, so no rule was run"
)

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

    def test_a_path_outside_the_project_is_named_by_what_named_it(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv(rules.SIGMA_RULES_ENV, str(tmp_path / "gone"))
        _code, message, _remedy = _failure(rules.sigma_match([]))
        assert message.startswith("no rule was loaded from the path MALJAN_SIGMA_RULES_DIR names,")
        assert str(tmp_path) not in message
        _code, message, _remedy = _failure(rules.sigma_match([], ruleset=str(tmp_path / "x")))
        assert message.startswith("no rule was loaded from the ruleset named,")
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")
        _code, message, _remedy = _failure(rules.capa(str(sample), rules_dir=str(tmp_path / "x")))
        assert message.startswith("no rule was loaded from the path static.capa.rules_dir names,")


class TestADirectoryCorpus:
    def test_its_files_are_compiled_once_and_a_bad_one_is_named_and_skipped(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        from maljan.analysis import yara_layer

        corpus = tmp_path / "yara"
        corpus.mkdir()
        (corpus / "a.yaml").write_text(YARA_RULES, encoding="utf-8")
        (corpus / "b.yml").write_text(YARA_RULES.replace("marker_rule", "second"), "utf-8")
        (corpus / "broken.yml").write_text("not: [a rule list\n", encoding="utf-8")
        monkeypatch.setenv(rules.YARA_RULES_ENV, str(corpus))
        compiled: list[int] = []
        real = yara_layer.YaraLayer.__init__

        def counting(self: Any, rules: list[Any]) -> None:
            compiled.append(len(rules))
            real(self, rules)

        monkeypatch.setattr(yara_layer.YaraLayer, "__init__", counting)
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"xx MARKER yy")

        answer = rules.yara_scan(path=str(sample))

        assert compiled == [2]
        assert answer["rule_count"] == 2
        (skipped,) = answer["files_not_loaded"]
        assert skipped["file"] == "broken.yml"
        assert str(tmp_path) not in skipped["error"]
        assert "broken.yml" in caplog.text


class TestADirectoryCorpusNoneOfWhoseFilesReads:
    def test_it_did_not_run_and_names_each_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        corpus = tmp_path / "yara"
        corpus.mkdir()
        (corpus / "a.yml").write_text("not: [a rule list\n", encoding="utf-8")
        (corpus / "b.yaml").write_text("rules\n", encoding="utf-8")
        monkeypatch.setenv(rules.YARA_RULES_ENV, str(corpus))
        answer = rules.yara_scan(text="x")
        code, message, _remedy = _failure(answer)
        assert code == MISSING_DEPENDENCY
        assert message == (
            "no rule was loaded from the path MALJAN_YARA_RULES_DIR names: none of its 2 rule "
            "files could be read, so no rule was run"
        )
        assert [row["file"] for row in answer["files_not_loaded"]] == ["a.yml", "b.yaml"]

    def test_some_unread_and_the_rest_empty_says_so(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        corpus = tmp_path / "yara"
        corpus.mkdir()
        (corpus / "a.yml").write_text("not: [a rule list\n", encoding="utf-8")
        (corpus / "b.yml").write_text("rules: []\n", encoding="utf-8")
        monkeypatch.setenv(rules.YARA_RULES_ENV, str(corpus))
        _code, message, _remedy = _failure(rules.yara_scan(text="x"))
        assert "1 of its 2 rule files could not be read and the rest hold no rule" in message


class TestAnEmptyCorpusIsReadAgainOnlyWhenItChanges:
    def test_the_warning_is_said_once_and_a_corpus_put_in_place_is_read(
        self, no_sigma: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        for _ in range(3):
            assert "error" in rules.sigma_match_sandbox(SANDBOX_REPORT)
        assert caplog.text.count("rules directory not found") == 1
        no_sigma.mkdir()
        (no_sigma / "rundll32.yml").write_text(SIGMA_RULE, encoding="utf-8")
        assert rules.sigma_match_sandbox(SANDBOX_REPORT)["rule_count"] == 1


class TestTheEvidenceOnlyProvider:
    """``capa_yara``, for a run with no triage pack: missing rules are a pass not made."""

    def test_missing_capa_rules_are_a_reason_the_bundle_carries(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import sys
        import types

        from maljan.core.config import StaticCapaConfig, StaticYaraConfig
        from maljan.providers.static.capa_yara import CapaYaraStaticProvider

        # capa's modules present, so the rules are what is missing.
        for name in (
            "capa",
            "capa.capabilities",
            "capa.capabilities.common",
            "capa.helpers",
            "capa.loader",
            "capa.render",
            "capa.render.result_document",
            "capa.rules",
            "capa.rules.cache",
        ):
            monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
        provider = CapaYaraStaticProvider(
            StaticCapaConfig(rules_dir=str(tmp_path / "capa-rules")),
            StaticYaraConfig(rules_dir=str(tmp_path / "no-yara")),
        )
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")

        bundle = provider.collect_evidence(str(sample))

        assert bundle is not None
        (reason,) = bundle.unavailable
        assert reason.startswith("static provider 'capa_yara' did not run capa: no rule was loaded")
        assert str(tmp_path) not in reason
        assert sidecar_needs.CAPA_RULES.remedy in reason
        assert provider.capabilities.provides_evidence, "rules put in place later are read"
        assert provider.capabilities.degrade_on_failure


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


def _degraded_report(reason: str = SIGMA_REASON) -> MalwareReport:
    return MalwareReport.model_validate(
        {
            "verdict": "Malware",
            "overall_confidence": 0.8,
            "degraded_mode": True,
            "identity": {"hashes": {"sha256": "e" * 64}, "file_type": "pe"},
            "degradation_reasons": ["triage.sigma_match_sandbox_failed"],
            "run_summary": {
                "lost_tools": [{"tool": "sigma_match_sandbox", "reason": reason}],
            },
        }
    )


def _scope(report: MalwareReport) -> str:
    markdown = MarkdownRenderer(layout=ANALYST).render(report)
    return markdown.split("## 2. Introduction and scope", 1)[1].split("\n## ", 1)[0]


class TestTheRunRecordsWhatItWentWithout:
    def test_each_lost_tool_with_its_own_error(self) -> None:
        facts = SampleFacts(
            file_type="pe",
            failures=(
                {"tool": "sigma_match_sandbox", "ok": False, "error": SIGMA_REASON},
                {"tool": "strings", "ok": True, "error": None},
            ),
        )
        rows = lost_tool_rows(["triage.sigma_match_sandbox_failed"], facts)
        assert rows == [{"tool": "sigma_match_sandbox", "reason": SIGMA_REASON}]

    def test_a_servers_tool_with_what_its_reason_brackets(self) -> None:
        reason = (
            "server.analysis.sigma_match_unavailable(data/sigma_rules is missing or empty "
            "(named by the default)); put the data in data/sigma_rules"
        )
        assert lost_tool_rows([reason]) == [
            {
                "tool": "sigma_match",
                "reason": "data/sigma_rules is missing or empty (named by the default)",
            }
        ]

    def test_a_host_path_is_shown_from_the_project_or_masked(self) -> None:
        root = get_project_root()
        error = f"rules at {root}/data/capa-rules and /srv/elsewhere/capa-rules are missing"
        facts = SampleFacts(failures=({"tool": "capa", "ok": False, "error": error},))
        (row,) = lost_tool_rows(["triage.capa_failed"], facts)
        assert row["reason"] == (f"rules at data/capa-rules and {OUTSIDE_PROJECT} are missing")


class TestOnlyAHostPathIsMasked:
    def test_an_http_route_is_kept(self) -> None:
        for text in (
            "GET /api/v1/jobs failed",
            "POST /live/ answered 404",
            "see https://x.test/a/b",
        ):
            assert host_paths_masked(text) == text

    def test_a_path_under_a_host_root_or_the_projects_parents_is_masked(self) -> None:
        parent = get_project_root().parent
        said = host_paths_masked(f"read /tmp/x/rules.yml, /etc/passwd and {parent}/other/r.yml")
        assert said == f"read {OUTSIDE_PROJECT}, {OUTSIDE_PROJECT} and {OUTSIDE_PROJECT}"

    def test_a_path_that_exists_here_is_masked(self, tmp_path: Path) -> None:
        assert host_paths_masked(f"at {tmp_path}") == f"at {OUTSIDE_PROJECT}"

    def test_a_file_url_is_a_path(self) -> None:
        root = get_project_root()
        said = host_paths_masked(f"file://{root}/data/sigma_rules and file:///srv/x/r.yml")
        assert said == f"data/sigma_rules and {OUTSIDE_PROJECT}"
        assert host_paths_masked("file://localhost/opt/rules") == OUTSIDE_PROJECT

    def test_the_run_summary_keeps_them_and_leaves_them_out_when_none(self) -> None:
        rows = [{"tool": "capa", "reason": "x"}]
        with_rows = RunSummaryBuilder(start_time=0.0).set_lost_tools(rows).build().to_dict()
        assert with_rows["lost_tools"] == rows
        assert "lost_tools" not in RunSummaryBuilder(start_time=0.0).build().to_dict()


class TestTheReportSaysItDidNotRun:
    def test_the_scope_says_what_the_run_went_without_and_why(self) -> None:
        assert (
            "The run went without sigma_match_sandbox (no rule was loaded from "
            "data/sigma_rules, which is missing or holds none, so no rule was run)."
        ) in _scope(_degraded_report())

    def test_a_run_that_is_not_degraded_says_nothing_of_it(self) -> None:
        report = _degraded_report()
        report.degraded_mode = False
        assert "went without" not in _scope(report)

    def test_a_tools_words_are_escaped_and_defanged(self) -> None:
        probe = "[click](http://evil.example/x) <img onerror=alert(1)> **bold**"
        scope = _scope(_degraded_report(probe))
        assert (
            "The run went without sigma_match_sandbox (\\[click\\](hxxp://evil[.]example/x) "
            "\\<img onerror=alert(1)\\> \\*\\*bold\\*\\*)."
        ) in scope
        # Nothing of it reads as a link, a tag or emphasis.
        assert not re.search(r"(?<!\\)\[click(?<!\\)\]\(", scope)
        assert not re.search(r"(?<!\\)<img", scope)
        assert not re.search(r"(?<!\\)\*\*bold", scope)

    def test_a_host_path_in_a_stored_reason_is_masked(self) -> None:
        scope = _scope(_degraded_report("rules at /srv/run-hk8/data/capa-rules are missing"))
        assert "/srv/run-hk8" not in scope
        assert OUTSIDE_PROJECT in scope

    def test_a_stored_run_renders_byte_for_byte_as_it_did(self) -> None:
        """A summary written before ``lost_tools`` says nothing new (haiku8's shape)."""
        stored = json.loads((FIXTURES / "stored_degraded_run.json").read_text(encoding="utf-8"))
        before = json.loads(
            (FIXTURES / "stored_degraded_run.rendered_on_dev.json").read_text(encoding="utf-8")
        )
        report = MalwareReport.model_validate(stored)
        assert MarkdownRenderer(layout=ANALYST).render(report) == before["analyst"]
        assert MarkdownRenderer().render(report) == before["full"]


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
        assert [(r["server"], r["tool"]) for r in rows] == [("pipeline", "sigma_match_sandbox")]
        (row,) = rows
        assert row["reason"] == "data/sigma_rules is missing or empty (named by the default)"
        assert row["remediation"] == sidecar_needs.SIGMA_RULES.remedy
        assert row["manifest_code"] == MISSING_DEPENDENCY
        assert row["still_answers"] == ""

    def test_it_is_named_beside_a_server_with_its_own_import_path(self, host: Path) -> None:
        settings = Settings()
        settings.mcp.servers["analysis"].env = {"PYTHONPATH": "/opt/libs"}
        assert _named(settings) == [("pipeline", "sigma_match_sandbox")]

    def test_the_server_and_the_worker_are_each_named_where_each_reads(self, host: Path) -> None:
        found = unavailable_tools(Settings())
        assert [(u.server, u.tool) for u in found] == [
            ("analysis", "sigma_match"),
            ("analysis", "sigma_match_sandbox"),
            ("pipeline", "sigma_match_sandbox"),
        ]
        # The same lack and remedy in two places is one row naming both.
        assert _named(Settings()) == [
            ("analysis", "sigma_match"),
            ("analysis, pipeline", "sigma_match_sandbox"),
        ]

    def test_rows_that_differ_stay_apart(self) -> None:
        from maljan.tools.capabilities import Unavailable

        def row(server: str, reason: str, remedy: str = "fetch it") -> Unavailable:
            return Unavailable(server=server, tool="t", reason=reason, remediation=remedy)

        rows = as_rows(
            [row("a", "gone"), row("b", "gone"), row("c", "empty"), row("d", "gone", "x")]
        )
        assert [(r["server"], r["reason"], r["remediation"]) for r in rows] == [
            ("a, b", "gone", "fetch it"),
            ("c", "empty", "fetch it"),
            ("d", "gone", "x"),
        ]
        assert rows[0]["degradation_reason"] == (
            "server.a.t_unavailable(gone); fetch it; server.b.t_unavailable(gone); fetch it"
        )

    def test_the_workers_label_is_the_server_its_entries_are_recorded_under(self) -> None:
        assert WORKER == PIPELINE

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
