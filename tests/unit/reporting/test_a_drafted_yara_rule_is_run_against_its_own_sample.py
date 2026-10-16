"""A drafted YARA rule is run against the sample it was drafted from.

A rule that compiled shipped as a draft for a SOC to paste whether or not it
matched anything. The draft is now run, through the engine that compiled it,
against the file the run analysed, read where it lies and within the
operator's budget for one YARA scan of the sample. Its record says whether it
matched and where the engine first found each of its strings, or why it was
not run. A draft that does not match its own sample is kept and said to be
one, in the report and on DETECTION.
"""

from __future__ import annotations

import errno
import hashlib
import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from maljan.reporting import detection_signatures as drafts
from maljan.reporting.builder import build_consolidated_iocs
from maljan.reporting.detection_signatures import (
    NOT_CHECKED_NO_ANSWER,
    NOT_CHECKED_NO_BUDGET,
    NOT_CHECKED_NO_ENGINE,
    NOT_CHECKED_NO_PATH,
    NOT_CHECKED_NO_SAMPLE,
    NOT_CHECKED_REFUSED,
    NOT_CHECKED_TIMED_OUT,
    NOT_CHECKED_UNCOMPILED,
    NOT_CHECKED_UNREAD,
    OwnSample,
    build_detection_rules,
)
from maljan.reporting.models import (
    DetectionRule,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
    SampleString,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer

needs_engine = pytest.mark.skipif(not drafts._YARA_AVAILABLE, reason="yara-python is not installed")

FIRST = "gate9.example.org"
SECOND = "relay4.example.net"
NOT_THE_SAMPLE = "c" * 64
BUDGET = 60


def _report(sha256: str = NOT_THE_SAMPLE) -> MalwareReport:
    """A run that publishes two names a sandbox watched, so the draft has two strings."""
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=sha256)),
        verdict="Malware",
        malware_category="loader",
        network=NetworkIOCs(
            domains=[NetworkDomain(fqdn=name, source="sandbox") for name in (FIRST, SECOND)]
        ),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


def _yara(report: MalwareReport, sample: OwnSample | None) -> DetectionRule:
    return next(rule for rule in build_detection_rules(report, sample) if rule.kind == "yara")


def _slot(rule: DetectionRule, value: str) -> str:
    """A drafted string's identifier, read off the rule's own sources in their order."""
    values = [item.split(":", 2)[2] for item in rule.source_evidence if item.startswith("string:")]
    return f"$s{values.index(value)}"


def _sample(tmp_path: Path, blob: bytes) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(blob)
    return path


# FIRST in ASCII at 16, SECOND in UTF-16LE at 40: the rule's strings are
# ``ascii wide nocase``, and the engine reads both forms.
BOTH = b"\x00" * 16 + FIRST.encode() + b"\x00" * 7 + SECOND.encode("utf-16-le") + b"\x00" * 8
ONLY_FIRST = b"\x00" * 16 + FIRST.encode() + b"\x00" * 8


@needs_engine
class TestTheRuleIsRunOnItsSample:
    def test_a_rule_whose_strings_the_sample_holds_matches_it(self, tmp_path: Path) -> None:
        path = _sample(tmp_path, BOTH)
        rule = _yara(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))

        assert rule.matches_sample is True
        assert rule.sample_not_checked is None
        assert rule.sample_strings == [
            SampleString(identifier=_slot(rule, FIRST), offset=16),
            SampleString(identifier=_slot(rule, SECOND), offset=40),
        ]

    def test_a_rule_that_does_not_match_its_sample_is_kept_and_says_so(
        self, tmp_path: Path
    ) -> None:
        path = _sample(tmp_path, ONLY_FIRST)
        report = _report()
        report.detection_signatures = build_detection_rules(
            report, OwnSample(path=str(path), budget_seconds=BUDGET)
        )
        rule = next(r for r in report.detection_signatures if r.kind == "yara")

        assert rule.matches_sample is False
        assert {s.identifier: s.offset for s in rule.sample_strings or []} == {
            _slot(rule, FIRST): 16,
            _slot(rule, SECOND): None,
        }
        said = (
            "Run against the sample it was drafted from: the rule does not match it. "
            f"Found in the sample (first match of each): `{_slot(rule, FIRST)}` at 0x10. "
            f"Found nowhere in the sample: `{_slot(rule, SECOND)}`."
        )
        markdown = MarkdownRenderer().render(report)
        assert said in markdown
        assert rule.body.rstrip() in markdown, "the rule is printed whole, never dropped"

    def test_the_hash_clause_matches_whatever_the_strings_do(self, tmp_path: Path) -> None:
        blob = b"\x00" * 64
        path = _sample(tmp_path, blob)
        rule = _yara(
            _report(sha256=hashlib.sha256(blob).hexdigest()),
            OwnSample(path=str(path), budget_seconds=BUDGET),
        )

        assert rule.matches_sample is True
        assert [s.offset for s in rule.sample_strings or []] == [None, None]

    def test_the_engine_is_given_the_sample_s_bytes_and_the_budget(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _sample(tmp_path, BOTH)
        asked: dict[str, Any] = {}
        compile_rule = drafts._compile_yara

        def spying(body: str) -> tuple[Any, str | None]:
            compiled, error = compile_rule(body)

            class _Spy:
                def match(self, **kwargs: Any) -> Any:
                    asked.update(kwargs)
                    return compiled.match(**kwargs)

            return _Spy(), error

        monkeypatch.setattr(drafts, "_compile_yara", spying)
        rule = _yara(_report(), OwnSample(path=str(path), budget_seconds=7))

        assert asked["timeout"] == 7
        assert asked["data"] == BOTH
        assert rule.matches_sample is True

    def test_reading_the_sample_changes_nothing_on_disk(self, tmp_path: Path) -> None:
        path = _sample(tmp_path, BOTH)
        before = (path.stat().st_mode, path.stat().st_mtime_ns, sorted(tmp_path.iterdir()))

        _yara(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))

        after = (path.stat().st_mode, path.stat().st_mtime_ns, sorted(tmp_path.iterdir()))
        assert after == before
        assert path.read_bytes() == BOTH

    def test_the_html_report_says_it_too(self, tmp_path: Path) -> None:
        from maljan.reporting.renderers import HtmlRenderer

        path = _sample(tmp_path, ONLY_FIRST)
        report = _report()
        report.detection_signatures = build_detection_rules(
            report, OwnSample(path=str(path), budget_seconds=BUDGET)
        )

        assert "the rule does not match it." in HtmlRenderer().render(report, nonce="fixed")


class TestARuleNotRunSaysWhy:
    @needs_engine
    @pytest.mark.parametrize(
        ("make", "reason"),
        [
            (lambda tmp: None, NOT_CHECKED_NO_SAMPLE),
            (lambda tmp: OwnSample(path=None, budget_seconds=BUDGET), NOT_CHECKED_NO_PATH),
            (lambda tmp: OwnSample(path="  ", budget_seconds=BUDGET), NOT_CHECKED_NO_PATH),
            (
                lambda tmp: OwnSample(path=str(tmp / "absent.bin"), budget_seconds=BUDGET),
                NOT_CHECKED_UNREAD.format(why=os.strerror(errno.ENOENT)),
            ),
            (
                lambda tmp: OwnSample(path=str(tmp), budget_seconds=BUDGET),
                NOT_CHECKED_UNREAD.format(why=os.strerror(errno.EISDIR)),
            ),
            (
                lambda tmp: OwnSample(path=str(_sample(tmp, BOTH)), budget_seconds=None),
                NOT_CHECKED_NO_BUDGET,
            ),
        ],
    )
    def test_without_a_readable_sample(self, tmp_path: Path, make: Any, reason: str) -> None:
        report = _report()
        report.detection_signatures = build_detection_rules(report, make(tmp_path))
        rule = next(r for r in report.detection_signatures if r.kind == "yara")

        assert rule.sample_not_checked == reason
        assert rule.matches_sample is None
        assert rule.sample_strings is None
        assert rule.compile_error is None
        markdown = MarkdownRenderer().render(report)
        assert f"Not run against the sample it was drafted from: {reason}." in markdown

    def test_without_the_engine(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(drafts, "_YARA_AVAILABLE", False)
        path = _sample(tmp_path, BOTH)
        rule = _yara(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))

        assert rule.compile_error == "yara-python not installed; rule body not validated"
        assert rule.sample_not_checked == NOT_CHECKED_NO_ENGINE
        assert rule.matches_sample is None

    @needs_engine
    def test_a_rule_that_did_not_compile(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(drafts, "_render_yara", lambda **_kwargs: "rule broken {\n")
        path = _sample(tmp_path, BOTH)
        rule = _yara(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))

        assert (rule.compile_error or "").startswith("yara.compile failed")
        assert rule.sample_not_checked == NOT_CHECKED_UNCOMPILED

    @needs_engine
    def test_a_scan_past_its_budget(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import yara

        class _Slow:
            def match(self, **_kwargs: Any) -> Any:
                raise yara.TimeoutError("scan timed out")

        monkeypatch.setattr(drafts, "_compile_yara", lambda body: (_Slow(), None))
        path = _sample(tmp_path, BOTH)
        rule = _yara(_report(), OwnSample(path=str(path), budget_seconds=7))

        assert rule.sample_not_checked == NOT_CHECKED_TIMED_OUT.format(seconds=7)
        assert "7 s (core.static.yara.timeout_seconds)" in rule.sample_not_checked

    @needs_engine
    def test_an_engine_that_refuses_the_scan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import yara

        class _Refusing:
            def match(self, **_kwargs: Any) -> Any:
                raise yara.Error("internal error: 30")

        monkeypatch.setattr(drafts, "_compile_yara", lambda body: (_Refusing(), None))
        path = _sample(tmp_path, BOTH)
        rule = _yara(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))

        assert rule.sample_not_checked == NOT_CHECKED_REFUSED.format(
            why="Error: internal error: 30"
        )

    @needs_engine
    def test_an_engine_that_gives_no_answer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Silent:
            def match(self, **_kwargs: Any) -> Any:
                return []

        monkeypatch.setattr(drafts, "_compile_yara", lambda body: (_Silent(), None))
        path = _sample(tmp_path, BOTH)
        rule = _yara(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))

        assert rule.sample_not_checked == NOT_CHECKED_NO_ANSWER


class TestOnlyTheYaraDraftCarriesACheck:
    @needs_engine
    def test_a_suricata_draft_carries_none(self, tmp_path: Path) -> None:
        path = _sample(tmp_path, BOTH)
        rules = build_detection_rules(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))
        suricata = next(rule for rule in rules if rule.kind == "suricata")

        assert (
            suricata.matches_sample,
            suricata.sample_strings,
            suricata.sample_not_checked,
        ) == (None, None, None)
        dumped = suricata.model_dump(mode="json")
        assert not {"matches_sample", "sample_strings", "sample_not_checked"} & set(dumped)


class TestAStoredRuleReadsAsBefore:
    STORED = {
        "kind": "yara",
        "name": "Maljan_AutoGen_loader",
        "body": "rule Maljan_AutoGen_loader\n{\n    condition:\n        (filesize > 0)\n}\n",
        "auto_generated": True,
        "source_evidence": ["sha256:" + NOT_THE_SAMPLE],
        "compile_error": None,
    }

    def test_its_record_round_trips_unchanged(self) -> None:
        assert DetectionRule.model_validate(self.STORED).model_dump(mode="json") == self.STORED

    def test_its_section_prints_no_line_of_the_check(self) -> None:
        report = _report()
        report.detection_signatures = [DetectionRule.model_validate(self.STORED)]

        section = MarkdownRenderer().render(report).split("Draft detection rules", 1)[1]
        section = section.split("10.3", 1)[0]
        paragraphs = section.split("\n\n")
        header = next(n for n, text in enumerate(paragraphs) if text.startswith("**YARA**"))

        assert "against the sample it was drafted from" not in section
        assert "— compiled; auto-generated from sha256:" in paragraphs[header]
        assert paragraphs[header + 1].startswith("```yara"), "the fence follows the header"


@needs_engine
class TestTheScanStaysLinear:
    def test_ten_times_the_repeats_cost_at_most_ten_times_and_keep_one_offset(
        self, tmp_path: Path
    ) -> None:
        def took(repeats: int) -> tuple[float, DetectionRule]:
            path = tmp_path / f"repeated-{repeats}.bin"
            path.write_bytes((FIRST + " ").encode() * repeats + SECOND.encode())
            start = time.perf_counter()
            rule = _yara(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))
            return time.perf_counter() - start, rule

        took(500)
        small, _rule = took(5_000)
        large, rule = took(50_000)

        assert large <= max(small, 1e-3) * 30, (small, large)
        assert {s.identifier: s.offset for s in rule.sample_strings or []} == {
            _slot(rule, FIRST): 0,
            _slot(rule, SECOND): (len(FIRST) + 1) * 50_000,
        }, "one offset per string, however often the sample repeats it"


class TestTheReportNodeHandsTheDrafterItsSample:
    def test_the_budget_is_the_operator_s_setting(self) -> None:
        from maljan.core.config import Settings
        from maljan.pipeline.nodes import _yara_scan_budget

        settings = Settings()

        assert _yara_scan_budget(SimpleNamespace(config=settings)) == (
            settings.static.yara.timeout_seconds
        )
        assert _yara_scan_budget(SimpleNamespace(config=SimpleNamespace())) is None

    @needs_engine
    @pytest.mark.asyncio
    async def test_the_node_runs_the_draft_on_the_file_it_read(self, tmp_path: Path) -> None:
        from maljan.pipeline.nodes import make_report_node
        from maljan.reporting.builder import MalwareReportBuilder
        from tests.stages import paper_profile
        from tests.unit.pipeline.test_what_is_served_is_the_final_report import _state

        path = _sample(tmp_path, BOTH)
        fake = MagicMock()
        fake.agent_registry.list_agents.return_value = ["static"]
        fake.analyst_keys.return_value = ["static"]
        fake.agent_role.side_effect = lambda n: n
        fake.is_mock = False
        fake.config.reporting.enabled = True
        fake.config.llm.parallel_analysts = False
        fake.config.negotiation.max_iterations = 3
        fake.config.static.yara.timeout_seconds = 9
        fake.active_profile.return_value = paper_profile(["static"], parallel=False)
        fake.get_narrative_agent.return_value = None
        fake.get_report_composer.return_value = None
        fake.get_static_provider.return_value.capabilities.provides_evidence = False
        stage = next(step for step in fake.active_profile().stages if step.kind == "report")

        deterministic = MalwareReportBuilder.build_deterministic

        def _build(self: MalwareReportBuilder) -> MalwareReport:
            report = deterministic(self)
            report.malware_category = "loader"
            return report

        handed: list[OwnSample | None] = []
        run_on_sample = drafts._run_on_sample

        def _spy(compiled: Any, identifiers: list[str], sample: OwnSample | None) -> Any:
            handed.append(sample)
            return run_on_sample(compiled, identifiers, sample)

        state = _state()
        state["sample_path"] = str(path)
        with (
            patch.object(MalwareReportBuilder, "build_deterministic", _build),
            patch.object(drafts, "_run_on_sample", _spy),
        ):
            result = await make_report_node(fake, stage=stage, announces=False)(state)  # type: ignore[arg-type]

        assert handed == [OwnSample(path=str(path), budget_seconds=9)]
        stored = (result["malware_report"] or {})["detection_signatures"]
        yara_rule = next(rule for rule in stored if rule["kind"] == "yara")
        # The builder read the file's own sha256, so the rule's hash clause holds.
        assert yara_rule["matches_sample"] is True
        assert yara_rule["sample_strings"] == []
