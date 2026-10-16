"""A drafted YARA rule is checked against the sample it was drafted from.

A rule that compiled shipped as a draft for a SOC to paste whether or not it
matched anything. The draft is now checked, through the engine that compiled
it, against the file the run analysed, which the engine maps read-only where it
lies, within the operator's budget for the check. The engine scans a probe
ruleset written from the draft's own declarations: one rule per string and one
reporter per clause, so it says which clause held, and it lists one match per
string however often a hostile sample repeats one. The record says whether the
rule matched, by which clause, where each string was first found, or why the
rule was not checked. A draft that does not match its own sample is kept and
said to be one, in the report and on DETECTION.
"""

from __future__ import annotations

import errno
import hashlib
import os
import random
import re
import time
import tracemalloc
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
    NOT_CHECKED_PROBE,
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
)
from maljan.reporting.renderers.markdown import MarkdownRenderer

needs_engine = pytest.mark.skipif(not drafts._YARA_AVAILABLE, reason="yara-python is not installed")

FIRST = "gate9.example.org"
SECOND = "relay4.example.net"
NOT_THE_SAMPLE = "c" * 64
BUDGET = 60
SAID = "Run against the sample it was drafted from: "


def _report(
    sha256: str = NOT_THE_SAMPLE,
    names: tuple[str, ...] = (FIRST, SECOND),
    imphash: str | None = None,
) -> MalwareReport:
    """A run that publishes the names a sandbox watched, each a string of the draft."""
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=sha256, imphash=imphash)),
        verdict="Malware",
        malware_category="loader",
        network=NetworkIOCs(domains=[NetworkDomain(fqdn=name, source="sandbox") for name in names]),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


def _drafted(report: MalwareReport, sample: OwnSample | None) -> MalwareReport:
    report.detection_signatures = build_detection_rules(report, sample)
    return report


def _yara(report: MalwareReport, sample: OwnSample | None) -> DetectionRule:
    return next(rule for rule in build_detection_rules(report, sample) if rule.kind == "yara")


def _rule_of(report: MalwareReport) -> DetectionRule:
    return next(rule for rule in report.detection_signatures if rule.kind == "yara")


def _said(report: MalwareReport) -> str:
    """The report's line under the YARA draft that says what its check found."""
    markdown = MarkdownRenderer().render(report)
    return next(
        line for line in markdown.splitlines() if "against the sample it was drafted from" in line
    )


def _slot(rule: DetectionRule, value: str) -> str:
    """A drafted string's identifier, read off the rule's own sources in their order."""
    values = [item.split(":", 2)[2] for item in rule.source_evidence if item.startswith("string:")]
    return f"$s{values.index(value)}"


def _sample(tmp_path: Path, blob: bytes, name: str = "sample.bin") -> Path:
    path = tmp_path / name
    path.write_bytes(blob)
    return path


def _sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _probe_answering(monkeypatch: pytest.MonkeyPatch, probe: Any) -> None:
    """The draft compiles as it does; the probe ruleset compiles to ``probe``."""
    compile_rules = drafts._compile_yara

    def compiling(body: str) -> tuple[Any, str | None]:
        if f"rule {drafts._PROBE_WHOLE}" in body:
            return probe, None
        return compile_rules(body)

    monkeypatch.setattr(drafts, "_compile_yara", compiling)


def _refusal_of_a_nul_path() -> str:
    """The system's own words for a path holding a NUL, which no file can have."""
    try:
        os.stat("sample\x00.bin")
    except ValueError as exc:
        return str(exc)
    raise AssertionError("a path holding a NUL was looked up")


def _engine_imphash(blob: bytes) -> str:
    """The import hash as the engine itself computes it, read through its console module."""
    import yara

    said: list[str] = []
    rules = yara.compile(
        source='import "pe"\nimport "console"\nrule r { condition: console.log(pe.imphash()) }\n',
        includes=False,
    )
    rules.match(data=blob, console_callback=said.append)
    return said[0]


# FIRST in ASCII at 16, SECOND in UTF-16LE at 40: the rule's strings are
# ``ascii wide nocase``, and the engine reads both forms.
BOTH = b"\x00" * 16 + FIRST.encode() + b"\x00" * 7 + SECOND.encode("utf-16-le") + b"\x00" * 8
ONLY_FIRST = b"\x00" * 16 + FIRST.encode() + b"\x00" * 8
NEITHER = b"\x00" * 64


@needs_engine
class TestTheEngineSaysWhichClauseHeld:
    def test_strings_that_hold_are_said_to_match(self, tmp_path: Path) -> None:
        path = _sample(tmp_path, BOTH)
        report = _drafted(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))
        rule = _rule_of(report)

        assert (rule.matches_sample, rule.matched_by) == (True, ["strings"])
        assert {s.identifier: s.offset for s in rule.sample_strings or []} == {
            _slot(rule, FIRST): 16,
            _slot(rule, SECOND): 40,
        }
        said = _said(report)
        assert said.startswith(
            f"{SAID}its strings match it (2 of 2 strings found). "
            "Found in the sample (first match of each): "
        )
        assert f"`{_slot(rule, FIRST)}` at 0x10" in said
        assert f"`{_slot(rule, SECOND)}` at 0x28" in said
        assert "Found nowhere" not in said

    def test_strings_and_the_sha256_holding_together_are_both_said(self, tmp_path: Path) -> None:
        path = _sample(tmp_path, BOTH)
        report = _drafted(
            _report(sha256=_sha256(BOTH)), OwnSample(path=str(path), budget_seconds=BUDGET)
        )

        assert _rule_of(report).matched_by == ["sha256", "strings"]
        assert _said(report).startswith(
            f"{SAID}its strings match it (2 of 2 strings found), and so does its sha256. "
        )

    def test_a_rule_held_by_its_sha256_alone_says_its_strings_do_not(self, tmp_path: Path) -> None:
        path = _sample(tmp_path, NEITHER)
        report = _drafted(
            _report(sha256=_sha256(NEITHER)), OwnSample(path=str(path), budget_seconds=BUDGET)
        )
        rule = _rule_of(report)

        assert (rule.matches_sample, rule.matched_by) == (True, ["sha256"])
        assert [s.offset for s in rule.sample_strings or []] == [None, None]
        assert _said(report) == (
            f"{SAID}the rule matches it by its sha256 only; its strings do not "
            "(0 of 2 strings found). Found nowhere in the sample: `$s0`, `$s1`."
        )

    def test_a_draft_with_no_strings_says_it_declares_none(self, tmp_path: Path) -> None:
        path = _sample(tmp_path, NEITHER)
        report = _drafted(
            _report(sha256=_sha256(NEITHER), names=()),
            OwnSample(path=str(path), budget_seconds=BUDGET),
        )
        rule = _rule_of(report)

        assert (rule.matched_by, rule.sample_strings) == (["sha256"], [])
        assert _said(report) == (
            f"{SAID}the rule matches it by its sha256 only; the draft declares no strings."
        )

    def test_a_rule_that_does_not_match_its_sample_is_kept_and_says_so(
        self, tmp_path: Path
    ) -> None:
        path = _sample(tmp_path, ONLY_FIRST)
        report = _drafted(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))
        rule = _rule_of(report)

        assert (rule.matches_sample, rule.matched_by) == (False, [])
        assert _said(report) == (
            f"{SAID}the rule does not match it (1 of 2 strings found). "
            f"Found in the sample (first match of each): `{_slot(rule, FIRST)}` at 0x10. "
            f"Found nowhere in the sample: `{_slot(rule, SECOND)}`."
        )
        assert rule.body.rstrip() in MarkdownRenderer().render(report), "never dropped"

    def test_the_imphash_clause_is_read_from_the_engine(self, tmp_path: Path) -> None:
        from scripts.rehearsal.sample import sample_bytes

        image = sample_bytes()
        path = _sample(tmp_path, image)
        report = _drafted(
            _report(imphash=_engine_imphash(image)),
            OwnSample(path=str(path), budget_seconds=BUDGET),
        )

        assert _rule_of(report).matched_by == ["imphash"]
        assert _said(report).startswith(
            f"{SAID}the rule matches it by its imphash only; its strings do not "
            "(0 of 2 strings found)."
        )

    def test_the_probe_alone_is_scanned_from_the_file_in_fast_mode_within_the_budget(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _sample(tmp_path, BOTH)
        calls: list[tuple[str, dict[str, Any]]] = []
        compile_rules = drafts._compile_yara

        def spying(body: str) -> tuple[Any, str | None]:
            compiled, error = compile_rules(body)

            class _Spy:
                def match(self, **kwargs: Any) -> Any:
                    calls.append((body, kwargs))
                    return compiled.match(**kwargs)

            return _Spy(), error

        monkeypatch.setattr(drafts, "_compile_yara", spying)
        rule = _yara(_report(), OwnSample(path=str(path), budget_seconds=7))

        assert len(calls) == 1, "the probe ruleset is scanned once, the draft never"
        body, kwargs = calls[0]
        assert f"rule {drafts._PROBE_WHOLE}" in body
        assert kwargs["filepath"] == str(path)
        assert "data" not in kwargs
        assert (kwargs["fast"], kwargs["timeout"]) == (True, 7)
        assert rule.matched_by == ["strings"]

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
        report = _drafted(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))

        html = HtmlRenderer().render(report, nonce="fixed")
        assert "the rule does not match it (1 of 2 strings found)." in html


class TestTheDraftAndItsProbeAreWrittenFromOneDeclaration:
    VALUES = (FIRST, "Global\\MtxQ7", 'a"quote', SECOND, "C:\\Users\\Public\\run.exe")

    def _rendered(self, imphash: str | None = "d" * 32) -> Any:
        return drafts._render_yara(
            rule_name="Maljan_AutoGen_loader",
            sha256=NOT_THE_SAMPLE,
            imphash=imphash,
            strings=[(f"$s{n}", value) for n, value in enumerate(self.VALUES)],
            family="loader",
            verdict="Malware",
            generated_at_iso="2000-01-01T00:00:00+00:00",
        )

    def test_each_probe_string_is_the_draft_s_own_declaration(self) -> None:
        rendered = self._rendered()
        drafted = dict(re.findall(r"^        (\$s\d+) = (.+)$", rendered.draft, re.M))
        probed = dict(
            re.findall(
                r"^rule (probe_string_\d+) \{ strings: \$a = (.+) condition: \$a \}$",
                rendered.probe,
                re.M,
            )
        )

        assert list(probed) == list(rendered.string_rules)
        assert [probed[name] for name in rendered.string_rules] == [
            drafted[f"$s{n}"] for n in range(len(self.VALUES))
        ]

    def test_each_reporter_states_the_draft_s_clause(self) -> None:
        rendered = self._rendered()
        condition = rendered.draft.split("    condition:\n", 1)[1].splitlines()[0].strip()
        reporters = dict(
            re.findall(r"^rule probe_part_(\w+) \{ condition: (.+) \}$", rendered.probe, re.M)
        )
        quantifier = re.search(r"\((\d+|any) of them\)", condition)

        assert rendered.parts == ("sha256", "imphash", "strings")
        assert f"({reporters['sha256']})" in condition
        assert f"({reporters['imphash']})" in condition
        assert quantifier is not None
        assert reporters["strings"] == (
            f"{quantifier.group(1)} of ({', '.join(rendered.string_rules)})"
        )
        assert re.search(
            r"^rule probe_whole \{ condition: \(probe_part_sha256\) or "
            r"\(probe_part_imphash\) or \(probe_part_strings\) \}$",
            rendered.probe,
            re.M,
        )

    def test_the_probe_names_are_no_keyword_and_no_drafted_name(self) -> None:
        keywords = set(
            "all and any ascii at base64 base64wide condition contains defined endswith "
            "entrypoint false filesize for fullword global icontains iendswith iequals import "
            "in include istartswith matches meta nocase none not of or private rule startswith "
            "strings them true wide xor".split()
        )
        names = re.findall(r"^rule (\w+)", self._rendered().probe, re.M)

        assert len(names) == len(set(names)) == len(self.VALUES) + 4
        assert not set(names) & keywords
        assert not [name for name in names if name.startswith("Maljan_AutoGen_")]


@needs_engine
class TestTheProbeAnswersAsTheDraftDoes:
    """A seeded differential: the probe's answer against the literal draft scanned whole."""

    VALUES = (
        "gate9.example.org",
        "relay4.example.net",
        "Global\\MtxQ7",
        "co.co.co",
        "abcabcab",
        "aaaa",
        "C:\\Users\\Public\\run.exe",
        "ab.ab.ab.ab",
        "HKCU\\Software\\Run",
        "xyxyxyx",
    )

    @staticmethod
    def _forms(value: str) -> list[bytes]:
        return [
            value.encode(),
            value.upper().encode(),
            value.encode("utf-16-le"),
            value.swapcase().encode("utf-16-le"),
        ]

    @staticmethod
    def _literal(draft: str, blob: bytes) -> tuple[bool, dict[str, int]]:
        """The draft itself scanned whole, every match listed: for tiny files only."""
        import yara

        held: list[bool] = []
        first: dict[str, int] = {}

        def answer(rule: dict[str, Any]) -> int:
            held.append(bool(rule["matches"]))
            for string in rule["strings"]:
                offsets = [instance.offset for instance in string.instances]
                if offsets:
                    first[string.identifier] = min(offsets)
            return int(yara.CALLBACK_CONTINUE)

        rules = yara.compile(source=draft, includes=False)
        rules.match(data=blob, callback=answer, which_callbacks=yara.CALLBACK_ALL)
        return any(held), first

    def test_the_verdict_clauses_and_every_first_offset_equal_the_draft_s_own_scan(
        self, tmp_path: Path
    ) -> None:
        rng = random.Random(7)
        path = tmp_path / "sample.bin"
        for trial in range(300):
            count = rng.choice((1, 2, 3, 5, 9))
            values = rng.sample(self.VALUES, count)
            chunks: list[bytes] = []
            for _ in range(rng.randint(0, 10)):
                chunks.append(rng.randbytes(rng.randint(0, 40)))
                if rng.random() < 0.7:
                    chunks.append(rng.choice(self._forms(rng.choice(values))))
            blob = b"".join(chunks)
            path.write_bytes(blob)
            sha256 = _sha256(blob) if rng.random() < 0.2 else NOT_THE_SAMPLE
            slots = [f"$s{n}" for n in range(count)]
            rendered = drafts._render_yara(
                rule_name="Maljan_AutoGen_loader",
                sha256=sha256,
                imphash="d" * 32 if rng.random() < 0.3 else None,
                strings=list(zip(slots, values, strict=True)),
                family="loader",
                verdict="Malware",
                generated_at_iso="2000-01-01T00:00:00+00:00",
            )

            check = drafts._run_on_sample(
                rendered, slots, OwnSample(path=str(path), budget_seconds=BUDGET)
            )
            verdict, first = self._literal(rendered.draft, blob)

            where = (trial, values, blob)
            assert check.matches is verdict, where
            assert {s.identifier: s.offset for s in check.strings or []} == {
                slot: first.get(slot) for slot in slots
            }, where
            # Which clauses held, worked out here from the literal scan alone.
            # The engine's hash of an empty range is undefined, so the sha256
            # clause never holds on an empty file.
            quantifier = re.search(r"\((\d+|any) of them\)", rendered.draft)
            assert quantifier is not None
            need = 1 if quantifier.group(1) == "any" else int(quantifier.group(1))
            expected = ["sha256"] if sha256 != NOT_THE_SAMPLE and blob else []
            if len(first) >= need:
                expected.append("strings")
            assert check.matched_by == expected, where


@needs_engine
class TestAHostileSampleCostsOneMatchPerString:
    UNIT = "co."

    def test_at_the_engine_s_limit_the_probe_lists_one_match_per_string(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Five published names, each matching every three bytes of a 3.3 MB
        # body: past the engine's limit of a million matches per string. The
        # literal draft, whose ``2 of them`` lists every match, is never
        # scanned over this file.
        names = tuple((self.UNIT * (k + 2)).rstrip(".") for k in range(5))
        path = _sample(tmp_path, self.UNIT.encode() * 1_100_000, "hostile.bin")
        listed: dict[str, int] = {}
        compile_rules = drafts._compile_yara

        def counting(body: str) -> tuple[Any, str | None]:
            compiled, error = compile_rules(body)
            if compiled is None or f"rule {drafts._PROBE_WHOLE}" not in body:
                return compiled, error

            class _Counting:
                def match(self, **kwargs: Any) -> Any:
                    answer = kwargs["callback"]

                    def counted(rule: dict[str, Any]) -> int:
                        listed[rule["rule"]] = sum(len(s.instances) for s in rule["strings"])
                        return int(answer(rule))

                    return compiled.match(**{**kwargs, "callback": counted})

            return _Counting(), error

        monkeypatch.setattr(drafts, "_compile_yara", counting)
        tracemalloc.start()
        start = time.perf_counter()
        rule = _yara(_report(names=names), OwnSample(path=str(path), budget_seconds=BUDGET))
        took = time.perf_counter() - start
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        per_string = {k: v for k, v in listed.items() if k.startswith(drafts._PROBE_STRING)}
        assert len(per_string) == len(names)
        assert max(per_string.values()) == 1, per_string
        assert rule.matched_by == ["strings"]
        assert [s.offset for s in rule.sample_strings or []] == [0] * len(names)
        assert took < 10, took
        # A scan that listed every match would build millions of match objects.
        assert peak < 32 * 2**20, peak

    def test_ten_times_the_sample_costs_at_most_ten_times(self, tmp_path: Path) -> None:
        def took(repeats: int) -> tuple[float, DetectionRule]:
            path = _sample(
                tmp_path, (FIRST + " ").encode() * repeats + SECOND.encode(), f"{repeats}.bin"
            )
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
        }


class TestARuleNotCheckedSaysWhy:
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
                lambda tmp: OwnSample(path=f"{tmp}/sample\x00.bin", budget_seconds=BUDGET),
                NOT_CHECKED_UNREAD.format(why=_refusal_of_a_nul_path()),
            ),
            (
                lambda tmp: OwnSample(path=str(_sample(tmp, BOTH)), budget_seconds=None),
                NOT_CHECKED_NO_BUDGET,
            ),
        ],
    )
    def test_without_a_readable_sample(self, tmp_path: Path, make: Any, reason: str) -> None:
        report = _drafted(_report(), make(tmp_path))
        rule = _rule_of(report)

        assert rule.sample_not_checked == reason
        assert (rule.matches_sample, rule.matched_by, rule.sample_strings) == (None, None, None)
        assert rule.compile_error is None
        assert str(tmp_path) not in reason
        assert _said(report) == f"Not run against the sample it was drafted from: {reason}."

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
        broken = drafts._YaraSources(
            draft="rule broken {\n", probe="", string_rules=(), parts=("sha256",)
        )
        monkeypatch.setattr(drafts, "_render_yara", lambda **_kwargs: broken)
        path = _sample(tmp_path, BOTH)
        rule = _yara(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))

        assert (rule.compile_error or "").startswith("yara.compile failed")
        assert rule.sample_not_checked == NOT_CHECKED_UNCOMPILED

    @needs_engine
    def test_an_include_is_refused_by_the_engine_and_names_no_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        included = tmp_path / "included.yar"
        included.write_text("rule elsewhere { condition: true }\n")
        source = f'include "{included}"\nrule here {{ condition: true }}\n'

        compiled, error = drafts._compile_yara(source)
        assert compiled is None
        assert "includes are disabled" in (error or "")
        assert str(tmp_path) not in (error or "")

        sources = drafts._YaraSources(
            draft=source, probe=source, string_rules=(), parts=("sha256",)
        )
        monkeypatch.setattr(drafts, "_render_yara", lambda **_kwargs: sources)
        path = _sample(tmp_path, BOTH)
        rule = _yara(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))

        assert "includes are disabled" in (rule.compile_error or "")
        assert rule.sample_not_checked == NOT_CHECKED_UNCOMPILED
        assert str(tmp_path) not in f"{rule.compile_error} {rule.sample_not_checked}"

    @needs_engine
    def test_a_probe_that_did_not_compile(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        compile_rules = drafts._compile_yara

        def compiling(body: str) -> tuple[Any, str | None]:
            if f"rule {drafts._PROBE_WHOLE}" in body:
                return None, "yara.compile failed: line 3: syntax error"
            return compile_rules(body)

        monkeypatch.setattr(drafts, "_compile_yara", compiling)
        path = _sample(tmp_path, BOTH)
        rule = _yara(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))

        assert rule.compile_error is None
        assert rule.sample_not_checked == NOT_CHECKED_PROBE.format(
            why="yara.compile failed: line 3: syntax error"
        )

    @needs_engine
    def test_a_scan_past_its_budget(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import yara

        class _Slow:
            def match(self, **_kwargs: Any) -> Any:
                raise yara.TimeoutError("scanning timed out")

        _probe_answering(monkeypatch, _Slow())
        path = _sample(tmp_path, BOTH)
        rule = _yara(_report(), OwnSample(path=str(path), budget_seconds=7))

        assert rule.sample_not_checked == NOT_CHECKED_TIMED_OUT.format(seconds=7)
        assert "7 s (core.static.yara.timeout_seconds)" in rule.sample_not_checked

    @needs_engine
    @pytest.mark.parametrize(
        ("message", "reason"),
        [
            (
                'could not open file "{path}"',
                NOT_CHECKED_UNREAD.format(why="the engine could not open it"),
            ),
            (
                'could not map file "{path}" into memory',
                NOT_CHECKED_UNREAD.format(why="the engine could not map it into memory"),
            ),
            (
                'internal error near "{path}"',
                NOT_CHECKED_REFUSED.format(why="Error: internal error near the sample"),
            ),
            ("internal error: 30", NOT_CHECKED_REFUSED.format(why="Error: internal error: 30")),
        ],
    )
    def test_an_engine_refusal_never_names_the_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, message: str, reason: str
    ) -> None:
        import yara

        path = _sample(tmp_path, BOTH)

        class _Refusing:
            def match(self, **_kwargs: Any) -> Any:
                raise yara.Error(message.format(path=path))

        _probe_answering(monkeypatch, _Refusing())
        rule = _yara(_report(), OwnSample(path=str(path), budget_seconds=BUDGET))

        assert rule.sample_not_checked == reason
        assert str(path) not in reason

    @needs_engine
    def test_an_engine_that_gives_no_answer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Silent:
            def match(self, **_kwargs: Any) -> Any:
                return []

        _probe_answering(monkeypatch, _Silent())
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
            suricata.matched_by,
            suricata.sample_strings,
            suricata.sample_not_checked,
        ) == (None, None, None, None)
        dumped = suricata.model_dump(mode="json")
        assert not {
            "matches_sample",
            "matched_by",
            "sample_strings",
            "sample_not_checked",
        } & set(dumped)


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
    async def test_the_node_checks_the_draft_on_the_file_it_read(self, tmp_path: Path) -> None:
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

        def _spy(rendered: Any, slots: list[str], sample: OwnSample | None) -> Any:
            handed.append(sample)
            return run_on_sample(rendered, slots, sample)

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
        # The builder read the file's own sha256, and the run published no
        # string: the draft holds by its sha256 alone, and says so.
        assert (yara_rule["matches_sample"], yara_rule["matched_by"]) == (True, ["sha256"])
        assert yara_rule["sample_strings"] == []
