"""Unit tests for the Wave 4 post-pipeline FP linter."""

from __future__ import annotations

from types import SimpleNamespace

from maljan.qa.fp_linter import lint_report


def _ns(**kw):  # type: ignore[no-untyped-def]
    return SimpleNamespace(**kw)


def _stub_report(
    *,
    capability_matrix=None,
    defensive_recommendations=None,
    executive_summary="",
    attribution=None,
    stix_bundle_extended=None,
    run_summary=None,
):
    return _ns(
        capability_matrix=capability_matrix or [],
        defensive_recommendations=defensive_recommendations or [],
        executive_summary=executive_summary,
        attribution=attribution,
        stix_bundle_extended=stix_bundle_extended,
        run_summary=run_summary or {},
    )


# ---------------------------------------------------------------------------
# Empty / clean report
# ---------------------------------------------------------------------------


class TestCleanReport:
    def test_empty_report_no_warnings(self) -> None:
        assert lint_report(_stub_report(), "android") == []

    def test_unknown_platform_skips_some_rules(self) -> None:
        # Ungrounded family still warns regardless of platform.
        report = _stub_report(
            attribution=_ns(family="rat", family_grounded=False),
        )
        warns = lint_report(report, "unknown")
        rules = {w.rule for w in warns}
        assert rules == {"C5"}


# ---------------------------------------------------------------------------
# C2 — defense recommendations citing unknown TTPs
# ---------------------------------------------------------------------------


class TestRuleC2:
    def test_warns_when_recommendation_cites_missing_ttp(self) -> None:
        report = _stub_report(
            capability_matrix=[_ns(technique_id="T1497")],
            defensive_recommendations=[
                _ns(action="Block PowerShell (T1059.001)", rationale="x", category="y"),
            ],
        )
        warns = lint_report(report, "linux")
        c2 = [w for w in warns if w.rule == "C2"]
        assert len(c2) == 1
        assert "T1059.001" in c2[0].message

    def test_no_warning_when_recommendation_ttp_present(self) -> None:
        report = _stub_report(
            capability_matrix=[_ns(technique_id="T1497")],
            defensive_recommendations=[
                _ns(action="Anti-emulation telemetry (T1497)", rationale="r", category="c"),
            ],
        )
        warns = lint_report(report, "linux")
        assert not any(w.rule == "C2" for w in warns)


# ---------------------------------------------------------------------------
# C3 — exec summary mentioning platform-incompatible concepts
# ---------------------------------------------------------------------------


class TestRuleC3:
    def test_linux_with_powershell_mention(self) -> None:
        # PowerShell is implausible on a Linux sample -> C3.
        report = _stub_report(
            executive_summary="The sample uses powershell to escalate privileges.",
        )
        warns = lint_report(report, "linux")
        rules = {w.rule for w in warns}
        assert "C3" in rules

    def test_linux_with_azure_mention(self) -> None:
        # Cloud (Azure) concepts are implausible on a Linux endpoint sample -> C3.
        report = _stub_report(
            executive_summary="Authenticates to Azure to exfiltrate data.",
        )
        warns = lint_report(report, "linux")
        assert any(w.rule == "C3" for w in warns)

    def test_windows_with_powershell_mention_not_flagged(self) -> None:
        report = _stub_report(
            executive_summary="Uses powershell for execution.",
        )
        warns = lint_report(report, "windows")
        assert not any(w.rule == "C3" for w in warns)


# ---------------------------------------------------------------------------
# C4 — file:name indicator overflow
# ---------------------------------------------------------------------------


class TestRuleC4:
    def test_overflow_triggers_warning(self) -> None:
        # 11 file:name indicators (cap is 10).
        objs = [{"type": "indicator", "pattern": f"[file:name = 'p{i}.exe']"} for i in range(11)]
        report = _stub_report(stix_bundle_extended={"objects": objs})
        warns = lint_report(report, "linux")
        assert any(w.rule == "C4" for w in warns)

    def test_at_threshold_not_flagged(self) -> None:
        objs = [{"type": "indicator", "pattern": f"[file:name = 'p{i}.exe']"} for i in range(10)]
        report = _stub_report(stix_bundle_extended={"objects": objs})
        warns = lint_report(report, "linux")
        assert not any(w.rule == "C4" for w in warns)


# ---------------------------------------------------------------------------
# C5 — ungrounded family
# ---------------------------------------------------------------------------


class TestRuleC5:
    def test_ungrounded_family_triggers_warning(self) -> None:
        report = _stub_report(
            attribution=_ns(family="rat", family_grounded=False),
        )
        warns = lint_report(report, "linux")
        c5 = [w for w in warns if w.rule == "C5"]
        assert len(c5) == 1
        assert "rat" in c5[0].message

    def test_grounded_family_no_warning(self) -> None:
        report = _stub_report(
            attribution=_ns(family="emotet", family_grounded=True),
        )
        warns = lint_report(report, "linux")
        assert not any(w.rule == "C5" for w in warns)

    def test_no_family_no_warning(self) -> None:
        report = _stub_report(
            attribution=_ns(family=None, family_grounded=True),
        )
        warns = lint_report(report, "linux")
        assert not any(w.rule == "C5" for w in warns)


# ---------------------------------------------------------------------------
# Wave 9 — FPWarning.explanation populated
# ---------------------------------------------------------------------------


class TestExplanationField:
    """Every emitted FPWarning must carry a non-empty explanation."""

    def test_c2_includes_explanation(self) -> None:
        report = _stub_report(
            capability_matrix=[_ns(technique_id="T1497")],
            defensive_recommendations=[
                _ns(action="Block PowerShell (T1059.001)", rationale="x", category="y"),
            ],
        )
        warns = lint_report(report, "linux")
        c2 = [w for w in warns if w.rule == "C2"]
        assert c2 and all(w.explanation for w in c2)

    def test_c3_includes_explanation(self) -> None:
        report = _stub_report(
            executive_summary="The sample uses powershell to escalate.",
        )
        warns = lint_report(report, "linux")
        c3 = [w for w in warns if w.rule == "C3"]
        assert c3 and all(w.explanation for w in c3)

    def test_c4_includes_explanation(self) -> None:
        objs = [{"type": "indicator", "pattern": f"[file:name = 'p{i}.exe']"} for i in range(11)]
        report = _stub_report(stix_bundle_extended={"objects": objs})
        warns = lint_report(report, "linux")
        c4 = [w for w in warns if w.rule == "C4"]
        assert c4 and all(w.explanation for w in c4)

    def test_c5_includes_explanation(self) -> None:
        report = _stub_report(attribution=_ns(family="rat", family_grounded=False))
        warns = lint_report(report, "linux")
        c5 = [w for w in warns if w.rule == "C5"]
        assert len(c5) == 1
        assert c5[0].explanation
        assert "D11" in c5[0].explanation


# ---------------------------------------------------------------------------
# Wave 9 — total-indicator cap branch of C4
# ---------------------------------------------------------------------------


class TestRuleC4Total:
    def test_total_overflow_triggers_warning(self) -> None:
        # 16 indicators of various kinds (cap is 15).
        objs = [
            {"type": "indicator", "pattern": f"[file:hashes.'SHA-256' = 'h{i}']"} for i in range(4)
        ]
        objs += [
            {"type": "indicator", "pattern": f"[domain-name:value = 'd{i}.test']"} for i in range(2)
        ]
        objs += [{"type": "indicator", "pattern": f"[file:name = 'p{i}.exe']"} for i in range(10)]
        report = _stub_report(stix_bundle_extended={"objects": objs})
        warns = lint_report(report, "linux")
        # Expect a C4 with the "total" wording (and the file:name C4 may also fire at >10).
        total_msgs = [w for w in warns if w.rule == "C4" and "total" in w.message]
        assert total_msgs, "expected total-indicator C4 warning"


# ---------------------------------------------------------------------------
# Wave 9 — C6 platform_filter_summary
# ---------------------------------------------------------------------------


class TestRuleC6:
    def test_missing_platform_filter_summary_warns(self) -> None:
        # Cascade dict exists (evidence) but no platform_filter_summary.
        report = _stub_report(
            capability_matrix=[_ns(technique_id="T1497", platforms=None)],
            run_summary={"cascade": {}},
        )
        warns = lint_report(report, "linux")
        c6 = [w for w in warns if w.rule == "C6"]
        assert len(c6) == 1
        assert "platform_filter_summary" in c6[0].message
        assert c6[0].explanation

    def test_zero_drops_warns(self) -> None:
        report = _stub_report(
            run_summary={
                "cascade": {
                    "platform_filter_summary": {
                        "sigma_dropped": 0,
                        "yara_dropped": 0,
                        "sample_platform": "linux",
                    }
                }
            }
        )
        warns = lint_report(report, "linux")
        c6 = [w for w in warns if w.rule == "C6"]
        assert len(c6) == 1
        assert "dropped 0 rules" in c6[0].message

    def test_nonzero_drops_no_warning(self) -> None:
        report = _stub_report(
            run_summary={
                "cascade": {
                    "platform_filter_summary": {
                        "sigma_dropped": 12,
                        "yara_dropped": 0,
                        "sample_platform": "linux",
                    }
                }
            }
        )
        warns = lint_report(report, "linux")
        assert not any(w.rule == "C6" for w in warns)

    def test_unknown_platform_skips_c6(self) -> None:
        # No platform → cannot validate, so skip.
        report = _stub_report(run_summary={})
        warns = lint_report(report, "unknown")
        assert not any(w.rule == "C6" for w in warns)
