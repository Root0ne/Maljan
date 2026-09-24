"""The pack renders as one line of facts per entry, ids in front, cut with a count.

What every agent reads is this block, so what is pinned is its shape: the
heading that tells the model to cite, one ``[ev_id] group: facts`` line per
entry in ledger order, the failure entries named as failures, the cut that
says how many entries it left out, and the two places the reputation answer
can come from rendered as the counts and labels they carry.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from maljan.pipeline.triage_pack import (
    PACK_HEADING,
    PIPELINE,
    pack_block,
    pack_entries,
    render_pack,
)
from maljan.schemas.evidence import build_entry, format_entry_id

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ledger"


def _entry(
    tool: str,
    payload: Any = None,
    *,
    seq: int = 1,
    agent: str = PIPELINE,
    server: str | None = PIPELINE,
    ok: bool = True,
    error: str | None = None,
) -> Any:
    if payload is None:
        payload = json.loads((_FIXTURES / f"{tool}.json").read_text(encoding="utf-8"))
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent=agent,
        tool=tool,
        args={},
        server=server,
        output=payload if isinstance(payload, str) else json.dumps(payload),
        ok=ok,
        error=error,
        stage="triage_pack",
    )


VT_ANSWER = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 31, "undetected": 40, "harmless": 4},
            "popular_threat_classification": {
                "suggested_threat_label": "trojan.filisto/agent",
                "popular_threat_name": [{"value": "Filisto", "count": 12}],
            },
        }
    }
}


class TestWhichEntriesArePack:
    def test_the_pipeline_s_entries_are_picked_out_of_the_ledger_in_order(self) -> None:
        rows = [
            _entry("identify_file", seq=2).model_dump(mode="json"),
            _entry("pe_info", seq=5, agent="static", server=None).model_dump(mode="json"),
            _entry("hashes", seq=1).model_dump(mode="json"),
        ]
        assert [e.id for e in pack_entries(rows)] == ["ev_0001", "ev_0002"]

    def test_the_reputation_call_counts_although_it_carries_its_server(self) -> None:
        rows = [
            _entry("get_file_report", VT_ANSWER, seq=3, server="virustotal").model_dump(mode="json")
        ]
        assert [e.tool for e in pack_entries(rows)] == ["get_file_report"]

    def test_an_unreadable_row_is_left_out_rather_than_raised(self) -> None:
        assert pack_entries([{"id": 5}, "junk", None]) == []


class TestTheLines:
    def test_identity_hashes_and_signature_lead(self) -> None:
        lines = render_pack(
            [
                _entry("identify_file", seq=1),
                _entry("hashes", seq=2),
                _entry(
                    "signing_info",
                    {
                        "format": "pe",
                        "authenticode": {
                            "present": True,
                            "subject": "Simon Tatham",
                            "issuer": "Sectigo",
                        },
                    },
                    seq=3,
                ),
            ],
            0,
        ).splitlines()
        assert lines[0].startswith("[ev_0001] identity: ")
        assert "bytes" in lines[0]
        assert lines[1].startswith("[ev_0002] hashes: sha256 ")
        assert lines[2] == (
            "[ev_0003] signature: authenticode present (subject Simon Tatham, issuer Sectigo)"
        )

    def test_every_digest_is_printed_whole(self) -> None:
        """A 16-character prefix was copied out as an MD5 indicator and refused."""
        digests = {
            "sha256": "6" * 64,
            "md5": "7" * 32,
            "sha1": "e" * 40,
            "imphash": "d" * 32,
            "ssdeep": "3072:" + "A" * 60 + ":" + "B" * 30,
        }
        line = render_pack([_entry("hashes", digests, seq=1)], 0)

        for key, value in digests.items():
            assert f"{key} {value}" in line
        assert "…" not in line

    def test_no_signature_is_said_as_none(self) -> None:
        payload = {"format": "pe", "authenticode": {"present": False}}
        assert render_pack([_entry("signing_info", payload)], 0) == "[ev_0001] signature: none"

    def test_a_format_with_no_signing_scheme_is_not_said_as_unsigned(self) -> None:
        """ "None" reads as "this one is not signed", which is a different fact."""
        payload = {"format": "elf", "applicable": False}
        assert render_pack([_entry("signing_info", payload)], 0) == (
            "[ev_0001] signature: no code-signing scheme for this format"
        )

    def test_a_report_recorded_before_the_tool_answered_once_still_renders(self) -> None:
        payload = {
            "authenticode": {"present": False},
            "apk": {"present": True, "schemes": ["v2"]},
            "macho": {"present": False},
        }
        assert render_pack([_entry("signing_info", payload)], 0) == "[ev_0001] signature: apk v2"

    def test_capa_carries_its_rule_asserted_technique_ids(self) -> None:
        payload = {
            "capabilities": [
                {"rule": "inject into process", "attck": "Privilege Escalation::x [T1055.001]"},
                {"rule": "obfuscated", "attck": "T1027"},
                {"rule": "no mapping", "attck": ""},
            ],
            "meta": {},
        }
        line = render_pack([_entry("capa", payload)], 0)
        assert line.startswith("[ev_0001] capa: 3 capabilities (")
        assert "ATT&CK T1055.001, T1027 (rule-asserted)" in line

    def test_yara_names_its_hits(self) -> None:
        payload = {"matches": [{"rule": "web_c2"}, {"rule": "upx_packed"}], "rule_count": 30}
        assert (
            render_pack([_entry("yara_scan", payload)], 0)
            == "[ev_0001] yara: 2 hits of 30 rules (web_c2, upx_packed)"
        )

    def test_the_fixture_answers_all_render_to_one_line_each(self) -> None:
        entries = [
            _entry(tool, seq=index + 1)
            for index, tool in enumerate(
                ("identify_file", "hashes", "pe_info", "strings", "iocs_from_file", "yara_scan")
            )
        ]
        lines = render_pack(entries, 0).splitlines()
        assert len(lines) == 6
        assert [line.split("]")[0] + "]" for line in lines] == [e.id.join("[]") for e in entries]
        assert not any("\n" in line for line in lines)

    def test_a_failed_entry_is_named_as_a_failure(self) -> None:
        entry = _entry(
            "capa", "RuntimeError: capa produced no result", ok=False, error="RuntimeError: no"
        )
        assert render_pack([entry], 0) == "[ev_0001] capa: failed (RuntimeError: no)"

    def test_the_virustotal_answer_is_read_for_its_counts_and_labels(self) -> None:
        entry = _entry("get_file_report", VT_ANSWER, server="virustotal")
        assert render_pack([entry], 0) == (
            "[ev_0001] reputation: VirusTotal: 31 of 75 engines flag it as malicious, "
            "labels trojan.filisto/agent, Filisto"
        )

    def test_no_detection_is_said_in_words_and_not_as_a_fraction(self) -> None:
        """ "0/75 malicious" was turned by a report model into "clean by 75/75 engines"."""
        answer = {
            "data": {
                "last_analysis_stats": {"malicious": 0, "undetected": 71, "type-unsupported": 4}
            }
        }
        entry = _entry("get_file_report", answer, server="virustotal")

        line = render_pack([entry], 0)

        assert line == "[ev_0001] reputation: VirusTotal: 0 of 75 engines flag it as malicious"
        assert "/75" not in line

    def test_the_detection_labels_the_answer_carries_are_stated_with_their_counts(
        self,
    ) -> None:
        """A recorded answer that carries ``detections`` and no popular classification.

        Its labels are stated with how many engines gave each, most first and
        then in the order the answer lists them, bounded, with the number of
        distinct labels left out. The line counts; it does not decide.
        """
        entry = _entry("get_file_report", seq=17, server="virustotal")

        line = render_pack([entry], 0)

        assert line.startswith(
            "[ev_0017] reputation: VirusTotal: 52 of 75 engines flag it as malicious, "
            "52 detection labels, "
            "47 distinct (engines per label, most first, 20 shown): "
            "Gen:Variant.Ulise.482338 ×4, Trojan ( 005ef6721 ) ×2, Troj/Loader-CB ×2, "
            "W32.Malware.D0BC8737 ×1, Trojan.Win32.Latrodectus.m!c ×1, "
        )
        assert line.endswith("(+27 more distinct labels)")
        shown = line.split(": ", 2)[2].rsplit(" (+", 1)[0]
        assert len(shown.split(" ×")) - 1 == 20

    def test_every_label_is_shown_when_they_fit_the_bound(self) -> None:
        answer = {
            "data": {
                "detections": ["Trojan.Example", "Trojan.Example", "Other.Label"],
                "last_analysis_stats": {"malicious": 3, "undetected": 7},
            }
        }
        entry = _entry("get_file_report", answer, server="virustotal")

        assert render_pack([entry], 0) == (
            "[ev_0001] reputation: VirusTotal: 3 of 10 engines flag it as malicious, "
            "3 detection labels, "
            "2 distinct (engines per label, most first): Trojan.Example ×2, Other.Label ×1"
        )

    def test_each_label_is_bounded_as_well_as_their_number(self) -> None:
        long_label = "Trojan." + "x" * 500
        answer = {
            "data": {
                "detections": [long_label, long_label],
                "last_analysis_stats": {"malicious": 2, "undetected": 8},
            }
        }
        line = render_pack([_entry("get_file_report", answer, server="virustotal")], 0)

        shown = line.split("most first): ", 1)[1]
        assert shown.endswith("… ×2")
        assert len(shown) == 80 + len(" ×2")

    def test_the_threat_intel_prose_is_read_for_its_count(self) -> None:
        entry = _entry(
            "check_hash",
            "Hash abc identified as Ransomware (LockBit) with 55/70 detections.",
            server="threatintel",
        )
        line = render_pack([entry], 0)
        assert line.startswith("[ev_0001] reputation: threatintel 55 malicious (")

    def test_a_skipped_reputation_says_why(self) -> None:
        entry = _entry(
            "reputation",
            "no reputation server is enabled",
            ok=False,
            error="not run: no reputation server is enabled (virustotal, threatintel)",
        )
        # A call the pipeline did not make is not a failure and is not called one.
        assert render_pack([entry], 0).startswith(
            "[ev_0001] reputation: not done (not run: no reputation"
        )

    def test_a_reputation_lookup_that_was_made_and_broke_says_failed(self) -> None:
        entry = _entry(
            "reputation",
            "TimeoutError: the server did not answer",
            ok=False,
            error="TimeoutError: the server did not answer",
        )
        line = render_pack([entry], 0)
        assert line.startswith("[ev_0001] reputation: failed (TimeoutError")
        assert "not done" not in line

    def test_a_step_the_budget_stopped_is_not_done_either(self) -> None:
        entry = _entry(
            "capa",
            "not run: the pack's budget of 1200 s was spent before this step",
            ok=False,
            error="not run: the pack's budget of 1200 s was spent before this step",
        )
        assert render_pack([entry], 0).startswith("[ev_0001] capa: not done (not run:")

    def test_a_tool_the_renderer_does_not_know_still_gets_its_line(self) -> None:
        entry = _entry("some_new_tool", {"rows": [1, 2]})
        assert render_pack([entry], 0) == '[ev_0001] some_new_tool: {"rows": [1, 2]}'


class TestTheCut:
    def _many(self, n: int) -> list[Any]:
        payload = {"matches": [{"rule": f"rule_{i}"} for i in range(4)], "rule_count": 30}
        return [_entry("yara_scan", payload, seq=i + 1) for i in range(n)]

    def test_a_block_that_fits_is_not_cut(self) -> None:
        text = render_pack(self._many(3), 10_000)
        assert text.count("\n") == 2
        assert "not shown" not in text

    def test_a_cut_block_ends_with_what_it_left_out(self) -> None:
        entries = self._many(12)
        text = render_pack(entries, 300)
        lines = text.splitlines()
        assert len(text) <= 300
        shown = len(lines) - 1
        assert lines[-1] == (
            f"{12 - shown} more pack entries not shown here; every entry's full output is "
            "reachable by tool call."
        )
        assert lines[0].startswith("[ev_0001]")

    def test_one_entry_left_out_is_said_in_the_singular(self) -> None:
        entries = self._many(2)
        one_line = len(render_pack(entries[:1], 0))
        text = render_pack(entries, one_line + 20)
        assert text.splitlines()[-1].startswith("1 more pack entry not shown here")

    def test_the_first_line_is_always_kept(self) -> None:
        text = render_pack(self._many(2), 10)
        assert text.splitlines()[0].startswith("[ev_0001]")

    def test_the_block_has_its_heading_and_none_without_entries(self) -> None:
        block = pack_block(self._many(1), 1000)
        assert block.startswith(PACK_HEADING + "\n[ev_0001] yara: ")
        assert "cite them" in PACK_HEADING
        assert pack_block([], 1000) == ""


class TestABudgetTrimmedEntry:
    def test_it_says_the_output_was_dropped_rather_than_recorded(self) -> None:
        from maljan.schemas.evidence import apply_budget

        entry = _entry("capa", '{"capabilities": [{"rule": "x"}]}')
        apply_budget([entry], 1)
        assert entry.truncated and entry.output == ""
        line = render_pack([entry], 0)
        assert line == "[ev_0001] capa: output dropped (evidence byte budget); call the tool for it"
