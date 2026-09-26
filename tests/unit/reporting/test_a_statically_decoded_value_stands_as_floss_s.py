"""An indicator the static decoder read out of the file's bytes stands where FLOSS's would.

``decode_string_blobs`` undoes the simple encodings a sample keeps its text
under, by arithmetic over the file's bytes, and states each result's file
offset, scheme and the functions around the code that uses it. A domain, an
address or a URL the existing parsers read in such a text is hidden text the
platform itself recovered, the same kind of fact as a FLOSS decoded string, so
the one publish rule reads it through the same record (``emulated_strings``),
with the same standing and the same refusals. The decoder's provenance rides
along: the rule's reason names the tool and its entry, and the IOC table and
the report state which tool recovered the value and where. A decoded text that
holds no indicator stays a decoded string fact and is no candidate.

Every value here is synthetic: example names and a documentation address.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.builder import build_consolidated_iocs
from maljan.reporting.models import (
    EmulatedStrings,
    EvidenceIndexRow,
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    SampleIdentity,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.reporting.renderers.stix_renderer import (
    DECODED_FROM_THE_BYTES,
    RECOVERED_BY_EMULATION,
    ExtendedSTIXRenderer,
    decoded_indicators,
    emulation_from_ledger,
    emulation_kwargs,
    indicator_publish_reason,
    recovered_by_words,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.stix_models import Bundle

C2 = "relay7.example.net"
C2_URL = f"https://{C2}/gate/"
DOC_ADDRESS = "192.0.2.44"
FLOSS_ENTRY = "ev_0012"
DECODER_ENTRY = "ev_0020"


def _decoder_row(
    text: str, *, scheme: str = "xor8", offset: str = "0xfd30", **extra: Any
) -> dict[str, Any]:
    return {
        "offset": offset,
        "rva": "0x11930",
        "text_rva": "0x11930",
        "section": ".data",
        "scheme": scheme,
        "parameters": {"key": "0x5a"},
        "text": text,
        "encoding": "ascii",
        "references": [
            {"at": "0x1a2b", "section": ".text", "function": "0x1a00"},
            {"at": "0x1c40", "section": ".text", "function": None},
        ],
        **extra,
    }


def _decoder_entry(*rows: dict[str, Any], entry: str = DECODER_ENTRY, **page: Any) -> LedgerEntry:
    return LedgerEntry(
        id=entry,
        agent="pipeline",
        tool="decode_string_blobs",
        structured={
            "tool": "decode_string_blobs",
            "results": list(rows),
            "total": len(rows),
            "page_offset": 0,
            "next_offset": None,
            **page,
        },
    )


def _floss_entry(*strings: str, entry: str = FLOSS_ENTRY) -> LedgerEntry:
    rows = [
        {"kind": "decoded", "string": text, "encoding": "ASCII", "function_rva": "0x1a00"}
        for text in strings
    ]
    return LedgerEntry(
        id=entry,
        agent="pipeline",
        tool="floss",
        structured={"total": len(rows), "strings": rows, "truncated": False},
    )


def _strings_entry(*texts: str) -> LedgerEntry:
    rows = [{"enc": "ascii", "text": text, "offset": 16 * i} for i, text in enumerate(texts)]
    return LedgerEntry(
        id="ev_0005",
        agent="pipeline",
        tool="strings",
        structured={"total": len(rows), "strings": rows, "truncated": False},
    )


def _report(
    ledger: list[LedgerEntry],
    *indicators: tuple[str, str],
    verdict: str = "Malware",
) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict=verdict,
        malware_category="loader",
        overall_confidence=0.8,
        evidence_index=[
            EvidenceIndexRow(id=e.id, agent="pipeline", tool=e.tool, ok=True) for e in ledger
        ],
        judge_indicators=[JudgeIndicator(kind=kind, value=value) for kind, value in indicators],
        emulated_strings=emulation_from_ledger(ledger),
    )


def _row(report: MalwareReport, value: str) -> Any:
    (row,) = [r for r in build_consolidated_iocs(report) if r.value == value]
    return row


def _exported(report: MalwareReport) -> str:
    """The export, with the judge's bundle naming the report's judge values as domains."""
    bundle = Bundle.model_validate(
        {
            "objects": [
                {
                    "type": "indicator",
                    "id": f"indicator--0f1e2d3c-4b5a-4968-8776-65544333221{i}",
                    "pattern": f"[domain-name:value = '{item.value}']",
                    "pattern_type": "stix",
                    "indicator_types": ["malicious-activity"],
                }
                for i, item in enumerate(report.judge_indicators)
                if item.kind == "domain"
            ]
        }
    )
    return str(ExtendedSTIXRenderer().render(report, bundle).model_dump(mode="json"))


def _as_floss(answer: str) -> str:
    """A decoder answer in the words the same answer for a FLOSS value is written in."""
    return answer.replace(
        f"{DECODED_FROM_THE_BYTES}, {DECODER_ENTRY}", f"{RECOVERED_BY_EMULATION}, {FLOSS_ENTRY}"
    )


def _decoded(text: str, *indicators: tuple[str, str], **kw: Any) -> MalwareReport:
    return _report([_strings_entry("x"), _decoder_entry(_decoder_row(text))], *indicators, **kw)


def _floss(text: str, *indicators: tuple[str, str], **kw: Any) -> MalwareReport:
    return _report([_strings_entry("x"), _floss_entry(text)], *indicators, **kw)


class TestADecodedDomain:
    def test_is_a_candidate_with_its_provenance(self) -> None:
        record = emulation_from_ledger([_strings_entry("x"), _decoder_entry(_decoder_row(C2))])

        assert record.values == {C2: DECODER_ENTRY}
        (how,) = record.recovered_by[C2]
        assert how.tool == "decode_string_blobs" and how.entry == DECODER_ENTRY
        assert how.scheme == "xor8" and how.offset == "0xfd30"
        assert how.functions == ["0x1a00"] and how.sites == ["0x1a2b", "0x1c40"]
        assert record.partial == ""

    def test_publishes_exactly_as_the_same_floss_value(self) -> None:
        decoded, floss = _decoded(C2, ("domain", C2)), _floss(C2, ("domain", C2))

        assert _row(decoded, C2).published == _row(floss, C2).published == "yes"
        assert C2 in _exported(decoded) and C2 in _exported(floss)
        assert indicator_publish_reason(
            "domain", C2, "strings", **emulation_kwargs(decoded, "domain", C2)
        ) == (f"{DECODED_FROM_THE_BYTES}, {DECODER_ENTRY}")

    def test_the_table_and_the_report_state_the_tool_and_where(self) -> None:
        report = _decoded(C2, ("domain", C2))

        said = _row(report, C2).recovered_by
        assert said == (
            f"decode_string_blobs, {DECODER_ENTRY} (xor8, at file offset 0xfd30, "
            "in function 0x1a00, used at 0x1a2b, 0x1c40)"
        )
        assert f"recovered by {said}" in MarkdownRenderer().render(report)

    def test_a_benign_verdict_refuses_it_in_the_floss_value_s_words(self) -> None:
        decoded = _decoded(C2, ("domain", C2), verdict="Benign")
        floss = _floss(C2, ("domain", C2), verdict="Benign")

        answer = str(_row(decoded, C2).published)
        assert answer.startswith(f"no: {DECODED_FROM_THE_BYTES}, {DECODER_ENTRY}, but the verdict")
        assert _as_floss(answer) == _row(floss, C2).published
        assert C2 not in _exported(decoded)


class TestADecodedDocumentationAddress:
    def test_is_a_candidate_and_is_refused_as_the_floss_value_is(self) -> None:
        text = f"{DOC_ADDRESS}:8443"
        decoded = _decoded(text, ("ip", DOC_ADDRESS))
        floss = _floss(DOC_ADDRESS, ("ip", DOC_ADDRESS))

        record = decoded.emulated_strings
        assert record is not None and record.values[DOC_ADDRESS] == DECODER_ENTRY
        assert record.recovered_by[DOC_ADDRESS][0].offset == "0xfd30"
        assert _row(decoded, DOC_ADDRESS).published == _row(floss, DOC_ADDRESS).published
        assert str(_row(decoded, DOC_ADDRESS).published).startswith("no:")


class TestADecodedUrl:
    def test_under_a_base64_layer_is_a_candidate_with_both_schemes(self) -> None:
        row = _decoder_row(
            "aHR0cHM6Ly9yZWxheTcuZXhhbXBsZS5uZXQvZ2F0ZS8=",
            layers=[{"scheme": "base64", "text": C2_URL}],
        )
        record = emulation_from_ledger([_strings_entry("x"), _decoder_entry(row)])

        assert record.values[C2_URL] == DECODER_ENTRY and record.values[C2] == DECODER_ENTRY
        assert record.recovered_by[C2_URL][0].scheme == "xor8+base64"

    def test_publishes_exactly_as_the_same_floss_url(self) -> None:
        decoded = _decoded(C2_URL, ("url", C2_URL))
        floss = _floss(C2_URL, ("url", C2_URL))

        assert _row(decoded, C2_URL).published == _row(floss, C2_URL).published == "yes"


class TestADecodedTextWithNoIndicator:
    def test_is_no_candidate(self) -> None:
        texts = ["Mozilla/4.0 (compatible; MSIE 8.0)", "%s\\%s_%d.tmp", "kernel32.dll"]
        record = emulation_from_ledger(
            [_strings_entry("x"), _decoder_entry(*[_decoder_row(t) for t in texts])]
        )

        assert record.values == {} and record.recovered_by == {}
        assert all(decoded_indicators(text) == [] for text in texts)


class TestWhatTheRecordHoldsOut:
    def test_a_decoded_value_the_sweep_read_is_the_sweep_s(self) -> None:
        ledger = [_strings_entry(f"http://{C2}/"), _decoder_entry(_decoder_row(C2))]
        report = _report(ledger, ("domain", C2))

        assert report.emulated_strings is not None
        assert report.emulated_strings.plain == {C2: "ev_0005"}
        assert _row(report, C2).published == (
            "no: seen only in the file's strings — also a plain string in the file "
            "(ev_0005), so not a value the sample hid"
        )
        assert _row(report, C2).recovered_by == ""

    def test_a_paged_decoder_entry_makes_the_record_partial(self) -> None:
        record = emulation_from_ledger(
            [
                _strings_entry("x"),
                _decoder_entry(_decoder_row(C2), total=40, next_offset=1),
            ]
        )

        assert record.partial == "no decode_string_blobs entry listed every result it decoded"


class TestBothTools:
    def test_the_first_entry_answers_and_the_table_names_both(self) -> None:
        ledger = [_strings_entry("x"), _floss_entry(C2), _decoder_entry(_decoder_row(C2))]
        report = _report(ledger, ("domain", C2))

        assert emulation_kwargs(report, "domain", C2)["recovered"] == (
            f"{RECOVERED_BY_EMULATION}, {FLOSS_ENTRY}"
        )
        said = _row(report, C2).recovered_by
        assert said.startswith(f"floss, {FLOSS_ENTRY} (decoded string, in function 0x1a00); ")
        assert f"decode_string_blobs, {DECODER_ENTRY} (xor8" in said


class TestARecordStoredBeforeTheProvenance:
    def test_names_floss_and_the_entry(self) -> None:
        record = EmulatedStrings(values={C2: FLOSS_ENTRY})

        assert recovered_by_words(record, "domain", C2) == f"floss, {FLOSS_ENTRY}"
        assert recovered_by_words(record, "path", C2) == ""
