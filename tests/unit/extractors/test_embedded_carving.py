"""A packed dropper's payload was invisible to every rule in the corpus.

``_pe_resources`` enumerated resources by type, id and size and never read the
bytes, and nothing anywhere looked at the overlay — the region past the last
section's raw data, which no section header describes and which is exactly
where a dropper keeps its second stage.

The consequence was not "we found nothing". It was worse: the judge's YARA
layer scanned the packed outer shell, which by construction matches nothing,
and the report said *no signatures fired*. A reader cannot tell that apart from
"we looked and it was clean".

Carving reports rather than recurses, deliberately — a carved child would need
its own ``sample_path``, its own Ghidra mirror and its own memory upsert, and
``AnalysisState`` carries exactly one of each. What it does do is hand the
payload to the YARA scan, which is where most of the value was.
"""

from __future__ import annotations

from maljan.extractors.pe_extractor import _carve_embedded, carve_payloads
from maljan.reporting.models import PESection

_PE_MAGIC = b"MZ\x90\x00"


def _section(name: str, raw_offset: int, raw_size: int) -> PESection:
    return PESection(
        name=name,
        virtual_address="0x1000",
        virtual_size=raw_size,
        raw_size=raw_size,
        raw_offset=raw_offset,
    )


def _host(payload: bytes, *, gap: int = 4096) -> bytes:
    """A stub PE with `payload` appended past the end of its only section."""
    return _PE_MAGIC + b"\x00" * (gap - len(_PE_MAGIC)) + payload


class TestAppendedPayloadsAreFound:
    def test_a_pe_appended_to_a_pe_is_carved(self) -> None:
        blob = _host(_PE_MAGIC + b"\x41" * 8192)
        rows = _carve_embedded(blob, [_section(".text", 512, 3584)])

        carved = [r for r in rows if r["type"] == "carved:PE"]
        assert carved, "an appended PE must be reported"
        assert carved[0]["offset"] == 4096
        assert carved[0]["source"] == "overlay"
        assert carved[0]["carved"] is True

    def test_the_host_itself_is_never_reported(self) -> None:
        """Offset 0 is the sample. Reporting it as its own child would be a
        confident-looking tautology."""
        rows = _carve_embedded(_host(b""), [_section(".text", 512, 3584)])
        assert all(r["offset"] != 0 for r in rows)

    def test_a_zip_is_carved(self) -> None:
        blob = _host(b"PK\x03\x04" + b"\x00" * 8192)
        assert any(r["type"] == "carved:ZIP" for r in _carve_embedded(blob, []))

    def test_a_pdf_is_carved(self) -> None:
        blob = _host(b"%PDF-1.7" + b"\x00" * 8192)
        assert any(r["type"] == "carved:PDF" for r in _carve_embedded(blob, []))

    def test_a_payload_inside_the_body_is_labelled_body(self) -> None:
        """Resource-embedded payloads and appended ones are different things."""
        body = _PE_MAGIC + b"\x00" * 2000 + _PE_MAGIC + b"\x42" * 8192
        rows = _carve_embedded(body, [_section(".rsrc", 0, 60000)])
        carved = [r for r in rows if r["offset"] != 0]
        assert carved and carved[0]["source"] == "body"

    def test_each_row_carries_a_hash_and_entropy(self) -> None:
        """Without them a reader cannot tell an encrypted stage from padding."""
        rows = _carve_embedded(_host(_PE_MAGIC + b"\x41" * 8192), [])
        assert rows
        assert len(rows[0]["sha256"]) == 64
        assert isinstance(rows[0]["entropy"], float)


class TestCarvingDoesNotInventFindings:
    def test_a_four_byte_coincidence_is_not_a_payload(self) -> None:
        """`MZ\\x90\\x00` occurs by chance. A 'payload' of a few bytes is noise
        dressed up as a finding."""
        blob = _PE_MAGIC + b"\x00" * 1000 + _PE_MAGIC + b"\x00" * 8
        assert not [r for r in _carve_embedded(blob, []) if r["offset"] != 0]

    def test_a_clean_binary_yields_nothing(self) -> None:
        assert _carve_embedded(_PE_MAGIC + b"\x00" * 40000, []) == []

    def test_the_child_count_is_bounded(self) -> None:
        """A blob full of MZ headers must not produce a hundred rows."""
        blob = _PE_MAGIC + b"".join(_PE_MAGIC + b"\x41" * 2048 for _ in range(60))
        assert len(_carve_embedded(blob, [])) <= 8

    def test_an_oversized_input_is_skipped(self) -> None:
        from maljan.extractors import pe_extractor

        assert _carve_embedded(b"MZ" * (pe_extractor._MAX_CARVE_INPUT // 2 + 8), []) == []

    def test_an_empty_blob_is_safe(self) -> None:
        assert _carve_embedded(b"", []) == []
        assert carve_payloads(b"") == []


class TestThePayloadsReachTheScanner:
    def test_carve_payloads_returns_labelled_bytes(self) -> None:
        blob = _host(_PE_MAGIC + b"\x41" * 8192)
        payloads = carve_payloads(blob)
        assert payloads, "the judge's YARA scan needs the bytes, not just a row"
        label, data = payloads[0]
        assert "0x" in label, "the label must locate the payload for the report"
        assert data.startswith(_PE_MAGIC)

    def test_carve_payloads_never_raises_on_junk(self) -> None:
        """Carving runs inside the judge; an exception here costs the verdict."""
        assert carve_payloads(b"MZ" + b"\xff" * 100) == []
        assert carve_payloads(b"\x00" * 100) == []


class TestTheYaraMatchRemembersWhereItFired:
    def test_a_carved_hit_is_labelled(self) -> None:
        """'This dropper carries Emotet' and 'this is Emotet' are different
        claims, and the second one is an attribution error."""
        from maljan.analysis.yara_layer import YaraMatch

        hit = YaraMatch(
            rule_id="emotet_stage2",
            technique_id="T1055",
            confidence=0.9,
            description="d",
            matched_patterns=["abc"],
            source_label="overlay+0x1a400",
        )
        assert "[overlay+0x1a400]" in hit.evidence_ref

    def test_a_sample_hit_is_not_labelled(self) -> None:
        from maljan.analysis.yara_layer import YaraMatch

        hit = YaraMatch(rule_id="r", technique_id="T1055", confidence=0.9, description="d")
        assert not hit.evidence_ref.startswith("[")
