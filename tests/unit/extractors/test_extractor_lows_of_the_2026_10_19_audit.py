"""One regression per extractor Low of the 2026-10-19 audit (AUD-51 B-L1, L4, L6, L7, L9)."""

from __future__ import annotations

from pathlib import Path

import pytest

from maljan.extractors.capability_matrix import (
    CORROBORATION_NOT_READ_NOTE,
    build_capability_matrix,
)
from maljan.extractors.network_extractor import _scored_domain
from maljan.extractors.pe_extractor import _parse_elf_imports
from maljan.extractors.sample_identity import _is_certificate_table, unparsed_container_reason
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def test_b_l1_every_elf_import_names_the_library_its_symbol_version_names() -> None:
    binary = Path("/bin/ls")
    if not binary.is_file():
        pytest.skip("no system ELF to read")
    rows = _parse_elf_imports(binary.read_bytes())
    assert any(r.function for r in rows)
    # Before: only the first import carried a library, and it was libraries[0].
    assert sum(1 for r in rows if r.dll == "libc.so.6") > 1


@pytest.mark.parametrize("host", ["bitdefender.com", "bitbucket.org", "www.bitly.com"])
def test_b_l4_bit_is_a_tld_not_a_substring(host: str) -> None:
    assert not _scored_domain(host).suspicious


def test_b_l4_a_bit_domain_is_still_flagged() -> None:
    assert _scored_domain("payload.bit").suspicious


def test_b_l6_authenticode_is_present_only_for_a_wellformed_certificate_table() -> None:
    blob = bytearray(4096)
    # A non-zero directory pointing at zeros, and one pointing past the file.
    assert not _is_certificate_table(bytes(blob), 1024, 512)
    assert not _is_certificate_table(bytes(blob), 10_000, 512)
    # A WIN_CERTIFICATE header: length 64, revision 2.0, PKCS#7 signed data.
    blob[1024:1032] = (
        (64).to_bytes(4, "little") + (0x0200).to_bytes(2, "little") + (2).to_bytes(2, "little")
    )
    assert _is_certificate_table(bytes(blob), 1024, 512)


def test_b_l7_an_iso_is_recognised_by_the_header_the_container_check_reads(
    tmp_path: Path,
) -> None:
    image = tmp_path / "disk.bin"
    body = bytearray(40_000)
    body[32769:32774] = b"CD001"
    image.write_bytes(bytes(body))
    reason = unparsed_container_reason(str(image), ledger=[])
    assert reason is not None and "disc image" in reason


def test_b_l9_a_technique_counted_without_its_corroboration_record_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unreadable(*_a: object, **_k: object) -> dict:
        raise RuntimeError("no record")

    monkeypatch.setattr("maljan.pipeline.validation.corroboration", unreadable)
    claim = ClaimEvidence(claim="injects", evidence_ref="r", confidence=0.8, technique_id="T1055")
    isr = {"static": AgentISR(agent_id="static", domain="static", claims=[claim])}
    stix = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "T1055",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1055"}],
            }
        ],
    }
    cells, _ = build_capability_matrix(stix_output=stix, isr_reports=isr, ledger=[object()])
    assert cells and CORROBORATION_NOT_READ_NOTE in cells[0].note
    cells, _ = build_capability_matrix(stix_output=stix, isr_reports=isr)
    assert CORROBORATION_NOT_READ_NOTE not in cells[0].note
