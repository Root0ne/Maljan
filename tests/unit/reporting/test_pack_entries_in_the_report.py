"""The report's identity and signature come from the pack when no model cited them.

The identity projection and the section builder read the ledger by tool, not
by who made the call, so the pack's ``identify_file``, ``hashes`` and
``signing_info`` entries fill the identity block and the signature rows on a
run whose analysts cited nothing — which is the run the pack exists for.
"""

from __future__ import annotations

import json

from maljan.pipeline.triage_pack import PIPELINE
from maljan.reporting.ledger_projection import identity_from_ledger
from maljan.reporting.ledger_report import build_sections
from maljan.schemas.evidence import build_entry, format_entry_id


def _pack_entry(tool: str, payload: dict, seq: int):
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent=PIPELINE,
        tool=tool,
        args={"path": "/samples/s.exe"},
        server=PIPELINE,
        output=json.dumps(payload),
        stage="triage_pack",
    )


PACK = [
    _pack_entry(
        "identify_file",
        {"file_type": "pe", "platform": "windows", "mime": "application/x-dosexec", "size": 4096},
        1,
    ),
    _pack_entry("hashes", {"sha256": "b" * 64, "md5": "c" * 32, "sha1": "d" * 40}, 2),
    _pack_entry(
        "signing_info",
        {
            "authenticode": {"present": True, "subject": "Simon Tatham", "issuer": "Sectigo"},
            "apk": {"present": False, "schemes": []},
            "macho": {"present": False},
        },
        3,
    ),
]


def test_the_identity_block_is_read_from_the_pack_not_recomputed(tmp_path) -> None:
    identity = identity_from_ledger(
        PACK,
        sample_path=str(tmp_path / "missing.exe"),
        file_name="s.exe",
        file_hash="a" * 64,
        file_type="unknown",
        platform="unknown",
    )
    assert identity.hashes.sha256 == "b" * 64
    assert identity.hashes.md5 == "c" * 32
    assert identity.file_type == "pe"
    assert identity.platform == "windows"
    assert identity.file_size_bytes == 4096
    assert identity.mime_type == "application/x-dosexec"


def test_the_identity_and_signature_sections_cite_the_pack_s_ids() -> None:
    sections = {section.key: section for section in build_sections(PACK)}
    identity = sections["identity"]
    rows = dict(identity.rows)
    assert rows["file type"] == "pe"
    assert rows["sha256"] == "b" * 64
    assert rows["authenticode"].startswith("present=yes")
    assert "Simon Tatham" in rows["authenticode"]
    assert identity.evidence_ids == ["ev_0001", "ev_0002", "ev_0003"]


def _signing_pack(payload: dict, file_type: str = "pe") -> list:
    """The three identity tools, with one signing answer to project."""
    return [
        _pack_entry("identify_file", {"file_type": file_type, "platform": "windows"}, 1),
        _pack_entry("hashes", {"sha256": "b" * 64}, 2),
        _pack_entry("signing_info", payload, 3),
    ]


def _identity_rows(pack: list) -> dict[str, str]:
    sections = {section.key: section for section in build_sections(pack)}
    return dict(sections["identity"].rows)


class TestOneSigningRowForTheRoutedFormat:
    """What the table says about a signature, per format.

    ``signing_info`` answers for the routed format alone and carries the
    routed ``format`` alongside its answer. Neither that nor the
    ``applicable`` flag a format with no scheme gets is a fact about the
    sample: one repeats what ``identify_file`` says two rows above, and the
    other is a statement about what the tool looks for, under the heading that
    exists for what was found.
    """

    def test_a_pe_carries_its_authenticode_row_and_nothing_else(self) -> None:
        rows = _identity_rows(
            _signing_pack(
                {
                    "format": "pe",
                    "authenticode": {"present": True, "subject": "Simon Tatham"},
                }
            )
        )

        assert rows["authenticode"].startswith("present=yes")
        assert "format" not in rows
        assert "apk" not in rows and "macho" not in rows

    def test_an_apk_carries_its_apk_row(self) -> None:
        rows = _identity_rows(
            _signing_pack(
                {"format": "apk", "apk": {"present": True, "schemes": ["v2"]}}, file_type="apk"
            )
        )

        assert rows["apk"].startswith("present=yes")
        assert "format" not in rows
        assert "authenticode" not in rows

    def test_a_macho_carries_its_macho_row(self) -> None:
        rows = _identity_rows(
            _signing_pack({"format": "mach-o", "macho": {"present": False}}, file_type="mach-o")
        )

        assert rows["macho"] == "present=no"
        assert "format" not in rows

    def test_a_format_with_no_signing_scheme_carries_no_signing_row(self) -> None:
        """An ELF, a document, an archive: the table simply has nothing to say."""
        rows = _identity_rows(
            _signing_pack({"format": "elf", "applicable": False}, file_type="elf")
        )

        assert "applicable" not in rows
        assert "format" not in rows
        assert not {"authenticode", "apk", "macho"} & set(rows)
        # The rest of the identity block is untouched.
        assert rows["file type"] == "elf"
        assert rows["sha256"] == "b" * 64

    def test_the_entry_is_not_cited_where_it_contributed_nothing(self) -> None:
        pack = _signing_pack({"format": "elf", "applicable": False}, file_type="elf")
        sections = {section.key: section for section in build_sections(pack)}

        assert sections["identity"].evidence_ids == ["ev_0001", "ev_0002"]

    def test_a_report_recorded_before_the_tool_answered_once_still_projects(self) -> None:
        """All three blocks, as a run made before this change recorded them."""
        rows = _identity_rows(
            _signing_pack(
                {
                    "authenticode": {"present": False},
                    "apk": {"present": True, "schemes": ["v1"]},
                    "macho": {"present": False},
                }
            )
        )

        assert rows["authenticode"] == "present=no"
        assert rows["apk"].startswith("present=yes")
        assert rows["macho"] == "present=no"
