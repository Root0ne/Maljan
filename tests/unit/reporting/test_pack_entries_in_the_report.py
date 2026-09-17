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
