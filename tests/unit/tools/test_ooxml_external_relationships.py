"""An OOXML document's external relationships are the ones it marks External.

``external_relationships`` used to be the number of ``.rels`` parts, which
every OOXML file has at least two of, so it said "relationships" for every
document and never read one. It now lists each relationship a relationship
part marks ``TargetMode="External"``, with its target defanged, and is absent
when there are none. A relationship part that cannot be read is named with the
reason, so its silence is never read as "none".

Every document here is a zip the test writes; nothing is opened by an office
program and no target is fetched.
"""

from __future__ import annotations

import gc
import io
import time
import zipfile
from pathlib import Path

from maljan.pipeline import triage_pack
from maljan.tools import binary as tool

RELS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def _relationships(*rows: str) -> str:
    return f'<?xml version="1.0"?><Relationships xmlns="{RELS_NS}">{"".join(rows)}</Relationships>'


def _row(rid: str, kind: str, target: str, mode: str = "") -> str:
    mode_attribute = f' TargetMode="{mode}"' if mode else ""
    return f'<Relationship Id="{rid}" Type="{OFFICE}/{kind}" Target="{target}"{mode_attribute}/>'


def _document(tmp_path: Path, extra: dict[str, str | bytes], name: str = "doc.docx") -> Path:
    """A word-processing package: its two usual relationship parts, plus ``extra`` parts."""
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr(
            "_rels/.rels", _relationships(_row("rId1", "officeDocument", "word/document.xml"))
        )
        archive.writestr("word/document.xml", "<w:document/>")
        archive.writestr(
            "word/_rels/document.xml.rels",
            _relationships(
                _row("rId1", "settings", "settings.xml"), _row("rId2", "styles", "styles.xml")
            ),
        )
        for part, body in extra.items():
            archive.writestr(part, body)
    return path


class TestWhatIsReported:
    def test_a_document_with_only_internal_relationships_reports_none(self, tmp_path: Path) -> None:
        answer = tool.document_info(str(_document(tmp_path, {})))

        assert answer["format"] == "ooxml"
        assert "external_relationships" not in answer
        assert "relationship_parts_unread" not in answer
        # The pack line no longer says "external_relationships 2" of it.
        assert "relationship" not in triage_pack._document(answer)

    def test_a_remote_template_is_listed_with_its_target_defanged(self, tmp_path: Path) -> None:
        settings = _relationships(
            _row("rId7", "attachedTemplate", "https://templates.example.invalid/t.dotm", "External")
        )
        answer = tool.document_info(
            str(_document(tmp_path, {"word/_rels/settings.xml.rels": settings}))
        )

        assert answer["external_relationships"] == [
            {
                "part": "word/_rels/settings.xml.rels",
                "id": "rId7",
                "type": "attachedTemplate",
                "target": "hxxps://templates[.]example[.]invalid/t.dotm",
            }
        ]
        assert triage_pack._document(answer).endswith(", 1 external_relationships")

    def test_every_external_relationship_of_every_part_in_order(self, tmp_path: Path) -> None:
        body = _relationships(
            _row("rId1", "hyperlink", "mailto:someone@example.invalid", "External"),
            _row("rId2", "image", "media/image1.png"),
            _row("rId3", "image", "media/image2.png", "Internal"),
            _row("rId4", "oleObject", "file://share.example.invalid/x.xlsx", "External"),
        )
        frame = _relationships(_row("rId1", "frame", "http://203.0.113.9/f.html", "External"))
        answer = tool.document_info(
            str(
                _document(
                    tmp_path,
                    {
                        "word/_rels/document2.xml.rels": body,
                        "WORD/_RELS/WEBSETTINGS.XML.RELS": frame,
                    },
                )
            )
        )

        assert [
            (r["part"], r["id"], r["type"], r["target"]) for r in answer["external_relationships"]
        ] == [
            (
                "word/_rels/document2.xml.rels",
                "rId1",
                "hyperlink",
                "mailto:someone@example[.]invalid",
            ),
            (
                "word/_rels/document2.xml.rels",
                "rId4",
                "oleObject",
                "file://share[.]example[.]invalid/x.xlsx",
            ),
            ("WORD/_RELS/WEBSETTINGS.XML.RELS", "rId1", "frame", "hxxp://203[.]0[.]113[.]9/f.html"),
        ]

    def test_only_relationship_parts_and_relationship_elements_count(self, tmp_path: Path) -> None:
        external = _row("rId1", "attachedTemplate", "https://x.example.invalid/t", "External")
        foreign = (
            '<Relationships xmlns="urn:example:not-packaging">'
            f'<Relationship Id="rId1" Type="{OFFICE}/attachedTemplate" '
            'Target="https://y.example.invalid/t" TargetMode="External"/></Relationships>'
        )
        answer = tool.document_info(
            str(
                _document(
                    tmp_path,
                    {
                        # Not under a _rels folder: no package reads it as relationships.
                        "word/settings.xml.rels": _relationships(external),
                        "customXml/notes.rels": _relationships(external),
                        # Under _rels, but its elements are not the packaging namespace's.
                        "word/_rels/footer1.xml.rels": foreign,
                    },
                )
            )
        )

        assert "external_relationships" not in answer
        assert "relationship_parts_unread" not in answer


class TestWhatIsNotRead:
    def test_a_document_type_is_refused_before_any_entity_is_expanded(self, tmp_path: Path) -> None:
        entities = '<!ENTITY a "aaaaaaaaaa">' + "".join(
            f'<!ENTITY {chr(98 + i)} "{("&" + chr(97 + i) + ";") * 10}">' for i in range(9)
        )
        laughs = (
            f'<?xml version="1.0"?><!DOCTYPE r [{entities}]><Relationships xmlns="{RELS_NS}">'
            f'<Relationship Id="rId1" Type="{OFFICE}/attachedTemplate" Target="&j;" '
            'TargetMode="External"/></Relationships>'
        )
        fetch = (
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>'
            f'<Relationships xmlns="{RELS_NS}"><Relationship Id="rId1" Type="{OFFICE}/frame" '
            'Target="&x;" TargetMode="External"/></Relationships>'
        )
        kept = _relationships(
            _row("rId9", "attachedTemplate", "https://z.example.invalid/t", "External")
        )
        path = _document(
            tmp_path,
            {
                "word/_rels/settings.xml.rels": laughs,
                "word/_rels/webSettings.xml.rels": fetch,
                "word/_rels/footer1.xml.rels": kept,
            },
        )

        started = time.perf_counter()
        answer = tool.document_info(str(path))

        assert time.perf_counter() - started < 2
        assert answer["relationship_parts_unread"] == [
            {
                "part": "word/_rels/settings.xml.rels",
                "reason": "it declares a document type, which a relationship part never needs",
            },
            {
                "part": "word/_rels/webSettings.xml.rels",
                "reason": "it declares a document type, which a relationship part never needs",
            },
        ]
        assert [r["id"] for r in answer["external_relationships"]] == ["rId9"]

    def test_a_part_that_is_not_xml_is_named_with_the_reason(self, tmp_path: Path) -> None:
        answer = tool.document_info(
            str(
                _document(
                    tmp_path, {"word/_rels/settings.xml.rels": "<Relationships><Relationship"}
                )
            )
        )

        (unread,) = answer["relationship_parts_unread"]
        assert unread["part"] == "word/_rels/settings.xml.rels"
        assert unread["reason"].startswith("it is not well-formed XML (")
        assert "external_relationships" not in answer

    def test_a_damaged_member_is_named_and_the_others_are_still_read(self, tmp_path: Path) -> None:
        target = "https://t.example.invalid/x"
        damaged = _relationships(_row("rId1", "attachedTemplate", target, "External")).encode()
        path = tmp_path / "damaged.docx"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("word/_rels/settings.xml.rels", damaged)
            archive.writestr(
                "word/_rels/footer1.xml.rels",
                _relationships(_row("rId2", "frame", target, "External")),
            )
        raw = path.read_bytes()
        at = raw.index(damaged) + len(damaged) - 20
        path.write_bytes(raw[:at] + bytes([raw[at] ^ 0x20]) + raw[at + 1 :])

        answer = tool.document_info(str(path))

        (unread,) = answer["relationship_parts_unread"]
        assert unread["part"] == "word/_rels/settings.xml.rels"
        assert unread["reason"].startswith("the archive member could not be read (BadZipFile: ")
        assert [r["id"] for r in answer["external_relationships"]] == ["rId2"]


def _timed(path: Path) -> float:
    """The fastest of three reads, the collector held so no sweep is timed."""
    gc.collect()
    gc.disable()
    try:
        seconds = []
        for _ in range(3):
            began = time.perf_counter()
            tool.document_info(str(path))
            seconds.append(time.perf_counter() - began)
        return min(seconds)
    finally:
        gc.enable()


def _one_part_of(tmp_path: Path, n: int) -> Path:
    rows = "".join(
        _row(f"rId{i}", "hyperlink", f"https://h{i}.example.invalid/{'p' * 40}", "External")
        for i in range(n)
    )
    return _document(
        tmp_path, {"word/_rels/settings.xml.rels": _relationships(rows)}, f"rows{n}.docx"
    )


def _many_parts_of(tmp_path: Path, n: int) -> Path:
    body = _relationships(_row("rId1", "hyperlink", "https://h.example.invalid/x", "External"))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for i in range(n):
            archive.writestr(f"word/_rels/footer{i}.xml.rels", body)
    path = tmp_path / f"parts{n}.docx"
    path.write_bytes(buffer.getvalue())
    return path


class TestLinearTime:
    def test_ten_times_the_relationships_take_about_ten_times_as_long(self, tmp_path: Path) -> None:
        low = _timed(_one_part_of(tmp_path, 2_000))
        high = _timed(_one_part_of(tmp_path, 20_000))

        assert high < low * 20

    def test_ten_times_the_relationship_parts_take_about_ten_times_as_long(
        self, tmp_path: Path
    ) -> None:
        low = _timed(_many_parts_of(tmp_path, 500))
        high = _timed(_many_parts_of(tmp_path, 5_000))

        assert high < low * 20
