"""An OOXML document's external relationships are the ones it marks External.

``external_relationships`` used to be the number of ``.rels`` parts, which
every OOXML file has at least two of, so it said "relationships" for every
document and never read one. It now lists each relationship a relationship
part marks ``TargetMode="External"``, with its target exactly as written (a tool
answer is live; the report's renderers defang where they print), and is absent
when there are none. A relationship part that cannot be read is named with the
reason, so its silence is never read as "none".

Every document here is a zip the test writes; nothing is opened by an office
program and no target is fetched.
"""

from __future__ import annotations

import gc
import io
import json
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

import pytest

from maljan.pipeline import triage_pack
from maljan.tools import binary as tool

MIB = 1024 * 1024

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

    def test_a_remote_template_is_listed_with_its_target_as_written(self, tmp_path: Path) -> None:
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
                "target": "https://templates.example.invalid/t.dotm",
            }
        ]
        assert triage_pack._document(answer).endswith(", 1 external_relationships")

    def test_every_target_is_kept_exactly_as_the_part_writes_it(self, tmp_path: Path) -> None:
        targets = [
            "https://templates.example.invalid/t.dotm",
            "\\\\192.0.2.10\\share\\t.dotm",
            "../x/report.dotx",
            "file:///\\\\192.0.2.10\\share\\t.dotm",
            "mhtml:http://192.0.2.10/page.mht!x.htm",
        ]
        rows = [
            _row(f"rId{n}", "attachedTemplate", target, "External")
            for n, target in enumerate(targets)
        ]
        answer = tool.document_info(
            str(_document(tmp_path, {"word/_rels/settings.xml.rels": _relationships(*rows)}))
        )

        assert [row["target"] for row in answer["external_relationships"]] == targets

    def test_the_report_prints_the_target_as_it_prints_any_tool_s_url(self, tmp_path: Path) -> None:
        """The answer is live; the report's own evidence pass defangs it where it prints it.

        ``_defanged_text`` is the pass the Markdown appendix applies to every
        evidence cell (``plain``), whichever tool the section came from.
        """
        from maljan.reporting.ledger_report import build_sections
        from maljan.reporting.renderers.markdown import _defanged_text
        from maljan.schemas.evidence import build_entry

        settings = _relationships(
            _row("rId7", "attachedTemplate", "https://templates.example.invalid/t.dotm", "External")
        )
        answer = tool.document_info(
            str(_document(tmp_path, {"word/_rels/settings.xml.rels": settings}))
        )
        entry = build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="pipeline",
            tool="document_info",
            args={},
            server=None,
            output=json.dumps(answer),
        )
        (table,) = [s for s in build_sections([entry]) if s.key.endswith("_external_relationships")]
        (cell,) = [c for row in table.rows for c in row if "templates" in str(c)]

        assert cell == "https://templates.example.invalid/t.dotm"
        assert _defanged_text(cell) == "hxxps://templates[.]example[.]invalid/t.dotm"

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
                "mailto:someone@example.invalid",
            ),
            (
                "word/_rels/document2.xml.rels",
                "rId4",
                "oleObject",
                "file://share.example.invalid/x.xlsx",
            ),
            ("WORD/_RELS/WEBSETTINGS.XML.RELS", "rId1", "frame", "http://203.0.113.9/f.html"),
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


class TestTheCap:
    """The relationship parts of one document inflate to no more than the upload cap together."""

    @staticmethod
    def _links(part: int, rows: int) -> str:
        return _relationships(
            *(
                _row(f"rId{i}", "hyperlink", f"https://p{part}h{i}.example.invalid/x", "External")
                for i in range(rows)
            )
        )

    def test_parts_under_the_cap_one_by_one_are_counted_against_it_together(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        extra = {f"word/_rels/footer{n}.xml.rels": self._links(n, 6) for n in range(1, 6)}
        path = _document(tmp_path, extra)
        with zipfile.ZipFile(path) as archive:
            rels = [i for i in archive.infolist() if "_rels/" in i.filename]
            sizes = [(i.filename, i.file_size) for i in rels]
        # Every part fits the cap alone; the first three extra parts fit it
        # together with the two usual ones, and the fourth would cross it.
        cap = sum(size for _, size in sizes[:5]) + sizes[5][1] // 2
        assert all(size < cap for _, size in sizes)
        monkeypatch.setattr(tool, "RELATIONSHIP_PART_CAP", cap)

        answer = tool.document_info(str(path))

        assert {row["part"] for row in answer["external_relationships"]} == {
            name for name, _ in sizes[2:5]
        }
        left = cap - sum(size for _, size in sizes[:5])
        assert answer["relationship_parts_unread"] == [
            {
                "part": sizes[5][0],
                "reason": tool.RELATIONSHIP_PART_OVER_CAP.format(
                    size=sizes[5][1], left=left, cap=cap
                ),
            },
            {"part": sizes[6][0], "reason": tool.RELATIONSHIP_PART_AFTER_CAP.format(cap=cap)},
        ]

    def test_a_part_stating_more_than_the_whole_cap_stops_the_reading_there(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tool, "RELATIONSHIP_PART_CAP", 1_000)
        big = self._links(1, 40)
        small = _relationships(_row("rId1", "frame", "https://f.example.invalid/x", "External"))
        path = _document(
            tmp_path, {"word/_rels/settings.xml.rels": big, "word/_rels/footer1.xml.rels": small}
        )
        with zipfile.ZipFile(path) as archive:
            usual = sum(i.file_size for i in archive.infolist()[:4] if "_rels/" in i.filename)

        answer = tool.document_info(str(path))

        assert "external_relationships" not in answer
        assert answer["relationship_parts_unread"] == [
            {
                "part": "word/_rels/settings.xml.rels",
                "reason": tool.RELATIONSHIP_PART_OVER_CAP.format(
                    size=len(big.encode()), left=1_000 - usual, cap=1_000
                ),
            },
            {
                "part": "word/_rels/footer1.xml.rels",
                "reason": tool.RELATIONSHIP_PART_AFTER_CAP.format(cap=1_000),
            },
        ]

    def test_reading_stops_past_what_is_left_whatever_the_member_states(self) -> None:
        body = _relationships(
            _row("rId1", "frame", "https://f.example.invalid/" + "p" * 500, "External")
        ).encode()

        with pytest.raises(tool._RelationshipPartPastCap) as refused:
            tool._external_relationships("word/_rels/x.rels", io.BytesIO(body), 100, 1_000)

        assert str(refused.value) == tool.RELATIONSHIP_PART_PAST_CAP.format(left=100, cap=1_000)

    @staticmethod
    def _sizes(path: Path) -> list[tuple[str, int]]:
        with zipfile.ZipFile(path) as archive:
            rels = [i for i in archive.infolist() if "_rels/" in i.filename]
            return [(i.filename, i.file_size) for i in rels]

    @staticmethod
    def _cap_after(sizes: list[tuple[str, int]], whole: int) -> int:
        """A cap the first ``whole`` relationship parts fit and the next one crosses."""
        return sum(size for _, size in sizes[:whole]) + sizes[whole][1] // 2

    def test_parts_that_fail_at_their_end_are_counted_against_the_cap_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Each part is a document that never closes: inflated whole, then refused.
        extra = {
            f"word/_rels/footer{n}.xml.rels": self._links(n, 6).removesuffix("</Relationships>")
            for n in range(1, 5)
        }
        path = _document(tmp_path, extra)
        sizes = self._sizes(path)
        cap = self._cap_after(sizes, 4)
        monkeypatch.setattr(tool, "RELATIONSHIP_PART_CAP", cap)
        inflated: list[int] = []
        real = tool._CountedStream.read

        def counting(self: Any, size: int = -1) -> bytes:
            chunk = real(self, size)
            inflated.append(len(chunk))
            return chunk

        monkeypatch.setattr(tool._CountedStream, "read", counting)

        answer = tool.document_info(str(path))

        unread = answer["relationship_parts_unread"]
        assert [row["part"] for row in unread] == [name for name, _ in sizes[2:]]
        assert all(row["reason"].startswith("it is not well-formed XML") for row in unread[:2])
        left = cap - sum(size for _, size in sizes[:4])
        assert unread[2]["reason"] == tool.RELATIONSHIP_PART_OVER_CAP.format(
            size=sizes[4][1], left=left, cap=cap
        )
        assert unread[3]["reason"] == tool.RELATIONSHIP_PART_AFTER_CAP.format(cap=cap)
        # Inflation stopped at the cap: nothing of the last two parts was read.
        assert sum(inflated) == sum(size for _, size in sizes[:4])

    def test_members_failing_their_crc_are_counted_against_the_cap_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        extra = {f"word/_rels/footer{n}.xml.rels": self._links(n, 6) for n in range(1, 5)}
        path = _document(tmp_path, extra)
        with zipfile.ZipFile(path) as archive:
            crcs = [i.CRC for i in archive.infolist() if i.filename.startswith("word/_rels/foot")]
        blob = path.read_bytes()
        for crc in crcs:
            right = crc.to_bytes(4, "little")
            blob = blob.replace(right, (crc ^ 1).to_bytes(4, "little"))
        path.write_bytes(blob)
        sizes = self._sizes(path)
        cap = self._cap_after(sizes, 4)
        monkeypatch.setattr(tool, "RELATIONSHIP_PART_CAP", cap)

        answer = tool.document_info(str(path))

        unread = answer["relationship_parts_unread"]
        assert [row["part"] for row in unread] == [name for name, _ in sizes[2:]]
        assert all("BadZipFile" in row["reason"] for row in unread[:2])
        assert unread[3]["reason"] == tool.RELATIONSHIP_PART_AFTER_CAP.format(cap=cap)
        assert "external_relationships" not in answer

    def test_a_part_read_whole_says_how_much_of_the_cap_it_took(self) -> None:
        body = self._links(1, 3).encode()

        found, read = tool._external_relationships(
            "word/_rels/x.rels", io.BytesIO(body), len(body), len(body)
        )

        assert len(found) == 3 and read == len(body)


# Run in a child of its own, so the peak resident memory it reports is the read's alone.
_PEAK_PROBE = """
import resource, sys, time
from maljan.tools import binary
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
began = time.perf_counter()
answer = binary.document_info(sys.argv[1])
took = time.perf_counter() - began
rise = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before
print(len(answer["external_relationships"][0]["target"]), took, rise * 1024)
"""


def _one_token_of(tmp_path: Path, megabytes: int) -> Path:
    token = "https://t.example.invalid/" + "a" * (megabytes * MIB)
    body = _relationships(_row("rId1", "attachedTemplate", token, "External"))
    return _document(tmp_path, {"word/_rels/settings.xml.rels": body}, f"token{megabytes}.docx")


def _measured(path: Path) -> tuple[int, float, int]:
    """The target's length, the read's seconds and its peak resident memory rise in bytes."""
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    done = subprocess.run(
        [sys.executable, "-c", _PEAK_PROBE, str(path)],
        capture_output=True,
        text=True,
        check=True,
        env=env,
        timeout=120,
    )
    length, took, rise = done.stdout.split()
    return int(length), float(took), int(rise)


class TestOneLongToken:
    def test_ten_times_the_token_costs_about_ten_times_the_time_and_memory(
        self, tmp_path: Path
    ) -> None:
        low_length, low_seconds, low_rise = _measured(_one_token_of(tmp_path, 4))
        high_length, high_seconds, high_rise = _measured(_one_token_of(tmp_path, 40))

        assert high_length > 40 * MIB > 10 * low_length * 0.99
        assert high_seconds < 20 * low_seconds
        # The reader holds the whole value: about three times the token here.
        assert high_rise < 6 * high_length
        assert high_rise < 25 * max(low_rise, MIB)
