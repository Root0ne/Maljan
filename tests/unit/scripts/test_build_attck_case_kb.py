"""tests/unit/scripts/test_build_attck_case_kb.py — build_attck_case_kb.py unit tests.

Covers the offline ATT&CK case-prior corpus builder's pure logic (no Qdrant / no
embeddings needed — the builder stores TEXT only and the runtime index embeds at load):
  - _row_from_payload() normalization (blank summary -> None, technique cleanup)
  - _cases_from_jsonl() parsing + malformed-line skip
  - main() --cases-jsonl: dedup by sample_id, technique floor, output schema
  - main() error paths (no input flag, empty result)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))

from build_attck_case_kb import (  # noqa: E402
    _cases_from_jsonl,
    _row_from_payload,
    main,
)


class TestRowFromPayload:
    def test_blank_summary_dropped(self) -> None:
        assert _row_from_payload({"sample_id": "x", "summary_text": "   "}) is None

    def test_normalizes_techniques_and_defaults(self) -> None:
        row = _row_from_payload(
            {
                "sample_id": " s1 ",
                "summary_text": " inject beacon ",
                "technique_ids": ["T1055", "  ", "T1071 "],
            }
        )
        assert row == {
            "sample_id": "s1",
            "summary_text": "inject beacon",
            "technique_ids": ["T1055", "T1071"],
            "malware_category": "UNKNOWN",
        }

    def test_keeps_category_when_present(self) -> None:
        row = _row_from_payload({"sample_id": "s", "summary_text": "t", "malware_category": "rat"})
        assert row is not None and row["malware_category"] == "rat"


class TestCasesFromJsonl:
    def test_parses_and_skips_malformed(self, tmp_path: Path) -> None:
        p = tmp_path / "cases.jsonl"
        p.write_text(
            '{"sample_id":"a","summary_text":"inject","technique_ids":["T1055"]}\n'
            "\n"  # blank line ignored
            "not-json\n"  # malformed skipped
            '{"sample_id":"b","summary_text":"","technique_ids":["T1"]}\n'  # blank summary dropped
            '{"sample_id":"c","summary_text":"encrypt","technique_ids":["T1486"]}\n',
            encoding="utf-8",
        )
        rows = _cases_from_jsonl(p)
        assert [r["sample_id"] for r in rows] == ["a", "c"]


class TestMain:
    def _write(self, tmp_path: Path, lines: list[dict]) -> Path:
        p = tmp_path / "in.jsonl"
        p.write_text("\n".join(json.dumps(x) for x in lines), encoding="utf-8")
        return p

    def test_dedup_floor_and_schema(self, tmp_path: Path, monkeypatch) -> None:
        src = self._write(
            tmp_path,
            [
                {"sample_id": "s1", "summary_text": "inject beacon", "technique_ids": ["T1055"]},
                {"sample_id": "s2", "summary_text": "old", "technique_ids": ["T1486"]},
                {"sample_id": "s2", "summary_text": "new", "technique_ids": ["T1486", "T1490"]},
                {"sample_id": "s3", "summary_text": "below floor", "technique_ids": []},
            ],
        )
        out = tmp_path / "corpus.json"
        monkeypatch.setattr(
            sys,
            "argv",
            ["x", "--cases-jsonl", str(src), "--out", str(out), "--min-techniques", "1"],
        )
        assert main() == 0
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["schema"] == "maljan-attck-case-corpus/v1"
        by_id = {c["sample_id"]: c for c in doc["cases"]}
        assert set(by_id) == {"s1", "s2"}  # s3 dropped by floor
        assert by_id["s2"]["summary_text"] == "new"  # dedup keeps last
        assert by_id["s2"]["technique_ids"] == ["T1486", "T1490"]

    def test_no_input_flag_errors(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(sys, "argv", ["x", "--out", str(tmp_path / "o.json")])
        assert main() == 2

    def test_all_below_floor_errors(self, tmp_path: Path, monkeypatch) -> None:
        src = self._write(
            tmp_path, [{"sample_id": "s", "summary_text": "t", "technique_ids": ["T1"]}]
        )
        out = tmp_path / "o.json"
        monkeypatch.setattr(
            sys,
            "argv",
            ["x", "--cases-jsonl", str(src), "--out", str(out), "--min-techniques", "5"],
        )
        assert main() == 1
        assert not out.exists()
