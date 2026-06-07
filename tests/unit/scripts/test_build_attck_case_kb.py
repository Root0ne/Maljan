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
    _cases_from_mabel,
    _mabel_category,
    _mabel_summary,
    _mabel_val,
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


# MABEL feature-CSV mining (the only header columns the parser reads).
_MABEL_HEADER = (
    "sha256_hash,family_name,mitre_attack_id,standardized_import_functions_sorted,"
    "capa_capability_name,yara_capabilities,yara_ransomware,yara_rat,yara_stealer,yara_miners"
)


class TestMabelHelpers:
    def test_mabel_val_normalizes_dash(self) -> None:
        assert _mabel_val({"c": "-"}, "c") == ""  # MABEL's null placeholder
        assert _mabel_val({"c": " x "}, "c") == "x"
        assert _mabel_val({}, "c") == ""

    def test_category_from_yara_columns(self) -> None:
        assert _mabel_category({"yara_ransomware": "ransom_rule"}) == "RANSOMWARE"
        assert _mabel_category({"yara_rat": "njrat"}) == "RAT"
        # All-dash (the common case) -> UNKNOWN, not a false RANSOMWARE.
        assert _mabel_category({"yara_ransomware": "-", "yara_rat": "-"}) == "UNKNOWN"

    def test_summary_renders_imports_capa_yara(self) -> None:
        s = _mabel_summary(
            {
                "standardized_import_functions_sorted": "createprocess createremotethread",
                "capa_capability_name": "inject process; allocate rwx memory",
                "yara_capabilities": "win_registry; network_tcp_socket",
            }
        )
        assert "suspicious imports: createprocess" in s
        assert "capabilities: inject process" in s
        assert "yara: win_registry" in s

    def test_summary_empty_when_all_dash(self) -> None:
        assert _mabel_summary({"standardized_import_functions_sorted": "-"}) == ""


class TestCasesFromMabel:
    def _write_csv(self, tmp_path: Path, rows: list[str]) -> Path:
        p = tmp_path / "mabel.csv"
        p.write_text(_MABEL_HEADER + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
        return p

    def test_extracts_techniques_and_caps_family(self, tmp_path: Path) -> None:
        # 3 rows for family Foo, cap=2 -> only 2 kept; technique ids parsed from the
        # "Txxxx: name; ..." cell; a row with no ATT&CK id is dropped.
        rows = [
            "h1,Foo,T1055: Injection; T1071: C2,createremotethread,inject,win_registry,-,-,-,-",
            "h2,Foo,T1486: Encrypt,cryptencrypt,encrypt files,-,ransom,-,-,-",
            "h3,Foo,T1057: Discovery,getprocess,enumerate,-,-,-,-,-",
            "h4,Bar,no-attack-here,someimport,cap,-,-,-,-,-",
        ]
        cases = _cases_from_mabel([str(self._write_csv(tmp_path, rows))], max_per_family=2)
        # Foo capped at 2 (h1,h2); h3 dropped by cap; h4 dropped (no ATT&CK id).
        assert len(cases) == 2
        assert {c["sample_id"] for c in cases} == {"h1", "h2"}
        h1 = next(c for c in cases if c["sample_id"] == "h1")
        assert h1["technique_ids"] == ["T1055", "T1071"]
        h2 = next(c for c in cases if c["sample_id"] == "h2")
        assert h2["malware_category"] == "RANSOMWARE"

    def test_missing_mitre_column_skips_file(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.csv"
        p.write_text("sha256_hash,family_name\nh1,Foo\n", encoding="utf-8")
        assert _cases_from_mabel([str(p)], max_per_family=10) == []

    def test_main_mabel_end_to_end(self, tmp_path: Path, monkeypatch) -> None:
        p = self._write_csv(
            tmp_path,
            ["h1,Foo,T1055: Injection,createremotethread,inject process,win_registry,-,-,-,-"],
        )
        out = tmp_path / "corpus.json"
        monkeypatch.setattr(
            sys, "argv", ["x", "--mabel-csv", str(p), "--out", str(out), "--max-per-family", "5"]
        )
        assert main() == 0
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["schema"] == "maljan-attck-case-corpus/v1"
        assert doc["cases"][0]["technique_ids"] == ["T1055"]
