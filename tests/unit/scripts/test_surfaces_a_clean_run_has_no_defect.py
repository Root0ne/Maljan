"""A job whose surfaces agree is clean, from memory and from a stored-run directory.

The synthetic run carries one finding of each kind on every surface that
should carry it. The checker finds no defect in it, exits 0 on its stored
copy and lists the surfaces the directory does not hold as not checked rather
than as defects.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.audit import surfaces

from tests.unit.scripts._surfaces_run import clean_run, clean_spec, defects, write_run


def test_the_clean_run_has_no_defect() -> None:
    result = surfaces.audit(clean_run(), clean_spec())

    assert defects(result) == []
    assert result["status"] == "clean"
    assert result["canonical"]["techniques"] == 1
    assert result["canonical"]["iocs"] == 3
    # Every finding kind was looked for.
    for kind in ("verdict", "severity", "technique", "ioc", "section", "citation", "process"):
        assert result["checked"].get(kind, 0) > 0, kind


def test_the_stored_copy_exits_zero_and_names_what_it_lacks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    run = write_run(tmp_path / "run", clean_run())
    spec = tmp_path / "web_fields.json"
    spec.write_text(json.dumps(clean_spec()), encoding="utf-8")
    out = tmp_path / "report.json"

    status = surfaces.main(["--run", str(run), "--web-fields", str(spec), "--out", str(out)])

    assert status == 0
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["defect_count"] == 0
    assert "package" in written["not_checked"]
    assert "follow_ups" in written["not_checked"]
    # The default /iocs is not stored: its rule is checked on the include=all rows.
    assert "include=all" in written["not_checked"]["iocs_default"]
    assert capsys.readouterr().err.startswith("clean: 0 defect(s)")


def test_a_directory_without_a_report_row_is_a_read_error(tmp_path: Path) -> None:
    run = clean_run()
    del run["report_row"]
    directory = write_run(tmp_path / "run", run)

    assert surfaces.main(["--run", str(directory)]) == 2


def test_a_live_read_takes_only_an_http_url() -> None:
    assert surfaces.main(["--api", "file:///etc", "--job", "job-1"]) == 2
    assert surfaces.main(["--api", "http://127.0.0.1:9"]) == 2


def test_the_shipped_field_map_names_no_kind_no_tab_renders() -> None:
    result = surfaces.audit(clean_run())

    unrendered = {kind for cls, kind, _ in defects(result) if cls == "unrendered"}
    assert unrendered == set()
