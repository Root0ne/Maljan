"""A surface that filters on purpose is held to its rule, never skipped.

The default ``/iocs`` must be exactly the ``include=all`` rows that are
published; the Markdown may cut a long value only where its rule cuts it,
and a cut anywhere else (or inside a defang mark) is a truncation; the STIX
export's withheld values are counted, not reported; a usage snapshot a stored
run took mid-run is set aside, while the same gap read live is a defect.
"""

from __future__ import annotations

from typing import Any

from scripts.audit import surfaces

from tests.unit.scripts._surfaces_run import IP, clean_run, clean_spec, defects


def _with_default_feed(run: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    run["iocs_default"] = {"items": rows, "total": len(rows)}
    return run


def test_the_default_feed_is_the_published_rows_of_include_all() -> None:
    run = clean_run()
    published = [r for r in run["iocs_all"]["items"] if r["published"]]

    result = surfaces.audit(_with_default_feed(run, published), clean_spec())

    assert defects(result) == []
    assert result["filtered"]["iocs_default: unpublished rows"] == 1
    assert "iocs_default" not in result["not_checked"]


def test_a_default_feed_with_a_withheld_row_breaks_its_rule() -> None:
    run = clean_run()
    rows = list(run["iocs_all"]["items"])

    result = surfaces.audit(_with_default_feed(run, rows), clean_spec())

    assert set(defects(result)) == {("filter", "ioc", "iocs_default")}


def test_a_default_feed_missing_a_published_row_breaks_its_rule() -> None:
    run = clean_run()
    rows = [r for r in run["iocs_all"]["items"] if r["published"]][:1]

    result = surfaces.audit(_with_default_feed(run, rows), clean_spec())

    assert set(defects(result)) == {("filter", "ioc", "iocs_default")}


def test_a_feed_row_without_a_flag_cannot_be_filtered() -> None:
    run = clean_run()
    del run["iocs_all"]["items"][2]["published"]

    result = surfaces.audit(run, clean_spec())

    assert set(defects(result)) == {("filter", "ioc", "iocs_default")}


def test_a_cell_cut_at_its_declared_length_is_filtered_not_a_defect() -> None:
    run = clean_run()
    long = "x" * 120 + " " + "y" * 120
    for mr in (run["report_row"]["malware_report"], run["report_full"]):
        mr["sections"][0]["rows"] = [[long]]
    cut = long[:159] + "…"
    run["markdown"] += f"\n| {cut} |"
    run["html"] += f"<td>{cut}</td>"

    result = surfaces.audit(run, clean_spec())

    assert defects(result) == []
    assert result["filtered"]["markdown:strings: value cut at its declared length"] == 1


def test_a_defanged_cell_may_be_cut_earlier_by_what_defanging_adds() -> None:
    run = clean_run()
    hosts = ", ".join(f"host{i}.example.org" for i in range(20))
    for mr in (run["report_row"]["malware_report"], run["report_full"]):
        mr["sections"][0]["rows"] = [[hosts]]
    written = hosts.replace(".", "[.]")[:159] + "…"
    run["markdown"] += f"\n| {written} |"
    run["html"] += f"<td>{written}</td>"

    result = surfaces.audit(run, clean_spec())

    assert defects(result) == []


def test_a_cell_cut_short_of_its_declared_length_is_truncated() -> None:
    run = clean_run()
    long = "z" * 300
    for mr in (run["report_row"]["malware_report"], run["report_full"]):
        mr["sections"][0]["rows"] = [[long]]
    run["markdown"] += f"\n| {long[:40]}… |"
    run["html"] += f"<td>{long[:40]}…</td>"

    result = surfaces.audit(run, clean_spec())

    assert set(defects(result)) == {
        ("truncated", "section_item", "markdown:strings"),
        ("truncated", "section_item", "html:strings"),
    }


def test_a_cut_inside_a_defang_mark_is_a_truncation() -> None:
    run = clean_run()
    value = "c2=https://first.example/live/, https://second.example/live/"
    for mr in (run["report_row"]["malware_report"], run["report_full"]):
        mr["sections"][0]["rows"] = [[value]]
    written = "c2=hxxps://first[.]example/live/, hxxps://second[.…"
    run["markdown"] += f"\n| {written} |"
    run["html"] += f"<td>{written}</td>"

    result = surfaces.audit(run, clean_spec())

    assert ("truncated", "section_item", "markdown:strings") in set(defects(result))


def test_the_export_s_withheld_values_are_counted() -> None:
    result = surfaces.audit(clean_run(), clean_spec())

    assert result["filtered"]["stix: withheld IOC"] == 1
    assert IP not in str(result["defects"])


def test_a_stored_usage_snapshot_is_set_aside_and_a_live_gap_is_a_defect() -> None:
    stored = clean_run()
    stored["report_row"]["run_summary"]["tokens"]["llm_calls"] = 3
    stored["run_summary"]["tokens"]["llm_calls"] = 3
    stored["events"][2:2] = [{"type": "model_usage", "payload": {}}] * 2
    stored["usage"] = {"calls": 2, "tokens": {"llm_calls": 2}}
    stored["_stored"] = True

    result = surfaces.audit(stored, clean_spec())

    assert defects(result) == []
    assert "snapshot" in result["not_checked"]["usage"]

    live = dict(stored)
    del live["_stored"]
    assert set(defects(surfaces.audit(live, clean_spec()))) == {("differs", "count", "usage")}
