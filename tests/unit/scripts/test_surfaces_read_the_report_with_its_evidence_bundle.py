"""The surface checker reads an analyst report with the evidence bundle beside it.

The analyst report prints its findings and leaves the record behind them to
the bundle, so a finding the report does not print is looked for in the two
together: the bundle's sections (its JSON's Markdown) after the report's
Markdown, its HTML after the report's HTML. A report in the single-file
layout, with no bundle, is read as it always was; the job package's
``report.md`` is compared with the served Markdown alone.
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.audit import surfaces

from tests.unit.scripts._surfaces_run import clean_run, clean_spec, defects, write_run


def _split(run: dict) -> tuple[dict, dict, str]:
    """The run with its Markdown cut to the title, and a bundle holding the rest."""
    title, _, rest = run["markdown"].partition("\n## ")
    bundle = {"sections": [{"anchor": "sec-x", "title": "x", "markdown": "## " + rest}]}
    html = run["html"]
    run = {**run, "markdown": title, "html": "<html><body><p>title</p></body></html>"}
    return run, bundle, html


def test_a_finding_the_bundle_holds_is_no_defect(tmp_path: Path) -> None:
    run, bundle, html = _split(clean_run())
    directory = write_run(tmp_path / "run", run)
    (directory / surfaces.BUNDLE_JSON).write_text(json.dumps(bundle), encoding="utf-8")
    (directory / surfaces.BUNDLE_HTML).write_text(html, encoding="utf-8")

    loaded = surfaces.load_run(directory)
    result = surfaces.audit(loaded, clean_spec())

    assert defects(result) == []
    assert loaded["markdown_served"] == run["markdown"]


def test_without_the_bundle_the_findings_it_holds_are_missed(tmp_path: Path) -> None:
    run, _, _ = _split(clean_run())
    directory = write_run(tmp_path / "run", run)

    result = surfaces.audit(surfaces.load_run(directory), clean_spec())

    assert {surface for _, _, surface in defects(result)} >= {"markdown", "html"}


def test_a_single_file_report_is_read_as_it_is() -> None:
    run = clean_run()
    read = surfaces.with_bundle(dict(run), None, None)

    assert read["markdown"] == run["markdown"] == read["markdown_served"]
    assert read["html"] == run["html"]


def test_the_package_s_markdown_is_compared_with_the_served_report_alone() -> None:
    run, bundle, html = _split(clean_run())
    served = run["markdown"]
    read = surfaces.with_bundle(run, bundle, html)
    read["package"] = {"report/report.md": served}

    result = surfaces.audit(read, clean_spec())

    assert not [d for d in result["defects"] if d["finding"] == "report.md"]
