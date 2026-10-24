"""The job package's stored run is held to what the served surfaces say.

A package whose run files carry the served report row, bundle and Markdown
adds no defect; one whose report row names another verdict, or whose bundle
drops a technique, is named as a package defect. The package is read from a
stored-run directory the way the live reader reads the download.
"""

from __future__ import annotations

import copy
import io
import json
import tarfile
from pathlib import Path
from typing import Any

from scripts.audit import surfaces

from tests.unit.scripts._surfaces_run import clean_run, clean_spec, defects, write_run


def _package(run: dict[str, Any]) -> bytes:
    members = {
        "run/report-byjob.json": json.dumps(run["report_row"]),
        "run/stix-bundle.json": json.dumps(run["stix"]),
        "report/report.md": run["markdown"],
    }
    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w:gz") as archive:
        for name, text in members.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return blob.getvalue()


def _audit_with(tmp_path: Path, packed: dict[str, Any]) -> dict[str, Any]:
    run = clean_run()
    directory = write_run(tmp_path / "run", run)
    (directory / "package.tar.gz").write_bytes(_package(packed))
    loaded = surfaces.load_run(directory)
    assert set(loaded["package"]) == {"report-byjob.json", "stix-bundle.json", "report/report.md"}
    return surfaces.audit(loaded, clean_spec())


def test_a_package_of_the_served_run_adds_no_defect(tmp_path: Path) -> None:
    result = _audit_with(tmp_path, clean_run())

    assert defects(result) == []
    assert "package" not in result["not_checked"]


def test_a_package_that_names_another_verdict_is_named(tmp_path: Path) -> None:
    packed = copy.deepcopy(clean_run())
    packed["report_row"]["verdict"] = "Benign"

    result = _audit_with(tmp_path, packed)

    assert set(defects(result)) == {("differs", "verdict", "package")}


def test_a_package_bundle_without_a_technique_is_named(tmp_path: Path) -> None:
    packed = copy.deepcopy(clean_run())
    packed["stix"]["objects"] = [
        o for o in packed["stix"]["objects"] if o["type"] != "attack-pattern"
    ]

    result = _audit_with(tmp_path, packed)

    assert set(defects(result)) == {("differs", "identity", "package")}
