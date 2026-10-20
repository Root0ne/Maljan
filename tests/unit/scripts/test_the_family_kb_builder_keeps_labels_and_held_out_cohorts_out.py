"""The family-fingerprint builder reads no label or id column and no held-out sample.

A fingerprint built from the cohort an evaluation scores, or from a column
that names the family or identifies the sample, would let the catalogue
answer the evaluation's own question. The held-out cohorts' sha256 set is
built once from the manifest and applied to every input: the manifest's own
training cohorts, a folder-per-family tree (by each file's SHA-256) and a CSV
(by its ``--sha-col``). The feature columns are taken by name, and one that is
the family column or an id column, or one the CSV lacks, is refused.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from scripts.knowledge import build_family_feature_kb as kb

HELD_SHA = "b" * 64


def _csv(path: Path) -> Path:
    path.write_text(
        "sha256,family,label,imports\n"
        f"{'a' * 64},FamA,FamA,CreateFileW\n"
        f"{'c' * 64},FamA,FamA,WriteFile\n"
        f"{HELD_SHA},FamB,FamB,socket\n",
        encoding="utf-8",
    )
    return path


def _run(monkeypatch: pytest.MonkeyPatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["build_family_feature_kb.py", *argv])
    return kb.main()


def _manifest(path: Path, test: list[dict[str, Any]] | None = None) -> Path:
    held = test if test is not None else [
        {"sha256": HELD_SHA, "signature": "FamB", "file_type": "exe"}
    ]  # fmt: skip
    path.write_text(
        json.dumps(
            {
                "cohorts": {
                    "train": [{"sha256": "a" * 64, "signature": "FamA", "file_type": "exe"}],
                    "test": held,
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def test_csv_rows_are_profiled_from_the_named_columns_only(tmp_path: Path) -> None:
    profiles = kb._profiles_from_csv(_csv(tmp_path / "f.csv"), "family", ["imports"], ["sha256"])
    assert profiles == {"FamA": ["imports: CreateFileW", "imports: WriteFile"],
                        "FamB": ["imports: socket"]}  # fmt: skip


@pytest.mark.parametrize(
    "argv",
    [
        ["--id-cols", "sha256"],
        ["--text-cols", "imports"],
    ],
)
def test_csv_without_text_or_id_columns_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
) -> None:
    out = tmp_path / "out.json"
    status = _run(monkeypatch, "--csv", str(_csv(tmp_path / "f.csv")), "--out", str(out),
                  "--min-per-family", "1", *argv)  # fmt: skip
    assert status == 2
    err = capsys.readouterr().err
    assert "--text-cols" in err and "--id-cols" in err
    assert not out.exists()


@pytest.mark.parametrize("text", [["imports", "family"], ["imports", "sha256"], ["label"]])
def test_a_text_column_overlapping_the_family_or_an_id_column_is_refused(
    tmp_path: Path, text: list[str]
) -> None:
    with pytest.raises(SystemExit, match="overlap"):
        kb._profiles_from_csv(_csv(tmp_path / "f.csv"), "family", text, ["sha256", "label"])


def test_a_named_column_the_csv_lacks_is_refused_not_replaced_by_every_column(
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit, match="not in the CSV"):
        kb._profiles_from_csv(_csv(tmp_path / "f.csv"), "family", ["exports"], ["sha256"])


def test_a_held_out_csv_row_is_left_out_by_its_sha_column(tmp_path: Path) -> None:
    held = kb.held_out_shas(_manifest(tmp_path / "m.json"), ["test"])
    profiles = kb._profiles_from_csv(
        _csv(tmp_path / "f.csv"), "family", ["imports"], ["sha256"], sha_col="sha256", held=held
    )
    assert "FamB" not in profiles and len(profiles["FamA"]) == 2


def test_a_held_out_csv_needs_its_sha_column(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit, match="--sha-col"):
        kb._profiles_from_csv(_csv(tmp_path / "f.csv"), "family", ["imports"], ["sha256"],
                              held=frozenset({HELD_SHA}))  # fmt: skip
    status = _run(monkeypatch, "--csv", str(_csv(tmp_path / "f.csv")), "--text-cols", "imports",
                  "--id-cols", "sha256", "--manifest", str(_manifest(tmp_path / "m.json")),
                  "--held-out", "test", "--out", str(tmp_path / "o.json"))  # fmt: skip
    assert status == 2
    assert "--sha-col" in capsys.readouterr().err


def test_a_held_out_sample_file_is_left_out_by_its_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "tree"
    (root / "FamA").mkdir(parents=True)
    kept, gone = root / "FamA" / "one.bin", root / "FamA" / "two.bin"
    kept.write_bytes(b"kept bytes")
    gone.write_bytes(b"held-out bytes")
    held = frozenset({hashlib.sha256(b"held-out bytes").hexdigest()})
    profiled: list[str] = []

    def profile(sample_path: str) -> object:
        profiled.append(Path(sample_path).name)
        return None

    monkeypatch.setattr(kb, "build_static_analysis", profile)
    kb._profiles_from_samples_dir(root, held)
    assert profiled == ["one.bin"]


def test_the_manifest_is_read_only_for_the_named_cohorts(tmp_path: Path) -> None:
    samples = kb._manifest_samples(_manifest(tmp_path / "m.json"), ["train"], ["test"])
    assert [s["signature"] for s in samples] == ["FamA"]


def test_a_held_out_cohort_is_refused_as_a_training_cohort(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="held out"):
        kb._manifest_samples(_manifest(tmp_path / "m.json"), ["train", "test"], ["test"])


def test_an_unknown_cohort_is_refused(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="not in the manifest"):
        kb._manifest_samples(_manifest(tmp_path / "m.json"), ["trian"], ["test"])


def test_a_sample_also_in_the_held_out_cohort_is_left_out(tmp_path: Path) -> None:
    shared = {"sha256": "a" * 64, "signature": "FamA", "file_type": "exe"}
    path = _manifest(tmp_path / "m.json", test=[shared])
    assert kb._manifest_samples(path, ["train"], ["test"]) == []


def test_a_manifest_without_held_out_cohorts_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    status = _run(monkeypatch, "--manifest", str(_manifest(tmp_path / "m.json")),
                  "--flat-dir", str(flat), "--cohorts", "train",
                  "--out", str(tmp_path / "o.json"))  # fmt: skip
    assert status == 2
    assert "--held-out" in capsys.readouterr().err


def test_building_from_a_manifest_needs_its_cohorts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    status = _run(monkeypatch, "--manifest", str(_manifest(tmp_path / "m.json")),
                  "--flat-dir", str(flat), "--held-out", "test",
                  "--out", str(tmp_path / "o.json"))  # fmt: skip
    assert status == 2
    assert "--cohorts" in capsys.readouterr().err


def test_a_built_catalogue_has_a_record_of_the_cohorts_folded_into_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "catalog.json"
    code = _run(
        monkeypatch,
        "--manifest", str(_manifest(tmp_path / "m.json")),
        "--held-out", "test",
        "--csv", str(_csv(tmp_path / "f.csv")),
        "--text-cols", "imports",
        "--id-cols", "sha256",
        "--sha-col", "sha256",
        "--min-per-family", "1",
        "--out", str(out),
    )  # fmt: skip
    assert code == 0
    record = json.loads(kb.build_manifest_path(out).read_text(encoding="utf-8"))
    assert record["held_out_cohorts"] == ["test"]
    assert record["training_cohorts"] == []
    assert record["held_out_sample_count"] == 1
    assert record["families"] == {"FamA": 2}
    assert record["catalog_sha256"] == hashlib.sha256(out.read_bytes()).hexdigest()


def test_a_samples_dir_build_records_its_tree_and_no_cohorts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "tree"
    (root / "FamA").mkdir(parents=True)
    for name in ("one.bin", "two.bin"):
        (root / "FamA" / name).write_bytes(name.encode())
    monkeypatch.setattr(kb, "build_static_analysis", lambda sample_path: object())
    monkeypatch.setattr(kb, "build_sample_profile_text", lambda static: "imports: CreateFileW")
    out = tmp_path / "catalog.json"
    code = _run(monkeypatch, "--samples-dir", str(root), "--min-per-family", "1", "--out", str(out))
    assert code == 0
    record = json.loads(kb.build_manifest_path(out).read_text(encoding="utf-8"))
    assert record["inputs"]["samples_dir"] == str(root)
    assert record["inputs"]["manifest"] is None and record["inputs"]["csv"] == []
    assert record["training_cohorts"] == [] and record["held_out_cohorts"] == []
    assert record["families"] == {"FamA": 2}


def test_a_csv_only_build_records_its_files_and_no_cohorts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "catalog.json"
    csv_path = _csv(tmp_path / "f.csv")
    code = _run(
        monkeypatch,
        "--csv", str(csv_path),
        "--text-cols", "imports",
        "--id-cols", "sha256",
        "--min-per-family", "1",
        "--out", str(out),
    )  # fmt: skip
    assert code == 0
    record = json.loads(kb.build_manifest_path(out).read_text(encoding="utf-8"))
    assert record["inputs"]["csv"] == [str(csv_path)]
    assert record["held_out_cohorts"] == [] and record["held_out_sample_count"] == 0
    assert set(record["families"]) == {"FamA", "FamB"}
    assert not list(tmp_path.glob(".*.part"))
