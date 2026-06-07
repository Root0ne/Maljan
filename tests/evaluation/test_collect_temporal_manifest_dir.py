"""Unit tests for the ``--source dir`` (undated folder-per-family) adapter of
``collect_temporal_manifest``. No network; pure filesystem with tmp dirs."""

from __future__ import annotations

import hashlib

from tests.evaluation.collect_temporal_manifest import (
    _UNDATED_YEAR,
    _detect_file_type,
    build_undated_manifest,
    copy_manifest_binaries,
    records_from_dir,
)

# Minimal valid magic-byte headers.
_MZ = b"MZ\x90\x00" + b"\x00" * 60  # PE
_ELF = b"\x7fELF" + b"\x00" * 60  # ELF


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestDetectFileType:
    def test_extension_wins_when_in_scope(self, tmp_path) -> None:
        p = tmp_path / "x.dll"
        p.write_bytes(b"\x00\x00")
        assert _detect_file_type(p) == "dll"

    def test_magic_fallback_pe_and_elf(self, tmp_path) -> None:
        pe = tmp_path / "builder"  # no extension
        pe.write_bytes(_MZ)
        elf = tmp_path / "payload.bin"  # out-of-scope ext, ELF magic
        elf.write_bytes(_ELF)
        assert _detect_file_type(pe) == "exe"
        assert _detect_file_type(elf) == "elf"

    def test_unknown_stays_out_of_scope(self, tmp_path) -> None:
        p = tmp_path / "note.txt"
        p.write_bytes(b"hello world")
        assert _detect_file_type(p) not in {"exe", "dll", "sys", "elf", "so"}


class TestRecordsFromDir:
    def _tree(self, tmp_path):
        root = tmp_path / "rats"
        (root / "AsyncRAT").mkdir(parents=True)
        (root / "QuasarRAT").mkdir(parents=True)
        # AsyncRAT: one PE-by-ext, one PE-by-magic, one out-of-scope apk (dropped)
        (root / "AsyncRAT" / "a.exe").write_bytes(_MZ + b"A")
        (root / "AsyncRAT" / "builder").write_bytes(_MZ + b"B")
        (root / "AsyncRAT" / "stub.apk").write_bytes(b"PK\x03\x04rest")
        # QuasarRAT: one ELF
        (root / "QuasarRAT" / "q.elf").write_bytes(_ELF + b"Q")
        return root

    def test_walks_family_folders_and_scopes(self, tmp_path) -> None:
        root = self._tree(tmp_path)
        records, path_map = records_from_dir(root, per_family=10)
        families = {r.signature for r in records}
        assert families == {"AsyncRAT", "QuasarRAT"}
        # apk dropped: AsyncRAT yields 2 (a.exe + magic builder), QuasarRAT 1.
        assert len(records) == 3
        assert all(r.year == _UNDATED_YEAR for r in records)
        assert all(r.first_seen == "" for r in records)
        # file types resolved via ext + magic.
        assert {r.file_type for r in records} == {"exe", "elf"}
        # path_map covers every emitted sha and points at a real file.
        assert set(path_map) == {r.sha256 for r in records}
        assert all(p.is_file() for p in path_map.values())

    def test_sha256_is_content_addressed(self, tmp_path) -> None:
        root = self._tree(tmp_path)
        records, _ = records_from_dir(root, per_family=10)
        shas = {r.sha256 for r in records}
        assert _sha(_MZ + b"A") in shas
        assert _sha(_ELF + b"Q") in shas

    def test_per_family_cap(self, tmp_path) -> None:
        root = tmp_path / "rats"
        (root / "BigFam").mkdir(parents=True)
        for i in range(8):
            (root / "BigFam" / f"s{i}.exe").write_bytes(_MZ + bytes([i]))
        records, path_map = records_from_dir(root, per_family=3)
        assert len(records) == 3
        assert len(path_map) == 3

    def test_dedup_identical_binaries(self, tmp_path) -> None:
        root = tmp_path / "rats"
        (root / "Dup").mkdir(parents=True)
        (root / "Dup" / "one.exe").write_bytes(_MZ + b"SAME")
        (root / "Dup" / "two.exe").write_bytes(_MZ + b"SAME")  # identical content
        records, _ = records_from_dir(root, per_family=10)
        assert len(records) == 1

    def test_missing_root_is_empty(self, tmp_path) -> None:
        records, path_map = records_from_dir(tmp_path / "nope", per_family=5)
        assert records == [] and path_map == {}


class TestBuildUndatedManifest:
    def test_single_undated_cohort(self, tmp_path) -> None:
        root = tmp_path / "rats"
        (root / "AsyncRAT").mkdir(parents=True)
        (root / "AsyncRAT" / "a.exe").write_bytes(_MZ + b"A")
        records, _ = records_from_dir(root, per_family=10)
        manifest = build_undated_manifest(records, source="dir")
        assert list(manifest["cohorts"]) == [_UNDATED_YEAR]
        assert manifest["counts"] == {_UNDATED_YEAR: 1}
        assert manifest["total"] == 1
        assert manifest["source"] == "dir"
        # samples carry the undated year so drift_delta excludes them.
        assert manifest["cohorts"][_UNDATED_YEAR][0]["year"] == _UNDATED_YEAR


class TestCopyManifestBinaries:
    def test_copies_sampled_binaries_content_addressed(self, tmp_path) -> None:
        root = tmp_path / "rats"
        (root / "AsyncRAT").mkdir(parents=True)
        (root / "AsyncRAT" / "a.exe").write_bytes(_MZ + b"A")
        (root / "AsyncRAT" / "q.bin").write_bytes(_ELF + b"Q")  # elf via magic
        records, path_map = records_from_dir(root, per_family=10)
        manifest = build_undated_manifest(records, source="dir")
        dest = tmp_path / "samples"

        n = copy_manifest_binaries(manifest, path_map, dest)

        assert n == 2
        for s in manifest["cohorts"][_UNDATED_YEAR]:
            assert (dest / f"{s['sha256']}.{s['file_type']}").is_file()

    def test_skips_already_present(self, tmp_path) -> None:
        root = tmp_path / "rats"
        (root / "AsyncRAT").mkdir(parents=True)
        (root / "AsyncRAT" / "a.exe").write_bytes(_MZ + b"A")
        records, path_map = records_from_dir(root, per_family=10)
        manifest = build_undated_manifest(records, source="dir")
        dest = tmp_path / "samples"
        dest.mkdir()
        sha = manifest["cohorts"][_UNDATED_YEAR][0]["sha256"]
        (dest / f"{sha}.exe").write_bytes(b"already")

        n = copy_manifest_binaries(manifest, path_map, dest)
        assert n == 0  # pre-existing target left untouched
        assert (dest / f"{sha}.exe").read_bytes() == b"already"
