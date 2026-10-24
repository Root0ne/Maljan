"""A job's package: deterministic, streamed, signed, and re-checked file by file.

The package is built from a stored-run directory (``app.services.job_package``)
and verified by ``python -m scripts.package.verify``: every file against the
manifest, the manifest against its HMAC signature, and the embedded ledger
seal with the X4b check (``scripts.ledger.verify.verify_run``).
"""

from __future__ import annotations

import gzip
import hashlib
import io
import itertools
import json
import tarfile
import tracemalloc
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException
from scripts.ledger.verify import verify_run
from scripts.package import build as build_cli
from scripts.package import verify as verify_cli
from scripts.replay.stored import FILES

from app.services import job_package, ledger_chain, run_export
from app.worker.analysis_worker import _evidence_row
from maljan.core.delivery_limits import SAMPLE_UPLOAD_MAX_BYTES
from maljan.reporting.models import DynamicBehavior, FileHashes, MalwareReport, SampleIdentity
from maljan.schemas.evidence import LedgerEntry

CHAIN = ledger_chain.derive_key("package-test-material")
SIGNER = ledger_chain.derive_key("package-test-material", job_package.SIGNATURE_LABEL)
OTHER_SIGNER = ledger_chain.derive_key("package-test-other", job_package.SIGNATURE_LABEL)
NOW = datetime(2026, 10, 19, 9, 0, tzinfo=UTC)
MAX = SAMPLE_UPLOAD_MAX_BYTES


@pytest.fixture(autouse=True)
def _keys(monkeypatch: Any) -> None:
    monkeypatch.setattr(ledger_chain, "known_keys", lambda: {CHAIN.key_id: CHAIN})


def _run(
    into: Path,
    *,
    spilled: list[dict[str, Any]] | None = None,
    dynamic: bool = False,
    misp: list[dict[str, Any]] | None = None,
) -> Path:
    """A sealed stored run written the way the replay export writes one."""
    job_id = uuid.uuid4()
    rows = [
        _evidence_row(
            LedgerEntry(
                id=f"ev_{seq:04d}",
                tool="pe_info",
                seq=seq,
                output=f"answer {seq}",
                spilled=spilled if seq == 1 else None,
            ).model_dump(mode="json"),
            job_id=job_id,
            written_at=NOW,
        )
        for seq in (1, 2, 3)
    ]
    head = ledger_chain.chain_rows(job_id, rows, CHAIN)
    malware_report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32, md5="cd" * 16)),
        verdict="Malware",
        dynamic=DynamicBehavior(notable_apis=[{"api": "VirtualAlloc"}]) if dynamic else None,
        misp_attributes=misp,
    ).model_dump(mode="json")
    report = {
        "id": str(uuid.uuid4()),
        "job_id": str(job_id),
        "verdict": "Malicious",
        "overall_confidence": 0.8,
        "malware_category": "loader",
        "stix_bundle": {"type": "bundle", "id": "bundle--1", "objects": []},
        "judge_stix_bundle": None,
        "mitre_techniques": [],
        "agent_reports": {},
        "negotiation_log": {},
        "run_summary": None,
        "malware_report": malware_report,
        "incomplete_reason": None,
    }
    core = ledger_chain.seal(
        job_id,
        rows,
        head,
        report_sha256=ledger_chain.report_digest(report),
        sealed_at=NOW,
        key=CHAIN,
        report_id=report["id"],
    )
    seal = ledger_chain.anchored(core, landed=False, key=CHAIN)
    report["ledger_seal"] = seal
    report["malware_report"] = ledger_chain.with_seal(report["malware_report"], seal)
    job_rows = run_export.JobRows(
        job=run_export.with_sample(
            {"id": str(job_id), "status": "completed"},
            {"sha256": "ab" * 32, "original_filename": "x.exe"},
        ),
        report=report,
        evidence=[
            ledger_chain.entry_fields(r) | {"digest": r.digest, "chain": r.chain} for r in rows
        ],
    )
    run_export.write_files(run_export.run_files(job_rows), into)
    return into


def _build(run: Path, out: Path, **kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault("key", SIGNER)
    kwargs.setdefault("max_bytes", MAX)
    with out.open("wb") as handle:
        return job_package.build_package(run, handle, verification=verify_run(run), **kwargs)


def _verify(path: Path, keys: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
    return job_package.verify_package(
        path,
        verify_run=verify_run,
        max_bytes=kwargs.pop("max_bytes", MAX),
        keys={SIGNER.key_id: SIGNER} if keys is None else keys,
        **kwargs,
    )


def _members(path: Path) -> dict[str, bytes]:
    with tarfile.open(path, "r:gz") as tar:
        out = {}
        for member in tar.getmembers():
            handle = tar.extractfile(member)
            assert handle is not None
            out[member.name] = handle.read()
        return out


def _rewrite(path: Path, members: dict[str, bytes], extra: list[tarfile.TarInfo] = ()) -> None:  # type: ignore[assignment]
    """``members`` written as a package by a holder of the key: the file digest is
    recomputed (under the key when the members hold a signature), so only what the
    archive holds is under test."""
    key = SIGNER if "manifest.sig" in members else None
    with (
        path.open("wb") as out,
        job_package.archive_stream(out, key=key) as gz,
        tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tar,
    ):
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for info in extra:
            tar.addfile(info)


def test_the_run_layout_is_the_one_the_replay_reads():
    assert set(run_export.LAYOUT) == set(FILES)


def test_the_same_run_builds_the_same_bytes_and_verifies(tmp_path: Path):
    run = _run(tmp_path / "run")
    first = _build(run, tmp_path / "a.tar.gz")
    second = _build(run, tmp_path / "b.tar.gz")
    assert (tmp_path / "a.tar.gz").read_bytes() == (tmp_path / "b.tar.gz").read_bytes()
    assert first == second
    with tarfile.open(tmp_path / "a.tar.gz", "r:gz") as tar:
        infos = tar.getmembers()
    names = [i.name for i in infos]
    assert names[:2] == ["manifest.json", "manifest.sig"]
    assert names == sorted(names, key=job_package.archive_order)
    assert all(
        (i.isreg(), i.mtime, i.mode, i.uid, i.gid, i.uname, i.gname)
        == (True, 0, 0o644, 0, 0, "", "")
        for i in infos
    )
    assert {"manifest.json", "manifest.sig", "seal.json", "report/report.md"} <= set(names)
    assert "run/evidence.json" in names and "export/stix-bundle.json" in names
    listed = {f["path"] for f in first["files"]}
    assert listed == set(names) - {"manifest.json", "manifest.sig"}
    assert first["sample"]["included"] is False
    assert first["sample"]["hashes"]["sha256"] == "ab" * 32
    assert first["sample"]["note"] == (
        "The sample file itself is not included; spilled tool answers may contain bytes from it."
    )
    manifest_bytes = _members(tmp_path / "a.tar.gz")["manifest.json"]
    assert job_package._depth(manifest_bytes) <= job_package.MANIFEST_DEPTH
    verdict = _verify(tmp_path / "a.tar.gz")
    assert (verdict["status"], verdict["signature"]) == ("verified", "valid"), verdict
    assert verdict["seal"]["status"] == "verified"
    assert "only to a holder of that key" in first["signature"]["proves"]


def test_a_tampered_file_is_broken_and_named(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    members = _members(tmp_path / "p.tar.gz")
    members["report/report.md"] += b"\nan edit"
    _rewrite(tmp_path / "p.tar.gz", members)
    verdict = _verify(tmp_path / "p.tar.gz")
    assert (verdict["status"], verdict["file"]) == ("broken", "report/report.md"), verdict


def test_a_tampered_manifest_fails_its_signature(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    members = _members(tmp_path / "p.tar.gz")
    members["report/report.md"] += b"\nan edit"
    manifest = json.loads(members["manifest.json"])
    for entry in manifest["files"]:
        if entry["path"] == "report/report.md":
            import hashlib

            entry["sha256"] = hashlib.sha256(members["report/report.md"]).hexdigest()
            entry["bytes"] = len(members["report/report.md"])
    members["manifest.json"] = json.dumps(manifest, indent=1, sort_keys=True).encode()
    _rewrite(tmp_path / "p.tar.gz", members)
    verdict = _verify(tmp_path / "p.tar.gz")
    assert (verdict["status"], verdict["file"], verdict["signature"]) == (
        "broken",
        "manifest.json",
        "invalid",
    ), verdict

    # The signature stripped: the manifest still says it was signed.
    del members["manifest.sig"]
    _rewrite(tmp_path / "p.tar.gz", members)
    verdict = _verify(tmp_path / "p.tar.gz")
    assert (verdict["status"], verdict["file"]) == ("broken", "manifest.sig"), verdict


def test_an_unsigned_package_fails_where_the_key_is_held_unless_allowed(tmp_path: Path):
    run = _run(tmp_path / "run")
    manifest = _build(run, tmp_path / "u.tar.gz", key=None, unsigned_reason="asked unsigned")
    assert manifest["signature"] == {"absent": "asked unsigned"}
    held = _verify(tmp_path / "u.tar.gz")
    assert (held["status"], held["file"], held["reason"]) == (
        "broken",
        "manifest.sig",
        job_package.UNSIGNED_HELD,
    ), held
    allowed = _verify(tmp_path / "u.tar.gz", allow_unsigned=True)
    assert (allowed["status"], allowed["reason"]) == ("unsigned", job_package.UNSIGNED_ACCEPTED)
    keyless = _verify(tmp_path / "u.tar.gz", keys={})
    assert (keyless["status"], keyless["reason"]) == ("unsigned", job_package.UNSIGNED_NO_KEY)


def test_a_package_signed_before_a_key_rotation_reads_other_key_named(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "o.tar.gz", key=OTHER_SIGNER)
    verdict = _verify(tmp_path / "o.tar.gz")
    assert (verdict["status"], verdict["signature"]) == ("other_key", "other_key"), verdict
    assert OTHER_SIGNER.key_id in verdict["reason"]


def test_missing_parts_are_listed_as_absent_with_why(tmp_path: Path):
    run = _run(tmp_path / "run", spilled=[{"part": "answer", "error": "exceeds upload_max_bytes"}])
    manifest = _build(run, tmp_path / "p.tar.gz")
    absent = {a["part"]: a["reason"] for a in manifest["absent"]}
    assert set(absent) == {
        "misp_event",
        "misp_attributes",
        "run_summary",
        "judge_stix_bundle",
        "sandbox_behaviour",
    }
    assert "builds no MISP event" in absent["misp_event"]
    assert "stored before the platform built them" in absent["misp_attributes"]
    assert "run-summary.json" in absent["run_summary"]
    assert all(absent.values())
    spilled = json.loads(_members(tmp_path / "p.tar.gz")["ledger/spilled.json"])
    assert spilled == [
        {
            "absent": "The part was not kept: exceeds upload_max_bytes.",
            "entry_id": "ev_0001",
            "part": "answer",
            "seq": 1,
        }
    ]
    with_sandbox = _build(_run(tmp_path / "run2", dynamic=True), tmp_path / "s.tar.gz")
    parts = {p["part"]: p for p in with_sandbox["parts"]}
    assert parts["sandbox_behaviour"] == {
        "part": "sandbox_behaviour",
        "path": "run/report.json",
        "pointer": "/dynamic",
    }


def test_a_report_s_misp_attributes_are_a_part_of_the_package(tmp_path: Path):
    attribute = {"type": "md5", "category": "Payload delivery", "value": "cd" * 16}
    manifest = _build(_run(tmp_path / "run", misp=[attribute]), tmp_path / "m.tar.gz")
    parts = {p["part"]: p for p in manifest["parts"]}
    assert parts["misp_attributes"] == {
        "part": "misp_attributes",
        "path": "run/report.json",
        "pointer": "/misp_attributes",
        "count": 1,
    }
    assert "misp_attributes" not in {a["part"] for a in manifest["absent"]}
    report = json.loads(_members(tmp_path / "m.tar.gz")["run/report.json"])
    assert report["misp_attributes"] == [attribute]


def test_a_spilled_part_is_packaged_only_when_its_bytes_verify(tmp_path: Path):
    import hashlib

    blob = b"the whole answer"
    good = hashlib.sha256(blob).hexdigest()
    refs = [
        {"part": "answer", "bytes": len(blob), "sha256": good, "key": "evidence/j/" + good},
        {"part": "output", "bytes": len(blob), "sha256": "0" * 64, "key": "evidence/j/zero"},
    ]
    run = _run(tmp_path / "run", spilled=refs)
    manifest = _build(
        run, tmp_path / "p.tar.gz", fetch=lambda key: iter([blob]), max_object_bytes=MAX
    )
    members = _members(tmp_path / "p.tar.gz")
    assert members[f"ledger/objects/{good}"] == blob
    listed = json.loads(members["ledger/spilled.json"])
    assert listed[0]["path"] == f"ledger/objects/{good}"
    assert listed[1]["absent"] == "The object store handed back bytes of another digest."
    assert {p["part"]: p for p in manifest["parts"]}["spilled_objects"]["kept"] == 1
    offline = _build(run, tmp_path / "o.tar.gz")
    listed = json.loads(_members(tmp_path / "o.tar.gz")["ledger/spilled.json"])
    assert all(r["absent"] == job_package.OFFLINE for r in listed)
    assert {p["part"]: p for p in offline["parts"]}["spilled_objects"]["kept"] == 0


@pytest.mark.parametrize("name", ["../evil.txt", "/etc/evil", "run/../../evil", "run/./x"])
def test_a_traversal_entry_is_rejected_and_nothing_lands_outside(tmp_path: Path, name: str):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    members = _members(tmp_path / "p.tar.gz")
    members[name] = b"planted"
    _rewrite(tmp_path / "p.tar.gz", members)
    verdict = _verify(tmp_path / "p.tar.gz")
    assert (verdict["status"], verdict["file"]) == ("broken", name), verdict
    assert not (tmp_path.parent / "evil.txt").exists()
    assert not (tmp_path / "evil.txt").exists()


def test_a_symbolic_link_entry_is_rejected(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    link = tarfile.TarInfo("run/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    _rewrite(tmp_path / "p.tar.gz", _members(tmp_path / "p.tar.gz"), [link])
    verdict = _verify(tmp_path / "p.tar.gz")
    assert (verdict["status"], verdict["file"]) == ("broken", "run/link"), verdict


def test_a_symbolic_link_in_the_run_directory_is_refused(tmp_path: Path):
    run = _run(tmp_path / "run")
    (run / "stix-judge.json").symlink_to(tmp_path / "elsewhere.json")
    with pytest.raises(job_package.PackageError):
        _build(run, tmp_path / "p.tar.gz")


def test_build_and_verify_stream_rather_than_hold_a_large_file(tmp_path: Path):
    run = _run(tmp_path / "run")
    size = 4 * 1024 * 1024
    with (run / "events.json").open("w", encoding="utf-8") as handle:
        handle.write("[")
        handle.write(",".join(['"' + "e" * 1000 + '"'] * (size // 1003)))
        handle.write("]")
    verification = verify_run(run)
    tracemalloc.start()
    try:
        with (tmp_path / "p.tar.gz").open("wb") as handle:
            job_package.build_package(
                run, handle, verification=verification, key=SIGNER, max_bytes=MAX
            )
        _, built_peak = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        verdict = _verify(tmp_path / "p.tar.gz")
        _, verify_peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert verdict["status"] == "verified", verdict
    assert built_peak < size // 4, built_peak
    assert verify_peak < size // 4, verify_peak


def test_the_offline_commands_build_and_verify_an_exported_run(
    tmp_path: Path, monkeypatch: Any, capsys: Any
):
    monkeypatch.setattr(job_package, "signature_key", lambda: (SIGNER, None))
    run = _run(tmp_path / "run")
    out = tmp_path / "job.tar.gz"
    assert build_cli.main(["--run", str(run), "--out", str(out)]) == 0
    manifest = json.loads(capsys.readouterr().out)
    assert manifest["signature"]["key_id"] == SIGNER.key_id
    assert not out.with_name(out.name + ".partial").exists()
    assert verify_cli.main([str(out)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "verified"

    members = _members(out)
    members["run/evidence.json"] = members["run/evidence.json"].replace(b"answer 2", b"answer X")
    _rewrite(out, members)
    assert verify_cli.main([str(out)]) == 1
    assert json.loads(capsys.readouterr().out)["file"] == "run/evidence.json"


class _Service:
    def __init__(self, job: Any) -> None:
        self._job = job

    async def get_job(self, job_id: uuid.UUID, user: Any) -> Any:
        return self._job


class _User:
    id = uuid.uuid4()


class _Db:
    bind = object()


@pytest.mark.asyncio
async def test_the_route_is_owner_only_and_streams_the_package(tmp_path: Path, monkeypatch: Any):
    from app.api.v1.jobs import get_job_package

    called: list[Any] = []

    async def _build_for_job(db: Any, job_id: Any, out: Any) -> dict[str, Any]:
        called.append(job_id)
        out.write(b"package bytes")
        return {"seal": {"status": "verified"}, "signature": {"key_id": SIGNER.key_id}}

    monkeypatch.setattr(job_package, "build_for_job", _build_for_job)
    with pytest.raises(HTTPException) as refused:
        await get_job_package(uuid.uuid4(), user=_User(), svc=_Service(None), db=_Db())
    assert refused.value.status_code == 404
    assert called == []

    job_id = uuid.uuid4()
    served = await get_job_package(job_id, user=_User(), svc=_Service(object()), db=_Db())
    body = b"".join([chunk async for chunk in served.body_iterator])  # type: ignore[misc]
    assert body == b"package bytes"
    assert served.headers["content-disposition"] == (
        f'attachment; filename="maljan-job-{job_id}.tar.gz"'
    )
    assert served.headers["x-package-seal-status"] == "verified"
    assert served.headers["x-package-signed"] == "true"


def test_the_replay_export_writes_the_bytes_it_wrote_before(tmp_path: Path):
    """``write_files`` streams with ``json.dump``: the same bytes ``json.dumps`` gave."""
    run = _run(tmp_path / "run")
    for name in run_export.LAYOUT:
        path = run / name
        if path.is_file():
            value = json.loads(path.read_bytes())
            assert path.read_text(encoding="utf-8") == json.dumps(value, indent=1, sort_keys=True)


# --- Hostile and malformed packages (adversarial review X22) ---------------


class _Zeros(io.RawIOBase):
    """``size`` zero bytes, read in pieces: a huge member never held whole."""

    def __init__(self, size: int) -> None:
        self.left = size

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        n = min(len(buffer), self.left)
        buffer[:n] = b"\0" * n
        self.left -= n
        return n


def _hostile(path: Path, entries: list[tuple[tarfile.TarInfo, Any]], **tar: Any) -> None:
    with (
        path.open("wb") as out,
        job_package.archive_stream(out) as gz,
        tarfile.open(fileobj=gz, mode="w", **tar) as archive,
    ):
        for info, data in entries:
            archive.addfile(info, data)


def _info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    return info


def _peak(work: Any) -> tuple[Any, int]:
    tracemalloc.start()
    try:
        result = work()
        return result, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_a_300_mib_manifest_is_refused_before_it_is_read(tmp_path: Path):
    size = 300 * 1024 * 1024
    _hostile(tmp_path / "p.tar.gz", [(_info("manifest.json", size), _Zeros(size))])
    verdict, peak = _peak(lambda: _verify(tmp_path / "p.tar.gz"))
    assert (verdict["status"], verdict["file"]) == ("broken", "manifest.json"), verdict
    assert "upload_max_bytes" in verdict["reason"]
    assert peak < 4 * 1024 * 1024, peak


def test_a_large_run_file_is_refused_before_a_byte_is_written(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    members = _members(tmp_path / "p.tar.gz")
    size = 200 * 1024 * 1024

    def _kept() -> list[tuple[tarfile.TarInfo, Any]]:
        return [
            (_info(n, len(d)), io.BytesIO(d)) for n, d in members.items() if n != "run/job.json"
        ]

    entries = [*_kept(), (_info("run/job.json", size), _Zeros(size))]
    _hostile(tmp_path / "p.tar.gz", entries, format=tarfile.USTAR_FORMAT)
    verdict, peak = _peak(lambda: _verify(tmp_path / "p.tar.gz"))
    assert (verdict["status"], verdict["file"]) == ("broken", "run/job.json"), verdict
    assert verdict["reason"] == "The file's size differs from the manifest."
    assert peak < 4 * 1024 * 1024, peak

    unlisted = [*_kept(), (_info("run/extra.json", size), _Zeros(size))]
    _hostile(tmp_path / "q.tar.gz", unlisted, format=tarfile.USTAR_FORMAT)
    verdict = _verify(tmp_path / "q.tar.gz")
    assert (verdict["status"], verdict["file"]) == ("broken", "run/extra.json"), verdict


def test_a_listed_size_above_the_bound_is_refused(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    verdict = _verify(tmp_path / "p.tar.gz", max_bytes=16)
    assert (verdict["status"], verdict["file"]) == ("broken", "manifest.json"), verdict
    with pytest.raises(job_package.PackageError):
        _build(run, tmp_path / "small.tar.gz", max_bytes=16)


@pytest.mark.parametrize("kind", ["sparse", "pax", "gnu_longname"])
def test_sparse_pax_and_gnu_members_are_refused(tmp_path: Path, kind: str):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    members = _members(tmp_path / "p.tar.gz")
    entries = [(_info(n, len(d)), io.BytesIO(d)) for n, d in members.items()]
    if kind == "sparse":
        info = _info("seal.json", 0)
        info.type = tarfile.GNUTYPE_SPARSE
        entries = [entries[0], (info, io.BytesIO(b""))]
        tar_format = tarfile.GNU_FORMAT
    elif kind == "pax":
        info = _info("seal.json", 0)
        info.pax_headers = {"GNU.sparse.size": str(2**30), "comment": "x"}
        entries = [entries[0], (info, io.BytesIO(b""))]
        tar_format = tarfile.PAX_FORMAT
    else:
        entries = [entries[0], (_info("run/" + "a" * 120 + ".json", 0), io.BytesIO(b""))]
        tar_format = tarfile.GNU_FORMAT
    _hostile(tmp_path / "h.tar.gz", entries, format=tar_format)
    verdict = _verify(tmp_path / "h.tar.gz")
    assert verdict["status"] == "broken", verdict
    assert verdict["reason"] == job_package.NOT_PLAIN, verdict


def _flips(good: bytes) -> Iterator[tuple[int, int, bytes]]:
    """Every offset of ``good`` with one bit flipped, then with every bit flipped."""
    for position in range(len(good)):
        for mask in (0x01, 0xFF):
            flipped = bytearray(good)
            flipped[position] ^= mask
            yield position, mask, bytes(flipped)


def test_every_byte_of_a_package_changed_reads_broken(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    good = (tmp_path / "p.tar.gz").read_bytes()
    for position, mask, flipped in _flips(good):
        (tmp_path / "f.tar.gz").write_bytes(flipped)
        verdict = _verify(tmp_path / "f.tar.gz")
        assert verdict["status"] == "broken" and verdict["reason"], (position, mask, verdict)
    crc = bytearray(good)
    crc[-6] ^= 0x01
    (tmp_path / "c.tar.gz").write_bytes(bytes(crc))
    verdict = _verify(tmp_path / "c.tar.gz")
    assert (verdict["status"], verdict["reason"]) == ("broken", job_package.UNREADABLE)


def test_appended_data_and_a_truncated_file_read_broken(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    good = (tmp_path / "p.tar.gz").read_bytes()
    assert _verify(tmp_path / "p.tar.gz")["file_digest"] == "valid"
    changed = [good + tail for tail in (b"\0", b"\0" * 512, b"x", gzip.compress(b"", mtime=0))]
    changed += [good[:cut] for cut in (0, 1, 10, 79, 80, 81, len(good) // 2, len(good) - 8)]
    changed.append(good[:-1])
    for index, data in enumerate(changed):
        (tmp_path / "t.tar.gz").write_bytes(data)
        verdict = _verify(tmp_path / "t.tar.gz")
        assert verdict["status"] == "broken" and verdict["reason"], (index, verdict)
        assert verdict["file"] == str(tmp_path / "t.tar.gz"), (index, verdict)


def test_a_package_re_encoded_without_the_key_reads_broken(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    tar = gzip.decompress((tmp_path / "p.tar.gz").read_bytes())
    # The same archive, the same signed manifest, its file digest recomputed by
    # someone without the key: the bytes changed, so the package is broken.
    with (tmp_path / "r.tar.gz").open("wb") as out, job_package.archive_stream(out) as gz:
        gz.write(tar)
    verdict = _verify(tmp_path / "r.tar.gz")
    assert (verdict["status"], verdict["reason"]) == (
        "broken",
        job_package.FILE_HMAC_DIFFERS,
    ), verdict
    # Where the key is not held the HMAC cannot be checked: the package reads
    # other_key, which proves nothing, as any package signed under that key does.
    verdict = _verify(tmp_path / "r.tar.gz", keys={})
    assert (verdict["status"], verdict["file_digest"]) == ("other_key", "valid"), verdict
    with (tmp_path / "o.tar.gz").open("wb") as out:
        with job_package.archive_stream(out, key=OTHER_SIGNER) as gz:
            gz.write(tar)
    verdict = _verify(tmp_path / "o.tar.gz")
    assert (verdict["status"], verdict["reason"]) == ("broken", job_package.FILE_HMAC_DIFFERS)
    # An unsigned package carries no HMAC in its header.
    _build(run, tmp_path / "u.tar.gz", key=None)
    unsigned = gzip.decompress((tmp_path / "u.tar.gz").read_bytes())
    with (
        (tmp_path / "m.tar.gz").open("wb") as out,
        job_package.archive_stream(out, key=SIGNER) as gz,
    ):
        gz.write(unsigned)
    verdict = _verify(tmp_path / "m.tar.gz", allow_unsigned=True)
    assert (verdict["status"], verdict["reason"]) == ("broken", job_package.FILE_HMAC_DIFFERS)


class _Reads:
    """The package file as the verifier reads it: every read recorded, and an I/O
    error raised once ``fail_at`` bytes have been read."""

    def __init__(self, handle: Any, log: list[tuple[str, int, int]], fail_at: int | None) -> None:
        self.handle = handle
        self.log = log
        self.fail_at = fail_at

    def read(self, size: int = -1) -> bytes:
        at = self.handle.tell()
        if self.fail_at is not None and at + max(size, 1) > self.fail_at:
            raise OSError(5, "Input/output error")
        data = self.handle.read(size)
        self.log.append(("read", at, len(data)))
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        self.log.append(("seek", self.handle.tell(), offset))
        return self.handle.seek(offset, whence)

    def __enter__(self) -> _Reads:
        return self

    def __exit__(self, *exc: object) -> None:
        self.handle.close()


def _watch_reads(
    monkeypatch: Any, target: Path, fail_at: int | None = None
) -> list[tuple[str, int, int]]:
    log: list[tuple[str, int, int]] = []
    real = Path.open

    def _open(self: Path, *args: Any, **kwargs: Any) -> Any:
        handle = real(self, *args, **kwargs)
        if self == target:
            log.append(("open", 0, 0))
            return _Reads(handle, log, fail_at)
        return handle

    monkeypatch.setattr(Path, "open", _open)
    return log


def test_the_package_file_is_read_once_front_to_back(tmp_path: Path, monkeypatch: Any):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    _legacy(tmp_path / "l.tar.gz", _legacy_members(tmp_path / "p.tar.gz"))
    for name in ("p.tar.gz", "l.tar.gz"):
        package = tmp_path / name
        size = package.stat().st_size
        with monkeypatch.context() as patch:
            log = _watch_reads(patch, package)
            verdict = _verify(package)
        assert verdict["status"] == "verified", (name, verdict)
        # Opened once; each byte read once, in order, to the end: nothing the
        # checks saw can differ from what the digest covered.
        assert [e for e in log if e[0] == "open"] == [("open", 0, 0)], (name, log)
        reads = [(at, n) for kind, at, n in log if kind == "read" and n]
        assert [at for at, _ in reads] == list(
            itertools.accumulate([0] + [n for _, n in reads[:-1]])
        ), (name, log)
        assert sum(n for _, n in reads) == size, (name, log)
        assert all(kind != "seek" for kind, _, _ in log), (name, log)


def test_an_i_o_error_while_reading_reads_broken(tmp_path: Path, monkeypatch: Any):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    _legacy(tmp_path / "l.tar.gz", _legacy_members(tmp_path / "p.tar.gz"))
    for name in ("p.tar.gz", "l.tar.gz"):
        package = tmp_path / name
        size = package.stat().st_size
        for fail_at in (0, 40, size // 2, size):
            with monkeypatch.context() as patch:
                _watch_reads(patch, package, fail_at)
                verdict = _verify(package)
            assert (verdict["status"], verdict["reason"]) == (
                "broken",
                job_package.UNREADABLE,
            ), (name, fail_at, verdict)


def _legacy(path: Path, members: dict[str, bytes]) -> None:
    """``members`` written the way the builder wrote every package before the file digest."""
    with (
        path.open("wb") as out,
        gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tar,
    ):
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.type = tarfile.REGTYPE
            tar.addfile(info, io.BytesIO(data))


def _legacy_members(path: Path) -> dict[str, bytes]:
    members = _members(path)
    manifest = json.loads(members["manifest.json"])
    manifest["format"] = job_package.LEGACY_FORMAT
    body = json.dumps(manifest, indent=1, sort_keys=True).encode()
    record = json.loads(members["manifest.sig"])
    record["manifest_sha256"] = hashlib.sha256(body).hexdigest()
    record["hmac"] = job_package.sign(body, SIGNER)
    signature = json.dumps(record, indent=1, sort_keys=True).encode()
    return {**members, "manifest.json": body, "manifest.sig": signature}


def test_a_package_built_before_the_file_digest_still_verifies_and_says_so(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    members = _legacy_members(tmp_path / "p.tar.gz")
    _legacy(tmp_path / "l.tar.gz", members)
    verdict = _verify(tmp_path / "l.tar.gz")
    assert (verdict["status"], verdict["file_digest"]) == ("verified", "legacy"), verdict
    assert verdict["file_digest_reason"] == job_package.FILE_DIGEST_LEGACY
    good = (tmp_path / "l.tar.gz").read_bytes()
    tar = gzip.decompress(good)
    # Every byte is checked but for an equivalent encoding of the deflate
    # stream, which yields the same archive: nothing a changed byte can hide.
    for position, mask, flipped in _flips(good):
        (tmp_path / "f.tar.gz").write_bytes(flipped)
        verdict = _verify(tmp_path / "f.tar.gz")
        if verdict["status"] != "broken":
            assert position >= 10 and gzip.decompress(flipped) == tar, (position, mask, verdict)
    for data in (good + b"\0", good + b"\0" * 64, good[:-1], good[:10]):
        (tmp_path / "t.tar.gz").write_bytes(data)
        assert _verify(tmp_path / "t.tar.gz")["status"] == "broken"
    # The archive re-encoded with a non-canonical tar byte: a padding byte, an
    # end marker byte, a header field no digest covers.
    size = len(members["manifest.json"])
    assert size % tarfile.BLOCKSIZE, "the manifest must end inside a block to leave padding"
    padding = bytearray(tar)
    padding[tarfile.BLOCKSIZE + size] = 0x20
    marker = bytearray(tar)
    marker[-1] = 0x01
    # The second header's device number, which a regular file never reads,
    # with the header's checksum made right again.
    second = tarfile.BLOCKSIZE * (2 + size // tarfile.BLOCKSIZE)
    header = bytearray(tar)
    header[second + 329 + 6] = ord("1")
    block = header[second : second + tarfile.BLOCKSIZE]
    checksum = sum(block[:148]) + 8 * ord(" ") + sum(block[156:])
    header[second + 148 : second + 155] = b"%06o\0" % checksum
    after_end = "The archive holds data after its end marker."
    variants = [
        (padding, job_package.NOT_CANONICAL),
        (header, job_package.NOT_CANONICAL),
        (marker, after_end),
        (tar + bytes(tarfile.RECORDSIZE), after_end),
    ]
    for index, (variant, reason) in enumerate(variants):
        with (tmp_path / "v.tar.gz").open("wb") as out:
            with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as gz:
                gz.write(bytes(variant))
        verdict = _verify(tmp_path / "v.tar.gz")
        assert (verdict["status"], verdict["reason"]) == ("broken", reason), (index, verdict)


def _signature_variants(signature: bytes) -> list[bytes]:
    """``signature`` with each field changed, a field added, and other spacing."""
    record = json.loads(signature)
    out = []
    for field in record:
        changed = dict(record)
        value = changed[field]
        changed[field] = value[:-1] + ("0" if value[-1] != "0" else "1")
        out.append(json.dumps(changed, indent=1, sort_keys=True).encode())
    out.append(json.dumps({**record, "note": "x"}, indent=1, sort_keys=True).encode())
    out.append(json.dumps(record, sort_keys=True).encode())
    out.append(json.dumps(record, indent=2, sort_keys=True).encode())
    out.append(json.dumps(record, indent=1).encode())
    out.append(signature + b"\n")
    out.append(b" " + signature)
    return [v for v in out if v != signature]


def test_every_change_to_the_signature_file_reads_broken(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    current = _members(tmp_path / "p.tar.gz")
    legacy = _legacy_members(tmp_path / "p.tar.gz")
    _rewrite(tmp_path / "c.tar.gz", current)
    assert _verify(tmp_path / "c.tar.gz")["status"] == "verified"
    _legacy(tmp_path / "l.tar.gz", legacy)
    assert _verify(tmp_path / "l.tar.gz")["status"] == "verified"
    variants = _signature_variants(current["manifest.sig"])
    assert len(variants) >= 10
    for index, signature in enumerate(variants):
        _rewrite(tmp_path / "c.tar.gz", {**current, "manifest.sig": signature})
        verdict = _verify(tmp_path / "c.tar.gz")
        assert (verdict["status"], verdict["file"]) == ("broken", "manifest.json"), (
            index,
            verdict,
        )
    for index, signature in enumerate(_signature_variants(legacy["manifest.sig"])):
        _legacy(tmp_path / "l.tar.gz", {**legacy, "manifest.sig": signature})
        verdict = _verify(tmp_path / "l.tar.gz")
        assert (verdict["status"], verdict["file"]) == ("broken", "manifest.json"), (
            index,
            verdict,
        )


def test_a_seek_past_the_end_never_leaves_bytes_unhashed(tmp_path: Path):
    package = tmp_path / "grows"
    package.write_bytes(bytes(range(256)) * 4)
    digest = hashlib.sha256()
    with package.open("rb") as raw:
        source = job_package._Once(raw, 16)
        source.watch(16, digest)
        with pytest.raises(EOFError):
            source.seek(4096)
        assert source.tell() == 1024
        # The file grows after the seek ran out: every byte of it is still seen.
        with package.open("ab") as more:
            more.write(b"appended after the end was reached")
        source.drain()
    assert digest.digest() == hashlib.sha256(package.read_bytes()[16:]).digest()


def test_a_package_that_grows_while_it_is_read_reads_broken(tmp_path: Path, monkeypatch: Any):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    package = tmp_path / "p.tar.gz"
    real = Path.open

    class _Growing(_Reads):
        """The file gains bytes the first time a read finds its end."""

        grown = False

        def read(self, size: int = -1) -> bytes:
            data = super().read(size)
            if not data and not self.grown:
                self.grown = True
                with real(package, "ab") as more:
                    more.write(b"\0" * 64)
            return data

    def _open(self: Path, *args: Any, **kwargs: Any) -> Any:
        handle = real(self, *args, **kwargs)
        return _Growing(handle, [], None) if self == package else handle

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", _open)
        verdict = _verify(package)
    # Whichever check meets the new bytes first, the package is broken.
    assert (verdict["status"], verdict["file"]) == ("broken", str(package)), verdict
    assert verdict["reason"] in (job_package.UNREADABLE, job_package.FILE_DIGEST_DIFFERS)


def test_the_manifest_format_must_match_the_package_envelope(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    # A current package rewritten in the old envelope: its file digest dropped.
    _legacy(tmp_path / "down.tar.gz", _members(tmp_path / "p.tar.gz"))
    verdict = _verify(tmp_path / "down.tar.gz")
    assert (verdict["status"], verdict["file"]) == ("broken", "manifest.json"), verdict
    assert verdict["reason"] == job_package.FORMAT_MISMATCH
    # An old manifest in the current envelope.
    _rewrite(tmp_path / "up.tar.gz", _legacy_members(tmp_path / "p.tar.gz"))
    verdict = _verify(tmp_path / "up.tar.gz")
    assert (verdict["status"], verdict["reason"]) == ("broken", job_package.FORMAT_MISMATCH)


def test_a_non_ascii_hmac_and_deep_nesting_read_broken(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    members = _members(tmp_path / "p.tar.gz")
    record = json.loads(members["manifest.sig"])
    record["hmac"] = "é" * 64
    _rewrite(tmp_path / "p.tar.gz", {**members, "manifest.sig": json.dumps(record).encode()})
    verdict = _verify(tmp_path / "p.tar.gz")
    assert (verdict["status"], verdict["file"]) == ("broken", "manifest.json"), verdict

    for nested in (b"[" * 200000, b'{"format": ' + b"[" * 200000):
        _rewrite(tmp_path / "d.tar.gz", {"manifest.json": nested})
        verdict = _verify(tmp_path / "d.tar.gz")
        assert (verdict["status"], verdict["file"]) == ("broken", "manifest.json"), verdict
    _rewrite(tmp_path / "s.tar.gz", {**members, "manifest.sig": b"[" * 200000})
    verdict = _verify(tmp_path / "s.tar.gz")
    assert (verdict["status"], verdict["file"]) == ("broken", "manifest.json"), verdict


def test_a_spilled_part_is_read_only_under_a_bound(tmp_path: Path):
    import hashlib

    blob = b"the whole answer"
    digest = hashlib.sha256(blob).hexdigest()
    ref = {"part": "answer", "bytes": len(blob), "sha256": digest, "key": "evidence/j/" + digest}
    served: list[int] = []

    def _fetch(key: str) -> Any:
        for _ in range(1000):
            served.append(1)
            yield blob

    run = _run(tmp_path / "run", spilled=[ref])
    _build(run, tmp_path / "p.tar.gz", fetch=_fetch, max_object_bytes=MAX)
    (row,) = json.loads(_members(tmp_path / "p.tar.gz")["ledger/spilled.json"])
    assert "more bytes than the reference records" in row["absent"]
    assert len(served) == 2  # stopped as soon as the bound was passed

    for bound in (0, None, "100", -1):
        _build(run, tmp_path / "b.tar.gz", fetch=_fetch, max_object_bytes=bound)
        (row,) = json.loads(_members(tmp_path / "b.tar.gz")["ledger/spilled.json"])
        assert row["absent"].startswith("No valid upload_max_bytes"), (bound, row)

    unsized = _run(tmp_path / "run2", spilled=[{k: v for k, v in ref.items() if k != "bytes"}])
    _build(unsized, tmp_path / "u.tar.gz", fetch=_fetch, max_object_bytes=MAX)
    (row,) = json.loads(_members(tmp_path / "u.tar.gz")["ledger/spilled.json"])
    assert row["absent"] == "The reference records no byte length to bound the read by."


def test_a_stripped_signature_never_speaks_in_the_verdict(tmp_path: Path):
    import hashlib

    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    members = _members(tmp_path / "p.tar.gz")
    members["report/report.md"] = b"# rewritten by someone\n"
    manifest = json.loads(members["manifest.json"])
    for entry in manifest["files"]:
        if entry["path"] == "report/report.md":
            entry["sha256"] = hashlib.sha256(members["report/report.md"]).hexdigest()
            entry["bytes"] = len(members["report/report.md"])
    claim = "Signed and verified by the platform"
    manifest["signature"] = {"absent": claim}
    members["manifest.json"] = json.dumps(manifest).encode()
    del members["manifest.sig"]
    _rewrite(tmp_path / "p.tar.gz", members)
    verdict = _verify(tmp_path / "p.tar.gz")
    assert (verdict["status"], verdict["file"]) == ("broken", "manifest.sig"), verdict
    assert claim not in verdict["reason"] and claim not in verdict["signature_reason"]
    assert verdict["manifest_says"] == claim
    allowed = _verify(tmp_path / "p.tar.gz", allow_unsigned=True)
    assert (allowed["status"], allowed["reason"]) == ("unsigned", job_package.UNSIGNED_ACCEPTED)


def test_data_after_the_end_marker_is_refused(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz")
    tar = gzip.decompress((tmp_path / "p.tar.gz").read_bytes())
    extra = io.BytesIO()
    with tarfile.open(fileobj=extra, mode="w", format=tarfile.USTAR_FORMAT) as appended:
        appended.addfile(_info("run/evil.json", 2), io.BytesIO(b"{}"))
    with (
        (tmp_path / "t.tar.gz").open("wb") as out,
        job_package.archive_stream(out, key=SIGNER) as gz,
    ):
        gz.write(tar + extra.getvalue())
    verdict = _verify(tmp_path / "t.tar.gz")
    assert (verdict["status"], verdict["reason"]) == (
        "broken",
        "The archive holds data after its end marker.",
    ), verdict
    second = (tmp_path / "p.tar.gz").read_bytes() + gzip.compress(b"x" * 64, mtime=0)
    (tmp_path / "m.tar.gz").write_bytes(second)
    assert _verify(tmp_path / "m.tar.gz")["status"] == "broken"


def test_a_report_without_a_generation_time_is_dated_by_the_job(tmp_path: Path):
    run = _run(tmp_path / "run")
    report = json.loads((run / "report.json").read_text())
    report.pop("generated_at", None)
    (run / "report.json").write_text(json.dumps(report))
    job = json.loads((run / "job.json").read_text())
    job["completed_at"] = "2026-10-01T08:30:00+00:00"
    (run / "job.json").write_text(json.dumps(job))
    _build(run, tmp_path / "a.tar.gz", key=None)
    _build(run, tmp_path / "b.tar.gz", key=None)
    assert (tmp_path / "a.tar.gz").read_bytes() == (tmp_path / "b.tar.gz").read_bytes()
    assert b"2026-10-01" in _members(tmp_path / "a.tar.gz")["report/report.md"]

    del job["completed_at"]
    (run / "job.json").write_text(json.dumps(job))
    manifest = _build(run, tmp_path / "c.tar.gz", key=None)
    absent = {a["part"]: a["reason"] for a in manifest["absent"]}
    assert "build's own clock" in absent["report_markdown"]


class _Result:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def mappings(self) -> _Result:
        return self

    def first(self) -> Any:
        return self._rows[0] if self._rows else None

    def __iter__(self) -> Any:
        return iter(self._rows)


class _Recording:
    """Answers ``read_job_rows``' statements and records them."""

    def __init__(self) -> None:
        self.statements: list[str] = []

    async def execute(self, statement: Any) -> _Result:
        text = str(statement)
        self.statements.append(text)
        if "FROM analysis_jobs" in text:
            return _Result([{"id": uuid.uuid4(), "sample_id": None}])
        if "FROM analysis_reports" in text:
            return _Result([{"id": uuid.uuid4()}])
        return _Result([])


@pytest.mark.asyncio
async def test_every_row_set_is_read_in_a_stable_order():
    db = _Recording()
    await run_export.read_job_rows(db, uuid.uuid4())
    ordered = {
        table: next(s for s in db.statements if f"FROM {table}" in s)
        for table in ("agent_findings", "agent_messages", "evidence_entries", "job_events")
    }
    assert "ORDER BY agent_findings.created_at, agent_findings.id" in ordered["agent_findings"]
    assert "ORDER BY agent_messages.seq" in ordered["agent_messages"]
    assert "ORDER BY evidence_entries.seq" in ordered["evidence_entries"]
    assert "ORDER BY job_events.seq" in ordered["job_events"]


class _Dialect:
    name = "postgresql"


class _Transaction:
    def __init__(self, conn: _Conn) -> None:
        self.conn = conn

    async def rollback(self) -> None:
        self.conn.rolled_back = True


class _Conn:
    def __init__(self) -> None:
        self.statements: list[str] = []
        self.rolled_back = False
        self.dialect = _Dialect()

    async def __aenter__(self) -> _Conn:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def begin(self) -> _Transaction:
        return _Transaction(self)

    async def execute(self, statement: Any) -> None:
        self.statements.append(str(statement))


class _Engine:
    def __init__(self) -> None:
        self.conn = _Conn()
        self.connections = 0

    def connect(self) -> _Conn:
        self.connections += 1
        return self.conn


@pytest.mark.asyncio
async def test_the_rows_and_the_seal_are_read_once_in_one_snapshot(
    tmp_path: Path, monkeypatch: Any
):
    from app.services import ledger_verify, object_store

    run = _run(tmp_path / "run")
    evidence = json.loads((run / "evidence.json").read_text())["items"]
    byjob = json.loads((run / "report-byjob.json").read_text())
    job = json.loads((run / "job.json").read_text())
    report = {**byjob, "malware_report": json.loads((run / "report.json").read_text())}
    rows = run_export.JobRows(job=job, report=report, evidence=evidence)
    engine = _Engine()
    seen: dict[str, Any] = {}

    async def _read(conn: Any, job_id: Any) -> Any:
        seen["read_on"] = conn
        return rows

    async def _verify_job(conn: Any, job_id: Any, *, preloaded: Any = None) -> dict[str, Any]:
        seen["verified_on"] = conn
        seen["preloaded"] = preloaded
        return verify_run(run)

    async def _bound() -> int:
        return MAX

    monkeypatch.setattr(run_export, "read_job_rows", _read)
    monkeypatch.setattr(ledger_verify, "verify_job", _verify_job)
    monkeypatch.setattr(object_store, "evidence_bound", _bound)
    monkeypatch.setattr(job_package, "signature_key", lambda: (SIGNER, None))
    with (tmp_path / "api.tar.gz").open("wb") as out:
        manifest = await job_package.build_for_job(engine, job["id"], out)
    assert manifest is not None and manifest["seal"]["status"] == "verified"
    assert engine.connections == 1
    assert seen["read_on"] is seen["verified_on"] is engine.conn
    assert seen["preloaded"][0] is evidence and seen["preloaded"][1] is report
    assert engine.conn.statements == ["SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"]
    assert engine.conn.rolled_back
    assert _verify(tmp_path / "api.tar.gz")["status"] == "verified"


def test_a_build_never_touches_another_build_s_partial_file(tmp_path: Path, monkeypatch: Any):
    monkeypatch.setattr(job_package, "signature_key", lambda: (SIGNER, None))
    run = _run(tmp_path / "run")
    out = tmp_path / "job.tar.gz"
    other = tmp_path / "job.tar.gz.partial"
    other.write_bytes(b"another build is writing here")
    build_cli.build(run, out)
    assert other.read_bytes() == b"another build is writing here"
    names = ["job.tar.gz", "job.tar.gz.partial", "run"]
    assert sorted(p.name for p in tmp_path.iterdir()) == names

    def _fails(*args: Any, **kwargs: Any) -> Any:
        raise OSError("the disk is full")

    monkeypatch.setattr(job_package, "build_package", _fails)
    with pytest.raises(OSError):
        build_cli.build(run, tmp_path / "second.tar.gz")
    assert sorted(p.name for p in tmp_path.iterdir()) == names


def test_the_verify_command_needs_allow_unsigned_where_the_key_is_held(
    tmp_path: Path, monkeypatch: Any, capsys: Any
):
    monkeypatch.setattr(job_package, "signature_key", lambda: (SIGNER, None))
    run = _run(tmp_path / "run")
    out = tmp_path / "u.tar.gz"
    assert build_cli.main(["--run", str(run), "--out", str(out), "--unsigned"]) == 0
    capsys.readouterr()
    assert verify_cli.main([str(out)]) == 1
    assert json.loads(capsys.readouterr().out)["file"] == "manifest.sig"
    assert verify_cli.main([str(out), "--allow-unsigned"]) == 3


def test_a_file_above_the_bound_is_listed_absent_with_its_digest(tmp_path: Path):
    import hashlib

    run = _run(tmp_path / "run")
    bound = 64 * 1024
    events = b"[" + b",".join([b'"' + b"e" * 1000 + b'"'] * 200) + b"]"
    (run / "events.json").write_bytes(events)
    manifest = _build(run, tmp_path / "p.tar.gz", max_bytes=bound)
    left_out = {
        "path": "run/events.json",
        "sha256": hashlib.sha256(events).hexdigest(),
        "bytes": len(events),
        "reason": "larger than the package bound",
    }
    assert manifest["oversized"] == [left_out]
    assert {"part": "events", **left_out} in manifest["absent"]
    assert "run/events.json" not in _members(tmp_path / "p.tar.gz")
    verdict = _verify(tmp_path / "p.tar.gz", max_bytes=bound)
    assert verdict["status"] == "verified", verdict
    assert verdict["oversized"] == [left_out]

    evidence = (run / "evidence.json").read_bytes()
    (run / "events.json").write_text("[]")
    (run / "evidence.json").write_bytes(evidence + b" " * bound)
    manifest = _build(run, tmp_path / "e.tar.gz", max_bytes=bound)
    assert [e["path"] for e in manifest["oversized"]] == ["run/evidence.json"]
    verdict = _verify(tmp_path / "e.tar.gz", max_bytes=bound)
    assert verdict["status"] == "seal_unverifiable", verdict
    assert verdict["oversized"][0]["path"] == "run/evidence.json"


def _oversize_evidence(run: Path, bound: int) -> None:
    evidence = (run / "evidence.json").read_bytes()
    (run / "evidence.json").write_bytes(evidence + b" " * bound)


def test_a_file_left_out_for_its_size_is_never_parsed(tmp_path: Path, monkeypatch: Any):
    run = _run(tmp_path / "run")
    bound = 64 * 1024
    _oversize_evidence(run, bound)
    byjob = (run / "report-byjob.json").read_bytes()
    (run / "report-byjob.json").write_bytes(byjob + b" " * bound)
    parsed: list[str] = []
    load = job_package._load

    def _recording(path: Path) -> Any:
        parsed.append(path.name)
        return load(path)

    monkeypatch.setattr(job_package, "_load", _recording)
    manifest = _build(run, tmp_path / "p.tar.gz", max_bytes=bound)
    assert "evidence.json" not in parsed and "report-byjob.json" not in parsed, parsed
    assert {e["path"] for e in manifest["oversized"]} == {
        "run/evidence.json",
        "run/report-byjob.json",
    }
    absent = {a["part"]: a for a in manifest["absent"]}
    assert absent["evidence_ledger"]["reason"] == "larger than the package bound"
    assert "spilled references were not read" in absent["spilled_objects"]["reason"]


def test_a_left_out_seal_file_never_hides_a_failure(tmp_path: Path):
    run = _run(tmp_path / "run")
    bound = 64 * 1024
    _oversize_evidence(run, bound)
    _build(run, tmp_path / "o.tar.gz", key=OTHER_SIGNER, max_bytes=bound)
    verdict = _verify(tmp_path / "o.tar.gz", max_bytes=bound)
    assert verdict["status"] == "other_key", verdict

    _build(run, tmp_path / "u.tar.gz", key=None, max_bytes=bound)
    verdict = _verify(tmp_path / "u.tar.gz", max_bytes=bound)
    assert (verdict["status"], verdict["file"]) == ("broken", "manifest.sig"), verdict

    _build(run, tmp_path / "s.tar.gz", max_bytes=bound)
    verdict = _verify(tmp_path / "s.tar.gz", max_bytes=bound)
    assert verdict["status"] == "seal_unverifiable", verdict


def test_a_small_file_cannot_be_declared_left_out(tmp_path: Path):
    run = _run(tmp_path / "run")
    _build(run, tmp_path / "p.tar.gz", key=None)
    members = _members(tmp_path / "p.tar.gz")
    manifest = json.loads(members["manifest.json"])
    (entry,) = [e for e in manifest["files"] if e["path"] == "run/evidence.json"]
    manifest["files"].remove(entry)
    manifest["oversized"] = [{**entry, "reason": "larger than the package bound"}]
    del members["run/evidence.json"]
    members["manifest.json"] = json.dumps(manifest).encode()
    _rewrite(tmp_path / "p.tar.gz", members)
    verdict = _verify(tmp_path / "p.tar.gz", keys={})
    assert (verdict["status"], verdict["file"]) == ("broken", "manifest.json"), verdict
    assert "not larger than the package bound" in verdict["reason"]

    manifest["package_bound"]["bytes"] = entry["bytes"] - 1
    members["manifest.json"] = json.dumps(manifest).encode()
    _rewrite(tmp_path / "q.tar.gz", members)
    verdict = _verify(tmp_path / "q.tar.gz", keys={})
    assert (verdict["status"], verdict["file"]) == ("broken", "manifest.json"), verdict
    assert "above the package bound" in verdict["reason"]
