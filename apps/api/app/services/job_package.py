"""One verifiable package per job: the run's stored files, its exports, its seal and a manifest.

A package is a gzip-compressed tar archive, built from a directory in the
stored-run layout (:mod:`app.services.run_export`): the API writes the job's
rows there first (:func:`build_for_job`), the offline command
(``python -m scripts.package.build``) reads an exported run directory as it
is. It holds:

- ``manifest.json``, always the first entry: every other file with its SHA-256
  and size, every part with where it is or why it is absent, the sample's
  hashes;
- ``manifest.sig``, optionally and always the second entry: an HMAC-SHA256
  over the manifest's bytes under a key derived from the settings encryption
  key the platform already holds, under its own purpose label
  (:data:`SIGNATURE_LABEL`). Like the ledger's chain it proves integrity only
  to a holder of that key: anyone who holds it can sign another manifest, and
  anyone without it cannot check it;
- ``run/``: the stored-run files as they are (the job row with the sample's
  hash and name, the report row, the report document, the evidence ledger, the
  run summary, the judge's bundle, the events), exactly what
  ``python -m scripts.ledger.verify --run`` checks the seal against;
- ``report/report.md``: the report rendered by the Markdown exporter;
- ``export/stix-bundle.json``: the STIX bundle the report row serves;
- ``ledger/spilled.json`` and ``ledger/objects/<sha256>``: every part of an
  answer the ledger does not keep whole (``maljan.schemas.evidence_spill``),
  with the kept bytes where the build could read them back, bounded, and
  verify them, else its reference and digest with the reason the bytes are
  not here;
- ``seal.json``: the ledger seal and the verification of it at build time
  (``app.services.ledger_verify``).

The sample file itself is not included; spilled tool answers may contain
bytes from it.

The archive is deterministic: the manifest first, its signature second, every
other entry sorted by path; plain USTAR regular files only, no directory
entries, every timestamp 0, mode 0644, owner 0:0 with no names, and the gzip
header carries no name and no time. The same job therefore gives the same
bytes on the same build of zlib (another zlib may compress the same tar
differently; the uncompressed tar is the same everywhere).

The gzip header carries the file's own digest in an extra field
(:data:`_HEADER`): the SHA-256 of every byte after the header, to the end of
the file, and beside it an HMAC-SHA256 of that digest under the package key
when the manifest is signed (zeros when it is not). Deflate is not canonical
(a match in a run of zeros may point at any earlier zero, and padding bits are
never read), so a changed byte can leave the archive and its CRC the same; the
digest makes every byte of the file count, and the HMAC keeps anyone without
the key from re-encoding a signed package. A package built before the digest
(:data:`LEGACY_FORMAT`) is checked byte for byte instead, against the header,
the tar headers, padding and end the builder wrote then, and the exact gzip
end; only an equivalent encoding of its deflate stream, which yields the same
archive, cannot be told apart.

What is held in memory: the archive is staged on disk file by file, hashed as
it is written, and streamed from there; verification reads it in one pass in
:data:`CHUNK` reads, and every entry's size is bounded by the manifest before
it is read. The API build holds the job's rows once (the ledger rows are read
once and shared between the seal verification and the written run); an
offline build loads ``evidence.json`` once to find the spilled references, and
the seal verification of a run directory loads it again, as it always does.
Each file is bounded by ``upload_max_bytes``, as verification bounds it: a
file above it is hashed as it streams, left out of the archive, and listed in
the manifest as absent with its SHA-256, its size and the reason
(:data:`OVERSIZED`).
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import posixpath
import re
import struct
import tarfile
import tempfile
import zlib
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any, BinaryIO, Protocol

from app.services import ledger_chain
from app.services.run_export import LAYOUT

FORMAT = "maljan-job-package/2"
# The HKDF purpose label the signature key is derived under.
SIGNATURE_LABEL = b"maljan-job-package-v1"
_SIGNATURE_TAG = b"maljan-job-package-manifest/1\n"
SIGNATURE_ALGORITHM = "HMAC-SHA256"
SIGNATURE_PROVES = (
    "An HMAC under a key derived from the platform's settings encryption key: it proves the "
    "manifest unchanged only to a holder of that key, who could also sign another one."
)

MANIFEST = "manifest.json"
SIGNATURE = "manifest.sig"
SEAL = "seal.json"
RUN = "run"
MARKDOWN = "report/report.md"
STIX = "export/stix-bundle.json"
SPILLED = "ledger/spilled.json"
OBJECTS = "ledger/objects"
# ``scripts.ledger.verify.report_row`` reads a STIX bundle file where a run has
# one, before the report row's column, so a run's own copy travels with it.
RUN_FILES: tuple[str, ...] = (*LAYOUT, "stix-bundle.json")
# The run files the seal's verification of a run directory reads: every one
# but the event log. One of them left out for its size leaves the seal unchecked.
SEAL_READS = frozenset(f"{RUN}/{name}" for name in RUN_FILES if name != "events.json")

# The nesting the format defines: the manifest is an object whose deepest
# values are objects inside a list or an object (``files[i]``, ``sample.hashes``),
# and the signature record is one flat object. Anything deeper is not a package.
MANIFEST_DEPTH = 3
SIGNATURE_DEPTH = 1

# What one read or write holds at a time: the standard library's own buffer.
CHUNK = io.DEFAULT_BUFFER_SIZE
# The length of a SHA-256 or an HMAC-SHA256 in hex characters.
HEX_SHA256 = hashlib.sha256().digest_size * 2
_FILE_MODE = 0o644
_HEX = frozenset("0123456789abcdef")

# A package built before the file digest: the same archive under the plain
# gzip header the builder wrote then (no flags, no time, maximum compression,
# no named system).
LEGACY_FORMAT = "maljan-job-package/1"
_LEGACY_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
# The current header: the same fields with FEXTRA set, and one extra subfield
# ("MJ") holding the SHA-256 of the rest of the file and its HMAC.
_DIGEST_FIELD = b"MJ"
_DIGEST_BYTES = hashlib.sha256().digest_size
_HEADER = (
    b"\x1f\x8b\x08\x04\x00\x00\x00\x00\x02\xff"
    + struct.pack("<H", 4 + 2 * _DIGEST_BYTES)
    + _DIGEST_FIELD
    + struct.pack("<H", 2 * _DIGEST_BYTES)
)
_HEADER_BYTES = len(_HEADER) + 2 * _DIGEST_BYTES
_FILE_TAG = b"maljan-job-package-file/1\n"
_NO_HMAC = bytes(_DIGEST_BYTES)

VERIFIED = "verified"
BROKEN = "broken"
UNSIGNED = "unsigned"
OTHER_KEY = "other_key"
SEAL_UNVERIFIABLE = "seal_unverifiable"

NO_MISP = (
    "The platform builds no MISP event: the report's MISP attributes, built from its published "
    "indicators and techniques, are the misp_attributes part."
)
NO_MISP_ATTRIBUTES = (
    "The report holds no MISP attributes: it was stored before the platform built them."
)
OFFLINE = (
    "An offline build from a run directory reads no object store: only the reference and its "
    "digest are packaged."
)
OVERSIZED = "larger than the package bound"
SAMPLE_NOTE = (
    "The sample file itself is not included; spilled tool answers may contain bytes from it."
)

# The verdict's reasons: fixed platform text, never text read from the package.
UNREADABLE = "The archive cannot be read: its gzip or tar data is corrupt or truncated."
NOT_A_PACKAGE_HEADER = "The gzip header is not the one the package builder writes."
FILE_DIGEST_DIFFERS = (
    "The file's bytes differ from the SHA-256 its gzip header carries: it was changed, cut "
    "short or extended after it was built."
)
FILE_HMAC_DIFFERS = (
    "The HMAC in the gzip header does not match the file under the manifest's signature key, "
    "or an unsigned package carries one: the file was re-encoded without the key."
)
FORMAT_MISMATCH = (
    "The manifest's format is not the one the gzip header belongs to: a current package must "
    "carry the file digest, and only an older one may lack it."
)
NOT_CANONICAL = (
    "The archive is not byte for byte the one the builder writes: a tar header, a padding "
    "byte or the end of the archive differs, or data follows the gzip end."
)
FILE_DIGEST_LEGACY = (
    "Built before the file digest (maljan-job-package/1): the gzip header, every tar header "
    "and padding byte, the archive's end and the gzip CRC, length and end are checked against "
    "what the builder wrote then; only an equivalent encoding of the deflate stream, which "
    "yields the same archive, cannot be told apart."
)
NOT_PLAIN = (
    "The entry is not a plain regular file (a link, a device, a sparse file, or one with PAX "
    "or GNU extended headers)."
)
UNSIGNED_HELD = (
    "The package carries no signature, and this environment holds the package key: the files "
    "outside run/ are not authenticated. Pass --allow-unsigned to accept an unsigned package."
)
UNSIGNED_ACCEPTED = (
    "The package carries no signature: every file matches its manifest, but the files outside "
    "run/ are not authenticated by a key."
)
UNSIGNED_NO_KEY = (
    "The package carries no signature and this environment holds no package key: every file "
    "matches its manifest, and nothing authenticates the manifest."
)

Fetch = Callable[[str], Iterable[bytes]]


class PackageError(ValueError):
    """A run directory the package cannot be built from, with why."""


class _Hashing:
    """A binary file written through, hashed and counted as it goes.

    Once more than ``limit`` bytes have arrived nothing more is written: the
    rest is only hashed and counted, so a file above the bound costs no disk
    beyond it.
    """

    def __init__(self, handle: BinaryIO, limit: int) -> None:
        self.handle = handle
        self.limit = limit
        self.digest = hashlib.sha256()
        self.size = 0

    def write(self, data: bytes) -> int:
        self.digest.update(data)
        self.size += len(data)
        if self.size <= self.limit:
            self.handle.write(data)
        return len(data)


class _Text:
    """``json.dump``'s text chunks, encoded into a :class:`_Hashing` writer."""

    def __init__(self, sink: _Hashing) -> None:
        self.sink = sink

    def write(self, text: str) -> int:
        return self.sink.write(text.encode("utf-8"))


class _Stage:
    """The package's files, written under a temporary directory, with their digests."""

    def __init__(self, root: Path, max_bytes: int) -> None:
        self.root = root
        self.max_bytes = max_bytes
        self.files: dict[str, dict[str, Any]] = {}
        # Files above the bound, left out of the archive: path, digest, size.
        self.oversized: dict[str, dict[str, Any]] = {}

    def _open(self, path: str) -> BinaryIO:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        return target.open("xb")

    def _record(self, path: str, sink: _Hashing, holds: str) -> None:
        if sink.size > self.max_bytes:
            (self.root / path).unlink(missing_ok=True)
            self.files.pop(path, None)
            self.oversized[path] = {
                "path": path,
                "sha256": sink.digest.hexdigest(),
                "bytes": sink.size,
                "reason": OVERSIZED,
            }
            return
        self.oversized.pop(path, None)
        self.files[path] = {
            "path": path,
            "sha256": sink.digest.hexdigest(),
            "bytes": sink.size,
            "holds": holds,
        }

    def chunks(self, path: str, chunks: Iterable[bytes], holds: str) -> dict[str, Any]:
        with self._open(path) as handle:
            sink = _Hashing(handle, self.max_bytes)
            for chunk in chunks:
                sink.write(chunk)
        self._record(path, sink, holds)
        return self.files.get(path) or self.oversized[path]

    def json(self, path: str, value: Any, holds: str) -> dict[str, Any]:
        with self._open(path) as handle:
            sink = _Hashing(handle, self.max_bytes)
            json.dump(value, _Text(sink), indent=1, sort_keys=True)
        self._record(path, sink, holds)
        return self.files.get(path) or self.oversized[path]

    def text(self, path: str, text: str, holds: str) -> dict[str, Any]:
        return self.chunks(path, [text.encode("utf-8")], holds)

    def drop(self, path: str) -> None:
        self.files.pop(path, None)
        self.oversized.pop(path, None)
        (self.root / path).unlink(missing_ok=True)


class _TooLong(Exception):
    """More bytes arrived than the bound allows."""


def _bounded(chunks: Iterable[bytes], limit: int) -> Iterator[bytes]:
    """``chunks``, stopped with :class:`_TooLong` as soon as more than ``limit`` bytes arrive."""
    count = 0
    for chunk in chunks:
        count += len(chunk)
        if count > limit:
            raise _TooLong
        yield chunk


def _read_file(path: Path) -> Iterator[bytes]:
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            yield chunk


def _load(path: Path) -> Any:
    if not path.is_file():
        return None
    with path.open("rb") as handle:
        return json.load(handle)


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and set(value) <= _HEX


def _markdown(report: Any, job: Any) -> tuple[str | None, str | None]:
    """The report rendered by the Markdown exporter, or ``None`` and why it is not.

    A report stored without ``generated_at`` is dated with the job's stored
    completion time, never the build's clock, so the rendering is the same on
    every build. It is read in sorted key order (``key_ordered``), as the
    served exports read it, whichever order the run's files hold.
    """
    if not isinstance(report, Mapping):
        return None, "The run holds no report document (report.json), so nothing is rendered."
    from maljan.reporting.models import MalwareReport, key_ordered
    from maljan.reporting.renderers import MarkdownRenderer

    document = key_ordered(report)
    if not document.get("generated_at"):
        completed = job.get("completed_at") if isinstance(job, Mapping) else None
        if not completed:
            return None, (
                "The report document carries no generation time and the job no completion "
                "time: it is not rendered with the build's own clock."
            )
        document["generated_at"] = completed
    try:
        typed = MalwareReport.model_validate(document)
    except ValueError as exc:
        return None, f"The report document does not validate ({type(exc).__name__})."
    return str(MarkdownRenderer().render(typed)), None


def spilled_refs(items: Iterable[Any]) -> list[dict[str, Any]]:
    """Every ``spilled`` reference of the ledger rows ``items``, with its entry id and seq."""
    out: list[dict[str, Any]] = []
    for item in items or ():
        if not isinstance(item, Mapping):
            continue
        for ref in item.get("spilled") or ():
            if isinstance(ref, Mapping):
                out.append(
                    {
                        "entry_id": item.get("entry_id") or item.get("id"),
                        "seq": item.get("seq"),
                        **{k: ref.get(k) for k in ("part", "bytes", "sha256", "key", "error")},
                    }
                )
    return out


def _stage_spilled(
    stage: _Stage,
    refs: list[dict[str, Any]],
    fetch: Fetch | None,
    unfetched: str,
    max_object_bytes: Any,
    bound_name: str,
) -> list[dict[str, Any]]:
    """Every spilled reference, with the path of its verified bytes or why they are absent.

    A part is read only under a bound: the length its reference records, which
    must itself lie within ``max_object_bytes``; the read stops as soon as more
    bytes arrive. No valid bound, or no recorded length, means the part is not
    read and is listed as absent with why.
    """
    bound_ok = _is_count(max_object_bytes) and int(max_object_bytes) > 0
    listed: list[dict[str, Any]] = []
    for ref in sorted(refs, key=lambda r: (int(r.get("seq") or 0), str(r.get("part")))):
        row: dict[str, Any] = {
            k: ref.get(k)
            for k in ("entry_id", "seq", "part", "bytes", "sha256")
            if ref.get(k) is not None
        }
        sha256 = ref.get("sha256")
        declared: Any = ref.get("bytes")
        path = f"{OBJECTS}/{sha256}"
        if not ref.get("key"):
            row["absent"] = f"The part was not kept: {ref.get('error') or 'no key recorded'}."
        elif not _is_hex(sha256, HEX_SHA256):
            row["absent"] = "The reference carries no SHA-256 to verify the kept bytes against."
        elif path in stage.files:
            row["path"] = path
        elif fetch is None:
            row["absent"] = unfetched
        elif not bound_ok:
            row["absent"] = (
                f"No valid {bound_name} is set, so the part cannot be read under a bound."
            )
        elif not _is_count(declared):
            row["absent"] = "The reference records no byte length to bound the read by."
        elif int(declared) > int(max_object_bytes):
            row["absent"] = f"The part exceeds {bound_name} ({max_object_bytes} bytes)."
        else:
            try:
                chunks = _bounded(fetch(str(ref["key"])), int(declared))
                staged = stage.chunks(path, chunks, "a part the ledger spilled")
            except _TooLong:
                stage.drop(path)
                row["absent"] = (
                    "The object store handed back more bytes than the reference records; the "
                    "read was stopped there."
                )
            except Exception as exc:  # noqa: BLE001 — a store that fails is stated, never fatal
                stage.drop(path)
                row["absent"] = f"The object store did not hand it back ({type(exc).__name__})."
            else:
                if staged["sha256"] != sha256:
                    stage.drop(path)
                    row["absent"] = "The object store handed back bytes of another digest."
                else:
                    row["path"] = path
        listed.append(row)
    return listed


def _sample(job: Any, report: Any) -> dict[str, Any]:
    identity = report.get("identity") if isinstance(report, Mapping) else None
    hashes = identity.get("hashes") if isinstance(identity, Mapping) else None
    out = {k: v for k, v in (hashes or {}).items() if isinstance(v, str) and v}
    if isinstance(job, Mapping) and job.get("sample_sha256") and "sha256" not in out:
        out["sha256"] = job["sample_sha256"]
    return {"hashes": dict(sorted(out.items())), "included": False, "note": SAMPLE_NOTE}


def signature_key() -> tuple[ledger_chain.ChainKey | None, str | None]:
    """The package signature key the platform's settings derive, or ``None`` and why."""
    return ledger_chain.platform_key_status(SIGNATURE_LABEL)


def signature_keys() -> dict[str, ledger_chain.ChainKey]:
    """Every package signature key the platform's settings can derive today, by key id.

    The same source as the ledger's own keys (``ledger_chain.known_keys``):
    one settings encryption key is held at a time, so this is the current key
    alone; a package signed under an earlier key reads ``other_key``.
    """
    key, _ = signature_key()
    return {key.key_id: key} if key is not None else {}


def sign(manifest: bytes, key: ledger_chain.ChainKey) -> str:
    """The signature of the manifest's bytes under ``key``, as hex."""
    return ledger_chain.keyed(key, _SIGNATURE_TAG, manifest)


def build_package(
    run_dir: Path,
    out: IO[bytes],
    *,
    verification: Mapping[str, Any],
    max_bytes: int,
    key: ledger_chain.ChainKey | None = None,
    unsigned_reason: str = "No signature was asked for.",
    fetch: Fetch | None = None,
    unfetched: str = OFFLINE,
    max_object_bytes: Any = None,
    bound_name: str = "upload_max_bytes",
    refs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the package of the run in ``run_dir`` into ``out``; returns the manifest.

    ``verification`` is the seal's verification at build time (from the
    database, or from the run directory offline). ``max_bytes`` is
    ``upload_max_bytes``: a file above it is left out of the archive and
    listed as absent with its SHA-256, its size and :data:`OVERSIZED` (only a
    manifest above it makes the build refuse, :class:`PackageError`). ``key`` signs
    the manifest; without one the manifest says why it is unsigned. ``fetch``
    reads a kept part back by its object key, in chunks; without one each part
    is listed with ``unfetched``. ``max_object_bytes`` is the bound one kept
    part was kept under (``bound_name``). ``refs`` are the ledger's spilled
    references when the caller already holds the rows; otherwise they are read
    from the run's ``evidence.json``.
    """
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise PackageError(f"not a run directory: {run_dir}")
    if not _is_count(max_bytes) or max_bytes <= 0:
        raise PackageError("no valid upload_max_bytes bounds the package's files")
    with tempfile.TemporaryDirectory(prefix="maljan-package-") as tmp:
        stage = _Stage(Path(tmp), max_bytes)
        parts: list[dict[str, Any]] = []
        absent: list[dict[str, Any]] = []

        def _part(name: str, path: str | None, reason: str | None, **more: Any) -> None:
            if path is not None and path in stage.oversized:
                absent.append({"part": name, **stage.oversized[path]})
            elif path is not None:
                parts.append({"part": name, "path": path, **more})
            else:
                absent.append({"part": name, "reason": reason})

        for name in RUN_FILES:
            source = run_dir / name
            if source.is_symlink():
                raise PackageError(f"{name} in the run directory is a symbolic link")
            if source.is_file():
                stage.chunks(f"{RUN}/{name}", _read_file(source), f"the stored run's {name}")
        # The run's files that were staged: the only ones ever parsed. A file
        # left out for its size is never read whole (``left_out``).
        present = {name for name in RUN_FILES if f"{RUN}/{name}" in stage.files}
        left_out = {name for name in RUN_FILES if f"{RUN}/{name}" in stage.oversized}

        def _run_part(name: str, file: str, what: str) -> None:
            if file in present or file in left_out:
                _part(name, f"{RUN}/{file}", None)
            else:
                _part(name, None, f"The run holds no {what} ({file}).")

        _run_part("job", "job.json", "job row")
        _run_part("report_row", "report-byjob.json", "report row")
        _run_part("report_json", "report.json", "report document")
        _run_part("evidence_ledger", "evidence.json", "evidence ledger")
        _run_part("run_summary", "run-summary.json", "run summary")
        _run_part("judge_stix_bundle", "stix-judge.json", "judge's STIX bundle")
        _run_part("events", "events.json", "event log")

        byjob = _load(run_dir / "report-byjob.json") if "report-byjob.json" in present else None
        report = _load(run_dir / "report.json") if "report.json" in present else None
        if report is None and isinstance(byjob, Mapping):
            report = byjob.get("malware_report")
        job = _load(run_dir / "job.json") if "job.json" in present else None
        # The seal as the report row holds it; a run without one may still
        # carry it in its report document.
        seal = byjob.get("ledger_seal") if isinstance(byjob, Mapping) else None
        if seal is None and isinstance(report, Mapping):
            seal = report.get(ledger_chain.SEAL_KEY)

        rendered, why = _markdown(report, job)
        if rendered is not None:
            stage.text(MARKDOWN, rendered, "the report rendered by the Markdown exporter")
        _part("report_markdown", MARKDOWN if rendered is not None else None, why)
        dynamic = report.get("dynamic") if isinstance(report, Mapping) else None
        if dynamic:
            _part("sandbox_behaviour", f"{RUN}/report.json", None, pointer="/dynamic")
        else:
            _part(
                "sandbox_behaviour",
                None,
                "The report holds no sandbox behaviour (its dynamic section is empty or absent).",
            )

        stix = byjob.get("stix_bundle") if isinstance(byjob, Mapping) else None
        if "stix-bundle.json" in present or "stix-bundle.json" in left_out:
            _part("stix_bundle", f"{RUN}/stix-bundle.json", None)
        elif stix is not None:
            stage.json(STIX, stix, "the STIX 2.1 bundle the report row serves")
            _part("stix_bundle", STIX, None)
        else:
            _part("stix_bundle", None, "The report row holds no STIX bundle.")
        del stix, byjob
        _part("misp_event", None, NO_MISP)
        attributes = report.get("misp_attributes") if isinstance(report, Mapping) else None
        if isinstance(attributes, list):
            # In the report document, or in the report row that carried it.
            where, pointer = (
                (f"{RUN}/report.json", "/misp_attributes")
                if "report.json" in present
                else (f"{RUN}/report-byjob.json", "/malware_report/misp_attributes")
            )
            _part("misp_attributes", where, None, pointer=pointer, count=len(attributes))
        else:
            _part("misp_attributes", None, NO_MISP_ATTRIBUTES)
        del attributes

        if refs is None and "evidence.json" in left_out:
            _part(
                "spilled_objects",
                None,
                "The evidence ledger was larger than the package bound, so its spilled "
                "references were not read.",
            )
        else:
            if refs is None:
                evidence = _load(run_dir / "evidence.json") if "evidence.json" in present else None
                items = evidence.get("items") if isinstance(evidence, Mapping) else evidence
                refs = spilled_refs(items if isinstance(items, list) else [])
                del evidence, items
            listed = _stage_spilled(stage, refs, fetch, unfetched, max_object_bytes, bound_name)
            stage.json(SPILLED, listed, "every spilled part: its digest, and its bytes or why not")
            _part("spilled_objects", SPILLED, None, kept=sum(1 for r in listed if "path" in r))

        stage.json(
            SEAL,
            {"seal": seal, "verification": dict(verification)},
            "the ledger seal and its verification at build time",
        )
        _part("seal", SEAL, None)

        manifest: dict[str, Any] = {
            "format": FORMAT,
            "job_id": str(verification.get("job_id") or (job or {}).get("id") or ""),
            "sample": _sample(job, report),
            "seal": {
                "status": verification.get("status"),
                "reason": verification.get("reason"),
                "first_broken_seq": verification.get("first_broken_seq"),
            },
            "files": [stage.files[p] for p in sorted(stage.files)],
            "oversized": [stage.oversized[p] for p in sorted(stage.oversized)],
            "package_bound": {"setting": "upload_max_bytes", "bytes": max_bytes},
            "parts": sorted(parts, key=lambda p: str(p["part"])),
            "absent": sorted(absent, key=lambda p: str(p["part"])),
            "signature": (
                {
                    "algorithm": SIGNATURE_ALGORITHM,
                    "key_label": SIGNATURE_LABEL.decode("ascii"),
                    "key_id": key.key_id,
                    "file": SIGNATURE,
                    "proves": SIGNATURE_PROVES,
                }
                if key is not None
                else {"absent": unsigned_reason}
            ),
        }
        del report, job
        stage.json(MANIFEST, manifest, "the manifest")
        if MANIFEST in stage.oversized:
            raise PackageError("the manifest itself is above upload_max_bytes")
        if key is not None:
            body = (stage.root / MANIFEST).read_bytes()
            stage.json(
                SIGNATURE,
                _signature_record(body, key.key_id, sign(body, key)),
                "the manifest's signature",
            )
        write_archive(((p, stage.root / p) for p in stage.files), out, key=key)
    return manifest


def _signature_record(body: bytes, key_id: str, mac: str) -> dict[str, str]:
    """The signature record the builder writes for the manifest's bytes ``body``."""
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_label": SIGNATURE_LABEL.decode("ascii"),
        "key_id": key_id,
        "manifest_sha256": hashlib.sha256(body).hexdigest(),
        "hmac": mac,
    }


def archive_order(name: str) -> tuple[int, str]:
    """The manifest first, its signature second, every other entry by path."""
    return ({MANIFEST: 0, SIGNATURE: 1}.get(name, 2), name)


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    """The header the builder writes for a file: plain USTAR, time 0, mode 0644, owner 0:0."""
    info = tarfile.TarInfo(name)
    info.size = size
    info.mtime = 0
    info.mode = _FILE_MODE
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.type = tarfile.REGTYPE
    return info


class _Deflating:
    """A gzip member's body written into ``sink``: the deflate stream, its CRC and length.

    The compressor is the one ``gzip.GzipFile`` uses at its default level, so
    the deflate bytes are those the builder always wrote; the header is
    written apart (:func:`archive_stream`).
    """

    def __init__(self, sink: IO[bytes]) -> None:
        self.sink = sink
        self.crc = 0
        self.size = 0
        self._compress = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS, zlib.DEF_MEM_LEVEL, 0)

    def write(self, data: bytes) -> int:
        self.crc = zlib.crc32(data, self.crc)
        self.size += len(data)
        self.sink.write(self._compress.compress(data))
        return len(data)

    def tell(self) -> int:
        return self.size

    # Write-only: what ``tarfile`` asks of a file object it is handed.
    def read(self, size: int, /) -> bytes:
        raise io.UnsupportedOperation("a package stream is write-only")

    def seek(self, pos: int, /) -> int:
        raise io.UnsupportedOperation("a package stream is write-only")

    def close(self) -> None:
        return None

    def finish(self) -> None:
        self.sink.write(self._compress.flush())
        self.sink.write(struct.pack("<II", self.crc, self.size & 0xFFFFFFFF))


def _file_hmac(digest: bytes, key: ledger_chain.ChainKey) -> bytes:
    """The HMAC the header carries beside the file digest, under the package key."""
    return bytes.fromhex(ledger_chain.keyed(key, _FILE_TAG, digest))


@contextmanager
def archive_stream(
    out: IO[bytes], *, key: ledger_chain.ChainKey | None = None
) -> Iterator[_Deflating]:
    """A writable stream whose bytes become one package file in ``out``.

    What is written is compressed into an anonymous temporary file; once the
    block ends, the header with the SHA-256 of that body (and its HMAC under
    ``key``, which must be the manifest's signature key, or zeros for an
    unsigned package) is written into ``out``, then the body.
    """
    with tempfile.TemporaryFile(prefix="maljan-package-body-") as body:
        stream = _Deflating(body)
        yield stream
        stream.finish()
        body.seek(0)
        digest = hashlib.sha256()
        while chunk := body.read(CHUNK):
            digest.update(chunk)
        value = digest.digest()
        out.write(_HEADER + value + (_file_hmac(value, key) if key is not None else _NO_HMAC))
        body.seek(0)
        while chunk := body.read(CHUNK):
            out.write(chunk)


def write_archive(
    entries: Iterable[tuple[str, Path]],
    out: IO[bytes],
    *,
    key: ledger_chain.ChainKey | None = None,
) -> None:
    """Write ``entries`` (archive path, source file) as a deterministic ``.tar.gz`` into ``out``.

    Entries are written in :func:`archive_order` whatever order they are given
    in, as plain USTAR regular files, under the header :func:`archive_stream`
    writes (``key`` is the manifest's signature key, or ``None`` unsigned).
    """
    with (
        archive_stream(out, key=key) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar,
    ):
        for name, source in sorted(entries, key=lambda e: archive_order(e[0])):
            with source.open("rb") as handle:
                tar.addfile(_tar_info(name, source.stat().st_size), handle)


def _unsafe(name: str) -> str | None:
    """Why ``name`` cannot be a package entry, or ``None`` when it can."""
    if not name or "\\" in name or "\x00" in name:
        return "The entry name is empty or holds a backslash or a NUL."
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return "The entry name is an absolute path."
    if any(part in ("", ".", "..") for part in name.split("/")):
        return "The entry name leaves the package or is not normalised."
    if posixpath.normpath(name) != name:
        return "The entry name is not normalised."
    return None


def _plain(member: tarfile.TarInfo) -> bool:
    """A plain USTAR regular file: no sparse map, no PAX or GNU extended header before it."""
    return (
        member.type == tarfile.REGTYPE
        and member.sparse is None
        and not member.pax_headers
        and member.offset_data == member.offset + tarfile.BLOCKSIZE
    )


_STRING = re.compile(rb'"(?:[^"\\]|\\.)*"', re.DOTALL)
_BRACKET = re.compile(rb"[\[\]{}]")


def _depth(data: bytes) -> int:
    """The deepest nesting of arrays and objects in the JSON text ``data``."""
    deepest = level = 0
    for found in _BRACKET.finditer(_STRING.sub(b"", data)):
        level += 1 if found.group() in (b"[", b"{") else -1
        deepest = max(deepest, level)
    return deepest


def _parse(data: bytes, depth: int) -> Any:
    """``data`` parsed as JSON no deeper than ``depth``; ``None`` when it is not."""
    if _depth(data) > depth:
        return None
    try:
        return json.loads(data)
    except (ValueError, RecursionError):
        return None


def _broken(file: str, reason: str, **more: Any) -> dict[str, Any]:
    return {"status": BROKEN, "file": file, "reason": reason, **more}


def _listing(manifest: Mapping[str, Any], max_bytes: int) -> dict[str, Mapping[str, Any]] | str:
    """The manifest's files by path, or the fixed reason the listing is not a package's."""
    listed: dict[str, Mapping[str, Any]] = {}
    recorded = manifest.get("package_bound")
    bound: Any = recorded.get("bytes") if isinstance(recorded, Mapping) else None
    if not _is_count(bound) or int(bound) <= 0:
        return "The manifest records no package bound."
    within = min(max_bytes, int(bound))
    files = manifest.get("files")
    if not isinstance(files, list):
        return "The manifest lists no files."
    for entry in files:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("path"), str):
            return "The manifest lists a file without a path."
        path = entry["path"]
        if _unsafe(path) is not None or path in (MANIFEST, SIGNATURE) or path in listed:
            return "The manifest lists an unsafe, reserved or repeated path."
        if not _is_count(entry.get("bytes")) or int(entry["bytes"]) > within:
            return "The manifest lists a file without a size, or one above the package bound."
        if not _is_hex(entry.get("sha256"), HEX_SHA256):
            return "The manifest lists a file without a SHA-256."
        listed[path] = entry
    left_out = manifest.get("oversized", [])
    if not isinstance(left_out, list):
        return "The manifest's list of files left out for their size is not a list."
    for entry in left_out:
        if (
            not isinstance(entry, Mapping)
            or not isinstance(entry.get("path"), str)
            or _unsafe(entry["path"]) is not None
            or entry["path"] in listed
            or not _is_count(entry.get("bytes"))
            or int(entry["bytes"]) <= int(bound)
            or not _is_hex(entry.get("sha256"), HEX_SHA256)
        ):
            return (
                "The manifest lists a file left out for its size that is not larger than the "
                "package bound it records, or without a path or SHA-256."
            )
    return listed


class _Null:
    """A sink that keeps nothing, for entries only hashed."""

    def __enter__(self) -> _Null:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def write(self, data: bytes) -> int:
        return len(data)


class _Sink(Protocol):
    def update(self, data: bytes, /) -> None: ...


class _Once:
    """``raw`` read once, front to back, as ``gzip`` reads it.

    The header is read first and served again from memory; every later byte
    is handed to the sink :meth:`watch` names the first time it passes, and a
    forward seek reads the bytes it skips, so the sink sees each byte of the
    file exactly once and the file is never read a second time.
    """

    mode = "rb"

    def __init__(self, raw: BinaryIO, head: int) -> None:
        self.raw = raw
        self.head = raw.read(head)
        self.read_to = len(self.head)
        self.raw_at = len(self.head)
        self.position = 0
        self.sink: _Sink | None = None

    def watch(self, start: int, sink: _Sink) -> None:
        self.sink = sink
        sink.update(self.head[start:])

    def read(self, size: int = -1, /) -> bytes:
        if self.position < len(self.head):
            end = len(self.head) if size < 0 else min(len(self.head), self.position + size)
            out = self.head[self.position : end]
            self.position = end
            return out
        if self.raw_at != self.position:
            self.raw.seek(self.position)
        data = self.raw.read(size)
        end = self.position + len(data)
        if end > self.read_to:
            fresh = data[max(0, self.read_to - self.position) :]
            self.read_to = end
            if self.sink is not None:
                self.sink.update(fresh)
        self.position = self.raw_at = end
        return data

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        if whence not in (io.SEEK_SET, io.SEEK_CUR):
            raise io.UnsupportedOperation("a package is read front to back")
        target = offset if whence == io.SEEK_SET else self.position + offset
        if target > self.read_to:
            # Only by reading: a file that ends first (or grows later) never
            # leaves bytes the sink has not seen.
            self.position = self.read_to
            while self.position < target:
                if not self.read(min(CHUNK, target - self.position)):
                    raise EOFError("the package ends before the position sought")
        self.position = target
        return target

    def tell(self) -> int:
        return self.position

    # Read-only: what ``tarfile`` asks of a file object it is handed.
    def write(self, data: bytes, /) -> int:
        raise io.UnsupportedOperation("a package is only read")

    def close(self) -> None:
        return None

    def drain(self) -> None:
        """Read what is left of the file, so the sink has seen all of it."""
        self.seek(self.read_to)
        while self.read(CHUNK):
            pass


class _Canonical:
    """A package built before the file digest, checked byte for byte as its bytes pass.

    Fed the deflate stream after the old plain header (:class:`_Once`), it
    inflates it in bounded steps and holds it to what the builder wrote then:
    every tar header the one :func:`_tar_info` gives for its name and size,
    every padding byte zero, the end marker and the record padding exact,
    nothing more inflated, and the gzip CRC and length right with nothing
    after them.
    """

    def __init__(self) -> None:
        self.inflate = zlib.decompressobj(-zlib.MAX_WBITS)
        self.buffer = bytearray()
        self.tail = bytearray()
        self.crc = 0
        self.size = 0
        self.ok = True
        self.state = "header"
        self.want = tarfile.BLOCKSIZE
        self.skip = 0
        self.offset = 0

    def update(self, data: bytes, /) -> None:
        if not self.ok:
            return
        if self.inflate.eof:
            self.tail += data
            self.ok = len(self.tail) <= 8
            return
        try:
            self._take(self.inflate.decompress(data, CHUNK))
            while self.ok and not self.inflate.eof and self.inflate.unconsumed_tail:
                self._take(self.inflate.decompress(self.inflate.unconsumed_tail, CHUNK))
        except zlib.error:
            self.ok = False
            return
        if self.inflate.eof:
            self.tail += self.inflate.unused_data
            self.ok = self.ok and len(self.tail) <= 8

    def _take(self, out: bytes) -> None:
        self.crc = zlib.crc32(out, self.crc)
        self.size += len(out)
        self.buffer += out
        while self.ok:
            if self.state == "data":
                step = min(self.skip, len(self.buffer))
                del self.buffer[:step]
                self.skip -= step
                if self.skip:
                    return
                self.state, self.want = "padding", -self.offset % tarfile.BLOCKSIZE
                self.offset += self.want
                continue
            if self.state == "done":
                self.ok = not self.buffer
                return
            if len(self.buffer) < self.want:
                return
            chunk = bytes(self.buffer[: self.want])
            del self.buffer[: self.want]
            self._step(chunk)

    def _step(self, chunk: bytes) -> None:
        if self.state in ("padding", "end"):
            self.ok = not chunk.strip(b"\0")
            self.state, self.want = (
                ("header", tarfile.BLOCKSIZE) if self.state == "padding" else ("done", 0)
            )
            return
        self.offset += tarfile.BLOCKSIZE
        if chunk == bytes(tarfile.BLOCKSIZE):
            # The second zero block, then zeros to the end of the record.
            end = self.offset + tarfile.BLOCKSIZE
            end += -end % tarfile.RECORDSIZE
            self.state, self.want = "end", end - self.offset
            return
        try:
            info = tarfile.TarInfo.frombuf(chunk, tarfile.ENCODING, "surrogateescape")
            canonical = _tar_info(info.name, info.size).tobuf(
                tarfile.USTAR_FORMAT, tarfile.ENCODING, "surrogateescape"
            )
        except (tarfile.TarError, ValueError):
            self.ok = False
            return
        self.ok = chunk == canonical
        self.state, self.skip = "data", info.size
        self.offset += info.size

    def finish(self) -> bool:
        trailer = struct.pack("<II", self.crc, self.size & 0xFFFFFFFF)
        return (
            self.ok
            and self.state == "done"
            and self.inflate.eof
            and not self.buffer
            and bytes(self.tail) == trailer
        )


def _file_digest(
    digest: bytes,
    carried: bytes,
    manifest: Mapping[str, Any],
    state: str,
    keys: Mapping[str, ledger_chain.ChainKey],
) -> tuple[str, str] | None:
    """The file digest's state and reason once it matched, or ``None`` when its HMAC does
    not: a signed package's under the manifest's key, an unsigned package's none."""
    matched = "The whole file matches the SHA-256 its gzip header carries"
    if state == "absent":
        if carried != _NO_HMAC:
            return None
        return "valid", f"{matched}; the package is unsigned, so no HMAC covers it."
    if state == "other_key":
        return "valid", f"{matched}; its HMAC is under a key this environment cannot derive."
    key_id = str(manifest["signature"]["key_id"])
    if not hmac.compare_digest(_file_hmac(digest, keys[key_id]), carried):
        return None
    return "valid", f"{matched}, and its HMAC verifies under key {key_id}."


def verify_package(
    path: Path,
    *,
    verify_run: Callable[[Path], Mapping[str, Any]],
    max_bytes: int,
    keys: Mapping[str, ledger_chain.ChainKey] | None = None,
    allow_unsigned: bool = False,
) -> dict[str, Any]:
    """Re-check a package: the manifest's digests, its signature and the embedded ledger seal.

    The file is opened once and read once, front to back (:class:`_Once`):
    its gzip header must be the builder's, and every byte after it is hashed
    as the archive reads it, then the rest to the end of the file; the
    SHA-256 must match the one the header carries, and once the signature is
    known the HMAC beside it must verify under the manifest's key (zeros for
    an unsigned package; not checked under a key this environment cannot
    derive). A package built before the digest (:data:`LEGACY_FORMAT`, under
    the old plain header) is instead compared byte for byte, in the same
    pass, with what the builder wrote then (:class:`_Canonical`). The
    manifest's format must be the one its header belongs to. Any change to
    the file therefore reads ``broken`` before the seal is looked at, and
    ``seal_unverifiable`` only ever means a key, a seal or a run file the
    package lacks, never damage.

    The archive is read through ``gzip``'s bounded reader in
    :data:`CHUNK` reads, to the gzip end (its CRC is checked) with nothing
    after the tar end marker but its zero padding. Every entry must be a plain
    USTAR regular file under a safe relative name. The manifest must come
    first and be no larger than ``max_bytes`` (``upload_max_bytes``), the
    signature second; every later entry must be listed in the manifest, with a
    listed size within ``max_bytes`` that equals its header's size before a
    byte of it is read, so the whole read is bounded by the manifest's
    declared sizes. Only the ``run/`` files are written to disk, into a
    temporary directory under names checked first, for ``verify_run`` (the
    X4b check of a stored-run directory) to read; nothing is ever extracted
    elsewhere.

    ``keys`` are the signature keys held, by key id (default
    :func:`signature_keys`). When a key is held, an unsigned package is
    ``broken`` unless ``allow_unsigned``. Answers ``verified``, ``broken``
    (naming the file), ``unsigned``, ``other_key`` (signed under a key this
    environment cannot derive, named) or ``seal_unverifiable``, always with a
    fixed reason; what the manifest itself says is quoted apart
    (``manifest_says``).
    """
    if not _is_count(max_bytes) or max_bytes <= 0:
        raise ValueError("verify_package needs a positive upload_max_bytes")
    keys = dict(signature_keys() if keys is None else keys)
    seen: dict[str, str] = {}
    listed: dict[str, Mapping[str, Any]] = {}
    manifest: dict[str, Any] | None = None
    manifest_bytes = b""
    signature: tuple[str, str, Any] | None = None
    try:
        raw = path.open("rb")
    except OSError:
        return _broken(str(path), UNREADABLE)
    file_hash = hashlib.sha256()
    canonical = _Canonical()
    with raw, tempfile.TemporaryDirectory(prefix="maljan-package-verify-") as tmp:
        root = Path(tmp).resolve()
        try:
            # One pass over the file: the header, then every later byte into
            # the file digest (or the byte-for-byte check of an older
            # package) as the archive reads it.
            source = _Once(raw, _HEADER_BYTES)
            head = source.head
            legacy = head[: len(_LEGACY_HEADER)] == _LEGACY_HEADER
            if legacy:
                source.watch(len(_LEGACY_HEADER), canonical)
            elif len(head) == _HEADER_BYTES and head[: len(_HEADER)] == _HEADER:
                source.watch(_HEADER_BYTES, file_hash)
            else:
                return _broken(str(path), NOT_A_PACKAGE_HEADER)
            with tarfile.open(fileobj=source, mode="r:gz") as tar:
                if tar.pax_headers:
                    return _broken(str(path), NOT_PLAIN)
                for index, member in enumerate(tar):
                    name = member.name
                    why = _unsafe(name)
                    if why is not None:
                        return _broken(name, why)
                    if not _plain(member):
                        return _broken(name, NOT_PLAIN)
                    if name in seen or (index and name == MANIFEST):
                        return _broken(name, "The entry appears twice.")
                    handle = tar.extractfile(member)
                    if handle is None:  # pragma: no cover — a regular file always has one
                        return _broken(name, UNREADABLE)
                    if index == 0:
                        if name != MANIFEST:
                            return _broken(name, "The first entry is not the manifest.")
                        if member.size > max_bytes:
                            return _broken(MANIFEST, "The manifest is above upload_max_bytes.")
                        manifest_bytes = handle.read()
                        parsed = _parse(manifest_bytes, MANIFEST_DEPTH)
                        formats = (FORMAT, LEGACY_FORMAT)
                        if not isinstance(parsed, dict) or parsed.get("format") not in formats:
                            return _broken(MANIFEST, f"The manifest is not a {FORMAT} manifest.")
                        if parsed["format"] != (LEGACY_FORMAT if legacy else FORMAT):
                            return _broken(MANIFEST, FORMAT_MISMATCH)
                        manifest = parsed
                        found = _listing(manifest, max_bytes)
                        if isinstance(found, str):
                            return _broken(MANIFEST, found)
                        listed = found
                        continue
                    assert manifest is not None
                    if name == SIGNATURE:
                        if index != 1:
                            return _broken(name, "The signature is not the second entry.")
                        if member.size > max_bytes:
                            return _broken(name, "The signature is above upload_max_bytes.")
                        signature = _check_signature(manifest, manifest_bytes, handle.read(), keys)
                        if signature[0] in ("invalid", "missing"):
                            return _signature_broken(signature)
                        continue
                    if signature is None:
                        signature = _check_signature(manifest, manifest_bytes, None, keys)
                        if signature[0] in ("invalid", "missing"):
                            return _signature_broken(signature)
                    if name not in listed:
                        return _broken(name, "The entry is not listed in the manifest.")
                    if member.size != listed[name]["bytes"]:
                        return _broken(name, "The file's size differs from the manifest.")
                    target = None
                    if name.startswith(f"{RUN}/"):
                        target = (root / name).resolve()
                        if root not in target.parents:
                            return _broken(name, "The entry leaves the package.")
                        target.parent.mkdir(parents=True, exist_ok=True)
                    digest = hashlib.sha256()
                    with target.open("xb") if target is not None else _Null() as copy:
                        while chunk := handle.read(CHUNK):
                            digest.update(chunk)
                            copy.write(chunk)
                    seen[name] = digest.hexdigest()
                    if seen[name] != listed[name]["sha256"]:
                        return _broken(name, "The file's SHA-256 differs from the manifest.")
                # Read to the gzip end: its CRC and length are checked there,
                # and anything after the tar end marker but its padding is
                # data no manifest covers.
                rest = tar.fileobj.read(tarfile.RECORDSIZE + 1) if tar.fileobj else b""
                if len(rest) > tarfile.RECORDSIZE or rest.strip(b"\0"):
                    return _broken(str(path), "The archive holds data after its end marker.")
                if tar.fileobj is not None and tar.fileobj.read(1):
                    return _broken(str(path), "The archive holds data after its end marker.")
            source.drain()
        except (tarfile.TarError, OSError, EOFError, zlib.error):
            return _broken(str(path), UNREADABLE)
        # Every byte of the file, before the seal is looked at.
        carried = head[len(_HEADER) : len(_HEADER) + _DIGEST_BYTES]
        if legacy and not canonical.finish():
            return _broken(str(path), NOT_CANONICAL)
        if not legacy and not hmac.compare_digest(file_hash.digest(), carried):
            return _broken(str(path), FILE_DIGEST_DIFFERS)

        if manifest is None:
            return _broken(MANIFEST, "The package holds no manifest.")
        if signature is None:
            signature = _check_signature(manifest, manifest_bytes, None, keys)
            if signature[0] in ("invalid", "missing"):
                return _signature_broken(signature)
        for name in sorted(listed):
            if name not in seen:
                return _broken(
                    name, "The manifest lists this file and the package does not hold it."
                )
        # The HMAC beside the file digest, before the seal: no change to the
        # file can read anything but broken.
        if legacy:
            file_digest = ("legacy", FILE_DIGEST_LEGACY)
        else:
            mac = head[len(_HEADER) + _DIGEST_BYTES :]
            matched = _file_digest(file_hash.digest(), mac, manifest, signature[0], keys)
            if matched is None:
                return _broken(str(path), FILE_HMAC_DIFFERS)
            file_digest = matched
        # A run file the seal check reads, left out for its size: the check
        # would read a partial run, so it is not run at all.
        blocked = any(str(e["path"]) in SEAL_READS for e in manifest.get("oversized") or [])
        seal = dict(verify_run(root / RUN)) if (root / RUN).is_dir() and not blocked else None
    state, reason, says = signature
    body: dict[str, Any] = {
        "files": len(listed),
        "signature": state,
        "signature_reason": reason,
        "seal": (
            {k: seal.get(k) for k in ("status", "reason", "first_broken_seq")}
            if seal is not None
            else None
        ),
        "seal_at_build": manifest.get("seal"),
        "file_digest": file_digest[0],
        "file_digest_reason": file_digest[1],
        "absent": manifest.get("absent") or [],
        "oversized": manifest.get("oversized") or [],
    }
    if says is not None:
        body["manifest_says"] = says
    # Failures first: a key this environment cannot derive, an unsigned package
    # where the key is held, a seal that does not verify. Only then the
    # answers that something could not be checked.
    if state == "other_key":
        return {"status": OTHER_KEY, "file": SIGNATURE, **body, "reason": reason}
    if state == "absent" and keys and not allow_unsigned:
        return {**body, **_broken(SIGNATURE, UNSIGNED_HELD)}
    if seal is not None and seal.get("status") == "broken":
        file = (
            f"{RUN}/evidence.json"
            if seal.get("first_broken_seq") is not None
            else f"{RUN}/report-byjob.json"
        )
        return {**body, **_broken(file, "The ledger seal does not verify (see seal.reason).")}
    if blocked:
        return {
            "status": SEAL_UNVERIFIABLE,
            "file": None,
            **body,
            "reason": (
                "A stored-run file was larger than the package bound and is absent (see "
                "oversized): the ledger seal cannot be checked against the run."
            ),
        }
    if seal is None:
        return {
            "status": SEAL_UNVERIFIABLE,
            "file": None,
            **body,
            "reason": "The package holds no stored run to check the seal against.",
        }
    if seal.get("status") != "verified":
        return {
            "status": SEAL_UNVERIFIABLE,
            "file": None,
            **body,
            "reason": "The ledger seal could not be verified (see seal.status and seal.reason).",
        }
    if state == "absent":
        return {
            "status": UNSIGNED,
            "file": None,
            **body,
            "reason": UNSIGNED_ACCEPTED if keys else UNSIGNED_NO_KEY,
        }
    return {
        "status": VERIFIED,
        "file": None,
        **body,
        "reason": "Every file matches the signed manifest and the ledger seal verifies.",
    }


def _signature_broken(signature: tuple[str, str, Any]) -> dict[str, Any]:
    state, reason, _ = signature
    return _broken(SIGNATURE if state == "missing" else MANIFEST, reason, signature=state)


def _check_signature(
    manifest: Mapping[str, Any],
    body: bytes,
    signature_bytes: bytes | None,
    keys: Mapping[str, ledger_chain.ChainKey],
) -> tuple[str, str, Any]:
    """``valid``, ``invalid``, ``missing``, ``absent`` or ``other_key``, a fixed reason, and
    what the manifest says of an absent signature (quoted, never used as the reason)."""
    held = manifest.get("signature")
    declared: Mapping[str, Any] = held if isinstance(held, Mapping) else {}
    if signature_bytes is None:
        if declared.get("key_id"):
            return (
                "missing",
                "The manifest says it is signed and the signature file is gone.",
                None,
            )
        says = declared.get("absent")
        return (
            "absent",
            "The package carries no signature.",
            says if isinstance(says, str) else None,
        )
    record = _parse(signature_bytes, SIGNATURE_DEPTH)
    if not isinstance(record, Mapping):
        return "invalid", "The signature file is not a signature record.", None
    key_id = record.get("key_id")
    mac = record.get("hmac")
    if not _is_hex(key_id, ledger_chain.KEY_ID_LENGTH) or not _is_hex(mac, HEX_SHA256):
        return "invalid", "The signature record carries no well-formed key id and HMAC.", None
    if key_id != declared.get("key_id"):
        return "invalid", "The signature names another key than the manifest does.", None
    # Byte for byte the record the builder writes (as ``_Stage.json`` writes
    # it): no field, value or spacing of it is left unchecked.
    canonical = json.dumps(_signature_record(body, str(key_id), str(mac)), indent=1, sort_keys=True)
    if signature_bytes != canonical.encode("utf-8"):
        return "invalid", "The signature file is not the record the builder writes.", None
    key = keys.get(str(key_id))
    if key is None:
        return (
            "other_key",
            f"The manifest is signed under key {key_id}, which this environment's settings "
            "cannot derive (a rotated settings key, or a relabelled signature): the signature "
            "proves nothing here.",
            None,
        )
    if not hmac.compare_digest(sign(body, key).encode("ascii"), str(mac).encode("ascii")):
        return "invalid", "The manifest does not match its signature.", None
    return (
        "valid",
        f"The manifest's signature verifies under key {key.key_id}. {SIGNATURE_PROVES}",
        None,
    )


async def build_for_job(engine: Any, job_id: Any, out: IO[bytes]) -> dict[str, Any] | None:
    """Build the package of one stored job into ``out``; ``None`` when there is no such job.

    The job's rows and the seal's verification are read in one snapshot: a
    connection of ``engine`` in a ``REPEATABLE READ READ ONLY`` transaction
    (PostgreSQL), rolled back at the end, as the ledger verification's own
    command reads read-only. The ledger rows are read once
    (:func:`run_export.read_job_rows`) and shared with the verification
    (``ledger_verify.verify_job``, which reads the job's audit rows too) and
    the written run; they are dropped once written. Each kept part is read
    back from the object store under the job's own prefix, bounded and
    verified; every file is bounded by ``upload_max_bytes``. The archive is
    built off the event loop.
    """
    import asyncio

    from sqlalchemy import text

    from app.services import object_store
    from app.services.ledger_verify import verify_job
    from app.services.run_export import read_job_rows, run_files, write_files

    async with engine.connect() as conn:
        transaction = await conn.begin()
        try:
            if conn.dialect.name == "postgresql":
                await conn.execute(
                    text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                )
            rows = await read_job_rows(conn, job_id)
            if rows is None:
                return None
            verification = await verify_job(conn, job_id, preloaded=(rows.evidence, rows.report))
        finally:
            await transaction.rollback()
    bound = await object_store.evidence_bound()
    prefix = object_store.evidence_prefix(job_id)
    key, why = signature_key()

    def _fetch(object_key: str) -> Iterator[bytes]:
        if not object_key.startswith(prefix):
            raise PermissionError("the key lies outside this job's prefix")
        response = object_store.open_object(object_store.client(), object_key)
        try:
            yield from response.stream(CHUNK)
        finally:
            response.close()
            response.release_conn()

    refs = spilled_refs(rows.evidence)
    with tempfile.TemporaryDirectory(prefix="maljan-package-run-") as tmp:
        run_dir = Path(tmp) / RUN
        await asyncio.to_thread(write_files, run_files(rows), run_dir)
        del rows
        return await asyncio.to_thread(
            build_package,
            run_dir,
            out,
            verification=verification,
            max_bytes=bound,
            key=key,
            unsigned_reason=f"The platform holds no signature key: {why}.",
            fetch=_fetch,
            max_object_bytes=bound,
            bound_name=object_store.EVIDENCE_BOUND_SETTING,
            refs=refs,
        )


def copy_chunks(source: IO[bytes]) -> Iterator[bytes]:
    """``source`` from its start, in :data:`CHUNK` reads, closed at the end."""
    try:
        source.seek(0)
        while chunk := source.read(CHUNK):
            yield chunk
    finally:
        source.close()


__all__ = [
    "BROKEN",
    "FORMAT",
    "OTHER_KEY",
    "SEAL_UNVERIFIABLE",
    "SIGNATURE_LABEL",
    "UNSIGNED",
    "VERIFIED",
    "PackageError",
    "build_for_job",
    "build_package",
    "copy_chunks",
    "signature_key",
    "signature_keys",
    "spilled_refs",
    "verify_package",
    "write_archive",
]
