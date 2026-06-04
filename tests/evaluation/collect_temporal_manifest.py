"""Build a dated sample manifest for the concept-drift eval (findings-log §4 Item 5, MARD).

Item 5 (temporal / concept-drift) is the one DATA-GATED roadmap item: the harness
``eval_temporal_drift.py`` needs samples bucketed by **first-seen year**, but the
current ground truth carries no date signal. This collector produces that missing
input — a **metadata-only** manifest (sha256 + first_seen + family signature +
file_type), bucketed into balanced per-year cohorts, scoped to our Windows/Linux
remit (§1.8). **No binaries are downloaded**; those must be fetched separately into
an isolated analysis environment and are never committed.

Sources (the cohort logic is identical for all three):
  * ``--selftest``         — synthetic rows through the full pipeline; runs OFFLINE,
                             proves the bucket/filter/sample/write logic end-to-end.
  * ``--source csv FILE``  — parse a locally-downloaded MalwareBazaar *full dump* CSV
                             (https://bazaar.abuse.ch/export/csv/full/ — a ~1 GB zip;
                             download it yourself, we do not fetch it here). Best for a
                             true multi-year span.
  * ``--source api``       — POST ``get_siginfo`` per family to the MalwareBazaar API.
                             Requires an Auth-Key in ``$MALWAREBAZAAR_AUTH_KEY``
                             (abuse.ch made auth mandatory in 2024). Returns the most
                             recent N per family, so a spread of long-lived families
                             yields a spread of years.

The emitted ``signature`` is only a weak family label; the technique-level
ground-truth Item 5 scores against still requires a curation pass (flagged in the
manifest as ``ground_truth_status: "uncurated"``).

Run:  uv run python tests/evaluation/collect_temporal_manifest.py --selftest
      uv run python tests/evaluation/collect_temporal_manifest.py --source csv full.csv
      uv run python tests/evaluation/collect_temporal_manifest.py --source api --families Mirai
      uv run python tests/evaluation/collect_temporal_manifest.py --download   # ISOLATED ENV ONLY
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import asdict, dataclass
from pathlib import Path

_OUT_FILE = Path("D:/tmp/temporal_manifest.json")
_MB_API = "https://mb-api.abuse.ch/api/v1/"
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SAMPLES_DIR = _REPO_ROOT / "data" / "samples"
# MalwareBazaar ships every binary in a password-protected zip; the password is
# the well-known constant below.
_ZIP_PASSWORD = b"infected"
_MB_UA = "Mozilla/5.0 (maljan-temporal-manifest/1.0)"

# Windows + Linux native binaries only (§1.8). MalwareBazaar ``file_type`` values;
# Android (apk/dex) and document droppers are deliberately excluded.
_SCOPE_FILE_TYPES: frozenset[str] = frozenset({"exe", "dll", "sys", "elf", "so"})

# MalwareBazaar full-dump CSV column order (the export ships a commented header,
# not a machine header row, so we index by position).
_CSV_COLS = (
    "first_seen_utc",
    "sha256_hash",
    "md5_hash",
    "sha1_hash",
    "reporter",
    "file_name",
    "file_type_guess",
    "mime_type",
    "signature",
    "clamav",
    "vtpercent",
    "imphash",
    "ssdeep",
    "tlsh",
)


@dataclass
class SampleRecord:
    """One normalized, dated sample (metadata only — no binary)."""

    sha256: str
    first_seen: str  # "YYYY-MM-DD HH:MM:SS" (UTC)
    year: str  # "YYYY"
    file_type: str
    signature: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Pure pipeline (network-free — these are what --selftest exercises)
# ---------------------------------------------------------------------------


def _year_of(first_seen: str) -> str:
    """Extract the 4-digit year from a 'YYYY-...' timestamp ('' if malformed)."""
    fs = (first_seen or "").strip()
    return fs[:4] if len(fs) >= 4 and fs[:4].isdigit() else ""


def normalize(
    *, sha256: str, first_seen: str, file_type: str, signature: str
) -> SampleRecord | None:
    """Build a SampleRecord, or None if the row lacks a usable hash/date/type."""
    sha = (sha256 or "").strip().lower()
    ftype = (file_type or "").strip().lower()
    year = _year_of(first_seen)
    if len(sha) != 64 or not year or not ftype:
        return None
    return SampleRecord(
        sha256=sha,
        first_seen=first_seen.strip(),
        year=year,
        file_type=ftype,
        signature=(signature or "").strip() or "unknown",
    )


def filter_scope(records: list[SampleRecord]) -> list[SampleRecord]:
    """Keep only Windows/Linux native binaries (§1.8 scope)."""
    return [r for r in records if r.file_type in _SCOPE_FILE_TYPES]


def bucket_by_year(records: list[SampleRecord]) -> OrderedDict[str, list[SampleRecord]]:
    """Group records by first-seen year, years ascending."""
    buckets: dict[str, list[SampleRecord]] = {}
    for r in records:
        buckets.setdefault(r.year, []).append(r)
    return OrderedDict(sorted(buckets.items()))


def sample_cohort(records: list[SampleRecord], n: int) -> list[SampleRecord]:
    """Pick up to ``n`` records, deterministically and evenly spread.

    Sorted by sha256 (stable, content-addressed) then evenly strided so the
    sample isn't biased toward whichever order the source happened to return.
    """
    if n <= 0 or len(records) <= n:
        return sorted(records, key=lambda r: r.sha256)
    ordered = sorted(records, key=lambda r: r.sha256)
    step = len(ordered) / n
    return [ordered[int(i * step)] for i in range(n)]


def build_manifest(records: list[SampleRecord], per_cohort: int, *, source: str) -> dict:
    """Filter to scope, bucket by year, balance-sample each cohort, package."""
    scoped = filter_scope(records)
    buckets = bucket_by_year(scoped)
    cohorts: OrderedDict[str, list[dict[str, str]]] = OrderedDict()
    counts: OrderedDict[str, int] = OrderedDict()
    for year, recs in buckets.items():
        chosen = sample_cohort(recs, per_cohort)
        cohorts[year] = [r.to_dict() for r in chosen]
        counts[year] = len(chosen)
    return {
        "schema": "maljan-temporal-manifest/v1",
        "source": source,
        "scope": ["windows", "linux"],
        "file_types": sorted(_SCOPE_FILE_TYPES),
        "per_cohort_target": per_cohort,
        "ground_truth_status": "uncurated",
        "note": (
            "Metadata only; binaries NOT included. The 'signature' is a weak family "
            "label — technique-level ground truth must be curated before this feeds "
            "eval_temporal_drift.py. Download binaries separately into an isolated env."
        ),
        "counts": dict(counts),
        "total": sum(counts.values()),
        "cohorts": dict(cohorts),
    }


def write_manifest(manifest: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Source adapters
# ---------------------------------------------------------------------------


def records_from_csv(text: str) -> list[SampleRecord]:
    """Parse a MalwareBazaar full-dump CSV (commented header, positional columns)."""
    out: list[SampleRecord] = []
    body = [ln for ln in text.splitlines() if ln and not ln.lstrip().startswith("#")]
    for row in csv.reader(body):
        if len(row) < len(_CSV_COLS):
            continue
        field = dict(zip(_CSV_COLS, (c.strip() for c in row), strict=False))
        rec = normalize(
            sha256=field["sha256_hash"],
            first_seen=field["first_seen_utc"],
            file_type=field["file_type_guess"],
            signature=field["signature"],
        )
        if rec:
            out.append(rec)
    return out


def records_from_api(families: list[str], auth_key: str, limit: int = 1000) -> list[SampleRecord]:
    """POST get_siginfo per family. Requires a valid abuse.ch Auth-Key."""
    out: list[SampleRecord] = []
    for fam in families:
        payload = urllib.parse.urlencode(
            {"query": "get_siginfo", "signature": fam, "limit": str(limit)}
        ).encode()
        req = urllib.request.Request(
            _MB_API,
            data=payload,
            # abuse.ch 403s the default ``Python-urllib`` UA — present a normal one.
            headers={"Auth-Key": auth_key, "User-Agent": _MB_UA},
        )
        try:
            # req targets the fixed _MB_API host constant (no user-controlled
            # scheme/host) — not an SSRF; both linters' URL warnings are moot.
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310  # nosemgrep
                doc = json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            # abuse.ch encodes the reason in the JSON body even on a 4xx (e.g.
            # ``unknown_auth_key`` on 403) — surface it instead of a bare code.
            detail = ""
            try:
                detail = json.loads(exc.read().decode("utf-8", "replace")).get("query_status", "")
            except (ValueError, OSError):
                pass
            print(
                f"  [api] family '{fam}' failed: HTTP {exc.code} ({detail or exc.reason})",
                flush=True,
            )
            if detail == "unknown_auth_key":
                print("  [api] -> Auth-Key not recognised by abuse.ch; aborting.", flush=True)
                break
            continue
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            print(f"  [api] family '{fam}' failed: {exc}", flush=True)
            continue
        status = doc.get("query_status")
        if status != "ok":
            print(f"  [api] family '{fam}': query_status={status}", flush=True)
            continue
        for item in doc.get("data", []):
            rec = normalize(
                sha256=item.get("sha256_hash", ""),
                first_seen=item.get("first_seen", ""),
                file_type=item.get("file_type", ""),
                signature=item.get("signature", "") or fam,
            )
            if rec:
                out.append(rec)
        print(f"  [api] family '{fam}': {len(doc.get('data', []))} records", flush=True)
    return out


def _extract_password_zip(zpath: Path, dest_dir: Path) -> str:
    """Extract the first file member of a MalwareBazaar password zip to dest_dir.

    MalwareBazaar ships WinZip-AES archives that the stdlib ``zipfile`` cannot
    decrypt ("That compression method is not supported"); fall back to
    ``pyzipper`` (AES-capable) when the stdlib path fails. Returns the extracted
    member's path; raises on a genuinely undecryptable / empty archive.
    """
    import zipfile

    def _first_member(names: list[str]) -> str:
        members = [m for m in names if not m.endswith("/")]
        if not members:
            raise zipfile.BadZipFile("empty archive")
        return members[0]

    try:  # plain Deflate zips open with the stdlib
        with zipfile.ZipFile(zpath) as zf:
            return zf.extract(_first_member(zf.namelist()), path=dest_dir, pwd=_ZIP_PASSWORD)
    except (RuntimeError, NotImplementedError, zipfile.BadZipFile, OSError):
        import pyzipper  # AES-encrypted MalwareBazaar archives

        with pyzipper.AESZipFile(zpath) as zf:
            return zf.extract(_first_member(zf.namelist()), path=dest_dir, pwd=_ZIP_PASSWORD)


def download_samples(
    manifest_path: Path, dest_dir: Path, auth_key: str, *, limit: int = 0
) -> tuple[int, int, int]:
    """Download each manifest sample's binary into ``dest_dir/<sha256>.<ext>``.

    Uses MalwareBazaar ``get_file`` (password-zip; password ``infected``) and
    extracts with the stdlib. AES-encrypted zips (stdlib can't open) are left on
    disk as ``<sha256>.zip`` for manual extraction with 7-zip/pyzipper.

    WARNING: this fetches **live malware**. Run it ONLY inside an isolated
    analysis VM/container — never on a normal workstation. Returns
    (extracted, zip_only, failed).
    """
    import zipfile

    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    samples = [s for recs in doc.get("cohorts", {}).values() for s in recs]
    if limit > 0:
        samples = samples[:limit]
    dest_dir.mkdir(parents=True, exist_ok=True)

    extracted = zip_only = failed = 0
    for s in samples:
        sha = s["sha256"]
        ext = s.get("file_type", "bin") or "bin"
        target = dest_dir / f"{sha}.{ext}"
        if target.exists():
            extracted += 1
            continue
        zpath = dest_dir / f"{sha}.zip"
        # Resume: reuse a zip left by a prior interrupted run instead of
        # re-fetching it (saves the API quota + bandwidth).
        if not zpath.exists():
            payload = urllib.parse.urlencode({"query": "get_file", "sha256_hash": sha}).encode()
            req = urllib.request.Request(
                _MB_API, data=payload, headers={"Auth-Key": auth_key, "User-Agent": _MB_UA}
            )
            try:
                # req targets the fixed _MB_API host constant — not an SSRF.
                with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310  # nosemgrep
                    blob = resp.read()
            except (urllib.error.URLError, TimeoutError, urllib.error.HTTPError) as exc:
                print(f"  [dl] {sha[:12]} request failed: {exc}", flush=True)
                failed += 1
                continue
            # abuse.ch returns a JSON status (not a zip) on not-found / auth failure.
            if blob[:1] in (b"{", b"["):
                try:
                    status = json.loads(blob.decode("utf-8", "replace")).get("query_status", "?")
                except ValueError:
                    status = "?"
                print(f"  [dl] {sha[:12]}: {status}", flush=True)
                failed += 1
                if status == "unknown_auth_key":
                    break
                continue
            zpath.write_bytes(blob)
        try:
            got = _extract_password_zip(zpath, dest_dir)
            Path(got).replace(target)
            zpath.unlink()
            extracted += 1
            print(f"  [dl] {sha[:12]} -> {target.name}", flush=True)
        except (RuntimeError, NotImplementedError, zipfile.BadZipFile, OSError, ValueError) as exc:
            print(
                f"  [dl] {sha[:12]} saved encrypted zip "
                f"(extract manually, password 'infected'): {exc}",
                flush=True,
            )
            zip_only += 1
    print(f"\nDownload: {extracted} extracted, {zip_only} zip-only, {failed} failed.", flush=True)
    return extracted, zip_only, failed


def _synthetic_rows() -> list[SampleRecord]:
    """Deterministic synthetic corpus for --selftest: 5 year-cohorts, mixed scope."""
    fams = ["AgentTesla", "Mirai", "Emotet", "CobaltStrike", "XMRig"]
    types = ["exe", "elf", "dll", "apk", "so"]  # apk must be filtered out
    rows: list[SampleRecord] = []
    for yi, year in enumerate(("2021", "2022", "2023", "2024", "2025")):
        for k in range(12):  # 12 candidates/year so sampling has something to thin
            sha = f"{(yi * 100 + k):064x}"
            ftype = types[k % len(types)]
            rec = normalize(
                sha256=sha,
                first_seen=f"{year}-0{(k % 9) + 1}-15 08:30:00",
                file_type=ftype,
                signature=fams[k % len(fams)],
            )
            if rec:
                rows.append(rec)
    return rows


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _print_summary(manifest: dict) -> None:
    print("\nCohort counts (post-filter, post-sample):", flush=True)
    for year, n in manifest["counts"].items():
        print(f"  {year}: {n}", flush=True)
    print(f"  total: {manifest['total']}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Dated sample manifest for the §4 Item 5 drift eval.")
    ap.add_argument("--source", choices=("csv", "api"), help="Live data source.")
    ap.add_argument(
        "--file", type=str, help="Path to a MalwareBazaar full-dump CSV (--source csv)."
    )
    ap.add_argument(
        "--families", type=str, default="", help="Comma list of family signatures (--source api)."
    )
    ap.add_argument("--per-cohort", type=int, default=40, help="Target samples per year cohort.")
    ap.add_argument("--out", type=str, default=str(_OUT_FILE), help="Output manifest path.")
    ap.add_argument("--selftest", action="store_true", help="Offline synthetic run (no network).")
    ap.add_argument(
        "--download",
        action="store_true",
        help="Download the --out manifest's binaries into data/samples/ (ISOLATED ENV ONLY).",
    )
    ap.add_argument("--dest", type=str, default=str(_SAMPLES_DIR), help="Binary download dir.")
    ap.add_argument("--limit", type=int, default=0, help="Cap downloads (0 = all).")
    args = ap.parse_args()

    out_path = Path(args.out)

    if args.download:
        import os

        key = os.environ.get("MALWAREBAZAAR_AUTH_KEY", "").strip()
        if not key:
            print("--download needs $MALWAREBAZAAR_AUTH_KEY.", flush=True)
            return 2
        if not out_path.exists():
            print(f"--download needs an existing manifest at {out_path}.", flush=True)
            return 2
        print(
            "WARNING: downloading LIVE malware. Run this only in an isolated VM/container.\n"
            f"Manifest: {out_path} -> dest: {args.dest}",
            flush=True,
        )
        download_samples(out_path, Path(args.dest), key, limit=args.limit)
        return 0

    if args.selftest:
        print("Self-test: synthetic 5-cohort corpus through the full pipeline.", flush=True)
        records = _synthetic_rows()
        manifest = build_manifest(records, args.per_cohort, source="selftest-synthetic")
        write_manifest(manifest, out_path)
        _print_summary(manifest)
        # Sanity: synthetic data spans exactly 5 years, apk rows must be dropped.
        ok = len(manifest["counts"]) == 5 and all(
            r["file_type"] in _SCOPE_FILE_TYPES
            for recs in manifest["cohorts"].values()
            for r in recs
        )
        print(f"\nWrote {out_path}", flush=True)
        print(f"Self-test {'PASSED' if ok else 'FAILED'}.", flush=True)
        return 0 if ok else 1

    if args.source == "csv":
        if not args.file or not Path(args.file).exists():
            print("--source csv needs an existing --file <full-dump.csv>.", flush=True)
            return 2
        print(f"Parsing CSV dump: {args.file}", flush=True)
        records = records_from_csv(Path(args.file).read_text(encoding="utf-8", errors="replace"))
    elif args.source == "api":
        import os

        key = os.environ.get("MALWAREBAZAAR_AUTH_KEY", "").strip()
        if not key:
            print(
                "--source api needs $MALWAREBAZAAR_AUTH_KEY (abuse.ch auth is mandatory).",
                flush=True,
            )
            return 2
        families = [f.strip() for f in args.families.split(",") if f.strip()]
        if not families:
            print("--source api needs --families <Fam1,Fam2,...>.", flush=True)
            return 2
        print(f"Querying MalwareBazaar get_siginfo for {len(families)} families...", flush=True)
        records = records_from_api(families, key)
    else:
        print("Pick a mode: --selftest, or --source {csv|api}. See --help.", flush=True)
        return 2

    if not records:
        print("No usable records collected — manifest not written.", flush=True)
        return 1
    manifest = build_manifest(records, args.per_cohort, source=args.source or "")
    write_manifest(manifest, out_path)
    _print_summary(manifest)
    print(f"\nWrote {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
