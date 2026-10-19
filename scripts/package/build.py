"""Build a job's package offline from an exported run directory.

    python -m scripts.package.build --run <directory> --out <file> [--unsigned]
        [--upload-max-bytes N]

``--run`` is a directory in the stored-run layout (``python -m scripts.replay.run
--job <id> --job-dir <dir>`` writes one, as does the benchmark). The seal is
verified from the directory alone (``scripts.ledger.verify.verify_run``; the
audit log is not in it, and the verification says so), and the package is
built by the platform's own builder (``app.services.job_package``), which the
API's ``GET /jobs/{id}/package`` uses too. No object store is read: each part
the ledger spilled is listed with its reference and digest, and why its bytes
are absent. The manifest is signed under the key the platform's settings
derive (``SETTINGS_ENCRYPTION_KEY``) unless ``--unsigned`` is given or no key
can be derived, which the manifest then states. Every file is bounded by
``upload_max_bytes`` (``--upload-max-bytes``, by default the setting's own
default, since an offline build reads no runtime settings), as a verification
bounds it.

The manifest is printed as JSON. Exit status: 0 built, 2 a usage or read error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from maljan.core.delivery_limits import SAMPLE_UPLOAD_MAX_BYTES


def build(
    run: Path, out: Path, *, signed: bool = True, max_bytes: int = SAMPLE_UPLOAD_MAX_BYTES
) -> dict[str, Any]:
    """Build the package of ``run`` into ``out``; returns its manifest.

    The archive is written into a file of its own, created exclusively next
    to ``out`` under a unique name, and moved into place once complete: ``out``
    is never a partial package, and two builds never touch each other's file.
    """
    from scripts.ledger.verify import verify_run

    from app.services import job_package

    key, why = job_package.signature_key() if signed else (None, None)
    reason = f"No signature key: {why}." if signed else "--unsigned was given."
    verification = verify_run(run)
    descriptor, name = tempfile.mkstemp(dir=out.parent, prefix=out.name + ".", suffix=".partial")
    partial = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            manifest = job_package.build_package(
                run,
                handle,
                verification=verification,
                max_bytes=max_bytes,
                key=key,
                unsigned_reason=reason,
            )
        partial.replace(out)
    finally:
        partial.unlink(missing_ok=True)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.package.build",
        description="Build a job's verifiable package from an exported run directory.",
    )
    parser.add_argument("--run", type=Path, required=True, help="a stored-run directory")
    parser.add_argument("--out", type=Path, required=True, help="the package file to write")
    parser.add_argument("--unsigned", action="store_true", help="do not sign the manifest")
    parser.add_argument(
        "--upload-max-bytes",
        type=int,
        default=SAMPLE_UPLOAD_MAX_BYTES,
        help="the bound on one file (upload_max_bytes; default: the setting's default)",
    )
    args = parser.parse_args(argv)
    if not args.run.is_dir():
        print(f"not a directory: {args.run}", file=sys.stderr)
        return 2
    try:
        manifest = build(
            args.run, args.out, signed=not args.unsigned, max_bytes=args.upload_max_bytes
        )
    except (OSError, ValueError) as exc:
        print(f"could not build the package: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
