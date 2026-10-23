"""Verify a job's package: the manifest's digests, its signature and the embedded ledger seal.

    python -m scripts.package.verify <file> [--allow-unsigned] [--upload-max-bytes N]

Reads the archive in one pass, to the gzip end (``app.services.job_package.
verify_package``): the manifest must come first and every entry must be a
plain regular file under a safe relative name, listed in the manifest with
its SHA-256 and size; every size is bounded by ``upload_max_bytes``
(``--upload-max-bytes``, by default the setting's own default, since an
offline verification reads no runtime settings). The signature, when the
package carries one, is checked under the key the platform's settings derive
(``SETTINGS_ENCRYPTION_KEY``, purpose label ``maljan-job-package-v1``); it
proves integrity only to holders of that key. When that key is held, an
unsigned package is a failure unless ``--allow-unsigned`` is given. The
stored run inside is written into a temporary directory and its ledger seal is
checked with ``scripts.ledger.verify.verify_run``. Nothing is extracted
anywhere else.

The answer is printed as JSON. Exit status: 0 verified, 1 broken (the answer
names the file), 3 unsigned (accepted: every file matches and the seal
verifies, but no signature), 4 seal_unverifiable, 5 other_key (signed under a
key this environment cannot derive, named), 2 a usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from maljan.core.delivery_limits import SAMPLE_UPLOAD_MAX_BYTES

EXIT = {"verified": 0, "broken": 1, "unsigned": 3, "seal_unverifiable": 4, "other_key": 5}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.package.verify",
        description="Verify a job's package against its manifest, signature and ledger seal.",
    )
    parser.add_argument("file", type=Path, help="the package file")
    parser.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="accept an unsigned package although this environment holds the package key",
    )
    parser.add_argument(
        "--upload-max-bytes",
        type=int,
        default=SAMPLE_UPLOAD_MAX_BYTES,
        help="the bound on one file (upload_max_bytes; default: the setting's default)",
    )
    args = parser.parse_args(argv)
    if not args.file.is_file():
        print(f"not a file: {args.file}", file=sys.stderr)
        return 2
    if args.upload_max_bytes <= 0:
        print("--upload-max-bytes must be positive", file=sys.stderr)
        return 2
    from scripts.ledger.verify import verify_run

    from app.services.job_package import verify_package

    verdict = verify_package(
        args.file,
        verify_run=verify_run,
        max_bytes=args.upload_max_bytes,
        allow_unsigned=args.allow_unsigned,
    )
    print(json.dumps(verdict, indent=1, sort_keys=True))
    return EXIT.get(str(verdict.get("status")), 2)


if __name__ == "__main__":
    sys.exit(main())
