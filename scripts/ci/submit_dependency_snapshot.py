"""Submit the resolved Python dependencies of ``uv.lock`` to GitHub's dependency graph.

The dependency graph parses ``apps/web/package-lock.json`` on every push to
the default branch, so the console's Dependabot alerts follow the lockfile.
``uv.lock`` was not re-read after a relock: the graph kept the versions from
the first parse, and every alert those versions carried stayed open after the
fix had shipped. The Dependency Submission API is the documented way to give
the graph an authoritative view, so this script exports the lock with ``uv``
and submits one snapshot per push to ``main``.

Runtime dependencies (``uv export --no-dev``) are reported with scope
``runtime``; everything only the dev group brings in is ``development``.
Run with ``--dry-run`` to print the snapshot instead of submitting it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import UTC, datetime

DETECTOR = {
    "name": "maljan-uv-export",
    "version": "1",
    "url": "https://github.com/Root0ne/Maljan/blob/main/scripts/ci/submit_dependency_snapshot.py",
}
MANIFEST = "uv.lock"
_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==(?P<version>[^\s;]+)"
)


def normalize(name: str) -> str:
    """PEP 503 normalisation, which is also what a pypi purl expects."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str) -> dict[str, str]:
    """``name==version`` pairs from ``uv export`` output; comments, editables and blanks skipped."""
    found: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-e ", "--")):
            continue
        match = _REQUIREMENT.match(line)
        if match:
            found[normalize(match.group("name"))] = match.group("version")
    return found


def export(extra_args: list[str]) -> str:
    cmd = ["uv", "export", "--frozen", "--no-hashes", "--no-emit-project", "--all-packages"]
    cmd.extend(extra_args)
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def build_snapshot(
    runtime: dict[str, str],
    everything: dict[str, str],
    *,
    sha: str,
    ref: str,
    job_id: str,
    correlator: str,
) -> dict[str, object]:
    resolved: dict[str, object] = {}
    for name, version in sorted(everything.items()):
        purl = f"pkg:pypi/{name}@{version}"
        resolved[purl] = {
            "package_url": purl,
            "scope": "runtime" if name in runtime else "development",
            "dependencies": [],
        }
    return {
        "version": 0,
        "sha": sha,
        "ref": ref,
        "job": {"correlator": correlator, "id": job_id},
        "detector": DETECTOR,
        "scanned": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "manifests": {
            MANIFEST: {
                "name": MANIFEST,
                "file": {"source_location": MANIFEST},
                "resolved": resolved,
            }
        },
    }


def submit(snapshot: dict[str, object], *, repository: str, token: str, api_url: str) -> str:
    request = urllib.request.Request(
        f"{api_url}/repos/{repository}/dependency-graph/snapshots",
        data=json.dumps(snapshot).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - fixed https host
        return response.read().decode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true", help="print the snapshot, submit nothing")
    args = parser.parse_args()

    runtime = parse_requirements(export(["--no-dev"]))
    everything = parse_requirements(export([]))
    snapshot = build_snapshot(
        runtime,
        everything,
        sha=os.environ.get("GITHUB_SHA", ""),
        ref=os.environ.get("GITHUB_REF", ""),
        job_id=os.environ.get("GITHUB_RUN_ID", "local"),
        correlator=(
            f"{os.environ.get('GITHUB_WORKFLOW', 'local')}-"
            f"{os.environ.get('GITHUB_JOB', 'uv-lock')}"
        ),
    )
    manifest = snapshot["manifests"]
    assert isinstance(manifest, dict)
    count = len(manifest[MANIFEST]["resolved"])  # type: ignore[index]
    if args.dry_run:
        print(json.dumps(snapshot, indent=2))
        print(f"{count} packages ({len(runtime)} runtime)", file=sys.stderr)
        return 0
    token = os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repository:
        print("GITHUB_TOKEN and GITHUB_REPOSITORY are required outside --dry-run", file=sys.stderr)
        return 2
    body = submit(
        snapshot,
        repository=repository,
        token=token,
        api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
    )
    print(f"submitted {count} packages ({len(runtime)} runtime): {body}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
