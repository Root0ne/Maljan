"""Replay the platform's deterministic rules over stored runs, at zero cost.

Over one or more stored runs, each a directory in the benchmark's layout::

    python scripts/replay/run.py runs/haiku4

re-runs every deterministic decision of the platform over what the run
stored, with no model call: the analysts' validation checks over each answer
stored as written and over the claims in force, the judge's checks over its
answer as written, the report's deterministic build, the export and its
publish rules, the report rounds' checks, the tool-call checks and
corroboration (``scripts/replay/rules.py`` says what each part reads). It
prints codes, entry ids and counts; ``--show-text`` adds each finding's words
and the claim it is about. ``--json OUT`` writes the record. The exit status
is 0 when every part replayed or was named as not replayable, and 2 when a
part raised (a crash is not a decision) or on an error.

``--compare REF_A REF_B`` replays the same runs under two git refs, each with
its own harness over its own rules, written out of the object store into a
directory of its own, and names every difference: codes gained or lost per
claim, published techniques and their reasons, indicator publish answers and
report values. The exit status is 0 when the two refs decide the same over
every run, 1 when they differ, and 2 when a part raised in either tree, when a
ref predates the replay tool, or on an error.

``--job ID`` reads a job from the database, read-only, into a directory in the
same layout (``--job-dir``, a temporary one by default) and replays that.

The stored runs are read and never written: every file of each run's
directory is digested before and after, and the replay fails when a digest
changed. No network is reached and nothing is written outside the output
named and a temporary directory of the replay's own.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, NoReturn

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.replay.guard import prepare_process, restore_process  # noqa: E402
from scripts.replay.record import errors  # noqa: E402
from scripts.replay.stored import check_unchanged, digests  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scripts/replay/run.py",
        description="Replay the platform's deterministic rules over stored runs, at zero cost.",
    )
    parser.add_argument("runs", nargs="*", type=Path, help="stored run directories")
    parser.add_argument("--json", type=Path, help="write the record (or the comparison) here")
    parser.add_argument(
        "--show-text",
        action="store_true",
        help="add each finding's words and the claim it is about",
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("REF_A", "REF_B"),
        help="replay under two git refs, each with its own harness, and name every difference",
    )
    parser.add_argument(
        "--work",
        type=Path,
        help="where --compare writes the two refs' trees (a temporary directory by default)",
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=_ROOT,
        help="the repository --compare reads the refs from (this checkout's by default)",
    )
    parser.add_argument(
        "--job", action="append", default=[], help="a job id to read from the database"
    )
    parser.add_argument("--job-dir", type=Path, help="where --job writes the job it reads")
    parser.add_argument(
        "--database-url",
        help="the database --job reads (DATABASE_URL, else the API's bootstrap setting)",
    )
    parser.add_argument("--quiet", action="store_true", help="print nothing; write --json only")
    return parser


def _error(message: str) -> NoReturn:
    """Say ``message`` and end with the status an error has (2)."""
    print(f"replay: {message}", file=sys.stderr)
    raise SystemExit(2)


def _outside(path: Path, runs: list[Path]) -> None:
    """Refuse a path the replay writes when it is inside a stored run's directory."""
    target = path.resolve()
    for run in runs:
        if target == run.resolve() or run.resolve() in target.parents:
            _error(f"refused: {path} is inside the stored run {run}")


def _write(path: Path | None, value: Any) -> None:
    if path is not None:
        path.write_text(json.dumps(value, indent=1, sort_keys=True), encoding="utf-8")


def _replay(runs: list[Path], show_text: bool) -> list[dict[str, Any]]:
    """Each run replayed with the rules this process imports."""
    cache = Path(tempfile.mkdtemp(prefix="maljan-replay-"))
    previous = prepare_process(cache)
    try:
        from scripts.replay.rules import replay_run
        from scripts.replay.stored import read_run

        records: list[dict[str, Any]] = []
        for run in runs:
            before = digests(run)
            record = replay_run(read_run(run), show_text=show_text)
            check_unchanged(before, digests(run))
            record["stored"] = {"files": before}
            records.append(record)
        return records
    finally:
        restore_process(previous)
        shutil.rmtree(cache, ignore_errors=True)


def _compare(
    runs: list[Path],
    refs: tuple[str, str],
    *,
    repo: Path,
    work: Path | None,
    show_text: bool,
    quiet: bool,
) -> tuple[list[dict[str, Any]], int]:
    """The diff of each run between the two refs, and the status the comparison ends with."""
    from scripts.replay.compare import (
        PredatesTheReplay,
        diff_records,
        differs,
        has_errors,
        materialise,
        replay_under,
    )
    from scripts.replay.output import render_diff

    ref_a, ref_b = refs
    owned = work is None
    base = Path(tempfile.mkdtemp(prefix="maljan-replay-compare-")) if work is None else work
    try:
        before = {str(run): digests(run) for run in runs}
        records: dict[str, list[dict[str, Any]]] = {}
        for side, ref in (("a", ref_a), ("b", ref_b)):
            try:
                tree = materialise(repo, ref, base / f"{side}-tree")
            except PredatesTheReplay as exc:
                _error(str(exc))
            records[side] = replay_under(
                tree, runs, base / f"{side}-replay.json", show_text=show_text
            )
        for run in runs:
            check_unchanged(before[str(run)], digests(run))
        diffs = [diff_records(a, b) for a, b in zip(records["a"], records["b"], strict=True)]
        if not quiet:
            print("\n\n".join(render_diff(diff, ref_a, ref_b) for diff in diffs))
        if any(has_errors(diff) for diff in diffs):
            return diffs, 2
        return diffs, 1 if any(differs(diff) for diff in diffs) else 0
    finally:
        if owned:
            shutil.rmtree(base, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    runs = [Path(run) for run in args.runs]
    job_dirs: list[Path] = []
    try:
        for written in (args.json, args.work, args.job_dir):
            if written is not None:
                _outside(written, runs)
        if args.job:
            from scripts.replay.database import export_jobs

            target = args.job_dir or Path(tempfile.mkdtemp(prefix="maljan-replay-jobs-"))
            job_dirs = [] if args.job_dir else [target]
            for directory, cleared in export_jobs(args.job, target, database_url=args.database_url):
                if cleared and not args.quiet:
                    print(
                        f"replay: cleared the earlier export's {', '.join(cleared)} in {directory}",
                        file=sys.stderr,
                    )
                runs.append(directory)
        if not runs:
            _parser().error("name a stored run or a --job")
        for run in runs:
            if not run.is_dir():
                _error(f"no stored run at {run}")
        if args.compare:
            diffs, status = _compare(
                runs,
                (args.compare[0], args.compare[1]),
                repo=args.repo,
                work=args.work,
                show_text=args.show_text,
                quiet=args.quiet,
            )
            _write(args.json, diffs[0] if len(diffs) == 1 else diffs)
            return status
        records = _replay(runs, args.show_text)
        _write(args.json, records[0] if len(records) == 1 else records)
        if not args.quiet:
            from scripts.replay.output import render_record

            print("\n\n".join(render_record(record) for record in records))
        raised = [(record.get("run"), row) for record in records for row in errors(record)]
        for name, row in raised:
            print(f"replay: {name}: {row['part']} raised: {row['why']}", file=sys.stderr)
        return 2 if raised else 0
    finally:
        for directory in job_dirs:
            shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — said, and the status says it failed
        print(f"replay failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)
