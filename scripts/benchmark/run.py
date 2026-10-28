"""The known-answer gate over scored runs.

    python scripts/benchmark/run.py score SCORED [SCORED ...] [--m M] [--sheet CSV --map JSON]
                                     [--json OUT]
    python scripts/benchmark/run.py gate --baseline SCORED [SCORED ...]
                                    --candidate SCORED [SCORED ...]
                                    [--baseline-m M] [--candidate-m M]
                                    [--sheet CSV --map JSON] [--json OUT]
    python scripts/benchmark/run.py intel-off [--settings JSON] [--profile NAME] [--json OUT]
    python scripts/benchmark/run.py job-config [--profile NAME] [--with-earlier-runs]

A ``SCORED`` is a key score (``score.md``), a calibration score or gate result
(``.json``), or ``blind:ARM``, one arm of the blind score sheet that ``--sheet``
and ``--map`` name. ``score`` prints each run's totals, then, for more than one
run, the runs as one arm (each item found in ``m`` of ``n``). ``gate`` exits 0
when nothing the baseline found dropped, 1 when something did, and 2 when the
scored runs cannot be read or compared. Both also say, for each credited item
of a key score with its stored run beside it, whether the run found it by its
own analysis or by a lookup (``scripts.benchmark.provenance``), and count each
arm's items both ways, and name first, under ``EARLIER RUNS NOT RULED OUT``,
every key score whose stored run summary does not say the run started without
an earlier run's memory and which does not state that it used one
(``scripts.benchmark.earlier_runs``). ``intel-off`` writes the arm that withholds every lookup
server from a profile (``scripts.benchmark.intel_off``), from the stored
settings in ``--settings`` (dotted keys) or the defaults; it exits 2 when the
arm cannot be derived. ``job-config`` prints the config a benchmark run is
submitted with: every run starts without an earlier run's memory of its sample
(``scripts.benchmark.jobs``) unless ``--with-earlier-runs`` says otherwise.
Nothing here starts a run or asks a model: it reads scores already written.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.benchmark import gate as gating  # noqa: E402
from scripts.benchmark import intel_off as arms  # noqa: E402
from scripts.benchmark import jobs  # noqa: E402
from scripts.benchmark.scores import (  # noqa: E402
    ScoredRun,
    ScoreFileError,
    read_blind,
    read_scored,
)

BLIND_PREFIX = "blind:"


def resolve(specs: list[str], sheet: Path | None, sealed: Path | None) -> list[ScoredRun]:
    """The scored runs ``specs`` name, a blind arm read from the sheet once."""
    arms: dict[str, ScoredRun] | None = None
    runs: list[ScoredRun] = []
    for spec in specs:
        if not spec.startswith(BLIND_PREFIX):
            runs.append(read_scored(Path(spec)))
            continue
        if sheet is None or sealed is None:
            raise ScoreFileError(f"{spec}: a blind arm needs --sheet and --map")
        if arms is None:
            arms = {run.name: run for run in read_blind(sheet, sealed)}
        name = spec[len(BLIND_PREFIX) :]
        if name not in arms:
            raise ScoreFileError(f"{spec}: the sealed map names no arm {name!r}")
        runs.append(arms[name])
    return runs


def _write(path: Path, payload: Any) -> None:
    Path(path).write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scripts/benchmark/run.py", description="The known-answer gate over scored runs."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def with_blind(p: argparse.ArgumentParser) -> None:
        p.add_argument("--sheet", type=Path, default=None, help="a filled blind score sheet")
        p.add_argument("--map", type=Path, default=None, help="the sheet's sealed map")
        p.add_argument("--json", type=Path, default=None, help="also write the result here")

    s = sub.add_parser("score", help="each scored run's totals, and theirs as one arm")
    s.add_argument("scored", nargs="+")
    s.add_argument(
        "--m", type=int, default=None, help="runs an item must reach (default: a majority)"
    )
    with_blind(s)
    g = sub.add_parser("gate", help="fail when an item the baseline found drops")
    g.add_argument("--baseline", nargs="+", required=True)
    g.add_argument("--candidate", nargs="+", required=True)
    g.add_argument("--baseline-m", type=int, default=None)
    g.add_argument("--candidate-m", type=int, default=None)
    with_blind(g)
    i = sub.add_parser("intel-off", help="the arm that withholds every lookup server")
    i.add_argument("--settings", type=Path, default=None, help="stored settings, dotted keys")
    i.add_argument("--profile", default=None, help="the base profile (default: the active one)")
    i.add_argument("--json", type=Path, default=None, help="also write the arm here")
    j = sub.add_parser("job-config", help="the config a benchmark run is submitted with")
    j.add_argument("--profile", default=None, help="the team profile the run selects")
    j.add_argument(
        "--with-earlier-runs",
        action="store_true",
        help="keep an earlier run's memory of the sample (the score must then state it)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "job-config":
            options = {"profile": args.profile} if args.profile else {}
            print(json.dumps(jobs.job_config(options, earlier_runs=args.with_earlier_runs)))
            return 0
        if args.command == "intel-off":
            overrides: Any = {}
            if args.settings is not None:
                overrides = json.loads(Path(args.settings).read_text(encoding="utf-8"))
                if not isinstance(overrides, dict):
                    raise ValueError(f"{args.settings}: not an object of settings by dotted key")
            derived = arms.intel_off(overrides, args.profile)
            print(arms.render(derived))
            if args.json:
                _write(args.json, derived)
            return 0
        if args.command == "score":
            runs = resolve(args.scored, args.sheet, args.map)
            singles = [gating.score_arm(gating.arm([run])) for run in runs]
            for run, result in zip(runs, singles, strict=True):
                where = f" (column {run.column!r})" if run.column else ""
                print(f"{run.name}: {run.source}{where}")
                print(gating.render_arm(result))
            payload: dict[str, Any] = {"runs": singles}
            if len(runs) > 1:
                together = gating.score_arm(gating.arm(runs, args.m))
                print("as one arm:")
                print(gating.render_arm(together))
                payload["arm"] = together
            if args.json:
                _write(args.json, payload)
            return 0
        baseline = gating.arm(resolve(args.baseline, args.sheet, args.map), args.baseline_m)
        candidate = gating.arm(resolve(args.candidate, args.sheet, args.map), args.candidate_m)
        result = gating.gate(baseline, candidate)
        print(gating.render(result))
        if args.json:
            _write(args.json, result)
        return 0 if result["passed"] else 1
    except (ScoreFileError, gating.GateError, arms.ArmError, OSError, ValueError) as exc:
        print(f"benchmark: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
