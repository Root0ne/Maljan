"""Blind A/B scoring of stored runs.

    python scripts/blind/run.py prepare RUN RUN [RUN ...] --out DIR --items ITEMS.txt [--seed N]
    python scripts/blind/run.py reveal DIR/scorer/scores.csv --map DIR/sealed-map.json

``prepare`` copies each arm's report (Markdown, HTML), STIX bundle and IOC table under a
shuffled anonymous id with every string that names the arm removed, checks that none survived,
and writes the id-to-arm map to ``DIR/sealed-map.json``, outside the directory ``DIR/scorer``
that goes to the scorer. ``reveal`` reads the filled score sheet and prints the arms.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.blind.prepare import BlindError, prepare, read_items  # noqa: E402
from scripts.blind.reveal import render, reveal  # noqa: E402
from scripts.replay.stored import StoredRunChanged  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scripts/blind/run.py", description="Blind A/B scoring of stored runs."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare", help="anonymise the arms and write the score template")
    prep.add_argument("runs", nargs="+", type=Path, help="two or more stored run directories")
    prep.add_argument("--out", type=Path, required=True, help="an empty or new output directory")
    prep.add_argument(
        "--items", type=Path, required=True, help="the answer list's item ids, one per line"
    )
    prep.add_argument(
        "--seed", type=int, default=None, help="a repeatable shuffle (tests); default is random"
    )
    prep.add_argument(
        "--identify",
        action="append",
        default=[],
        metavar="TEXT",
        help="one more string that names an arm (repeatable)",
    )
    rev = sub.add_parser("reveal", help="print the per-arm scores and the differences")
    rev.add_argument("scores", type=Path, help="the filled score sheet (CSV or JSON)")
    rev.add_argument("--map", type=Path, required=True, help="the sealed map from prepare")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare":
            done = prepare(
                args.runs,
                args.out,
                read_items(args.items),
                seed=args.seed,
                identify=tuple(args.identify),
            )
            print(
                f"blind: {len(done.ids)} arms ({', '.join(done.ids)}) prepared; self-check passed"
            )
            print(f"scorer directory: {done.scorer_dir}")
            print(f"score template:   {done.template}")
            print(f"sealed map:       {done.sealed} (keep it away from the scorer)")
        else:
            print(render(reveal(args.scores, args.map)))
    except (BlindError, StoredRunChanged, OSError, ValueError) as exc:
        print(f"blind: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
