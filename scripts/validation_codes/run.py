"""Write the validation-code register page from the source, or check the tree against it.

    uv run python scripts/validation_codes/run.py            # write the page
    uv run python scripts/validation_codes/run.py --check    # write nothing; exit 1 on a finding
    uv run python scripts/validation_codes/run.py --stdout   # print the page
    uv run python scripts/validation_codes/run.py --tests [CODE ...]   # the tests naming each code

The page is ``apps/docs/content/docs/validation-codes.mdx``. The register is read
from the source alone (``scripts/validation_codes/register.py``: ``ast`` and
``tokenize``, nothing imported, no network); ``--root`` reads another tree laid
out like this one. Writing also prints what ``--check`` would fail on: a stale
page, a code nothing raises, a code no test names.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.validation_codes.guard import check  # noqa: E402
from scripts.validation_codes.page import render  # noqa: E402
from scripts.validation_codes.register import PAGE, build  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scripts/validation_codes/run.py",
        description="Write the validation-code register page from the source, or check it.",
    )
    parser.add_argument("--root", type=Path, default=_ROOT, help="the tree to read")
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--check", action="store_true", help="write nothing; exit 1 when the tree has a finding"
    )
    action.add_argument("--stdout", action="store_true", help="print the page instead")
    action.add_argument(
        "--tests",
        nargs="*",
        metavar="CODE",
        help="print the tests naming each code (or the codes named), and write nothing",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    register = build(root)
    if args.tests is not None:
        wanted = set(args.tests)
        for code in register.codes:
            if wanted and code.code not in wanted:
                continue
            print(code.code)
            for test in code.tests:
                print(f"  {test}")
            for test in code.console_tests:
                print(f"  {test} (console)")
            if not code.tests and not code.console_tests:
                print("  no test names it")
        unknown = sorted(wanted - {code.code for code in register.codes})
        for code in unknown:
            print(f"{code}: not a code the register knows")
        return 1 if unknown else 0
    text = render(register)
    if args.stdout:
        sys.stdout.write(text)
        return 0
    page = root / PAGE
    committed = page.read_text(encoding="utf-8") if page.is_file() else None
    if args.check:
        found = check(register, text, committed).all()
        for finding in found:
            print(finding)
        return 1 if found else 0
    page.write_text(text, encoding="utf-8")
    print(
        f"wrote {PAGE}: {len(register.codes)} codes in {len(register.families())} families, "
        f"{len(register.unresolved)} unresolved code positions"
    )
    for finding in check(register, text, text).all():
        print(finding)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
