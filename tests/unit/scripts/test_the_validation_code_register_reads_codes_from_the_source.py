"""The validation-code register is read from the source alone, and names what it could not read.

A small tree holds one of each thing the register tells apart: a code named by
a constant, a code written as a literal, a code that reaches its raise site
through a parameter its only caller feeds a constant, a code read out of a row
the register cannot follow, and a constant nothing raises. That tree's page is
pinned whole. Each other way a value is followed, and each use that reads a
code rather than raising it, has a tree of its own; so does each finding of the
guard (a stale page, a dead constant, an untested code), each failing alone.
The page is the same bytes under any hash seed, a chain of names too long to
follow is named rather than a crash, and the work stays linear on a hostile
tree ten times the size.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

from scripts.validation_codes.guard import check
from scripts.validation_codes.page import COMMAND, HEADER, render
from scripts.validation_codes.register import PAGE, Code, Register, Unresolved, build

ROOT = Path(__file__).resolve().parents[3]
RUN = ROOT / "scripts" / "validation_codes" / "run.py"

_VIOLATION = """\
from dataclasses import dataclass


@dataclass(frozen=True)
class Violation:
    code: str
    message: str
"""


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text), encoding="utf-8")
    return root


def _tree(root: Path, checks: str, files: dict[str, str] | None = None) -> Register:
    """A one-module platform under ``src/demo``, plus any other files named."""
    _write(
        root,
        {
            "src/demo/__init__.py": "",
            "src/demo/base.py": _VIOLATION,
            "src/demo/checks.py": checks,
            **(files or {}),
        },
    )
    return build(root)


def _codes(register: Register) -> dict[str, Code]:
    return {code.code: code for code in register.codes}


SMALL_CHECKS = '''\
"""Checks that file what they find under codes."""

import os

from demo.base import Violation

# A claim that cites no evidence.
EMPTY_CODE = "demo.empty"
# A constant nothing raises.
DEAD_CODE = "demo.dead"
LAYOUT = os.path.join("demo.cfg", "os.path")


def check(claim: str) -> list[Violation]:
    found = [Violation(code="demo.literal", message="a code written where it is raised.")]
    if not claim:
        found.append(Violation(code=EMPTY_CODE, message="the claim is empty."))
    return found


def ask(code: str, text: str) -> Violation:
    return Violation(code=code, message=text)


def asked() -> Violation:
    return ask("demo.fed", "fed by its only caller")


def handed_over(rows: list[dict[str, str]]) -> list[Violation]:
    return [Violation(code=row["code"], message="a code read out of a row") for row in rows]


def is_empty(violation: Violation) -> bool:
    return violation.code == EMPTY_CODE
'''

SMALL_TESTS = '''\
"""What the checks file."""

from demo.checks import EMPTY_CODE, asked, check


def test_an_empty_claim_is_asked_about() -> None:
    assert any(v.code == EMPTY_CODE for v in check(""))


def test_the_caller_feeds_its_code() -> None:
    assert asked().code == "demo.fed"
'''

SMALL_PAGE = """\
---
title: "Checks"
---

An empty claim is filed under `demo.empty`.
"""

SMALL_REGISTER = """
**4 codes in 1 family:** [demo](#demo) 4. One code position the register could not resolve is \
[listed at the end](#unresolved-code-positions).

## demo

### `demo.dead`

A constant nothing raises.

- **Raised at** nothing
- **Constant** `demo.checks:DEAD_CODE`
- **Tests** none
- **Docs** none

### `demo.empty`

A claim that cites no evidence.

- **Raised at** `demo.checks:check`
- **Constant** `demo.checks:EMPTY_CODE`
- **Tests** `tests/test_checks.py`
- **Docs** [Checks](/)

### `demo.fed`

No comment names its meaning; the message at `demo.checks:ask` reads: "fed by its only caller"

- **Raised at** `demo.checks:ask`
- **Constant** none: the code is written as a literal
- **Tests** `tests/test_checks.py`
- **Docs** none

### `demo.literal`

No comment names its meaning; the message at `demo.checks:check` reads: "a code written where \
it is raised."

- **Raised at** `demo.checks:check`
- **Constant** none: the code is written as a literal
- **Tests** none
- **Docs** none

## Unresolved code positions

Each of these is a code position whose value the register could not follow to a literal or a \
constant. It may raise a code this page does not list.

- `demo.checks:handed_over`: `code=row['code']`, an item of a value.
"""


def _small(root: Path) -> Path:
    _tree(
        root,
        SMALL_CHECKS,
        {"tests/test_checks.py": SMALL_TESTS, "apps/docs/content/docs/index.mdx": SMALL_PAGE},
    )
    return root


def test_the_register_of_the_small_tree_is_pinned_whole(tmp_path: Path) -> None:
    page = render(build(_small(tmp_path)))

    head, _, body = page.partition(HEADER)
    assert head.startswith('---\ntitle: "Validation codes"\n')
    assert body == "\n" + SMALL_REGISTER


def test_a_dotted_string_outside_a_code_position_is_never_a_code(tmp_path: Path) -> None:
    codes = _codes(build(_small(tmp_path)))

    assert "os.path" not in codes
    assert "demo.cfg" not in codes


def test_two_runs_under_different_hash_seeds_write_the_same_bytes(tmp_path: Path) -> None:
    root = _small(tmp_path)

    def run(seed: str) -> bytes:
        env = {**os.environ, "PYTHONHASHSEED": seed}
        command = [sys.executable, str(RUN), "--root", str(root), "--stdout"]
        return subprocess.run(command, env=env, capture_output=True, check=True).stdout

    first, second = run("1"), run("2")
    assert first == second
    assert first.decode("utf-8") == render(build(root))


class TestWhatIsFollowed:
    def test_a_loop_over_a_constant_collection_is_followed(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            def every() -> list[Violation]:
                return [Violation(code=code, message="m") for code in ("demo.one", "demo.two")]
            """,
        )

        assert {c.code: c.raised_at for c in register.codes} == {
            "demo.one": ("demo.checks:every",),
            "demo.two": ("demo.checks:every",),
        }
        assert register.unresolved == ()

    def test_a_conditional_between_constants_is_followed(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            def pick(flag: bool) -> Violation:
                code = "demo.yes" if flag else "demo.no"
                return Violation(code=code, message="m")
            """,
        )

        assert sorted(_codes(register)) == ["demo.no", "demo.yes"]
        assert register.unresolved == ()

    def test_a_lookup_in_a_constant_mapping_is_followed(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            _BY_KIND = {"file": "demo.file", "mail": "demo.mail"}

            def decline(kind: str) -> Violation:
                return Violation(code=_BY_KIND.get(kind, "demo.other"), message="m")
            """,
        )

        assert sorted(_codes(register)) == ["demo.file", "demo.mail", "demo.other"]
        assert register.unresolved == ()

    def test_a_constant_imported_and_aliased_is_followed(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo import names
            from demo.base import Violation
            from demo.names import ORIGINAL

            ALIAS_CODE = ORIGINAL

            def by_alias() -> Violation:
                return Violation(code=ALIAS_CODE, message="m")

            def by_module() -> Violation:
                return Violation(code=names.ORIGINAL, message="m")
            """,
            {"src/demo/names.py": '# The name the code had first.\nORIGINAL = "demo.renamed"\n'},
        )

        (code,) = register.codes
        assert code.code == "demo.renamed"
        assert code.raised_at == ("demo.checks:by_alias", "demo.checks:by_module")
        assert code.constants == ("demo.checks:ALIAS_CODE", "demo.names:ORIGINAL")
        assert code.meaning == "The name the code had first."

    def test_a_parameter_left_to_its_default_is_followed(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            DEFAULT_CODE = "demo.default"

            def check(text: str, *, code: str = DEFAULT_CODE) -> Violation:
                return Violation(code=code, message=text)

            def callers() -> list[Violation]:
                return [check("a"), check("b", code="demo.given")]
            """,
        )

        codes = _codes(register)
        assert codes["demo.default"].raised_at == ("demo.checks:check",)
        assert codes["demo.given"].raised_at == ("demo.checks:callers", "demo.checks:check")
        assert register.unresolved == ()

    def test_a_parameter_of_a_function_passed_as_a_value_is_unresolved(
        self, tmp_path: Path
    ) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            def check(code: str) -> Violation:
                return Violation(code=code, message="m")

            HANDLERS = [check]
            """,
        )

        assert register.codes == ()
        assert register.unresolved == (
            Unresolved(
                "demo.checks:check",
                "code=code",
                "`code`, a parameter of a function passed as a value, whose callers are not "
                "all known",
            ),
        )

    def test_a_parameter_of_a_method_is_unresolved(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            class Checker:
                def check(self, code: str) -> Violation:
                    return Violation(code=code, message="m")

            def run() -> Violation:
                return Checker().check("demo.hidden")
            """,
        )

        assert register.codes == ()
        (site,) = register.unresolved
        assert site.site == "demo.checks:Checker.check"
        assert "a parameter of a method" in site.why

    def test_a_number_a_flag_or_an_unshaped_word_in_code_position_is_not_a_code(
        self, tmp_path: Path
    ) -> None:
        register = _tree(
            tmp_path,
            """\
            def close(socket: object, code: int, reason: str) -> None:
                socket.close(code=code, reason=reason)

            def run(socket: object, reading: object) -> None:
                close(socket, 1008, "refused")
                reading(code=1 in (1, 2))
                raise SystemExit(code=1)

            TEAM_RULE_CODES = frozenset({"no_stages", "duplicate_key"})
            READING_CODE = "code"
            """,
        )

        assert register.codes == ()
        assert register.unresolved == ()


class TestRaisesAndReads:
    def test_a_constant_passed_returned_or_stored_is_raised_there(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            # The export declined the object.
            DECLINED_CODE = "demo.declined"
            # A row kept for the summary.
            STORED_CODE = "demo.stored"

            class Declined(tuple[str, str]):
                pass

            def decline() -> Declined:
                return Declined((DECLINED_CODE, "why"))

            def reason() -> tuple[str, str]:
                return (DECLINED_CODE, "why")

            def note(rows: list[dict[str, str]]) -> None:
                rows.append({"code": STORED_CODE, "message": "kept"})
            """,
        )

        codes = _codes(register)
        assert codes["demo.declined"].raised_at == ("demo.checks:decline", "demo.checks:reason")
        assert codes["demo.stored"].raised_at == ("demo.checks:note",)

    def test_a_comparison_a_set_of_codes_and_formatted_text_read_a_code(
        self, tmp_path: Path
    ) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            EMPTY_CODE = "demo.empty"
            OTHER_CODE = "demo.other"
            SETTLED = frozenset({EMPTY_CODE, OTHER_CODE})

            def raises() -> list[Violation]:
                empty = Violation(code=EMPTY_CODE, message="m")
                return [empty, Violation(code=OTHER_CODE, message="m")]

            def reads(violation: Violation, keep: object, log: object) -> bool:
                keep(drop=frozenset({EMPTY_CODE}))
                log(f"filed under {OTHER_CODE}")
                return (
                    violation.code == EMPTY_CODE
                    or violation.code in (EMPTY_CODE, OTHER_CODE)
                    or violation.code in SETTLED
                )
            """,
        )

        assert {c.code: c.raised_at for c in register.codes} == {
            "demo.empty": ("demo.checks:raises",),
            "demo.other": ("demo.checks:raises",),
        }

    def test_a_name_a_code_is_assigned_to_raises_it_where_the_name_is_used(
        self, tmp_path: Path
    ) -> None:
        register = _tree(
            tmp_path,
            """\
            FOUND_CODE = "demo.found"

            def written(rows: list[tuple[str, str]]) -> None:
                code = FOUND_CODE
                rows.append((code, "written"))

            def compared(written: str) -> bool:
                code = FOUND_CODE
                return written == code
            """,
        )

        assert _codes(register)["demo.found"].raised_at == ("demo.checks:written",)

    def test_a_chain_of_names_too_long_to_follow_is_named_not_a_crash(self, tmp_path: Path) -> None:
        names = "\n".join(f"NAME_{index + 1} = NAME_{index}" for index in range(5000))
        register = _tree(
            tmp_path,
            f'NAME_0 = "demo.deep"\n{names}\nDEEP_CODE = NAME_5000\n',
        )

        (site,) = register.unresolved
        assert site.site == "demo.checks:DEEP_CODE"
        assert site.why == "a chain of names too long to follow"


CLEAN_CHECKS = """\
from demo.base import Violation

# A claim that cites no evidence.
EMPTY_CODE = "demo.empty"


def check(claim: str) -> list[Violation]:
    return [] if claim else [Violation(code=EMPTY_CODE, message="the claim is empty.")]
"""

CLEAN_TESTS = """\
from demo.checks import EMPTY_CODE, check


def test_an_empty_claim_is_asked_about() -> None:
    assert check("")[0].code == EMPTY_CODE
"""


def _clean(root: Path, checks: str = CLEAN_CHECKS, files: dict[str, str] | None = None) -> Register:
    return _tree(root, checks, {"tests/test_checks.py": CLEAN_TESTS, **(files or {})})


def _findings(root: Path, register: Register) -> tuple[tuple[str, ...], ...]:
    rendered = render(register)
    page = root / PAGE
    committed = page.read_text(encoding="utf-8") if page.is_file() else rendered
    findings = check(register, rendered, committed)
    return findings.stale, findings.dead, findings.untested


CONSOLE_TEST = "apps/web/src/lib/__tests__/rows.test.ts"


class TestTheGuard:
    def test_a_clean_tree_has_no_finding(self, tmp_path: Path) -> None:
        assert _findings(tmp_path, _clean(tmp_path)) == ((), (), ())

    def test_a_stale_page_is_named_with_the_command(self, tmp_path: Path) -> None:
        _write(tmp_path, {PAGE: render(_clean(tmp_path))})
        changed = CLEAN_CHECKS.replace("cites no evidence", "has no evidence line")

        stale, dead, untested = _findings(tmp_path, _clean(tmp_path, changed))

        assert stale == (
            f"{PAGE} is not what the source gives: run `{COMMAND}` and commit the page",
        )
        assert (dead, untested) == ((), ())

    def test_a_dead_constant_is_named(self, tmp_path: Path) -> None:
        checks = CLEAN_CHECKS + 'DEAD_CODE = "demo.dead"\n'
        named = 'def test_the_dead_code() -> None:\n    assert "demo.dead"\n'

        stale, dead, untested = _findings(
            tmp_path, _clean(tmp_path, checks, {"tests/test_dead.py": named})
        )

        assert dead == (
            "`demo.dead` (demo.checks:DEAD_CODE): nothing raises it. Remove it, or bind it "
            "under a LEGACY_ name whose comment says which stored runs carry it and what "
            "reads it",
        )
        assert (stale, untested) == ((), ())

    def test_an_untested_code_is_named(self, tmp_path: Path) -> None:
        checks = CLEAN_CHECKS + (
            "\n\ndef other() -> Violation:\n"
            '    return Violation(code="demo.untested", message="nobody asks")\n'
        )

        stale, dead, untested = _findings(tmp_path, _clean(tmp_path, checks))

        assert untested == (
            "`demo.untested`: no test names it. Add a test that makes the platform raise it, "
            "beside its family's tests",
        )
        assert (stale, dead) == ((), ())

    def test_a_code_kept_for_stored_runs_needs_its_reason_in_the_code(self, tmp_path: Path) -> None:
        console = {CONSOLE_TEST: 'expect(isExportDecision("demo.old")).toBe(true);\n'}
        kept = CLEAN_CHECKS + 'LEGACY_OLD_CODES = ("demo.old",)\n'
        reasoned = CLEAN_CHECKS + (
            "# What runs stored before the rename carry; the console reads it.\n"
            'LEGACY_OLD_CODES = ("demo.old",)\n'
        )

        silent = _findings(tmp_path / "a", _clean(tmp_path / "a", kept, console))
        said = _findings(tmp_path / "b", _clean(tmp_path / "b", reasoned, console))

        assert silent == (
            (),
            (
                "`demo.old` is kept for stored runs by demo.checks:LEGACY_OLD_CODES, which has "
                "no comment saying which stored runs carry it and what reads it",
            ),
            (),
        )
        assert said == ((), (), ())

    def test_a_kept_code_that_is_still_raised_is_dead(self, tmp_path: Path) -> None:
        checks = CLEAN_CHECKS + (
            "# What runs stored before the rename carry.\n"
            'LEGACY_OLD_CODES = ("demo.old",)\n\n\n'
            "def old() -> Violation:\n"
            '    return Violation(code="demo.old", message="still raised")\n'
        )
        named = 'def test_old() -> None:\n    assert "demo.old"\n'

        found = _findings(tmp_path, _clean(tmp_path, checks, {"tests/test_old.py": named}))

        assert found == (
            (),
            (
                "`demo.old` is kept for stored runs by demo.checks:LEGACY_OLD_CODES but is "
                "raised at demo.checks:old: take it out of the LEGACY_ binding",
            ),
            (),
        )

    def test_a_raised_code_only_the_console_names_needs_a_platform_test(
        self, tmp_path: Path
    ) -> None:
        checks = CLEAN_CHECKS + (
            "\n\ndef other() -> Violation:\n"
            '    return Violation(code="demo.worded", message="worded by the console")\n'
        )
        console = {CONSOLE_TEST: 'it("words demo.worded", () => {});\n'}

        found = _findings(tmp_path, _clean(tmp_path, checks, console))

        assert found == (
            (),
            (),
            (
                f"`demo.worded`: only the console's tests name it ({CONSOLE_TEST}). Add a test "
                "that makes the platform raise it, beside its family's tests",
            ),
        )


def _hostile(root: Path, modules: int) -> Path:
    """Every module aliases the one before it, feeds a parameter and loops over its codes."""
    files = {"src/demo/__init__.py": "", "src/demo/base.py": _VIOLATION}
    tests: list[str] = []
    page = ['---\ntitle: "Codes"\n---\n']
    for index in range(modules):
        codes = [f"fam{index % 7}.code_{index}_{k}" for k in range(20)]
        lines = ["from demo.base import Violation"]
        if index:
            lines.append(f"from demo.m{index - 1} import C0_CODE as PREVIOUS")
            lines.append("ALIAS_CODE = PREVIOUS")
        lines += [f'C{k}_CODE = "{code}"' for k, code in enumerate(codes)]
        lines.append(
            "def ask(code: str) -> Violation:\n    return Violation(code=code, message='m')"
        )
        lines.append(
            "def callers() -> list[Violation]:\n    return ["
            + ", ".join(f"ask(C{k}_CODE)" for k in range(20))
            + "]"
        )
        lines.append(
            "def every(seen: str) -> list[Violation]:\n    return [Violation(code=code, "
            "message='m') for code in ("
            + ", ".join(f"C{k}_CODE" for k in range(20))
            + f") if seen not in {{{', '.join(f'C{k}_CODE' for k in range(20))}}}]"
        )
        files[f"src/demo/m{index}.py"] = "\n".join(lines) + "\n"
        tests.append(f"def test_m{index}() -> None:\n    assert {codes!r}\n")
        page.append(" ".join(f"`{code}`" for code in codes))
    files["tests/test_hostile.py"] = "\n\n".join(tests)
    files["apps/docs/content/docs/index.mdx"] = "\n".join(page) + "\n"
    return _write(root, files)


def test_the_work_stays_linear_on_a_tree_ten_times_the_size(tmp_path: Path) -> None:
    def took(modules: int) -> float:
        root = _hostile(tmp_path / str(modules), modules)
        start = time.perf_counter()
        register = build(root)
        elapsed = time.perf_counter() - start
        assert len(register.codes) == modules * 20
        assert register.unresolved == ()
        return elapsed

    small, large = took(30), took(300)
    assert large < small * 30, (small, large)
