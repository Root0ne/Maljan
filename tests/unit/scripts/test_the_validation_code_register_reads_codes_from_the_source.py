"""The validation-code register is read from the source alone, and names what it could not read.

A small tree holds one of each thing the register tells apart: a code named by
a constant, a code written as a literal, a code that reaches its raise site
through a parameter its only caller feeds a constant, a code read out of a row
the register cannot follow, and a constant nothing raises. That tree's page is
pinned whole. Each way a value is followed, each kind of finding that raises a
code, each use that only reads one or passes it on, each source of a meaning,
and each finding of the guard (a stale page, a dead constant, an untested code)
has a tree of its own. The page is the same bytes under any hash seed, a chain
too long to follow is named rather than a crash, and the work stays linear on
hostile trees ten times the size, alias and re-export chains included.
"""

from __future__ import annotations

import gc
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from scripts.validation_codes.guard import check
from scripts.validation_codes.page import COMMAND, HEADER, render
from scripts.validation_codes.register import MAX_CHAIN, PAGE, Code, Register, Unresolved, build

ROOT = Path(__file__).resolve().parents[3]
RUN = ROOT / "scripts" / "validation_codes" / "run.py"
CONSOLE_TEST = "apps/web/src/lib/__tests__/rows.test.ts"

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


def _raised(register: Register) -> dict[str, tuple[str, ...]]:
    return {code.code: code.raised_at for code in register.codes}


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


CHECKS = (check, asked, handed_over, is_empty)
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
- **Docs** none

### `demo.empty`

A claim that cites no evidence.

- **Raised at** `demo.checks:check`
- **Constant** `demo.checks:EMPTY_CODE`
- **Docs** [Checks](/)

### `demo.fed`

No comment names its meaning; the message at `demo.checks:ask` reads: "fed by its only caller"

- **Raised at** `demo.checks:ask`, `demo.checks:asked`
- **Constant** none: the code is written as a literal
- **Docs** none

### `demo.literal`

No comment names its meaning; the message at `demo.checks:check` reads: "a code written where \
it is raised."

- **Raised at** `demo.checks:check`
- **Constant** none: the code is written as a literal
- **Docs** none

## Unresolved code positions

Each of these is a code position whose value the register could not follow to a literal or a \
constant: mostly a finding built from a code it was handed, out of a row or another finding. It \
may carry a code this page does not list.

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


def test_the_tests_are_kept_for_the_guard_and_printed_on_demand(tmp_path: Path) -> None:
    root = _small(tmp_path)
    codes = _codes(build(root))
    command = [sys.executable, str(RUN), "--root", str(root), "--tests", "demo.fed", "demo.dead"]

    printed = subprocess.run(command, capture_output=True, check=True, text=True).stdout

    assert codes["demo.empty"].tests == ("tests/test_checks.py",)
    assert printed == "demo.dead\n  no test names it\ndemo.fed\n  tests/test_checks.py\n"


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

            ENTRY = every
            """,
        )

        assert _raised(register) == {
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

            ENTRY = pick
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

            ENTRY = decline
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

            ENTRY = (by_alias, by_module)
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

            ENTRY = callers
            """,
        )

        assert _raised(register) == {
            "demo.default": ("demo.checks:check",),
            "demo.given": ("demo.checks:callers", "demo.checks:check"),
        }
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
                return Checker().check(code=str(run))

            ENTRY = run
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
            ENTRY = run
            """,
        )

        assert register.codes == ()
        assert register.unresolved == ()

    def test_a_chain_of_names_too_long_to_follow_is_named_not_a_crash(self, tmp_path: Path) -> None:
        length = MAX_CHAIN * 2
        names = "\n".join(f"NAME_{index + 1} = NAME_{index}" for index in range(length))
        register = _tree(tmp_path, f'NAME_0 = "demo.deep"\n{names}\nDEEP_CODE = NAME_{length}\n')

        (site,) = register.unresolved
        assert site.site == "demo.checks:DEEP_CODE"
        assert site.why == f"a chain of more than {MAX_CHAIN} names"


DECLINED = """\
class Declined(tuple[str, str]):
    def __new__(cls, code: str, why: str) -> "Declined":
        return super().__new__(cls, (code, why))
"""


class TestWhatRaises:
    def test_a_finding_class_raises_by_keyword_and_by_its_positional_place(
        self, tmp_path: Path
    ) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            def keyword() -> Violation:
                return Violation(code="demo.keyword", message="m")

            def positional() -> Violation:
                return Violation("demo.positional", "written in the code's place")

            ENTRY = (keyword, positional)
            """,
        )

        assert _raised(register) == {
            "demo.keyword": ("demo.checks:keyword",),
            "demo.positional": ("demo.checks:positional",),
        }
        assert _codes(register)["demo.positional"].meaning == "written in the code's place"

    def test_a_dict_row_and_a_tuple_shaped_like_a_finding_raise_a_known_code(
        self, tmp_path: Path
    ) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.declined import Declined

            ROW_CODE = "demo.row"
            PAIR_CODE = "demo.pair"
            CLASS_CODE = "demo.class"

            def rows(found: list[object]) -> None:
                found.append({"code": ROW_CODE, "message": "a row"})
                found.append((PAIR_CODE, "a pair"))
                found.append(Declined(CLASS_CODE, "a declined object"))

            ENTRY = rows
            """,
            {"src/demo/declined.py": DECLINED},
        )

        assert _raised(register) == {
            "demo.class": ("demo.checks:rows",),
            "demo.pair": ("demo.checks:rows",),
            "demo.row": ("demo.checks:rows",),
        }
        assert _codes(register)["demo.pair"].meaning == "a pair"

    def test_a_code_shaped_string_where_no_code_position_is_is_listed(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.declined import Declined

            KNOWN_CODE = "demo.known"

            def rows(found: list[object]) -> None:
                found.append(Declined(KNOWN_CODE, "known"))
                found.append(Declined("demo.literal_place", "a literal in the code's place"))
                found.append(("demo.paired", "a literal in a pair"))
                found.append({"kind": "demo.kind"})

            ENTRY = rows
            """,
            {"src/demo/declined.py": DECLINED},
        )

        assert sorted(_raised(register)) == ["demo.known", "demo.literal_place"]
        assert register.unresolved == (
            Unresolved(
                "demo.checks:rows",
                "'demo.kind'",
                "a code-shaped string where no code position is, nor a read",
            ),
            Unresolved("demo.checks:rows", "'demo.paired'", LOOSE),
        )

    def test_a_factory_raises_where_it_is_called_and_inside_it(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            def finding(code: str) -> Violation:
                return Violation(code=code, message="made by a factory")

            def relayed(code: str) -> Violation:
                return finding(code)

            def checks() -> list[Violation]:
                return [relayed("demo.relayed"), finding(code="demo.direct")]

            ENTRY = checks
            """,
        )

        assert _raised(register) == {
            "demo.direct": ("demo.checks:checks", "demo.checks:finding"),
            "demo.relayed": ("demo.checks:checks", "demo.checks:finding", "demo.checks:relayed"),
        }

    def test_a_known_code_handed_to_a_callback_is_raised(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            from collections.abc import Callable

            from demo.base import Violation

            ASKED_CODE = "demo.asked"

            def record(on_question: Callable[[str], None]) -> None:
                on_question(ASKED_CODE)

            def keep() -> Violation:
                return Violation(code=ASKED_CODE, message="m")

            ENTRY = (record, keep)
            """,
        )

        assert _raised(register)["demo.asked"] == ("demo.checks:keep", "demo.checks:record")

    def test_a_finding_built_where_nothing_calls_it_raises_nothing(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            DEAD_CODE = "demo.dead"

            def _never_called() -> Violation:
                return Violation(code=DEAD_CODE, message="m")
            """,
        )

        (code,) = register.codes
        assert code.raised_at == ()
        assert code.uncalled == ("demo.checks:_never_called",)


# Each a code literal written where nothing files it; none may vanish.
ROW_READ = "a code in a row handed to a call that only reads it, so nothing here files it"
LOOSE = "a code-shaped string handed to a callback or put in a pair, which is not a code position"
UNFILED = {
    "a row sent over a socket": (
        "async def send(ws: object) -> None:\n"
        "    await ws.send_json({'code': 'demo.sent', 'message': 'm'})",
        "send",
        "\"code\": 'demo.sent'",
        ROW_READ,
    ),
    "a row dumped as JSON": (
        "import json\n\ndef dumped() -> str:\n    return json.dumps({'code': 'demo.dumped'})",
        "dumped",
        "\"code\": 'demo.dumped'",
        ROW_READ,
    ),
    "a row given as a copy's update": (
        "def copied(v: object) -> object:\n    return v.model_copy(update={'code': 'demo.copied'})",
        "copied",
        "\"code\": 'demo.copied'",
        ROW_READ,
    ),
    "a row handed to a function that only reads it": (
        "def emit(sink: object, kind: str, row: dict) -> bool:\n"
        "    return kind in row\n\n"
        "def emitted(sink: object) -> bool:\n"
        "    return emit(sink, 'x', {'code': 'demo.emitted'})",
        "emitted",
        "\"code\": 'demo.emitted'",
        ROW_READ,
    ),
    "a new family handed to a callback": (
        "def asked(on_question: object) -> None:\n    on_question('other.asked')",
        "asked",
        "'other.asked'",
        LOOSE,
    ),
}


class TestNothingIsDroppedSilently:
    @pytest.mark.parametrize("shape", sorted(UNFILED))
    def test_a_code_literal_written_where_nothing_files_it_is_listed(
        self, tmp_path: Path, shape: str
    ) -> None:
        source, function, expression, why = UNFILED[shape]
        register = _tree(tmp_path, f"{source}\n\nENTRY = {function}\n")

        assert Unresolved(f"demo.checks:{function}", expression, why) in register.unresolved


# Each a use of DEAD_CODE that only reads it; LIVE_CODE is raised for real.
READS = {
    "a lookup by it": "def summary(counts: dict) -> int:\n    return counts.get(DEAD_CODE, 0)",
    "a filter by it": (
        "def rows_named(rows: list, code: str) -> list:\n"
        "    return [row for row in rows if row.code == code]\n\n"
        "def render(rows: list) -> int:\n"
        "    return len(rows_named(rows, DEAD_CODE))"
    ),
    "a log line": (
        "import logging\nLOG = logging.getLogger(__name__)\n\n"
        "def note() -> None:\n"
        '    LOG.info("no longer filed: %s", DEAD_CODE)'
    ),
    "an item read by it": "def count(by_code: dict) -> int:\n    return by_code[DEAD_CODE]",
    "a string test": "def is_dead(code: str) -> bool:\n    return code.startswith(DEAD_CODE)",
    "counters zeroed by it": (
        "def zeroed(counts: dict) -> None:\n"
        "    for code in (LIVE_CODE, DEAD_CODE):\n"
        "        counts[code] = 0"
    ),
    "a default that reaches no finding": (
        "def is_kind(code: str, kind: str = DEAD_CODE) -> bool:\n    return code == kind"
    ),
    "a code keyword given to a reader": (
        "def unresolved_of(rows: list, code: str) -> list:\n"
        "    return [row for row in rows if row.code == code]\n\n"
        "def shown(rows: list) -> list:\n"
        "    return unresolved_of(rows, code=DEAD_CODE)"
    ),
    "a key of a mapping": (
        'def label(code: str) -> str:\n    return {DEAD_CODE: "old"}.get(code, "")'
    ),
}


class TestReadsAndPassesOn:
    @pytest.mark.parametrize("use", sorted(READS))
    def test_a_code_only_read_is_dead(self, tmp_path: Path, use: str) -> None:
        checks = (
            "from demo.base import Violation\n\n"
            'LIVE_CODE = "demo.live"\nDEAD_CODE = "demo.dead"\n\n'
            "def live() -> Violation:\n"
            '    return Violation(code=LIVE_CODE, message="m")\n\n'
            f"{READS[use]}\n"
        )
        # Every function of the tree is named, so none is left out as uncalled.
        names = [line[4:].split("(")[0] for line in checks.splitlines() if line.startswith("def ")]
        checks += f"\nENTRY = ({', '.join(names)},)\n"

        register = _tree(tmp_path, checks)
        findings = check(register, render(register), render(register))

        assert _raised(register) == {"demo.dead": (), "demo.live": ("demo.checks:live",)}
        assert [line.split(" ")[0] for line in findings.dead] == ["`demo.dead`"]

    def test_a_code_stored_or_forwarded_passes_on_and_is_not_raised(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            CHECK_CODE = "demo.check"
            TIMEOUT_CODE = "demo.timeout"

            def check() -> Violation:
                return Violation(code=CHECK_CODE, message="m")

            def judge() -> Violation:
                return Violation(code=TIMEOUT_CODE, message="m")

            def not_run(record: list[str]) -> None:
                record.append(CHECK_CODE)

            def summary(codes: set[str]) -> dict[str, str]:
                return {"failure": TIMEOUT_CODE if TIMEOUT_CODE in codes else CHECK_CODE}

            ENTRY = (check, judge, not_run, summary)
            """,
        )

        codes = _codes(register)
        assert codes["demo.check"].raised_at == ("demo.checks:check",)
        assert codes["demo.check"].passes_on == ("demo.checks:not_run", "demo.checks:summary")
        assert codes["demo.timeout"].raised_at == ("demo.checks:judge",)
        assert codes["demo.timeout"].passes_on == ("demo.checks:summary",)


class TestTheMeaning:
    def test_a_reader_s_list_comment_does_not_outrank_the_raise_message(
        self, tmp_path: Path
    ) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            CREDIT_CODE = "demo.credit"

            # The codes a renderer prints beside a technique's row.
            _ROW_CODES = ("demo.", "demo.credit")

            def credit() -> Violation:
                return Violation(code=CREDIT_CODE, message="the credit names no claim")

            ENTRY = credit
            """,
        )

        (code,) = register.codes
        assert (code.meaning, code.meaning_kind) == ("the credit names no claim", "message")

    def test_a_comment_over_a_group_yields_to_each_message(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            # The report's own citations. Each of these is asked once.
            CITED_CODE = "demo.cited"
            VOICE_CODE = "demo.voice"
            QUIET_CODE = "demo.quiet"

            def cited() -> Violation:
                return Violation(code=CITED_CODE, message="the finding cites nothing")

            def voice() -> Violation:
                return Violation(code=VOICE_CODE, message="the step is marked observed")

            def quiet(found: list) -> None:
                found.append(Violation(QUIET_CODE, message=str(found)))

            ENTRY = (cited, voice, quiet)
            """,
        )

        codes = _codes(register)
        assert (codes["demo.cited"].meaning, codes["demo.cited"].meaning_kind) == (
            "the finding cites nothing",
            "message",
        )
        assert codes["demo.voice"].meaning_kind == "message"
        assert (codes["demo.quiet"].meaning_kind, codes["demo.quiet"].meaning_from) == (
            "group",
            "demo.checks:CITED_CODE",
        )
        assert codes["demo.quiet"].meaning.startswith("The report's own citations.")

    def test_a_comment_opening_a_run_of_commented_constants_heads_the_group(
        self, tmp_path: Path
    ) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            # What the export declined. Each says what is not in the bundle.
            BENIGN_CODE = "demo.benign"
            # A host no consumer can block.
            HOST_CODE = "demo.host"

            def declined(found: list) -> None:
                found.append(Violation(code=BENIGN_CODE, message="the object is not exported"))
                found.append(Violation(code=HOST_CODE, message="the host is not exported"))

            ENTRY = declined
            """,
        )

        codes = _codes(register)
        assert codes["demo.benign"].meaning == "the object is not exported"
        assert (codes["demo.host"].meaning, codes["demo.host"].meaning_kind) == (
            "A host no consumer can block.",
            "comment",
        )

    def test_a_message_made_only_of_values_points_at_its_site(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            def cited(why: str, remedy: str) -> Violation:
                return Violation(code="demo.cited", message=f"{why} {remedy}")

            ENTRY = cited
            """,
        )

        (code,) = register.codes
        assert (code.meaning, code.meaning_kind, code.meaning_from) == (
            "",
            "pointer",
            "demo.checks:cited",
        )
        assert "see the message there" in render(register)

    def test_a_filled_in_value_is_named_by_its_callee_or_its_key(self, tmp_path: Path) -> None:
        register = _tree(
            tmp_path,
            """\
            from demo.base import Violation

            def note(tid: str, catalogue: object) -> str:
                return ""

            def unknown(tid: str, best: dict, catalogue: object) -> Violation:
                return Violation(
                    code="demo.unknown",
                    message=(
                        f"{str(tid)} is not in the catalogue{note(tid, catalogue)}; "
                        f"{best['technique_id']} ranks above it"
                    ),
                )

            ENTRY = unknown
            """,
        )

        (code,) = register.codes
        assert code.meaning == "<tid> is not in the catalogue<note>; <technique_id> ranks above it"


CLEAN_CHECKS = """\
from demo.base import Violation

# A claim that cites no evidence.
EMPTY_CODE = "demo.empty"


def check(claim: str) -> list[Violation]:
    return [] if claim else [Violation(code=EMPTY_CODE, message="the claim is empty.")]


def other() -> None:
    return None


ENTRY = (check, other)
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


def _with_other(body: str) -> str:
    return CLEAN_CHECKS.replace("def other() -> None:\n    return None", body)


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
        checks = _with_other(
            'def other() -> Violation:\n    return Violation(code="demo.untested", message="m")'
        )

        stale, dead, untested = _findings(tmp_path, _clean(tmp_path, checks))

        assert untested == (
            "`demo.untested`: no test names it. Add a test that makes the platform raise it, "
            "beside its family's tests",
        )
        assert (stale, dead) == ((), ())

    def test_a_code_kept_for_stored_runs_needs_its_reason_in_the_code(self, tmp_path: Path) -> None:
        console = {CONSOLE_TEST: 'expect(isExportDecision("demo.old")).toBe(true);\n'}
        kept = CLEAN_CHECKS + '\nLEGACY_OLD_CODES = ("demo.old",)\n'
        reasoned = CLEAN_CHECKS + (
            "\n# What runs stored before the rename carry; the console reads it.\n"
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
        checks = _with_other(
            'def other() -> Violation:\n    return Violation(code="demo.old", message="m")'
        ) + ('\n# What runs stored before the rename carry.\nLEGACY_OLD_CODES = ("demo.old",)\n')
        named = 'def test_old() -> None:\n    assert "demo.old"\n'

        found = _findings(tmp_path, _clean(tmp_path, checks, {"tests/test_old.py": named}))

        assert found == (
            (),
            (
                "`demo.old` is kept for stored runs by demo.checks:LEGACY_OLD_CODES but is "
                "raised at demo.checks:other: take it out of the LEGACY_ binding",
            ),
            (),
        )

    def test_a_raised_code_only_the_console_names_needs_a_platform_test(
        self, tmp_path: Path
    ) -> None:
        checks = _with_other(
            'def other() -> Violation:\n    return Violation(code="demo.worded", message="m")'
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
    """Every module re-exports and aliases the one before it, feeds a factory and loops."""
    files = {"src/demo/__init__.py": "", "src/demo/base.py": _VIOLATION}
    tests: list[str] = []
    page = ['---\ntitle: "Codes"\n---\n']
    for index in range(modules):
        codes = [f"fam{index % 7}.code_{index}_{k}" for k in range(20)]
        lines = ["from demo.base import Violation"]
        if index:
            # A chain through every module: an alias of the previous alias, and
            # a name re-exported from the previous module unchanged.
            lines.append(f"from demo.m{index - 1:04d} import CHAIN_CODE as PREVIOUS")
            lines.append(f"from demo.m{index - 1:04d} import RELAYED_CODE")
            lines.append("CHAIN_CODE = PREVIOUS")
        else:
            lines.append('CHAIN_CODE = "fam0.chain"')
            lines.append('RELAYED_CODE = "fam0.relayed"')
            # And a run of aliases inside one module, five per module of the tree.
            lines.append('ALIAS0_CODE = "fam0.alias"')
            lines += [f"ALIAS{k}_CODE = ALIAS{k - 1}_CODE" for k in range(1, modules * 5)]
        lines += [f'C{k}_CODE = "{code}"' for k, code in enumerate(codes)]
        lines.append(
            "def ask(code: str) -> Violation:\n    return Violation(code=code, message='m')"
        )
        lines.append(
            "def callers() -> list[Violation]:\n    return ["
            + ", ".join(f"ask(C{k}_CODE)" for k in range(20))
            + ", ask(CHAIN_CODE), ask(RELAYED_CODE)]"
        )
        lines.append(
            "def every(seen: str) -> list[Violation]:\n    return [Violation(code=code, "
            "message='m') for code in ("
            + ", ".join(f"C{k}_CODE" for k in range(20))
            + f") if seen not in {{{', '.join(f'C{k}_CODE' for k in range(20))}}}]"
        )
        lines.append("ENTRY = (callers, every)")
        files[f"src/demo/m{index:04d}.py"] = "\n".join(lines) + "\n"
        tests.append(f"def test_m{index}() -> None:\n    assert {codes!r}\n")
        page.append(" ".join(f"`{code}`" for code in codes))
    files["tests/test_hostile.py"] = "\n\n".join(tests)
    files["apps/docs/content/docs/index.mdx"] = "\n".join(page) + "\n"
    return _write(root, files)


def test_the_work_stays_linear_on_a_tree_ten_times_the_size(tmp_path: Path) -> None:
    def took(modules: int) -> float:
        root = _hostile(tmp_path / str(modules), modules)
        best = float("inf")
        for _ in range(2):
            gc.collect()
            gc.disable()
            try:
                start = time.perf_counter()
                register = build(root)
                best = min(best, time.perf_counter() - start)
            finally:
                gc.enable()
        assert len(register.codes) == modules * 20 + 3
        assert register.unresolved == ()
        return best

    small, large = took(30), took(300)
    assert large < small * 30, (small, large)
