"""Each of the platform's processes pins LC_CTYPE at its start, and nothing else.

C code folds case with the C library's ``tolower``, by the process's LC_CTYPE.
Under a Turkish one a capital I does not fold, and the YARA engine's
``nocase`` then misses every I it should match. Every test here that changes
the locale runs in a subprocess, because ``setlocale`` is process-wide.
"""

from __future__ import annotations

import json
import locale
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from maljan.core import ctype_locale

ROOT = Path(__file__).resolve().parents[3]
TURKISH = "tr_TR.UTF-8"
# The exit status a subprocess gives when the host has no Turkish locale.
NO_TURKISH = 77


def _run(script: str, **environment: str) -> subprocess.CompletedProcess[str]:
    """``script`` in a fresh interpreter whose locale variables are only ``environment``."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("LC_") and key not in {"LANG", "LANGUAGE"}
    }
    env.update(environment)
    env["PYTHONPATH"] = os.pathsep.join(entry for entry in sys.path if entry)
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        env=env,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _finished(result: subprocess.CompletedProcess[str]) -> str:
    if result.returncode == NO_TURKISH:
        pytest.skip(f"{TURKISH} is not installed on this host, so the Turkish fold cannot be shown")
    assert result.returncode == 0, result.stderr
    return result.stdout


def _last_line(out: str) -> str:
    """The script's own answer, after the lines the platform's logger wrote."""
    return out.strip().splitlines()[-1]


class TestUnderATurkishCtype:
    def test_the_pin_restores_ascii_folding_and_the_engine_s_nocase(self) -> None:
        out = _finished(
            _run(
                """
                import locale, sys
                if locale.setlocale(locale.LC_CTYPE) != "tr_TR.UTF-8":
                    sys.exit(77)
                from maljan.core import ctype_locale
                assert not ctype_locale.libc_folds_ascii(), "the Turkish fold, before the pin"
                chosen = ctype_locale.pin_character_classification()
                assert chosen in ctype_locale.CANDIDATES, chosen
                assert ctype_locale.libc_folds_ascii()
                import yara
                # Longer than one atom, so the engine's locale-built case table
                # decides it (``ctype_locale._SELF_TEST_TEXT``).
                rules = yara.compile(
                    source='rule t { strings: $a = "wininet" nocase condition: $a }',
                    includes=False,
                )
                assert rules.match(data=b"WININET"), "the engine loaded after the pin folds I"
                print(chosen)
                """,
                LC_CTYPE=TURKISH,
            )
        )
        assert _last_line(out) in ctype_locale.CANDIDATES
        assert f"LC_CTYPE set to {_last_line(out)} (it was {TURKISH})" in out

    def test_the_analysis_server_pins_before_its_manifest_loads_the_engine(self) -> None:
        out = _finished(
            _run(
                """
                import importlib.util, json, locale, sys
                if locale.setlocale(locale.LC_CTYPE) != "tr_TR.UTF-8":
                    sys.exit(77)
                spec = importlib.util.spec_from_file_location(
                    "analysis_server", "services/analysis-mcp/server.py"
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                import yara
                rules = yara.compile(
                    source='rule t { strings: $a = "wininet" nocase condition: $a }',
                    includes=False,
                )
                print(json.dumps({"folds": bool(rules.match(data=b"WININET"))}))
                """,
                LC_CTYPE=TURKISH,
            )
        )
        # Nothing but the script's own answer on standard output, the server's
        # protocol channel: the pin's line went to standard error.
        assert json.loads(out) == {"folds": True}


class TestWhatThePinLeavesAlone:
    def test_messages_times_and_collation_stay_the_operator_s(self) -> None:
        out = _finished(
            _run(
                """
                import json, locale, sys
                try:
                    locale.setlocale(locale.LC_ALL, "")
                except locale.Error:
                    sys.exit(77)
                if locale.setlocale(locale.LC_MESSAGES) != "tr_TR.UTF-8":
                    sys.exit(77)
                names = ("LC_MESSAGES", "LC_TIME", "LC_COLLATE", "LC_NUMERIC", "LC_MONETARY")
                before = {name: locale.setlocale(getattr(locale, name)) for name in names}
                from maljan.core.ctype_locale import CANDIDATES, pin_character_classification
                assert pin_character_classification() in CANDIDATES
                after = {name: locale.setlocale(getattr(locale, name)) for name in names}
                print(json.dumps({
                    "before": before, "after": after, "ctype": locale.setlocale(locale.LC_CTYPE)
                }))
                """,
                LANG=TURKISH,
            )
        )
        seen = json.loads(_last_line(out))
        assert seen["after"] == seen["before"]
        assert seen["after"]["LC_MESSAGES"] == seen["after"]["LC_TIME"] == TURKISH
        assert seen["ctype"] in ctype_locale.CANDIDATES

    def test_a_pin_with_no_candidate_keeps_the_locale_and_warns(self) -> None:
        result = _run(
            """
            import locale, sys
            if locale.setlocale(locale.LC_CTYPE) != "tr_TR.UTF-8":
                sys.exit(77)
            from maljan.core import ctype_locale
            ctype_locale.CANDIDATES = ("xx_NO.SUCH-LOCALE",)
            said = []
            assert ctype_locale.pin_character_classification(
                say=lambda level, text: said.append((level, text))
            ) is None
            assert locale.setlocale(locale.LC_CTYPE) == "tr_TR.UTF-8"
            assert [level for level, _ in said] == [30], said
            print(said[0][1])
            """,
            LC_CTYPE=TURKISH,
        )
        line = _finished(result)
        assert "LC_CTYPE stays tr_TR.UTF-8" in line
        assert "folds a capital I by this locale" in line


class TestThePinActsOncePerProcess:
    def test_a_later_call_answers_the_first_and_changes_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The test process pinned at its start (``tests/conftest.py``); a later
        # call must not set a locale again.
        first = ctype_locale.pin_character_classification()
        ctype = locale.setlocale(locale.LC_CTYPE)

        def refuse(category: int, value: str | None = None) -> str:
            assert value is None, "a later call set the locale again"
            return ctype

        monkeypatch.setattr(ctype_locale.locale, "setlocale", refuse)

        assert ctype_locale.pin_character_classification() == first
        assert first is not None


class TestTheEngineSelfTest:
    def test_it_is_asked_once_per_process_and_passes_here(self) -> None:
        pytest.importorskip("yara", reason="yara-python is not installed")
        ctype_locale.yara_case_folding_problem()
        hits = ctype_locale.yara_case_folding_problem.cache_info().hits

        assert ctype_locale.yara_case_folding_problem() is None
        assert ctype_locale.yara_case_folding_problem.cache_info().hits == hits + 1

    def test_under_a_turkish_ctype_without_the_pin_it_names_the_locale(self) -> None:
        out = _finished(
            _run(
                """
                import locale, sys
                if locale.setlocale(locale.LC_CTYPE) != "tr_TR.UTF-8":
                    sys.exit(77)
                from maljan.core import ctype_locale
                print(ctype_locale.yara_case_folding_problem())
                """,
                LC_CTYPE=TURKISH,
            )
        )
        reason = _last_line(out)
        assert reason == ctype_locale.YARA_FOLDING_BROKEN.format(ctype=TURKISH)
        assert "the import-hash clause" in reason

    def test_an_engine_that_raises_is_not_blamed_on_the_locale(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        yara = pytest.importorskip("yara", reason="yara-python is not installed")

        def raising(**_kwargs: object) -> None:
            raise yara.Error("internal error: 30")

        monkeypatch.setattr(yara, "compile", raising)
        # The uncached function: the process's own answer stays as it was.
        reason = ctype_locale.yara_case_folding_problem.__wrapped__()

        assert reason == ctype_locale.YARA_SELF_TEST_FAILED.format(why="Error: internal error: 30")
        assert "LC_CTYPE" not in reason

    def test_its_string_is_far_longer_than_any_atom(self) -> None:
        assert ctype_locale._SELF_TEST_TEXT == "i" * 32


class TestFromANonUtf8Locale:
    def test_the_pin_says_python_s_preferred_encoding_changes(self) -> None:
        out = _finished(
            _run(
                """
                import json, locale, sys
                if locale.setlocale(locale.LC_CTYPE) != "C":
                    sys.exit(77)
                if locale.getpreferredencoding(False).upper().replace("-", "") == "UTF8":
                    sys.exit(77)
                from maljan.core import ctype_locale
                said = []
                chosen = ctype_locale.pin_character_classification(
                    say=lambda level, text: said.append(text)
                )
                print(json.dumps({
                    "chosen": chosen, "said": said, "now": locale.getpreferredencoding(False)
                }))
                """,
                LC_CTYPE="C",
                PYTHONCOERCECLOCALE="0",
                PYTHONUTF8="0",
            )
        )
        seen = json.loads(_last_line(out))
        assert seen["chosen"] in ctype_locale.CANDIDATES
        assert seen["now"] == "UTF-8"
        assert len(seen["said"]) == 1
        assert "Python's preferred encoding changes with it" in seen["said"][0]
        assert "to UTF-8, as in the image" in seen["said"][0]


# Each child records, the moment anything first imports the YARA engine,
# whether the pin had run and the LC_CTYPE then in force; then it loads the
# engine as a job would and asks the self-test.
_WATCH_THE_ENGINE = """
    import json, locale, sys
    if locale.setlocale(locale.LC_CTYPE) != "tr_TR.UTF-8":
        sys.exit(77)
    first = {}

    class _Watch:
        def find_spec(self, fullname, path=None, target=None):
            if fullname == "yara" and not first:
                from maljan.core import ctype_locale
                first.update(
                    pinned=bool(ctype_locale._pinned), ctype=locale.setlocale(locale.LC_CTYPE)
                )
            return None

    sys.meta_path.insert(0, _Watch())

    def report():
        from maljan.core import ctype_locale
        import maljan.reporting.detection_signatures  # the engine loads here, as in a job
        print(json.dumps({"first": first, "problem": ctype_locale.yara_case_folding_problem()}))
"""

# How production starts each of our processes, up to the point it would serve.
_STARTS = {
    # arq imports the settings module, then awaits the startup hook; the hook
    # is stopped at the bootstrap check, before it touches a sample directory.
    "worker": """
        import asyncio
        import app.bootstrap
        import app.worker.analysis_worker as worker

        def stop(*_args, **_kwargs):
            raise RuntimeError("the test stops the start-up here")

        app.bootstrap.require_bootstrap = stop
        try:
            asyncio.run(worker.startup({}))
        except Exception:
            pass
    """,
    # The console script imports the module and calls main().
    "cli": """
        import maljan.cli
        sys.argv = ["maljan", "--help"]
        try:
            maljan.cli.main()
        except SystemExit:
            pass
    """,
    "validation runner": """
        import runpy
        sys.argv = ["run.py", "--help"]
        try:
            runpy.run_path("scripts/validation/run.py", run_name="__main__")
        except SystemExit:
            pass
    """,
    "rehearsal runner": """
        import runpy
        sys.argv = ["run.py", "--help"]
        try:
            runpy.run_path("scripts/rehearsal/run.py", run_name="__main__")
        except SystemExit:
            pass
    """,
    # Run as a script, as the worker starts it; serving stdio is skipped.
    "analysis sidecar": """
        import runpy
        import mcp.server.fastmcp as fastmcp
        fastmcp.FastMCP.run = lambda self, *args, **kwargs: None
        runpy.run_path("services/analysis-mcp/server.py", run_name="__main__")
    """,
    "network sidecar": """
        import runpy
        import mcp.server.fastmcp as fastmcp
        fastmcp.FastMCP.run = lambda self, *args, **kwargs: None
        runpy.run_path("services/network-mcp/server.py", run_name="__main__")
    """,
}


class TestEveryProcessOfOursPinsAtItsStart:
    """Each entrypoint, started as production starts it, pins before the YARA engine loads."""

    @pytest.mark.parametrize("entrypoint", sorted(_STARTS))
    def test_the_engine_loads_only_after_the_pin(self, entrypoint: str) -> None:
        pytest.importorskip("yara", reason="yara-python is not installed")
        script = (
            textwrap.dedent(_WATCH_THE_ENGINE) + textwrap.dedent(_STARTS[entrypoint]) + "report()\n"
        )
        out = _finished(_run(script, LC_CTYPE=TURKISH))
        seen = json.loads(_last_line(out))

        assert seen["first"]["pinned"] is True, f"the {entrypoint} loads YARA before it pins"
        assert seen["first"]["ctype"] in ctype_locale.CANDIDATES
        assert seen["problem"] is None
        if entrypoint.endswith("sidecar"):
            # Standard output is a sidecar's protocol: the pin's line went to stderr.
            assert json.loads(out) == seen

    def test_a_stdio_server_says_its_line_on_standard_error(self) -> None:
        for path in ("services/analysis-mcp/server.py", "services/network-mcp/server.py"):
            text = (ROOT / path).read_text(encoding="utf-8")
            assert "pin_character_classification(say=say_on_stderr)" in text, path
