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
                rules = yara.compile(
                    source='rule t { strings: $a = "i" nocase condition: $a }', includes=False
                )
                assert rules.match(data=b"I"), "the engine loaded after the pin folds I"
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
                    source='rule t { strings: $a = "i" nocase condition: $a }', includes=False
                )
                print(json.dumps({"folds": bool(rules.match(data=b"I"))}))
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


class TestEveryProcessOfOursPinsAtItsStart:
    """Each entrypoint pins before the thing that would load C code or start threads."""

    @pytest.mark.parametrize(
        ("path", "before"),
        [
            ("apps/api/app/worker/analysis_worker.py", "concurrent_analyses_refusal(Worker"),
            ("src/maljan/cli.py", "    app()\n"),
            ("scripts/validation/run.py", "    raise SystemExit(main())"),
            ("scripts/rehearsal/run.py", "    raise SystemExit(main())"),
            ("services/analysis-mcp/server.py", 'CAPABILITIES = manifest("analysis"'),
            ("services/network-mcp/server.py", '    mcp.run(transport="stdio")'),
        ],
    )
    def test_the_entrypoint_pins_first(self, path: str, before: str) -> None:
        text = (ROOT / path).read_text(encoding="utf-8")
        pinned = text.find("pin_character_classification(")

        assert pinned != -1, f"{path} never pins its character classes"
        assert pinned < text.index(before), f"{path} pins after {before.strip()!r}"

    def test_a_stdio_server_says_its_line_on_standard_error(self) -> None:
        for path in ("services/analysis-mcp/server.py", "services/network-mcp/server.py"):
            text = (ROOT / path).read_text(encoding="utf-8")
            assert "pin_character_classification(say=say_on_stderr)" in text, path
