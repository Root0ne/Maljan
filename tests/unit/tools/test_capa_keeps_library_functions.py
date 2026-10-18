"""capa's library functions keep their starts and are named; when none were looked for, it says why.

A function capa's signatures identify as library code is matched against no
rule and left out of capa's feature counts, which the function starts were
read from. On an image with no function table of its own the function before
it then seemed to run on over it: an address in the runtime's entry point was
placed in the user function before it. The starts now read capa's library
functions too, the answer names them, and a run that looked for none says why
in their place, so an empty list always means "looked, found none".

Every capa result here is a document the test writes; no sample is read.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.providers.static import capa_child, capa_yara
from maljan.providers.static.capa_child import (
    LIBRARY_FUNCTIONS_NO_DIRECTORY,
    LIBRARY_FUNCTIONS_NO_FILES,
    LIBRARY_FUNCTIONS_NOT_FOR_FORMAT,
    LIBRARY_FUNCTIONS_UNSTATED,
    NOT_IDENTIFIED_KEY,
)
from maljan.providers.static.capa_yara import CapaYaraStaticProvider
from maljan.tools import pe_image, staging
from maljan.tools import rules as tool

BASE = 0x400000


@pytest.fixture(autouse=True)
def _own_cache_and_scratch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """capa's ruleset cache and the runs' scratch, in tmp."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))


def _at(offset: int) -> dict[str, Any]:
    return {"type": "absolute", "value": BASE + offset}


def _document(*, library: list[tuple[int, str]], not_identified: str | None) -> dict[str, Any]:
    """A capa result: three analysed functions and the library functions given."""
    return {
        "meta": {
            "version": "9.4.0",
            "analysis": {
                "format": "pe",
                "arch": "i386",
                "os": "windows",
                "base_address": {"type": "absolute", "value": BASE},
                "feature_counts": {
                    "functions": [
                        {"address": _at(0x1000), "count": 9},
                        {"address": _at(0x26AE), "count": 4},
                        {"address": _at(0x28A4), "count": 2},
                    ]
                },
                "library_functions": [
                    {"address": _at(offset), "name": name} for offset, name in library
                ],
            },
            "sample": {"sha256": "a" * 64},
        },
        "rules": {},
        NOT_IDENTIFIED_KEY: not_identified,
    }


_RUNTIME = [(0x2740, "_WinMainCRTStartup"), (0x28B0, "__setdefaultprecision")]


def _image() -> pe_image.Image:
    """An x86 image with no function table of its own: one code section, no data."""
    text = pe_image.Section(".text", 0x1000, 0x2000, 0x400, 0x2000, 0x60000020)
    return pe_image.Image(
        data=b"", image_base=BASE, is64=False, size_of_image=0x4000, sections=[text]
    )


class TestTheStarts:
    def test_the_library_functions_start_after_the_analysed_ones(self) -> None:
        document = _document(library=_RUNTIME, not_identified=None)

        assert tool.capa_function_starts(document) == [
            "0x1000",
            "0x26ae",
            "0x28a4",
            "0x2740",
            "0x28b0",
        ]

    def test_an_address_in_the_runtime_s_entry_falls_in_it_and_not_before_it(self) -> None:
        without = _image()
        pe_image.take_function_starts(
            without, tool.capa_function_starts(_document(library=[], not_identified=None)), "capa"
        )
        with_them = _image()
        pe_image.take_function_starts(
            with_them,
            tool.capa_function_starts(_document(library=_RUNTIME, not_identified=None)),
            "capa",
        )

        assert without.function_bounds(0x2750) == (0x26AE, 0x28A4)
        assert with_them.function_bounds(0x2750) == (0x2740, 0x28A4)

    def test_with_no_library_functions_the_starts_are_as_before(self) -> None:
        document = _document(library=[], not_identified=LIBRARY_FUNCTIONS_NO_DIRECTORY)

        assert tool.capa_function_starts(document) == ["0x1000", "0x26ae", "0x28a4"]


class TestTheNames:
    def test_each_library_function_is_named_where_it_starts(self) -> None:
        document = _document(library=_RUNTIME, not_identified=None)

        assert tool.capa_library_functions(document) == [
            {"address": "0x2740", "name": "_WinMainCRTStartup"},
            {"address": "0x28b0", "name": "__setdefaultprecision"},
        ]

    def test_a_library_function_capa_places_nowhere_in_the_image_says_so(self) -> None:
        document = _document(library=[(0x2740, "_WinMainCRTStartup")], not_identified=None)
        analysis = document["meta"]["analysis"]
        analysis["library_functions"].append(
            {"address": {"type": "token", "value": 7}, "name": "f"}
        )

        assert tool.capa_library_functions(document) == [
            {"address": "0x2740", "name": "_WinMainCRTStartup"},
            {"address": tool.LIBRARY_FUNCTION_NOT_IN_IMAGE, "name": "f"},
        ]
        assert tool.LIBRARY_FUNCTION_NOT_IN_IMAGE == "no: not a place in the image"

    def test_looked_and_found_none_is_an_empty_list(self) -> None:
        assert tool.capa_library_functions(_document(library=[], not_identified=None)) == []

    @pytest.mark.parametrize(
        "reason",
        [
            LIBRARY_FUNCTIONS_NO_DIRECTORY,
            LIBRARY_FUNCTIONS_NOT_FOR_FORMAT,
            LIBRARY_FUNCTIONS_NO_FILES,
        ],
    )
    def test_not_looked_for_says_why_in_place_of_the_list(self, reason: str) -> None:
        document = _document(library=[], not_identified=reason)

        assert tool.capa_library_functions(document) == reason

    def test_a_result_that_does_not_say_is_stated_as_such(self) -> None:
        document = _document(library=[], not_identified=None)
        del document[NOT_IDENTIFIED_KEY]

        assert tool.capa_library_functions(document) == LIBRARY_FUNCTIONS_UNSTATED


def _rules_dir(tmp_path: Path) -> Path:
    rules_dir = tmp_path / "capa-rules"
    rules_dir.mkdir()
    (rules_dir / "r.yml").write_text("rule:\n  meta:\n    name: r\n", encoding="utf-8")
    return rules_dir


class TestTheAnswer:
    def test_without_signatures_the_answer_gains_the_one_stated_field(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")
        document = _document(library=[], not_identified=LIBRARY_FUNCTIONS_NO_DIRECTORY)
        monkeypatch.setattr(capa_yara, "run_capa_document", lambda **kwargs: document)

        answer = tool.capa(str(sample), rules_dir=str(_rules_dir(tmp_path)))

        assert list(answer) == ["capabilities", "meta", "function_starts", "library_functions"]
        assert answer["library_functions"] == LIBRARY_FUNCTIONS_NO_DIRECTORY

    def test_an_empty_setting_reaches_the_child_empty_not_as_the_project_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")
        handed: list[str] = []

        def run(**kwargs: Any) -> dict[str, Any]:
            handed.append(kwargs["signatures_dir"])
            return _document(library=[], not_identified=LIBRARY_FUNCTIONS_NO_DIRECTORY)

        monkeypatch.setattr(capa_yara, "run_capa_document", run)
        tool.capa(str(sample), rules_dir=str(_rules_dir(tmp_path)), signatures_dir="")
        cfg = Settings(_env_file=None)
        cfg.static.capa.signatures_dir = ""
        CapaYaraStaticProvider.from_settings(cfg)._run_capa_bounded(str(sample), tmp_path)

        assert handed == ["", ""]

    def test_no_directory_is_a_stated_reason_and_capa_is_not_asked(self, tmp_path: Path) -> None:
        for given in ("", "   ", str(tmp_path / "absent")):
            assert capa_child._capa_signatures(given, "pe", "vivisect") == (
                [],
                LIBRARY_FUNCTIONS_NO_DIRECTORY,
            )


class TestWithCapaInstalled:
    def test_capa_s_choice_gives_the_set_or_the_reason(self, tmp_path: Path) -> None:
        capa_loader = pytest.importorskip("capa.loader")
        pytest.importorskip("capa.main")
        signatures = tmp_path / "signatures"
        signatures.mkdir()
        (signatures / "1_a.sig").write_bytes(b"")
        empty = tmp_path / "empty"
        empty.mkdir()

        chosen, reason = capa_child._capa_signatures(str(signatures), "pe", capa_loader.BACKEND_VIV)
        assert [path.name for path in chosen] == ["1_a.sig"]
        assert reason is None
        assert capa_child._capa_signatures(str(signatures), "elf", capa_loader.BACKEND_VIV) == (
            [],
            LIBRARY_FUNCTIONS_NOT_FOR_FORMAT,
        )
        assert capa_child._capa_signatures(str(empty), "pe", capa_loader.BACKEND_VIV) == (
            [],
            LIBRARY_FUNCTIONS_NO_FILES,
        )

    def test_an_empty_setting_runs_capa_and_says_no_library_identification(
        self, tmp_path: Path
    ) -> None:
        pytest.importorskip("capa.main")
        from tests.unit.providers.static.test_capa_auto_backend_follows_the_format import (
            _assembly_and_rules,
            _signature_dir,
        )

        sample, rules_dir = _assembly_and_rules(tmp_path)
        unset = tool.capa(str(sample), timeout_s=120, rules_dir=str(rules_dir), signatures_dir="")
        for_pe_only = tool.capa(
            str(sample),
            timeout_s=120,
            rules_dir=str(rules_dir),
            signatures_dir=str(_signature_dir(tmp_path)),
        )

        assert "error" not in unset, unset
        assert unset["library_functions"] == LIBRARY_FUNCTIONS_NO_DIRECTORY
        assert unset["capabilities"] == for_pe_only["capabilities"]
        assert for_pe_only["library_functions"] == LIBRARY_FUNCTIONS_NOT_FOR_FORMAT
