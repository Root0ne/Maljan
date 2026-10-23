"""The answer-key leak check: every hit by file and line, the private list optional, the tree clean.

The scan is checked on files the test writes; the last test runs the check
itself over the files that ship, with the calibration terms (the private list
is not in the tree, so the check runs as it does anywhere the list was not
supplied).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from scripts.calibration import cases, leak_check
from scripts.calibration.leak_check import Term, check, digest, read_private_terms, scan
from scripts.calibration.run import main

ABSENT = Path("/nonexistent/answer-key-terms.txt")


@pytest.fixture(autouse=True)
def _no_local_private_allow_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """The private allow-list is a local file; no test reads the one a machine may hold."""
    monkeypatch.setattr(leak_check, "PRIVATE_ALLOW", Path("/nonexistent/answer-key-allow.json"))


def _tree(root: Path, files: dict[str, str]) -> list[str]:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return sorted(files)


def _empty_allow(tmp_path: Path) -> Path:
    path = tmp_path / "empty-allow.json"
    path.write_text(json.dumps({"allow": []}), encoding="utf-8")
    return path


class TestTheScan:
    def test_each_hit_is_named_by_file_line_and_term(self, tmp_path: Path) -> None:
        paths = _tree(
            tmp_path,
            {
                "src/a.py": "PROMPT = 'look for the Zorbex family'\nother = 1\nzorbex again\n",
                "data/b.json": '{"x": "nothing here"}\n',
            },
        )
        result = scan(tmp_path, paths, [Term("zorbex", False, "list")])
        assert [(h.path, h.line, h.term.text) for h in result.hits] == [
            ("src/a.py", 1, "zorbex"),
            ("src/a.py", 3, "zorbex"),
        ]
        assert result.scanned == 2

    def test_a_term_inside_a_longer_word_is_no_hit(self, tmp_path: Path) -> None:
        paths = _tree(tmp_path, {"a.txt": "zorbexes and prezorbex\nzorbex.dll\n"})
        result = scan(tmp_path, paths, [Term("zorbex", False, "list")])
        assert [h.line for h in result.hits] == [2]

    def test_a_case_sensitive_term_matches_only_as_written(self, tmp_path: Path) -> None:
        paths = _tree(tmp_path, {"a.txt": "a COMMAND here\na command there\n"})
        result = scan(tmp_path, paths, [Term("COMMAND", True, "list")])
        assert [h.line for h in result.hits] == [1]

    def test_a_hex_term_matches_in_every_spelling_of_its_bytes(self, tmp_path: Path) -> None:
        lines = [
            "key d00dfeed",
            "key 0xD00DFEED",
            "key d0 0d fe ed",
            "key D0:0D:FE:ED",
            "xd00dfeed",
        ]
        paths = _tree(tmp_path, {"a.txt": "\n".join(lines) + "\n"})
        result = scan(tmp_path, paths, [Term("d00dfeed", False, "case")])
        assert [h.line for h in result.hits] == [1, 2, 3, 4]

    def test_one_folding_for_matching_and_naming(self, tmp_path: Path) -> None:
        paths = _tree(tmp_path, {"a.txt": "İNDIGO here\nINDIGO there\n"})
        result = scan(tmp_path, paths, [Term("indigo", False, "list")])
        assert [h.line for h in result.hits] == [2]

    def test_a_third_party_table_is_named_and_a_file_not_utf8_is_an_error(
        self, tmp_path: Path
    ) -> None:
        third = next(iter(leak_check.THIRD_PARTY))
        paths = _tree(tmp_path, {third: "zorbex\n"})
        result = scan(tmp_path, paths, [Term("zorbex", False, "list")])
        assert result.hits == [] and any(third in n for n in result.notices)
        (tmp_path / "blob.txt").write_bytes(b"\xff\xfe\x00zorbex")
        with pytest.raises(leak_check.LeakCheckError, match="blob.txt: not UTF-8"):
            scan(tmp_path, ["blob.txt"], [Term("zorbex", False, "list")])

    def test_untracked_files_are_scanned_and_ignored_ones_are_not(self, tmp_path: Path) -> None:
        def git(*args: str) -> None:
            subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)  # noqa: S603, S607

        git("init", "-q")
        _tree(
            tmp_path,
            {
                ".gitignore": "*.log\n",
                "src/maljan/tracked.py": "x\n",
                "src/maljan/local_prompt.md": "y\n",
                "src/maljan/run.log": "z\n",
                "elsewhere.md": "w\n",
            },
        )
        git("add", "src/maljan/tracked.py")
        assert leak_check.shipped_files(tmp_path) == [
            "src/maljan/local_prompt.md",
            "src/maljan/tracked.py",
        ]


class TestThePrivateList:
    def test_its_format(self, tmp_path: Path) -> None:
        path = tmp_path / "terms.txt"
        path.write_text("# a comment\n\nzorbex\ncs: COMMAND\n  spaced term  \n", encoding="utf-8")
        assert [(t.text, t.case_sensitive) for t in read_private_terms(path) or []] == [
            ("zorbex", False),
            ("COMMAND", True),
            ("spaced term", False),
        ]

    def test_the_default_absent_is_a_notice_and_the_check_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(leak_check, "PRIVATE_TERMS", tmp_path / "missing.txt")
        paths = _tree(tmp_path, {"src/a.py": "zorbex\n"})
        result = check(tmp_path, paths=paths, allow=_empty_allow(tmp_path))
        assert result.hits == []
        assert result.notices[0].startswith("notice: no private term list at ")
        assert leak_check.render(result).endswith("private list: not read")

    def test_a_named_list_that_is_absent_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(leak_check.LeakCheckError, match="no private term list"):
            check(tmp_path, private=tmp_path / "typo.txt", paths=[])
        assert main(["leak-check", "--terms", str(tmp_path / "typo.txt")]) == 2

    def test_present_its_terms_fail_the_check(self, tmp_path: Path) -> None:
        paths = _tree(tmp_path, {"src/a.py": "x = 1\nsay zorbex\n"})
        terms = tmp_path / "terms.txt"
        terms.write_text("zorbex\n", encoding="utf-8")
        result = check(tmp_path, private=terms, paths=paths, allow=_empty_allow(tmp_path))
        assert [(h.path, h.line) for h in result.hits] == [("src/a.py", 2)]
        text = leak_check.render(result)
        assert "src/a.py:2: zorbex (from terms.txt)" in text
        assert text.endswith("FAIL: 1 hits in 1 files scanned; private list: read (1 terms)")

    def test_the_calibration_terms_and_template_phrases_are_checked_too(
        self, tmp_path: Path
    ) -> None:
        term = leak_check.calibration_terms()[0].text
        phrase = cases.TEMPLATE_PHRASES[0]
        paths = _tree(tmp_path, {"src/prompt.md": f"Remember {term}.\nA string {phrase}.\n"})
        result = check(tmp_path, private=None, paths=paths, allow=_empty_allow(tmp_path))
        assert [h.term.text for h in result.hits] == [term, phrase]

    def test_a_settings_export_is_scanned_by_json_path(self, tmp_path: Path) -> None:
        export = tmp_path / "settings.json"
        prompt = "Read the sample.\nLook for zorbex."
        export.write_text(json.dumps({"core": {"agents": {"static": {"prompt": prompt}}}}))
        terms = tmp_path / "terms.txt"
        terms.write_text("zorbex\n", encoding="utf-8")
        result = check(
            tmp_path, private=terms, paths=[], allow=_empty_allow(tmp_path), settings_export=export
        )
        assert [(h.path, h.line) for h in result.hits] == [
            (f"{export}#core.agents.static.prompt", 2)
        ]
        export.write_text("not json")
        with pytest.raises(leak_check.LeakCheckError, match="settings export"):
            check(tmp_path, private=terms, paths=[], settings_export=export)

    def test_the_command_fails_on_a_hit_and_prints_the_entry_to_allow_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        paths = _tree(tmp_path, {"src/a.py": "zorbex\n"})
        terms = tmp_path / "terms.txt"
        terms.write_text("zorbex\n", encoding="utf-8")
        real = leak_check.check
        monkeypatch.setattr(
            leak_check,
            "check",
            lambda private, settings_export, private_allow: real(
                tmp_path, private, paths=paths, allow=_empty_allow(tmp_path)
            ),
        )
        assert main(["leak-check", "--terms", str(terms), "--allow-entries"]) == 1
        out = capsys.readouterr().out
        assert "src/a.py:1: zorbex" in out
        entry = json.loads(out[out.index("[") :])[0]
        assert entry["term_sha256"] == digest("zorbex") and entry["line_sha256"] == digest("zorbex")


class TestTheAllowList:
    def _allow(self, tmp_path: Path, rows: list[dict[str, str]]) -> Path:
        path = tmp_path / "allow.json"
        path.write_text(json.dumps({"allow": rows}), encoding="utf-8")
        return path

    def _entry(self, path: str, term: str, line: str, reason: str) -> dict[str, str]:
        return {"path": path, "term_sha256": digest(term), "line_sha256": digest(line),
                "reason": reason}  # fmt: skip

    def test_an_entry_allows_one_occurrence_on_one_line(self, tmp_path: Path) -> None:
        paths = _tree(
            tmp_path,
            {"data/corpus.json": "zorbex\nzorbex, again\n", "src/a.py": "zorbex\n"},
        )
        terms = tmp_path / "terms.txt"
        terms.write_text("zorbex\n", encoding="utf-8")
        allow = self._allow(
            tmp_path,
            [
                self._entry("data/corpus.json", "zorbex", "zorbex", "a public corpus row"),
                self._entry("data/gone.json", "zorbex", "zorbex", "stale"),
            ],
        )
        result = check(
            tmp_path, private=terms, paths=paths, allow=_empty_allow(tmp_path), private_allow=allow
        )
        assert [(h.path, h.line) for h in result.hits] == [
            ("data/corpus.json", 2),
            ("src/a.py", 1),
        ]
        text = leak_check.render(result)
        assert "allowed: data/corpus.json:1: zorbex (a public corpus row)" in text
        assert "allow-list entry matched nothing: data/gone.json (stale)" in text

    def test_a_committed_entry_never_allows_a_private_term(self, tmp_path: Path) -> None:
        paths = _tree(tmp_path, {"data/corpus.json": "zorbex\n"})
        terms = tmp_path / "terms.txt"
        terms.write_text("zorbex\n", encoding="utf-8")
        committed = self._allow(
            tmp_path, [self._entry("data/corpus.json", "zorbex", "zorbex", "public")]
        )
        result = check(tmp_path, private=terms, paths=paths, allow=committed)
        assert [(h.path, h.line) for h in result.hits] == [("data/corpus.json", 1)]

    def test_a_named_private_allow_list_that_is_absent_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(leak_check.LeakCheckError, match="no private allow-list"):
            check(tmp_path, paths=[], allow=_empty_allow(tmp_path), private_allow=tmp_path / "x")

    def test_the_committed_list_holds_only_calibration_terms(self) -> None:
        public = {digest(t.text) for t in leak_check.calibration_terms()}
        assert all(e.term_sha256 in public for e in leak_check.read_allow_list())

    def test_the_list_holds_no_term(self) -> None:
        text = leak_check.ALLOW_LIST.read_text(encoding="utf-8")
        for entry in leak_check.read_allow_list():
            assert len(entry.term_sha256) == len(entry.line_sha256) == len(digest(""))
        assert 'term"' not in text.replace("term_sha256", "")

    @pytest.mark.parametrize(
        "document",
        [
            {"allow": [{"path": "a", "term_sha256": "b", "line_sha256": "c", "reason": ""}]},
            {"allow": [{"path": "a", "term": "b", "line_sha256": "c", "reason": "d"}]},
            {"allows": []},
            {"allow": [], "extra": 1},
            [],
        ],
    )
    def test_an_invalid_list_is_an_error_naming_it(self, tmp_path: Path, document: object) -> None:
        path = tmp_path / "allow.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(leak_check.LeakCheckError, match="allow.json"):
            leak_check.read_allow_list(path)

    def test_the_committed_list_gives_a_reason_for_every_entry(self) -> None:
        entries = leak_check.read_allow_list()
        assert all(e.reason for e in entries)
        shipped = set(leak_check.shipped_files())
        assert all(e.path in shipped for e in entries)


def test_the_shipped_files_carry_no_calibration_term(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(leak_check, "PRIVATE_TERMS", ABSENT)
    result = check()
    assert result.scanned > 0
    assert result.hits == [], leak_check.render(result)
    shipped = leak_check.shipped_files()
    for root in leak_check.SHIPPED:
        assert any(p.startswith(root + "/") for p in shipped), root
    assert not any(p.startswith("tests/") for p in shipped)


def test_the_hoisted_boundaries_find_what_one_boundary_per_term_found() -> None:
    """The combined pattern against the per-term pattern it replaced, over the shipped files."""
    import re

    words = ["running", "test", "error", "trust", ".zq9tst", "d00dfeed", "a.b"]
    terms = [t.text.casefold() for t in leak_check.calibration_terms()] + words
    ordered = sorted(set(terms), key=lambda t: (-len(t), t))
    old = re.compile("|".join(leak_check._piece(t) for t in ordered))
    new = re.compile(leak_check._combined(ordered))
    lines = ["x d00dfeed 0xD00DFEED d0:0d:fe:ed .zq9tst a.b running-test error_x trust."]
    for path in leak_check.shipped_files():
        if path not in leak_check.THIRD_PARTY:
            lines += (leak_check.ROOT / path).read_text(encoding="utf-8").casefold().splitlines()
    hits = 0
    for line in lines:
        found = [(m.start(), m.group(0)) for m in new.finditer(line)]
        assert found == [(m.start(), m.group(0)) for m in old.finditer(line)], line
        hits += len(found)
    assert hits
