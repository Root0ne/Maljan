"""A search argument wrapped in quotes searches for what is inside them.

A pattern sent with a pair of literal quotes around ``CreateMutex`` finds
``CreateMutexW`` as the bare pattern does. Every argument a sidecar tool
searches for or looks up by is read without the quotes that enclose it, as
``carved_path`` is; the answer says what it was read as, and the tool's
description says the argument is the raw text, unquoted.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]

# Every argument a sidecar tool searches for or looks up by, by server and
# tool. Written out rather than derived: the list is the claim, and the
# description check below holds each server to it.
SEARCH_ARGUMENTS: dict[str, dict[str, tuple[str, ...]]] = {
    "analysis-mcp": {"strings": ("pattern",), "floss": ("pattern",)},
    "knowledge-mcp": {
        "resolve_technique": ("text",),
        "attck_lookup": ("technique_id",),
        "attck_validate": ("ids",),
        "api_capability": ("api_names",),
        "family_lookup": ("query",),
        "similar_cases": ("text",),
    },
    "threatintel-mcp": {
        "check_ip_reputation": ("ip_address",),
        "check_domain_reputation": ("domain",),
        "check_hash": ("file_hash",),
    },
}


def _load(directory: str) -> Any:
    path = ROOT / "services" / directory / "server.py"
    name = f"{directory.replace('-', '_')}_quoted_search"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def analysis() -> Any:
    return _load("analysis-mcp")


@pytest.fixture(scope="module")
def knowledge() -> Any:
    return _load("knowledge-mcp")


@pytest.fixture(scope="module")
def threatintel() -> Any:
    return _load("threatintel-mcp")


@pytest.fixture(autouse=True)
def _the_test_s_own_directory_is_a_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MALJAN_SAMPLE_ROOTS", str(tmp_path))


def _sample(tmp_path: Path) -> str:
    target = tmp_path / "s.dll"
    target.write_bytes(b"MZ" + b"\x00" * 64 + b"CreateMutexW\x00" + b"\x00" * 16)
    return str(target)


class TestTheAnalysisServer:
    def test_a_quoted_pattern_finds_what_the_unquoted_one_finds(
        self, analysis: Any, tmp_path: Path
    ) -> None:
        path = _sample(tmp_path)

        bare = analysis.strings(path=path, pattern="CreateMutex")
        quoted = analysis.strings(path=path, pattern='"CreateMutex"')

        assert bare["total_matched"] == 1
        assert quoted["total_matched"] == 1
        assert quoted["strings"] == bare["strings"]

    def test_the_answer_says_first_what_the_pattern_was_read_as(
        self, analysis: Any, tmp_path: Path
    ) -> None:
        answer = analysis.strings(path=_sample(tmp_path), pattern="'CreateMutex'")

        assert next(iter(answer)) == "read_as"
        assert answer["read_as"] == {"pattern": "CreateMutex"}
        assert answer["pattern"] == "CreateMutex"

    def test_an_unquoted_pattern_leaves_no_record(self, analysis: Any, tmp_path: Path) -> None:
        answer = analysis.strings(path=_sample(tmp_path), pattern="CreateMutex")

        assert "read_as" not in answer

    def test_a_quoted_absence_word_is_still_no_filter(self, analysis: Any, tmp_path: Path) -> None:
        answer = analysis.strings(path=_sample(tmp_path), pattern='"null"')

        assert answer["pattern"] is None
        assert answer["total_matched"] == answer["total"]

    def test_floss_reads_its_pattern_the_same_way(
        self, analysis: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked: list[Any] = []

        def _fake(**kwargs: Any) -> dict[str, Any]:
            asked.append(kwargs["pattern"])
            return {"strings": [], "pattern": kwargs["pattern"]}

        monkeypatch.setattr(analysis.emulated_strings, "floss", _fake)

        answer = analysis.floss(path=_sample(tmp_path), pattern='"runnung"')

        assert asked == ["runnung"]
        assert answer["read_as"] == {"pattern": "runnung"}


class TestTheKnowledgeServer:
    @pytest.mark.parametrize(
        "tool, argument, target, passed_as",
        [
            ("resolve_technique", "text", "resolve_technique", "text"),
            ("attck_lookup", "technique_id", "attck_lookup", "technique_id"),
            ("family_lookup", "query", "family_lookup", "query"),
            ("similar_cases", "text", "similar_cases", "query"),
        ],
    )
    def test_a_quoted_lookup_is_the_same_lookup(
        self,
        knowledge: Any,
        monkeypatch: pytest.MonkeyPatch,
        tool: str,
        argument: str,
        target: str,
        passed_as: str,
    ) -> None:
        seen: list[Any] = []

        def _fake(**kwargs: Any) -> dict[str, Any]:
            seen.append(kwargs[passed_as])
            return {"results": []}

        monkeypatch.setattr(knowledge.knowledge_tools, target, _fake)

        answer = getattr(knowledge, tool)(**{argument: '"T1055"'})

        assert seen == ["T1055"]
        assert answer == {"read_as": {argument: "T1055"}, "results": []}

    @pytest.mark.parametrize(
        "tool, argument", [("attck_validate", "ids"), ("api_capability", "api_names")]
    )
    def test_each_quoted_name_in_a_list_is_read(
        self, knowledge: Any, monkeypatch: pytest.MonkeyPatch, tool: str, argument: str
    ) -> None:
        seen: list[Any] = []

        def _fake(**kwargs: Any) -> dict[str, Any]:
            seen.append(kwargs[argument])
            return {"results": []}

        monkeypatch.setattr(knowledge.knowledge_tools, tool, _fake)

        answer = getattr(knowledge, tool)(**{argument: ['"CreateMutexW"', "GetLastError"]})

        assert seen == [["CreateMutexW", "GetLastError"]]
        assert answer["read_as"] == {argument: ["CreateMutexW", "GetLastError"]}


class TestTheThreatIntelServer:
    def test_a_quoted_hash_is_looked_up_as_the_hash(
        self, threatintel: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(threatintel, "VT_API_KEY", "")
        monkeypatch.setattr(threatintel, "_cache", {})
        digest = "9" * 64

        answer = threatintel.check_hash(f'"{digest}"')

        assert answer == threatintel.check_hash(digest)
        assert f"Hash {digest} " in answer

    def test_a_quoted_domain_and_address_are_looked_up_bare(
        self, threatintel: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(threatintel, "VT_API_KEY", "")
        monkeypatch.setattr(threatintel, "ABUSEIPDB_API_KEY", "")
        monkeypatch.setattr(threatintel, "_cache", {})

        assert threatintel.check_domain_reputation("'c2.example.org'") == (
            "Domain c2.example.org is benign."
        )
        assert threatintel.check_ip_reputation('"192.0.2.10"').startswith("IP 192.0.2.10 ")


@pytest.mark.parametrize(
    "directory, tool, argument",
    [
        (directory, tool, name)
        for directory, tools in SEARCH_ARGUMENTS.items()
        for tool, names in tools.items()
        for name in names
    ],
)
def test_the_published_description_says_unquoted(directory: str, tool: str, argument: str) -> None:
    module = _load(directory)
    described = getattr(module, tool).__doc__ or ""
    assert f"``{argument}``" in described
    assert "the value itself, as it should be matched" in described
