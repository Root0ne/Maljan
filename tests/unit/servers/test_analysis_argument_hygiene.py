"""The page a model is given has to fit the answer it is shown.

Measured on a live run: ``strings`` was called with its old default of 2000
runs and answered with 250-530 KB, the agent's output guardrail cut every
answer to 8000 characters, and the model — shown a twentieth of a page with
nothing saying so — paged blindly through offsets 0, 5000, 10000 and up. Twelve
of the run's nineteen tool calls were that walk.

Two things come out of it. The page is small enough to survive the guardrail
and says where the next one starts, and the words a local model writes when it
means "no filter" are read as the absence they mean rather than passed through
as a literal.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
SERVER = ROOT / "services" / "analysis-mcp" / "server.py"


@pytest.fixture(scope="module")
def server() -> Any:
    """The sidecar module, imported under a name of its own."""
    spec = importlib.util.spec_from_file_location("analysis_mcp_server", SERVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sample(tmp_path: Path) -> str:
    """A file with 40 findable runs in it."""
    blob = b"".join(b"\x00\x00" + f"marker{index:03d}".encode() for index in range(40))
    target = tmp_path / "s.bin"
    target.write_bytes(blob)
    return str(target)


class TestTheWordsThatMeanAbsence:
    @pytest.mark.parametrize("word", ["null", "None", "", "  ", '""', "''", ' "" ', "'\"'"])
    def test_an_optional_argument_carrying_one_is_read_as_absent(
        self, server: Any, tmp_path: Path, word: str
    ) -> None:
        path = _sample(tmp_path)

        answer = server.strings(path, pattern=word)

        assert answer.get("error") is None
        assert len(answer["strings"]) == 40, "the filter was read as no filter"

    def test_the_answer_echoes_the_value_as_it_was_understood(
        self, server: Any, tmp_path: Path
    ) -> None:
        answer = server.strings(_sample(tmp_path), pattern="null")

        assert answer["pattern"] is None

    def test_a_capitalised_null_is_a_search_for_that_token(
        self, server: Any, tmp_path: Path
    ) -> None:
        """``NULL`` is an ordinary string to look for in a binary."""
        path = _sample(tmp_path)

        answer = server.strings(path, pattern="NULL")

        assert answer["pattern"] == "NULL"
        assert answer["strings"] == [], "the filter was applied, not discarded"

    def test_a_quoted_value_keeps_its_value(self, server: Any, tmp_path: Path) -> None:
        """Only a string made of nothing but quotes is absent; a quoted word is
        a word, and the quotes stay because the model wrote them."""
        assert server._means_absent('"marker"') is False
        assert server._means_absent('"') is True

    def test_a_real_pattern_is_untouched(self, server: Any, tmp_path: Path) -> None:
        answer = server.strings(_sample(tmp_path), pattern="marker00")

        assert answer["pattern"] == "marker00"
        assert [row["text"] for row in answer["strings"]] == [
            f"marker00{index}" for index in range(10)
        ]

    def test_a_required_argument_is_left_to_the_tool_to_answer_for(self, server: Any) -> None:
        """ "null" as a path is a wrong call, and the error naming it is more
        use than a second error about something else."""
        answer = server.strings("null")

        assert "no such file" in answer["error"]

    def test_every_tool_on_the_server_gets_it(self, server: Any, tmp_path: Path) -> None:
        """The normalisation is in the guard every tool calls, not in one tool."""
        answer = server.iocs_from_file(_sample(tmp_path), kinds="null")

        assert answer.get("error") is None


class TestThePageAndItsSuccessor:
    def test_the_default_page_fits_the_budget_the_answer_is_read_under(self, server: Any) -> None:
        import inspect

        from maljan.tools.strings import DEFAULT_STRINGS_LIMIT

        assert DEFAULT_STRINGS_LIMIT == 150
        assert inspect.signature(server.strings).parameters["limit"].default == 150

    def test_next_offset_names_the_following_page(self, server: Any, tmp_path: Path) -> None:
        path = _sample(tmp_path)

        first = server.strings(path, limit=10)

        assert first["next_offset"] == 10
        assert first["total_matched"] == 40
        assert first["truncated"] is True

        second = server.strings(path, limit=10, offset=first["next_offset"])

        assert [row["text"] for row in second["strings"]][0] == "marker010"

    def test_a_page_of_nothing_does_not_point_at_itself(self, server: Any, tmp_path: Path) -> None:
        """``limit=0`` returns no rows with matches still behind them, and an
        offset that does not advance is a caller paging forever."""
        answer = server.strings(_sample(tmp_path), limit=0)

        assert answer["strings"] == []
        assert answer["next_offset"] is None
        assert answer["total_matched"] == 40

    def test_the_last_page_says_it_is_the_last(self, server: Any, tmp_path: Path) -> None:
        answer = server.strings(_sample(tmp_path), limit=10, offset=30)

        assert answer["next_offset"] is None
        assert answer["truncated"] is False

    def test_a_page_past_the_end_is_empty_and_says_how_many_there_were(
        self, server: Any, tmp_path: Path
    ) -> None:
        answer = server.strings(_sample(tmp_path), offset=500)

        assert answer["strings"] == []
        assert answer["total_matched"] == 40
        assert answer["next_offset"] is None

    def test_the_description_tells_the_model_where_the_next_page_is(self, server: Any) -> None:
        description = server.strings.__doc__ or ""

        assert "next_offset" in description
        assert "total_matched" in description
