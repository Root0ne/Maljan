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


@pytest.fixture(autouse=True)
def _the_test_s_own_directory_is_a_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The sample a test writes is a sample this server may read.

    Every path argument is held to the staging directory plus the roots
    ``MALJAN_SAMPLE_ROOTS`` names (see ``maljan.tools.roots``), which is how a
    deployment says where its samples arrive. A test that writes one under
    ``tmp_path`` says the same thing about that directory.
    """
    monkeypatch.setenv("MALJAN_SAMPLE_ROOTS", str(tmp_path))


def _sample(tmp_path: Path) -> str:
    """A file with 40 findable runs in it."""
    blob = b"".join(b"\x00\x00" + f"marker{index:03d}".encode() for index in range(40))
    target = tmp_path / "s.bin"
    target.write_bytes(blob)
    return str(target)


class TestCarvedPayloadsLandUnderStaging:
    """The destination is the sidecar's, never the model's.

    A live run passed the two-character string "" as ``out_dir``, the wrapper
    defaulted only the empty string, and a directory literally named "" with a
    931 KB carved PE body in it appeared under the sidecar's own cwd. A
    model-chosen directory lets a tool write live malware anywhere the sidecar
    can write, so the argument is gone: carved files land in
    ``<staging>/carved/<sha256>/``, created private like the staging dir.
    """

    def _sample(self, tmp_path: Path) -> tuple[str, str]:
        import hashlib

        blob = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 57
        target = tmp_path / "dropper.bin"
        target.write_bytes(blob)
        return str(target), hashlib.sha256(blob).hexdigest()

    def test_the_directory_is_the_staging_dir_keyed_by_the_sample_s_hash(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import os

        staging = tmp_path / "staging"
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(staging))
        path, digest = self._sample(tmp_path)
        before = set(os.listdir(os.getcwd()))

        answer = server.carve_payloads(path)

        assert answer == {"payloads": [], "count": 0}
        carved = staging / "carved" / digest
        assert carved.is_dir()
        assert (staging / "carved").stat().st_mode & 0o777 == 0o700
        assert carved.stat().st_mode & 0o777 == 0o700
        assert set(os.listdir(os.getcwd())) == before, "nothing is written where the sidecar runs"

    def test_the_tool_takes_no_destination(self, server: Any, tmp_path: Path) -> None:
        import inspect

        path, _digest = self._sample(tmp_path)

        # Two arguments, and neither is a place to write: the file to read,
        # and the qualified way of naming one an earlier call produced.
        assert list(inspect.signature(server.carve_payloads).parameters) == [
            "path",
            "carved_path",
        ]
        with pytest.raises(TypeError):
            server.carve_payloads(path, out_dir=str(tmp_path))
        # A model writing a pair of quote characters means "not passing this
        # one", and it is read as the absence rather than as a file name.
        assert server.carve_payloads(path, '""') == {"payloads": [], "count": 0}

    def test_the_description_says_where_the_files_land(self, server: Any) -> None:
        assert "carved/<sha256 of the sample>/" in str(server.carve_payloads.__doc__)

    def test_a_missing_sample_is_an_error_and_creates_nothing(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        staging = tmp_path / "staging"
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(staging))

        answer = server.carve_payloads(str(tmp_path / "absent.bin"))

        assert answer["tool"] == "carve_payloads"
        assert "no such file" in answer["error"]["message"]
        assert answer["error"]["code"] == "no_such_file" and answer["error"]["remediation"]
        assert not (staging / "carved").exists()


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
        """ "null" as a path is a wrong call, and it is answered as one.

        A bare name resolves against the server's own working directory, which
        is not a directory this server may read, so the refusal is the root
        check's rather than the tool's — and it carries the remedy that names
        the right path, which is the thing the caller has to do next.
        """
        answer = server.strings("null")

        assert answer["error"]["code"] == "path_outside_roots"
        assert answer["error"]["remediation"]

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


class TestReadingAFileAnEarlierCallWrote:
    """``carve_payloads`` hands back paths, and something has to read them.

    The sample's own path left the schema a model binds to, which is what stops
    a model typing it wrongly — and it took the carved payloads with it: the
    tool returned a list of paths the model had nothing to pass to.
    ``carved_path`` is the qualified argument that gives that back. It names a
    file this run produced, so it is held to the staging base and to nothing
    else: not the sample roots, which hold whatever the deployment put there.
    """

    @staticmethod
    def _staged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, server: Any) -> Path:
        staging = tmp_path / "staging"
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(staging))
        return Path(server._staging_dir())

    def test_a_carved_payload_is_read_through_it(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = self._staged(tmp_path, monkeypatch, server)
        # A second-stage PE appended past the decoy, which is what carving
        # finds: the signature the carver looks for, then enough body for it
        # not to be four coincidental bytes.
        payload = b"MZ\x90\x00" + b"\x00" * 2048 + b"CARVEDPAYLOADMARKER\x00"
        sample = tmp_path / "dropper.bin"
        sample.write_bytes(b"DECOY-HEADER\x00" + payload)

        carved = server.carve_payloads(str(sample))
        assert carved["count"] >= 1, carved
        written = Path(carved["payloads"][0]["path"])
        assert base in written.parents

        answer = server.strings(
            path=str(sample), carved_path=str(written.relative_to(base)), min_len=4
        )

        assert answer["read_path"] == str(written)
        assert answer["strings"] != server.strings(path=str(sample), min_len=4)["strings"]

    def test_an_absolute_path_inside_the_staging_base_is_read(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = self._staged(tmp_path, monkeypatch, server)
        written = base / "carved" / "abc" / "payload_0.bin"
        written.parent.mkdir(parents=True, exist_ok=True)
        written.write_bytes(b"CARVED-PAYLOAD-CONTENT\x00")
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"SAMPLE-CONTENT\x00")

        answer = server.strings(path=str(sample), carved_path=str(written), min_len=4)

        assert [row["text"] for row in answer["strings"]] == ["CARVED-PAYLOAD-CONTENT"]

    def test_a_traversal_is_refused(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._staged(tmp_path, monkeypatch, server)
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"SAMPLE\x00")

        answer = server.strings(path=str(sample), carved_path="../../etc/passwd", min_len=4)

        assert answer["error"]["code"] == "path_outside_roots"

    def test_an_absolute_path_outside_the_staging_base_is_refused(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._staged(tmp_path, monkeypatch, server)
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"SAMPLE\x00")

        answer = server.identify_file(path=str(sample), carved_path="/etc/passwd")

        assert answer["error"]["code"] == "path_outside_roots"

    def test_a_sample_root_is_not_reachable_through_it(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A deployment's sample directory holds whatever it holds."""
        self._staged(tmp_path, monkeypatch, server)
        neighbour = tmp_path / "someone-elses.bin"
        neighbour.write_bytes(b"NOT-THIS-ONE\x00")
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"SAMPLE\x00")

        answer = server.strings(path=str(sample), carved_path=str(neighbour), min_len=4)

        assert answer["error"]["code"] == "path_outside_roots"

    def test_a_symlink_out_of_the_staging_base_is_refused(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = self._staged(tmp_path, monkeypatch, server)
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"NOT-IN-STAGING\x00")
        link = base / "escape.bin"
        link.symlink_to(outside)
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"SAMPLE\x00")

        answer = server.strings(path=str(sample), carved_path="escape.bin", min_len=4)

        assert answer["error"]["code"] == "path_outside_roots"

    def test_the_absence_words_are_read_as_the_absence(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._staged(tmp_path, monkeypatch, server)
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"SAMPLE-CONTENT\x00")

        for absent in ("", "null", "None", "   ", '""'):
            answer = server.strings(path=str(sample), carved_path=absent, min_len=4)
            assert [row["text"] for row in answer["strings"]] == ["SAMPLE-CONTENT"], absent
            assert "read_path" not in answer, absent
