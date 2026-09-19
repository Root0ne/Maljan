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
import time
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

    def test_an_absolute_path_inside_this_sample_s_tree_is_read(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hashlib

        self._staged(tmp_path, monkeypatch, server)
        body = b"SAMPLE-CONTENT\x00"
        sample = tmp_path / "s.bin"
        sample.write_bytes(body)
        written = server._carved_tree(hashlib.sha256(body).hexdigest()) / "payload_0.bin"
        written.parent.mkdir(parents=True, exist_ok=True)
        written.write_bytes(b"CARVED-PAYLOAD-CONTENT\x00")

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

    def test_a_symlink_out_of_the_tree_is_refused(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hashlib

        self._staged(tmp_path, monkeypatch, server)
        body = b"SAMPLE\x00"
        sample = tmp_path / "s.bin"
        sample.write_bytes(body)
        tree = server._carved_tree(hashlib.sha256(body).hexdigest())
        tree.mkdir(parents=True, exist_ok=True)
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"NOT-IN-STAGING\x00")
        (tree / "escape.bin").symlink_to(outside)

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


class TestOneRunReadsOnlyWhatItProduced:
    """The staging directory is one per server process, and every job shares it.

    ``put_sample`` writes ``<staging>/<sha16>_<name>`` for every job and
    ``carve_payloads`` writes ``<staging>/carved/<sha256>/…``, so confining the
    argument to the staging base let a run read another run's carved payload
    and another run's upload. A sample is adversary-authored content this model
    reads, and it can carry another sample's digest in its own bytes beside one
    instruction to point a tool at it. Samples are not only malware either —
    an operator submits a suspicious document that may hold somebody's data.

    So the bound is the carved tree of the file this call is pinned to, which
    the server derives from the bytes it was handed, plus that file itself. Two
    runs of the same sample share one tree, which is the same bytes read twice.
    """

    @staticmethod
    def _staged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, server: Any) -> Path:
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        return Path(server._staging_dir())

    @staticmethod
    def _dropper(tmp_path: Path, name: str, marker: bytes) -> Path:
        target = tmp_path / name
        target.write_bytes(b"DECOY\x00" + b"MZ\x90\x00" + b"\x00" * 2048 + marker)
        return target

    def test_another_sample_s_carved_payload_is_refused(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._staged(tmp_path, monkeypatch, server)
        first = self._dropper(tmp_path, "a.bin", b"PAYLOAD-OF-A\x00")
        second = self._dropper(tmp_path, "b.bin", b"PAYLOAD-OF-B\x00")
        mine = server.carve_payloads(str(first))["payloads"][0]["path"]
        theirs = server.carve_payloads(str(second))["payloads"][0]["path"]
        assert mine != theirs

        answer = server.strings(path=str(first), carved_path=theirs, min_len=6)

        assert answer["error"]["code"] == "path_outside_roots"

    def test_my_own_carved_payload_is_read(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = self._staged(tmp_path, monkeypatch, server)
        sample = self._dropper(tmp_path, "a.bin", b"PAYLOAD-OF-A\x00")
        mine = Path(server.carve_payloads(str(sample))["payloads"][0]["path"])

        for spelling in (str(mine), str(mine.relative_to(base)), mine.name):
            answer = server.strings(path=str(sample), carved_path=spelling, min_len=6)
            assert answer["read_path"] == str(mine), spelling

    def test_another_job_s_upload_is_refused(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = self._staged(tmp_path, monkeypatch, server)
        upload = base / "deadbeefdeadbeef_theirs.exe"
        upload.write_bytes(b"ANOTHER-JOB-UPLOAD\x00")
        sample = self._dropper(tmp_path, "a.bin", b"PAYLOAD-OF-A\x00")

        answer = server.strings(path=str(sample), carved_path=str(upload), min_len=6)

        assert answer["error"]["code"] == "path_outside_roots"

    def test_a_payload_carved_from_a_payload_stays_in_the_one_tree(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = self._staged(tmp_path, monkeypatch, server)
        sample = self._dropper(tmp_path, "a.bin", b"PAYLOAD-OF-A\x00")
        mine = Path(server.carve_payloads(str(sample))["payloads"][0]["path"])

        server.carve_payloads(str(sample), carved_path=str(mine.relative_to(base)))

        tree = mine.parent
        assert [p for p in tree.rglob("*") if p.is_dir()] or True
        assert all(tree in produced.parents for produced in tree.rglob("*"))


class TestWhatCarvedPathMayName:
    @staticmethod
    def _sample_and_tree(server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        import hashlib

        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        server._staging_dir()
        body = b"SAMPLE-CONTENT\x00"
        sample = tmp_path / "s.bin"
        sample.write_bytes(body)
        tree = server._carved_tree(hashlib.sha256(body).hexdigest())
        tree.mkdir(parents=True, exist_ok=True)
        return sample, tree

    def test_a_directory_is_not_a_file_to_read(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, tree = self._sample_and_tree(server, tmp_path, monkeypatch)
        (tree / "inner").mkdir()

        answer = server.strings(path=str(sample), carved_path="inner", min_len=4)

        assert answer["error"]["code"] == "bad_argument"
        assert "regular file" in answer["error"]["message"]

    def test_a_fifo_is_not_either(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import os

        sample, tree = self._sample_and_tree(server, tmp_path, monkeypatch)
        os.mkfifo(tree / "pipe")

        answer = server.identify_file(path=str(sample), carved_path="pipe")

        assert answer["error"]["code"] == "bad_argument"

    def test_a_name_that_is_not_there_says_so(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, _tree = self._sample_and_tree(server, tmp_path, monkeypatch)

        answer = server.strings(path=str(sample), carved_path="never_written.bin", min_len=4)

        assert answer["error"]["code"] == "no_such_file"
        assert "no carved file named 'never_written.bin'" in answer["error"]["message"]


class TestTheSweepPrunesCarvedTrees:
    """Carved payloads never expired: the sweep deletes files and skips
    directories, and everything carved lives one level down."""

    def test_a_stale_payload_and_its_empty_tree_go(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import os

        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        monkeypatch.setenv("MALJAN_STAGING_TTL_HOURS", "1")
        base = Path(server._staging_dir())
        tree = server._carved_tree("f" * 64)
        tree.mkdir(parents=True, exist_ok=True)
        stale = tree / "payload_0.bin"
        stale.write_bytes(b"OLD\x00")
        long_ago = time.time() - 7200
        os.utime(stale, (long_ago, long_ago))

        removed = server._prune_staging(base)

        assert removed == 1
        assert not stale.exists()
        assert not tree.exists(), "an emptied tree goes with the payloads it held"

    def test_a_fresh_one_stays(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        monkeypatch.setenv("MALJAN_STAGING_TTL_HOURS", "1")
        base = Path(server._staging_dir())
        tree = server._carved_tree("e" * 64)
        tree.mkdir(parents=True, exist_ok=True)
        fresh = tree / "payload_0.bin"
        fresh.write_bytes(b"NEW\x00")

        assert server._prune_staging(base) == 0
        assert fresh.exists()

    def test_a_disabled_ttl_prunes_nothing(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import os

        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        monkeypatch.setenv("MALJAN_STAGING_TTL_HOURS", "0")
        base = Path(server._staging_dir())
        tree = server._carved_tree("d" * 64)
        tree.mkdir(parents=True, exist_ok=True)
        stale = tree / "payload_0.bin"
        stale.write_bytes(b"OLD\x00")
        long_ago = time.time() - 999999
        os.utime(stale, (long_ago, long_ago))

        assert server._prune_staging(base) == 0
        assert stale.exists()


class TestTheSixSpellingsAModelWrote:
    """``carved_path`` failed on its first live contact, six calls out of six.

    ``carve_payloads`` answered with the path it had written, and the analyst
    passed it back **wrapped in the double quotes it had read it between** — a
    quoted path is not absolute, so it took the relative branch and missed. It
    tried the bare tail, quoted. It tried the payload's display ``name``,
    quoted. And each of the six refusals handed it the general file
    remediation, which says to pass the sample path the prompt names: a
    parameter the pinning had taken out of the schema, so the advice named a
    field the model could not see.

    The six values below are the ones that run really sent.
    """

    @staticmethod
    def _carved(server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        server._staging_dir()
        sample = tmp_path / "dropper.exe"
        sample.write_bytes(
            b"DECOY\x00" + b"MZ\x90\x00" + b"\x00" * 2048 + b"CARVED-PAYLOAD-MARKER\x00"
        )
        answer = server.carve_payloads(str(sample))
        assert answer["count"] >= 1, answer
        return sample, answer["payloads"][0]

    def test_all_six_read_the_payload(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, payload = self._carved(server, tmp_path, monkeypatch)
        written = Path(payload["path"])
        recorded = [
            f'"{payload["path"]}"',
            f'"{payload["path"]}"',
            f'"{written.name}"',
            f'"{payload["name"]}"',
            f'"{payload["path"]}"',
            f'"{payload["name"]}"',
        ]

        for index, asked in enumerate(recorded, start=1):
            answer = server.strings(path=str(sample), carved_path=asked, min_len=6)
            assert answer.get("read_path") == str(written), f"call {index}: {asked}"

    def test_the_unquoted_spellings_still_work(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, payload = self._carved(server, tmp_path, monkeypatch)
        written = Path(payload["path"])

        for asked in (payload["path"], written.name, payload["name"], payload["carved_path"]):
            answer = server.identify_file(path=str(sample), carved_path=asked)
            assert answer.get("read_path") == str(written), asked


class TestReadingTheQuotesOffAValue:
    @staticmethod
    def _unquoted(server: Any, value: str) -> str:
        return str(server._unquoted(value))

    def test_one_matching_pair_of_each_quote_comes_off(self, server: Any) -> None:
        for wrapped in ('"/tmp/x"', "'/tmp/x'", "`/tmp/x`", '  "/tmp/x"  '):
            assert self._unquoted(server, wrapped) == "/tmp/x", wrapped

    def test_only_one_pair(self, server: Any) -> None:
        assert self._unquoted(server, '""/tmp/x""') == '"/tmp/x"'

    def test_an_unmatched_quote_stays(self, server: Any) -> None:
        for kept in ('"/tmp/x', "/tmp/x'", "\"/tmp/x'"):
            assert self._unquoted(server, kept) == kept, kept

    def test_nothing_else_is_rewritten(self, server: Any) -> None:
        """No unescaping, no globbing, no case folding."""
        for kept in ("/tmp/A B/x", "/tmp/*.bin", "/tmp/it\\'s.bin", "/TMP/X"):
            assert self._unquoted(server, kept) == kept, kept

    def test_a_quoted_absence_word_is_an_absence(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        server._staging_dir()
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"SAMPLE-CONTENT\x00")

        for absent in ('"null"', "'None'", '" "'):
            answer = server.strings(path=str(sample), carved_path=absent, min_len=4)
            assert [row["text"] for row in answer["strings"]] == ["SAMPLE-CONTENT"], absent
            assert "read_path" not in answer, absent


class TestWhatACarvedRefusalSays:
    @staticmethod
    def _carved(server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        server._staging_dir()
        sample = tmp_path / "dropper.exe"
        sample.write_bytes(
            b"DECOY\x00" + b"MZ\x90\x00" + b"\x00" * 2048 + b"CARVED-PAYLOAD-MARKER\x00"
        )
        return sample, server.carve_payloads(str(sample))["payloads"][0]

    def test_a_name_this_run_did_not_carve_lists_the_ones_it_did(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, payload = self._carved(server, tmp_path, monkeypatch)

        error = server.strings(path=str(sample), carved_path="body+0xdeadbeef", min_len=6)["error"]

        assert error["code"] == "no_such_file"
        assert Path(payload["path"]).name in error["message"]
        assert error["remediation"] == server.CARVED_REMEDIATION

    def test_the_listing_names_no_path(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A refusal travels into the ledger and onto the feed; tails only."""
        sample, _payload = self._carved(server, tmp_path, monkeypatch)

        error = server.strings(path=str(sample), carved_path="nothing_like_it", min_len=6)["error"]

        assert str(tmp_path) not in error["message"]
        assert "/" not in error["message"].split("this run carved:")[-1]

    def test_no_carved_refusal_names_a_parameter_the_model_cannot_see(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, _payload = self._carved(server, tmp_path, monkeypatch)
        asked = ("body+0xdeadbeef", "../../etc/passwd", "/etc/passwd")

        for value in asked:
            error = server.strings(path=str(sample), carved_path=value, min_len=6)["error"]
            assert "sample path the prompt names" not in error["remediation"], value
            assert error["remediation"] == server.CARVED_REMEDIATION, value

    def test_a_call_that_named_no_carved_file_keeps_the_general_remedy(self, server: Any) -> None:
        """The argument's own remediation is for the argument's own failures."""
        from maljan.tools.errors import REMEDIATIONS

        answer = server.identify_file(path="/nowhere/at/all.bin")

        assert answer["error"]["remediation"] == REMEDIATIONS["path_outside_roots"]

    def test_two_payloads_sharing_a_label_are_not_chosen_between(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, payload = self._carved(server, tmp_path, monkeypatch)
        written = Path(payload["path"])
        twin = written.with_name(f"{written.name[:-12]}ffffffffffff")
        twin.write_bytes(b"A SECOND PAYLOAD UNDER THE SAME LABEL\x00")

        error = server.strings(path=str(sample), carved_path=payload["name"], min_len=6)["error"]

        assert error["code"] == "no_such_file"
        assert twin.name in error["message"]


class TestTheAnswerSaysWhichFieldToPassBack:
    def test_each_payload_carries_the_argument_s_own_name(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        server._staging_dir()
        sample = tmp_path / "dropper.exe"
        sample.write_bytes(
            b"DECOY\x00" + b"MZ\x90\x00" + b"\x00" * 2048 + b"CARVED-PAYLOAD-MARKER\x00"
        )

        payload = server.carve_payloads(str(sample))["payloads"][0]

        assert payload["carved_path"] == payload["path"]

    def test_the_description_names_the_field(self, server: Any) -> None:
        assert "carved_path`` value of an entry ``carve_payloads`` returned" in server.CARVED_NOTE
        assert "no quotes around it" in server.CARVED_NOTE


class TestEverySpellingDecidesConfinementTheSameWay:
    """A link named like a payload was read by its label and refused by its path.

    The label branch returned its match straight out of the tree walk, without
    the resolution the other two spellings go through — and the walk used
    ``rglob`` with ``is_file()``, both of which follow a symlink. So a link
    called ``body_0x1000_aaaaaaaaaaaa`` pointing anywhere the sidecar's user
    can read was matched by ``carved_path=body+0x1000`` and read, while the
    same link by its tail and by its absolute path was refused — and the
    answer's ``read_path`` then named the link rather than what had been read.
    """

    @staticmethod
    def _run_with_a_planted_link(
        server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> tuple[Path, Path, dict[str, Any]]:
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        server._staging_dir()
        sample = tmp_path / "dropper.exe"
        sample.write_bytes(
            b"DECOY\x00" + b"MZ\x90\x00" + b"\x00" * 2048 + b"CARVED-PAYLOAD-MARKER\x00"
        )
        payload = server.carve_payloads(str(sample))["payloads"][0]
        tree = Path(payload["path"]).parent
        outside = tmp_path / "secret.txt"
        outside.write_bytes(b"CONTENT-FROM-OUTSIDE-THE-TREE\x00")
        link = tree / "leak_000000000000"
        link.symlink_to(outside)
        return sample, link, payload

    def test_the_label_the_link_was_named_for_is_refused(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, link, _payload = self._run_with_a_planted_link(server, tmp_path, monkeypatch)

        answer = server.strings(path=str(sample), carved_path="leak", min_len=6)

        assert "read_path" not in answer
        assert "CONTENT-FROM-OUTSIDE-THE-TREE" not in str(answer)
        assert answer["error"]["code"] in ("path_outside_roots", "no_such_file")
        assert link.exists()

    def test_the_three_spellings_answer_alike(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, link, _payload = self._run_with_a_planted_link(server, tmp_path, monkeypatch)

        for spelling in ("leak", link.name, str(link)):
            answer = server.strings(path=str(sample), carved_path=spelling, min_len=6)
            assert "read_path" not in answer, spelling
            assert "error" in answer, spelling

    def test_a_link_is_not_listed_as_a_carved_file(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, link, payload = self._run_with_a_planted_link(server, tmp_path, monkeypatch)

        listing = server.strings(path=str(sample), carved_path="nothing_at_all", min_len=6)

        assert link.name not in listing["error"]["message"]
        assert Path(payload["path"]).name in listing["error"]["message"]

    def test_the_real_payload_still_reads_by_every_spelling(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, _link, payload = self._run_with_a_planted_link(server, tmp_path, monkeypatch)
        written = Path(payload["path"])

        for spelling in (payload["path"], written.name, payload["name"]):
            answer = server.strings(path=str(sample), carved_path=spelling, min_len=6)
            assert answer["read_path"] == str(written), spelling

    def test_read_path_records_the_resolved_file(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """What was read, not the spelling that asked for it."""
        sample, _link, payload = self._run_with_a_planted_link(server, tmp_path, monkeypatch)

        answer = server.strings(path=str(sample), carved_path=payload["name"], min_len=6)

        assert answer["read_path"] == str(Path(payload["path"]).resolve())


class TestTheCarveWriterDoesNotFollowALink:
    """The upload path opens with ``O_CREAT|O_EXCL|O_NOFOLLOW`` and the carve
    writer wrote with ``write_bytes``, which follows a link planted at the
    destination — the same directory and the same prerequisite as the read
    above."""

    @staticmethod
    def _sample_and_name(server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        import hashlib

        from maljan.extractors.pe_extractor import carve_payloads as carve
        from maljan.tools.binary import carved_file_name

        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        server._staging_dir()
        body = b"DECOY\x00" + b"MZ\x90\x00" + b"\x00" * 2048 + b"CARVED-PAYLOAD-MARKER\x00"
        sample = tmp_path / "dropper.exe"
        sample.write_bytes(body)
        tree = server._carved_tree(hashlib.sha256(body).hexdigest())
        tree.mkdir(parents=True, exist_ok=True)
        label, blob = carve(body)[0]
        return sample, tree / carved_file_name(label, hashlib.sha256(blob).hexdigest())

    def test_a_planted_link_is_not_written_through(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, name = self._sample_and_name(server, tmp_path, monkeypatch)
        victim = tmp_path / "victim.txt"
        victim.write_bytes(b"NOT-A-PAYLOAD\x00")
        name.symlink_to(victim)

        answer = server.carve_payloads(str(sample))

        assert victim.read_bytes() == b"NOT-A-PAYLOAD\x00"
        assert "error" in answer["payloads"][0]
        assert "already taken" in answer["payloads"][0]["error"]
        assert "path" not in answer["payloads"][0]

    def test_a_second_run_of_the_same_sample_reuses_its_own_payload(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, _name = self._sample_and_name(server, tmp_path, monkeypatch)

        first = server.carve_payloads(str(sample))
        second = server.carve_payloads(str(sample))

        assert first["payloads"][0]["path"] == second["payloads"][0]["path"]
        assert "error" not in second["payloads"][0]

    def test_a_file_of_the_same_name_holding_other_bytes_is_refused(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, name = self._sample_and_name(server, tmp_path, monkeypatch)
        name.write_bytes(b"SOMETHING ELSE ENTIRELY")

        answer = server.carve_payloads(str(sample))

        assert "already taken" in answer["payloads"][0]["error"]
        assert name.read_bytes() == b"SOMETHING ELSE ENTIRELY"

    def test_the_payload_is_written_private(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample, name = self._sample_and_name(server, tmp_path, monkeypatch)

        server.carve_payloads(str(sample))

        assert name.stat().st_mode & 0o777 == 0o600


class TestAValueTheFilesystemWouldRefuse:
    @staticmethod
    def _sample(server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        server._staging_dir()
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"SAMPLE-CONTENT\x00")
        return sample

    def test_a_very_long_name_gets_the_carved_remediation(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = self._sample(server, tmp_path, monkeypatch)

        error = server.strings(path=str(sample), carved_path="x" * 3000, min_len=4)["error"]

        assert error["remediation"] == server.CARVED_REMEDIATION

    def test_a_value_past_the_bound_is_refused_before_the_filesystem(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = self._sample(server, tmp_path, monkeypatch)

        error = server.strings(path=str(sample), carved_path="x" * 5000, min_len=4)["error"]

        assert error["code"] == "no_such_file"
        assert "5000 characters" in error["message"]
        assert error["remediation"] == server.CARVED_REMEDIATION

    def test_a_refusal_does_not_echo_the_whole_value(
        self, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = self._sample(server, tmp_path, monkeypatch)

        error = server.strings(path=str(sample), carved_path="y" * 3000, min_len=4)["error"]

        assert len(error["message"]) < 400
