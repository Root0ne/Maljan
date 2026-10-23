"""A file one tool server wrote reaches another server's tool through the job's artefact store.

The store (``pipeline.artefacts``) takes in what a step's answer names as
written, under a stable id (its digest), and hands each file to a later step's
server at the path that server opens it at, exactly as the sample is handed:
a server on this host's filesystem a copy under its own job staging
directory, a server with a ``sample_mount`` the worker's copy under it, a
server across a network an upload over ``put_sample``. The capture and the
sandbox report are files of the store too. Whatever cannot be taken in or
handed over is said, never raised, and no host path is handed to a server
that cannot open it. The ledger records what each call wrote and read.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.core import config as config_module
from maljan.core.config import MCPServerConfig, Settings, TriageConfig
from maljan.core.container import ServiceContainer
from maljan.core.pack_steps import effective_steps
from maljan.pipeline import artefacts as store_module
from maljan.pipeline.artefacts import (
    FETCH_TOOL,
    ArtefactStore,
    open_beneath,
    safe_name,
    take_in_outputs,
    written_names,
)
from maljan.pipeline.nodes import _server_step_call
from maljan.pipeline.triage_pack import (
    PIPELINE,
    CapaSettings,
    PackInputs,
    ServerAnswer,
    run_pack,
)
from maljan.schemas.evidence import EvidenceCounter
from maljan.tools import staging

PAYLOAD = b"\x00payload written by one server\xff"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


@pytest.fixture
def base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """This process's staging base, under the test's own directory."""
    held = tmp_path / "staging"
    monkeypatch.setenv(staging.STAGING_DIR_ENV, str(held))
    return held


def _local(**over: Any) -> MCPServerConfig:
    return MCPServerConfig.model_validate({"command": "invented", "enabled": True, **over})


class TestTheStore:
    def test_a_file_is_kept_private_under_the_job_by_its_digest(self, base: Path) -> None:
        store = ArtefactStore("job-one")
        artefact = store.take_in_bytes(PAYLOAD, "drop.exe")
        assert artefact.id == f"art_{DIGEST}" and artefact.sha256 == DIGEST
        assert artefact.size == len(PAYLOAD) and artefact.name == "drop.exe"
        job_dir = base / staging.job_directory_name("job-one")
        assert artefact.path == job_dir / "artefacts" / DIGEST / "drop.exe"
        assert artefact.path.read_bytes() == PAYLOAD
        assert stat.S_IMODE(artefact.path.stat().st_mode) == 0o600
        for level in (job_dir, job_dir / "artefacts", artefact.path.parent):
            assert stat.S_IMODE(level.stat().st_mode) == 0o700
        # The job's teardown removes it with everything else the job staged.
        assert job_dir in staging.job_directories("job-one")
        staging.remove_job_staging("job-one")
        assert not job_dir.exists()

    def test_one_file_is_one_artefact_under_its_first_name(self, base: Path) -> None:
        store = ArtefactStore("job-two")
        first = store.take_in_bytes(PAYLOAD, "a.bin")
        again = store.take_in_chunks([PAYLOAD[:5], PAYLOAD[5:]], "b.bin")
        assert again == first and store.get(first.id) == first
        assert set(first.record()) == {"id", "sha256", "size", "name"}
        assert sorted(p.name for p in first.path.parent.iterdir()) == ["a.bin"]

    def test_a_stated_digest_that_does_not_match_is_refused_and_nothing_kept(
        self, base: Path
    ) -> None:
        store = ArtefactStore("job-three")
        with pytest.raises(ValueError, match="not to the"):
            store.take_in_chunks([PAYLOAD], "x", sha256="0" * 64)
        assert [p.name for p in store.directory.iterdir()] == []

    @pytest.mark.parametrize(
        ("raw", "kept"),
        [
            ("../../etc/passwd", "passwd"),
            ("C:\\Users\\a\\payload.exe", "payload.exe"),
            ("..", "artefact"),
            (".hidden", "hidden"),
            ("we ird$name.js", "we_ird_name.js"),
            ("", "artefact"),
            ("a" * 300 + ".js", "a" * 125 + ".js"),
        ],
    )
    def test_a_file_s_own_name_never_decides_where_it_lands(self, raw: str, kept: str) -> None:
        assert safe_name(raw) == kept

    def test_the_named_files_are_read_at_the_declared_path(self) -> None:
        answer = {"files": [{"path": "a"}, {"path": ["b", "a"]}, {"path": 3}, {"path": " "}]}
        assert written_names(answer, "/files/*/path") == ["a", "b"]
        assert written_names(answer, "") == []


class TestTakingInWhatAServerWrote:
    def test_a_server_on_this_host_is_read_inside_its_own_job_directory_only(
        self, base: Path, tmp_path: Path
    ) -> None:
        store = ArtefactStore("job-local")
        root = base / staging.job_directory_name("job-local")
        (root / "carved").mkdir(parents=True)
        (root / "carved" / "x.bin").write_bytes(PAYLOAD)
        outside = tmp_path / "secret.txt"
        outside.write_bytes(b"not the job's")
        (root / "carved" / "link").symlink_to(outside)
        names = ["carved/x.bin", str(root / "carved" / "x.bin"), str(outside), "carved/link"]
        taken, missed = store.take_in_written("unpacker", _local(), names)
        assert [a.id for a in taken] == [f"art_{DIGEST}"] * 2
        assert [m["name"] for m in missed] == ["secret.txt", "link"]
        assert all("staging directory" in m["reason"] for m in missed)
        assert str(tmp_path) not in json.dumps(missed)

    def test_a_file_is_opened_beneath_its_root_with_no_link_followed_anywhere(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "root"
        (root / "a").mkdir(parents=True)
        (root / "a" / "f").write_bytes(PAYLOAD)
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "f").write_bytes(b"not the job's")
        # A link at any component, the last or one between, is never followed:
        # a directory swapped for a link after any check would be refused too.
        (root / "dirlink").symlink_to(outside, target_is_directory=True)
        (root / "a" / "filelink").symlink_to(outside / "f")
        os.mkfifo(root / "a" / "fifo")
        # A hard link names the outside file itself: no link of any kind is read.
        os.link(outside / "f", root / "a" / "hard")
        for good in ("a/f", str(root / "a" / "f"), "./a/f"):
            fd = open_beneath(root, good, "the root")
            try:
                assert os.read(fd, 100) == PAYLOAD
            finally:
                os.close(fd)
        for bad, said in (
            ("dirlink/f", "not inside the root"),
            ("a/filelink", "cannot be opened as a file"),
            ("../outside/f", "not inside the root"),
            ("a/../../outside/f", "not inside the root"),
            (str(outside / "f"), "not inside the root"),
            ("a", "not a regular file"),
            ("a/fifo", "not a regular file"),
            ("a/missing", "cannot be opened as a file"),
            ("a/hard", "2 hard links"),
        ):
            with pytest.raises(ValueError, match=said):
                open_beneath(root, bad, "the root")

    def test_a_server_offering_get_artefact_is_read_over_it_in_chunks(
        self, base: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(store_module, "FETCH_CHUNK_BYTES", 7)
        handle = _Handle({FETCH_TOOL: _serving(PAYLOAD)})
        store = ArtefactStore("job-remote")
        taken, missed = store.take_in_written(
            "remote",
            _remote(),
            ["/out/x.bin"],
            handle=handle,
            run_blocking=asyncio.run,
        )
        assert missed == [] and taken[0].path.read_bytes() == PAYLOAD
        offsets = [call["offset"] for name, call in handle.calls if name == FETCH_TOOL]
        assert offsets == list(range(0, len(PAYLOAD), 7))

    def test_a_server_whose_digest_disagrees_or_that_refuses_is_said(self, base: Path) -> None:
        wrong = _Handle({FETCH_TOOL: _serving(PAYLOAD, sha256="1" * 64)})
        refusing = _Handle({FETCH_TOOL: lambda **_: {"error": "no such file"}})
        store = ArtefactStore("job-remote-2")
        _taken, missed = store.take_in_written(
            "remote", _remote(), ["x"], handle=wrong, run_blocking=asyncio.run
        )
        assert "not to the" in missed[0]["reason"]
        _taken, missed = store.take_in_written(
            "remote", _remote(), ["x"], handle=refusing, run_blocking=asyncio.run
        )
        assert "no such file" in missed[0]["reason"]

    @pytest.mark.parametrize(
        ("answers", "said"),
        [
            # The size changes between answers: the read is held to the first.
            ([(0, 7, 10), (7, 7, 99)], "changed the file's size from 10 to 99"),
            # A chunk that would pass the stated size.
            ([(0, 7, 10), (7, 7, 10)], "past the file's stated size of 10"),
            # An empty chunk before the end: the loop never spins.
            ([(0, 7, 10), (7, 0, 10)], "no bytes at offset 7 of 10"),
            # No size stated at all: a read with no end is refused.
            ([(0, 7, None)], "stated no size"),
        ],
    )
    def test_a_read_is_held_to_the_size_the_server_first_stated(
        self, base: Path, answers: list[tuple[int, int, int | None]], said: str
    ) -> None:
        script = iter(answers)
        asked: list[int] = []

        def answer(path: str, offset: int, length: int) -> dict[str, Any]:
            at, count, size = next(script)
            asked.append(offset)
            held: dict[str, Any] = {"content_b64": base64.b64encode(b"x" * count).decode()}
            if size is not None:
                held["size"] = size
            return held

        taken, missed = ArtefactStore("job-bounded").take_in_written(
            "remote",
            _remote(),
            ["x"],
            handle=_Handle({FETCH_TOOL: answer}),
            run_blocking=asyncio.run,
        )
        assert taken == [] and said in missed[0]["reason"]
        assert len(asked) == len(answers)

    def test_a_digest_that_changes_between_answers_is_refused(self, base: Path) -> None:
        digests = iter(["a" * 64, "b" * 64])

        def answer(path: str, offset: int, length: int) -> dict[str, Any]:
            return {
                "content_b64": base64.b64encode(b"xy").decode(),
                "size": 4,
                "sha256": next(digests),
            }

        _taken, missed = ArtefactStore("job-digest").take_in_written(
            "remote",
            _remote(),
            ["x"],
            handle=_Handle({FETCH_TOOL: answer}),
            run_blocking=asyncio.run,
        )
        assert "changed the file's stated sha256" in missed[0]["reason"]

    def test_a_server_across_a_network_offering_no_get_artefact_is_said(self, base: Path) -> None:
        taken, missed = ArtefactStore("j").take_in_written(
            "remote", _remote(), ["x"], handle=_Handle({}), run_blocking=asyncio.run
        )
        assert taken == [] and "offers no get_artefact" in missed[0]["reason"]

    def test_with_no_store_every_written_file_is_named_as_not_taken(self) -> None:
        wrote, missed = take_in_outputs(None, None, "s", _local(), "/w", json.dumps({"w": ["a"]}))
        assert wrote == () and missed == (
            {"name": "a", "reason": "this run keeps no artefact store"},
        )


def _remote(**over: Any) -> MCPServerConfig:
    return MCPServerConfig.model_validate(
        {"transport": "http", "url": "https://tools.invalid/mcp", "enabled": True, **over}
    )


def _serving(blob: bytes, sha256: str = "") -> Any:
    def answer(path: str, offset: int, length: int) -> dict[str, Any]:
        chunk = blob[offset : offset + length]
        return {
            "content_b64": base64.b64encode(chunk).decode(),
            "size": len(blob),
            "sha256": sha256 or hashlib.sha256(blob).hexdigest(),
        }

    return answer


class _Handle:
    """An open server handle whose tools answer from a table, recording each call."""

    is_open = True

    def __init__(self, tools: dict[str, Any]) -> None:
        self._tools = tools
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.config = type("C", (), {"transport": "http", "url": "https://tools.invalid/mcp"})()

    def all_tool_names(self) -> list[str]:
        return list(self._tools)

    def tools(self) -> list[Any]:
        outer = self

        class _Tool:
            def __init__(self, name: str) -> None:
                self.name = name

            async def ainvoke(self, args: dict[str, Any]) -> Any:
                outer.calls.append((self.name, dict(args)))
                return outer._tools[self.name](**args)

        return [_Tool(name) for name in self._tools]


class TestHandingAFileOver:
    def test_a_server_on_this_host_with_this_base_opens_the_store_s_own_file(
        self, base: Path
    ) -> None:
        store = ArtefactStore("job-h1")
        artefact = store.take_in_bytes(PAYLOAD, "x.bin")
        assert store.path_for(artefact, "local", _local()) == (str(artefact.path), "")

    def test_a_server_on_this_host_with_a_base_of_its_own_gets_a_copy_under_it(
        self, base: Path, tmp_path: Path
    ) -> None:
        store = ArtefactStore("job-h2")
        artefact = store.take_in_bytes(PAYLOAD, "x.bin")
        own = tmp_path / "own-base"
        config = _local(env={staging.STAGING_DIR_ENV: str(own)})
        path, why = store.path_for(artefact, "local", config)
        expected = own / staging.job_directory_name("job-h2") / "artefacts" / DIGEST / "x.bin"
        assert why == "" and path == str(expected) and expected.read_bytes() == PAYLOAD
        assert own / staging.job_directory_name("job-h2") in staging.job_directories("job-h2")

    def test_a_server_with_a_mount_is_handed_the_worker_s_copy_under_it(self, base: Path) -> None:
        store = ArtefactStore("job-h3")
        artefact = store.take_in_bytes(PAYLOAD, "x.bin")
        placed: list[tuple[str, Path, str, str]] = []

        def place(server: str, source: Path, sha256: str, name: str) -> str:
            placed.append((server, source, sha256, name))
            return f"/samples/.work/{sha256}.bin"

        config = _local(sample_mount="/samples")
        assert store.path_for(artefact, "m", config, place=place) == (
            f"/samples/.work/{DIGEST}.bin",
            "",
        )
        assert placed == [("m", artefact.path, DIGEST, "x.bin")]
        # Handed once: a second step on the same server is given the same path.
        store.path_for(artefact, "m", config, place=place)
        assert len(placed) == 1
        path, why = ArtefactStore("job-h3b").path_for(
            ArtefactStore("job-h3b").take_in_bytes(PAYLOAD, "x"), "m", config
        )
        assert path == "" and "places no file under m's sample_mount" in why

    def test_a_server_across_a_network_is_uploaded_to_over_put_sample(self, base: Path) -> None:
        store = ArtefactStore("job-h4")
        artefact = store.take_in_bytes(PAYLOAD, "x.bin")
        handle = _Handle({"put_sample": lambda **_: {"path": "/remote/staged/x.bin"}})
        stagings: list[dict[str, Any]] = []
        path, why = store.path_for(
            artefact,
            "remote",
            _remote(),
            handle=handle,
            run_blocking=asyncio.run,
            stagings=stagings,
        )
        assert (path, why) == ("/remote/staged/x.bin", "")
        ((name, sent),) = handle.calls
        assert name == "put_sample" and sent["sha256"] == DIGEST
        assert base64.b64decode(sent["content_b64"]) == PAYLOAD
        assert [record["state"] for record in stagings] == ["done"]
        # The record says what was sent, and the disclosure line says it too.
        assert [record["what"] for record in stagings] == ["artefact"]
        from maljan.analysis.disclosure import _staging_uploads, _upload_line

        (row,) = _staging_uploads(stagings)
        assert _upload_line(row, lambda text: text).startswith(
            "Sample upload: a file a tool wrote out of the sample was staged once to"
        )

    def test_a_large_file_is_streamed_from_disk_in_chunks_with_its_digest_checked(
        self, base: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import sample_staging

        monkeypatch.setattr(sample_staging, "CHUNK_BYTES", 8)
        blob = bytes(range(30))
        store = ArtefactStore("job-stream")
        artefact = store.take_in_bytes(blob, "big.bin")
        received: list[bytes] = []

        def chunk(upload_id: str, seq: int, content_b64: str) -> dict[str, Any]:
            assert seq == len(received)
            received.append(base64.b64decode(content_b64))
            return {"seq": seq}

        handle = _Handle(
            {
                "put_sample": lambda **_: pytest.fail("a single-shot call for a chunked server"),
                "put_sample_begin": lambda **_: {"upload_id": "u1"},
                "put_sample_chunk": chunk,
                "put_sample_finish": lambda **_: {"path": "/remote/big.bin"},
            }
        )
        # The whole file is never read into memory at once.
        monkeypatch.setattr(Path, "read_bytes", lambda self: pytest.fail("read whole"))
        path, why = store.path_for(
            artefact, "remote", _remote(), handle=handle, run_blocking=asyncio.run
        )
        assert (path, why) == ("/remote/big.bin", "")
        assert [len(c) for c in received] == [8, 8, 8, 6] and b"".join(received) == blob
        begin = next(call for name, call in handle.calls if name == "put_sample_begin")
        assert begin["sha256"] == artefact.sha256 and begin["size"] == len(blob)

    def test_a_file_changed_on_disk_is_not_finished_and_a_large_one_needs_chunks(
        self, base: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import sample_staging

        store = ArtefactStore("job-stream-2")
        artefact = store.take_in_bytes(b"original", "f.bin")
        artefact.path.write_bytes(b"tampered")
        chunked = _Handle(
            {
                "put_sample": lambda **_: {"path": "/x"},
                "put_sample_begin": lambda **_: {"upload_id": "u"},
                "put_sample_chunk": lambda **_: {"seq": 0},
                "put_sample_finish": lambda **_: pytest.fail("finished a changed file"),
            }
        )
        path, why = store.path_for(
            artefact, "remote", _remote(), handle=chunked, run_blocking=asyncio.run
        )
        assert path == "" and "no longer hash" in why
        # A server with only the single-shot call is sent the file in it, at any
        # size, as the sample is: no limit of the platform's own.
        monkeypatch.setattr(sample_staging, "CHUNK_THRESHOLD_BYTES", 4)
        single = _Handle({"put_sample": lambda **_: {"path": "/remote/g"}})
        path, why = ArtefactStore("job-stream-3").path_for(
            ArtefactStore("job-stream-3").take_in_bytes(b"0123456789", "g"),
            "remote",
            _remote(),
            handle=single,
            run_blocking=asyncio.run,
        )
        assert (path, why) == ("/remote/g", "")
        ((_name, sent),) = single.calls
        assert base64.b64decode(sent["content_b64"]) == b"0123456789"

    def test_each_call_waits_no_longer_than_the_step_s_declared_budget(
        self, base: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import base_agent
        from maljan.pipeline.artefacts import hand_over

        waited: list[float | None] = []

        def blocking(coroutine: Any, wait: float | None, label: str = "") -> Any:
            waited.append(wait)
            return asyncio.run(coroutine)

        monkeypatch.setattr(base_agent, "run_coro_blocking", blocking)
        store = ArtefactStore("job-budget")
        artefact = store.take_in_bytes(PAYLOAD, "x.bin")
        handle = _Handle(
            {
                "put_sample": lambda **_: {"path": "/remote/x.bin"},
                FETCH_TOOL: _serving(b"written"),
            }
        )

        class _Registry:
            def get(self, key: str) -> Any:
                return handle

        container = type(
            "C",
            (),
            {"get_server_registry": lambda self: _Registry(), "artefact_paths": []},
        )()
        values = {"artefact_path": artefact.id}
        assert hand_over(store, container, "remote", _remote(), values, 42.0) == ""
        assert values["artefact_path"] == "/remote/x.bin" and waited == [42.0]
        wrote, missed = take_in_outputs(
            store, container, "remote", _remote(), "/w", json.dumps({"w": ["o"]}), 7.5
        )
        assert missed == () and len(wrote) == 1 and waited[1:] == [7.5]

    def test_a_server_none_of_these_reaches_is_handed_no_host_path(self, base: Path) -> None:
        store = ArtefactStore("job-h5")
        artefact = store.take_in_bytes(PAYLOAD, "x.bin")
        path, why = store.path_for(
            artefact, "remote", _remote(), handle=_Handle({}), run_blocking=asyncio.run
        )
        assert path == "" and "offers no put_sample and declares no sample_mount" in why


# -- the pack ------------------------------------------------------------------


def _sample(tmp_path: Path) -> str:
    target = tmp_path / "s.bin"
    target.write_bytes(b"not a format the pack reads\n")
    return str(target)


UNPACK = {"id": "unpack", "server": "carver", "tool": "extract", "outputs": "/written/*"}
SCAN = {
    "id": "scan",
    "server": "scanner",
    "tool": "scan",
    "reads": "unpack",
    "arguments": {"file": "{artefact_path}", "digest": "{artefact_sha256}"},
}


class _Calls:
    """The node's call, standing in: each step answered from a table, its values kept."""

    def __init__(self, answers: dict[str, ServerAnswer | dict[str, Any]]) -> None:
        self.answers = answers
        self.asked: list[tuple[str, dict[str, str]]] = []

    def __call__(self, step: Any, values: Any, left: float | None) -> ServerAnswer:
        self.asked.append((step.id, dict(values)))
        held = self.answers[step.id]
        if isinstance(held, ServerAnswer):
            return held
        return ServerAnswer(
            tool=step.called,
            args={},
            server=step.server,
            output=json.dumps(held),
            started_at=time.time(),
        )


def _pack(path: str, steps: list[dict[str, Any]], calls: Any, **over: Any) -> Any:
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    inputs = PackInputs(
        sample_path=path,
        sha256="a" * 64,
        file_type="unknown",
        strings_head=10,
        capa=CapaSettings(rules_dir="r", signatures_dir="s", timeout_s=7),
        steps=effective_steps(steps),
        **over,
    )
    return run_pack(recorder, inputs, server_step=calls)


def _entries(result: Any, tool: str) -> list[Any]:
    return [entry for entry in result.entries if entry.tool == tool]


class TestThePackPassesFiles:
    def _wrote(self, store: ArtefactStore, *blobs: bytes) -> ServerAnswer:
        records = tuple(store.take_in_bytes(b, f"f{i}.bin").record() for i, b in enumerate(blobs))
        return ServerAnswer(
            tool="extract",
            args={},
            server="carver",
            output=json.dumps({"written": ["f0.bin"]}),
            started_at=time.time(),
            wrote=records,
            not_taken=({"name": "gone.bin", "reason": "no such file"},),
        )

    def test_a_reader_runs_once_per_file_and_the_ledger_says_which(
        self, base: Path, tmp_path: Path
    ) -> None:
        store = ArtefactStore("job-p1")
        calls = _Calls({"unpack": self._wrote(store, b"one", b"two"), "scan": {"hits": 0}})
        result = _pack(_sample(tmp_path), [UNPACK, SCAN], calls, artefacts=store)
        first, second = (
            store.get(f"art_{hashlib.sha256(b).hexdigest()}") for b in (b"one", b"two")
        )
        assert [values.get("artefact_path") for step, values in calls.asked if step == "scan"] == [
            first.id,
            second.id,
        ]
        assert [values["artefact_sha256"] for step, values in calls.asked if step == "scan"] == [
            first.sha256,
            second.sha256,
        ]
        (unpack,) = _entries(result, "extract")
        assert unpack.pack_step["wrote"] == [first.record(), second.record()]
        assert unpack.pack_step["not_taken"] == [{"name": "gone.bin", "reason": "no such file"}]
        reads = [entry.pack_step["read"] for entry in _entries(result, "scan")]
        assert reads == [{"artefact_path": first.id}, {"artefact_path": second.id}]
        assert not {"extract", "scan"} & set(result.failed)

    def test_a_file_written_twice_is_read_once(self, base: Path, tmp_path: Path) -> None:
        store = ArtefactStore("job-p-dup")
        record = store.take_in_bytes(b"same", "f.bin").record()
        twice = ServerAnswer(
            tool="extract",
            args={},
            server="carver",
            output="{}",
            started_at=time.time(),
            wrote=(record, dict(record)),
        )
        calls = _Calls({"unpack": twice, "scan": {"hits": 0}})
        _pack(_sample(tmp_path), [UNPACK, SCAN], calls, artefacts=store)
        assert [step for step, _values in calls.asked] == ["unpack", "scan"]

    def test_a_reader_of_a_step_left_out_for_the_format_says_so(
        self, base: Path, tmp_path: Path
    ) -> None:
        calls = _Calls({"unpack": {"written": []}, "scan": {}})
        result = _pack(
            _sample(tmp_path),
            [{**UNPACK, "formats": ["pe"]}, SCAN],
            calls,
            artefacts=ArtefactStore("j"),
        )
        assert _entries(result, "scan")[0].error == (
            "not run: it reads the files unpack writes, and unpack does not run for a sample "
            "routed as unknown"
        )

    def test_a_reader_of_a_step_that_wrote_nothing_is_not_run_and_says_why(
        self, base: Path, tmp_path: Path
    ) -> None:
        calls = _Calls({"unpack": {"written": []}, "scan": {"hits": 0}})
        result = _pack(_sample(tmp_path), [UNPACK, SCAN], calls, artefacts=ArtefactStore("j"))
        (scan,) = _entries(result, "scan")
        assert not scan.ok and scan.error == (
            "not run: it reads the files unpack writes, and unpack wrote none the artefact store "
            "took in"
        )
        assert "scan" not in result.failed and [s for s, _ in calls.asked] == ["unpack"]
        dropped = _pack(
            _sample(tmp_path),
            [{**UNPACK, "enabled": False}, SCAN],
            calls,
            artefacts=ArtefactStore("j"),
        )
        assert _entries(dropped, "scan")[0].error.endswith("and unpack did not run")

    def test_a_run_with_no_store_runs_no_step_that_names_a_file(self, tmp_path: Path) -> None:
        calls = _Calls({"unpack": {"written": []}, "scan": {}})
        result = _pack(_sample(tmp_path), [UNPACK, SCAN], calls)
        assert _entries(result, "scan")[0].error == (
            "not run: it names a file of the job's artefact store, and this run keeps none"
        )


REPORT_STEP = {
    "id": "report_reader",
    "server": "reader",
    "tool": "read_report",
    "arguments": {"report": "{sandbox_report_path}"},
}
CAPTURE_STEP = {
    "id": "capture_reader",
    "server": "reader",
    "tool": "read_capture",
    "arguments": {"pcap": "{capture_path}", "of": "{sha256}"},
}


class TestTheCaptureAndTheReport:
    def test_a_capture_the_report_names_outside_the_job_s_captures_is_never_read(
        self, base: Path, tmp_path: Path
    ) -> None:
        """The report's words are no path: a capture named anywhere else is refused, unread."""
        secret = tmp_path / "secret.env"
        secret.write_bytes(b"TOKEN=not for any server")
        captures = staging.job_capture_dir("job-c2")
        captures.mkdir(parents=True)
        (captures / "planted.pcap").symlink_to(secret)
        store = ArtefactStore("job-c2")
        for named in (str(secret), str(captures / "planted.pcap"), "../../secret.env"):
            calls = _Calls({"capture_reader": {}})
            result = _pack(
                _sample(tmp_path),
                [CAPTURE_STEP],
                calls,
                artefacts=store,
                sandbox_report={"network": {"pcap_local_path": named}},
            )
            (entry,) = _entries(result, "read_capture")
            assert entry.error.startswith(
                "not run: the job's sandbox capture could not be taken into the artefact store: "
            )
            assert calls.asked == [] and "read_capture" not in result.failed
            assert str(tmp_path) not in entry.error
        held = (
            [p for p in store.directory.rglob("*") if p.is_file()]
            if store.directory.exists()
            else []
        )
        assert all(p.read_bytes() != secret.read_bytes() for p in held)

    def test_a_step_naming_one_the_job_does_not_have_is_skipped_never_failed(
        self, base: Path, tmp_path: Path
    ) -> None:
        calls = _Calls({"report_reader": {}, "capture_reader": {}})
        result = _pack(
            _sample(tmp_path), [REPORT_STEP, CAPTURE_STEP], calls, artefacts=ArtefactStore("j")
        )
        (report,) = _entries(result, "read_report")
        (capture,) = _entries(result, "read_capture")
        assert report.error == (
            "not run: it names the sandbox report (sandbox_report_path), and this job has none"
        )
        assert capture.error == (
            "not run: it names the sandbox capture (capture_path), and this job has none"
        )
        # No call was made, and the arguments shown hold no path.
        assert calls.asked == [] and not {"read_report", "read_capture"} & set(result.failed)
        assert capture.args == {"pcap": "{capture_path}", "of": "a" * 64}

    def test_the_job_s_report_and_capture_are_files_of_the_store(
        self, base: Path, tmp_path: Path
    ) -> None:
        # Where the worker fetches this job's captures.
        captures = staging.job_capture_dir("job-c1")
        captures.mkdir(parents=True)
        pcap = captures / "dump.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1capture")
        report = {"network": {"pcap_local_path": str(pcap), "dns": []}, "processes": []}
        stored = json.loads(json.dumps(report))
        store = ArtefactStore("job-c1")
        calls = _Calls({"report_reader": {}, "capture_reader": {}})
        result = _pack(
            _sample(tmp_path),
            [REPORT_STEP, CAPTURE_STEP],
            calls,
            artefacts=store,
            sandbox_report=report,
        )
        values = dict(calls.asked)
        held_report = store.get(values["report_reader"]["sandbox_report_path"])
        held_capture = store.get(values["capture_reader"]["capture_path"])
        # The worker's own capture path is not handed over; the stored report is untouched.
        assert json.loads(held_report.path.read_text()) == {
            "network": {"dns": []},
            "processes": [],
        }
        assert report == stored
        assert held_report.name == "sandbox_report.json"
        assert (held_report.kind, store.get(values["capture_reader"]["capture_path"]).kind) == (
            "sandbox_report",
            "capture",
        )
        assert held_capture.path.read_bytes() == pcap.read_bytes()
        assert held_capture.name == "dump.pcap"
        (entry,) = _entries(result, "read_capture")
        assert entry.pack_step["read"] == {"capture_path": held_capture.id}


IDENTIFY = {"id": "identify", "server": "ident", "tool": "detect"}
DECOMPILE = {
    "id": "decompile",
    "server": "decomp",
    "tool": "decompile",
    "when": [{"step": "identify", "value": "runtime", "equals": [".NET", "true"]}],
}
IDENT_SERVER = {
    "command": "invented-ident",
    "enabled": True,
    "tool_facts": {
        "detect": {"kind": "identification", "rows": "/detects/*", "values": {"runtime": "/rt"}}
    },
}


@pytest.fixture
def ident_settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    held = Settings(_env_file=None)
    held.mcp.servers["ident"] = MCPServerConfig.model_validate(IDENT_SERVER)
    monkeypatch.setattr(config_module, "_settings_instance", held)
    return held


@pytest.mark.usefixtures("ident_settings")
class TestARunTimeConditionOnADeclaredValue:
    @pytest.mark.parametrize(
        ("detected", "runs"),
        [
            ({"detects": [{"rt": "native"}, {"rt": ".NET"}]}, True),
            ({"detects": [{"rt": True}]}, True),
            ({"detects": [{"rt": ".net"}]}, False),
            ({"detects": [{"rt": "native"}]}, False),
            ({"detects": []}, False),
        ],
    )
    def test_the_step_runs_only_when_a_row_holds_the_value(
        self, tmp_path: Path, detected: dict[str, Any], runs: bool
    ) -> None:
        calls = _Calls({"identify": detected, "decompile": {"ok": 1}})
        result = _pack(_sample(tmp_path), [IDENTIFY, DECOMPILE], calls)
        (decompile,) = _entries(result, "decompile")
        assert decompile.ok is runs
        assert ("decompile" in dict(calls.asked)) is runs
        if not runs:
            assert decompile.error == (
                "not run: it runs when identify's runtime is '.NET' or 'true', and identify's "
                "answer holds no such value"
            )
            assert "decompile" not in result.failed

    def test_a_tool_that_declares_no_such_value_or_did_not_answer_is_said(
        self, tmp_path: Path
    ) -> None:
        undeclared = {
            **DECOMPILE,
            "when": [{"step": "identify", "value": "other", "equals": ["x"]}],
        }
        calls = _Calls({"identify": {"detects": [{"rt": ".NET"}]}, "decompile": {}})
        result = _pack(_sample(tmp_path), [IDENTIFY, undeclared], calls)
        assert _entries(result, "decompile")[0].error.endswith(
            "and identify's tool declares no value 'other'"
        )
        failed = ServerAnswer(
            tool="detect", args={}, server="ident", output="boom", ok=False, error="boom"
        )
        result = _pack(_sample(tmp_path), [IDENTIFY, DECOMPILE], _Calls({"identify": failed}))
        assert _entries(result, "decompile")[0].error.endswith("identify gave no answer to read")

    def test_a_condition_on_one_of_the_platform_s_own_steps_holds_it_back_too(
        self, tmp_path: Path
    ) -> None:
        steps = [
            IDENTIFY,
            {"id": "strings", "after": "identify", "when": DECOMPILE["when"]},
        ]
        result = _pack(_sample(tmp_path), steps, _Calls({"identify": {"detects": []}}))
        (strings,) = _entries(result, "strings")
        assert strings.error.startswith("not run: it runs when identify's runtime is")

    def test_a_step_started_beside_the_pack_waits_for_what_it_runs_on(self, tmp_path: Path) -> None:
        early = {**DECOMPILE, "starts_after": "hashes"}
        calls = _Calls({"identify": {"detects": [{"rt": ".NET"}]}, "decompile": {"ok": 1}})
        result = _pack(_sample(tmp_path), [IDENTIFY, early], calls)
        assert _entries(result, "decompile")[0].ok
        assert result.schedules["decompile"] == (
            "in turn: it runs on what identify answers, which has not run yet"
        )


# -- the node's call, end to end -------------------------------------------------


CARVER = {"command": "invented-carver", "enabled": True}
SCANNER = {"command": "invented-scanner", "enabled": True}


class _Tool:
    def __init__(self, name: str, act: Any) -> None:
        self.name = name
        self.metadata: dict[str, Any] = {}
        self._act = act
        self.asked: list[dict[str, Any]] = []

    async def ainvoke(self, args: dict[str, Any]) -> str:
        self.asked.append(dict(args))
        return json.dumps(self._act(args))


class TestTheNodeHandsAFileFromOneServerToAnother:
    def test_a_carved_file_reaches_the_scanner_at_a_path_it_opens(
        self, base: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(_env_file=None)
        settings.mcp.servers["carver"] = MCPServerConfig.model_validate(CARVER)
        settings.mcp.servers["scanner"] = MCPServerConfig.model_validate(SCANNER)
        monkeypatch.setattr(config_module, "_settings_instance", settings)
        container = ServiceContainer(settings, mock=True)
        job_root = base / staging.job_directory_name(container.job_key())

        def carve(_args: dict[str, Any]) -> dict[str, Any]:
            (job_root / "carved").mkdir(parents=True, exist_ok=True)
            (job_root / "carved" / "inner.js").write_bytes(PAYLOAD)
            return {"written": ["carved/inner.js", "/etc/hostname"]}

        def scan(args: dict[str, Any]) -> dict[str, Any]:
            return {"bytes": Path(args["file"]).read_bytes().hex()}

        tools = {"carver": _Tool("extract", carve), "scanner": _Tool("scan", scan)}

        class _Registry:
            def tools_for_ref(self, ref: Any, job_id: str, **_: Any) -> Any:
                return [tools[ref.server]], []

        monkeypatch.setattr(container, "get_server_registry", lambda: _Registry())
        settings.triage.steps = TriageConfig(steps=[UNPACK, SCAN]).steps
        store = ArtefactStore(container.job_key())
        result = _pack(
            _sample(tmp_path),
            [UNPACK, SCAN],
            _server_step_call(container, store),
            artefacts=store,
        )
        (carved,) = _entries(result, "extract")
        (record,) = carved.pack_step["wrote"]
        assert record == {
            "id": f"art_{DIGEST}",
            "sha256": DIGEST,
            "size": len(PAYLOAD),
            "name": "inner.js",
        }
        assert carved.pack_step["not_taken"][0]["name"] == "hostname"
        (scanned,) = _entries(result, "scan")
        assert scanned.ok and json.loads(scanned.output) == {"bytes": PAYLOAD.hex()}
        (asked,) = tools["scanner"].asked
        assert asked["file"] == str(job_root / "artefacts" / DIGEST / "inner.js")
        assert asked["digest"] == DIGEST
        assert scanned.pack_step["read"] == {"artefact_path": f"art_{DIGEST}"}
        # The run's isolation part counts the call handed the file as a read of
        # what came out of the sample, though its server declares nothing.
        from maljan.analysis.disclosure import job_sample_paths
        from maljan.analysis.isolation import sample_readers

        assert container.artefact_paths == [asked["file"]]
        assert asked["file"] in job_sample_paths(container)
        readers, _unsourced = sample_readers(
            {}, [scanned], lambda _source: None, job_sample_paths(container)
        )
        assert readers == {"mcp:scanner": 1}

    def test_the_node_keeps_a_store_for_the_job(
        self, base: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.pipeline.nodes import make_triage_node
        from tests.unit.pipeline.test_stage_events import _state

        settings = Settings(_env_file=None)
        settings.mcp.servers["carver"] = MCPServerConfig.model_validate(CARVER)
        settings.mcp.servers["scanner"] = MCPServerConfig.model_validate(SCANNER)
        monkeypatch.setattr(config_module, "_settings_instance", settings)
        settings.triage.steps = TriageConfig(steps=[REPORT_STEP | {"server": "scanner"}]).steps
        container = ServiceContainer(settings, mock=True)
        node = make_triage_node(container, stage=container.active_profile().stage("triage_pack"))
        update = asyncio.run(node(_state(sample_path=_sample(tmp_path))))
        last = update["evidence_ledger"][-1]
        assert last["tool"] == "read_report"
        assert last["error"].endswith("this job has none")
