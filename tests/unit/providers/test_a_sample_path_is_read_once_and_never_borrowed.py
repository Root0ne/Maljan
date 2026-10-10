"""The path a server opens is read once: one spelling keys the note and is the argument sent.

The differential this closes: the note was keyed by a lexical tidy-up of the
path (``..`` segments folded, backslashes turned into separators, doubled
separators collapsed) while the server was sent the path as the model wrote it.
The server resolves its own symlinks, case and mounts, so a crafted spelling
could be answered from another file's note, or open another file and have that
file's program written into the job's own sample's note.

Now the opener reads a path once (``sample_open.open_key``): the key it notes
under is the string it sends. A spelling a server might read its own way is not
keyed and not refused either: it is forwarded as written and never noted, so
no note can be borrowed or poisoned through it. The job's own copy of the
sample (the held path) is platform data, compared exactly whatever characters
it holds; a relative name is read against it only where the job holds one.
Nothing read from a tool's answer decides which note answers. The server and
its tools are invented.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.core.config import SampleOpenConfig
from maljan.providers.sample_open import (
    SampleNotes,
    SampleOpener,
    open_key,
    path_refusal,
    wrap_open_tool,
)

HELD = "/data/samples/.work/s.exe"
OTHER = "/data/samples/.work/other.exe"
SERVER = "invented"
SPEC = SampleOpenConfig(
    open_tool="open_thing",
    path_argument="where",
    name_field="handle",
    select_tool="pick",
    select_argument="handle",
    analyse_tool="study",
    analyse_argument="handle",
)

# Every spelling a server might resolve to a file other than the job's own
# sample, or to the sample by a route a lexical reading does not see.
HOSTILE = {
    "a .. segment": "/data/samples/.work/../.work/s.exe",
    "a .. through a symlinked directory": "/data/samples/link/../.work/s.exe",
    "a . segment": "/data/samples/./.work/s.exe",
    "a symlink of another name": "/data/samples/.work/s-link.exe",
    "another case": "/data/samples/.work/S.exe",
    "a trailing slash": "/data/samples/.work/s.exe/",
    "url encoding": "/data/samples/.work/s%2eexe",
    "an encoded separator": "/data/samples%2f.work/s.exe",
    "a backslash": "\\data\\samples\\.work\\s.exe",
    "a mixed backslash": "/data/samples/.work\\s.exe",
    "a doubled separator": "/data/samples//.work/s.exe",
    "a leading doubled separator": "//data/samples/.work/s.exe",
    "the host's mount": "/home/user/Maljan/data/samples/.work/s.exe",
    "a file url": "file:///data/samples/.work/s.exe",
    "surrounding blanks": " /data/samples/.work/s.exe",
    "a control character": "/data/samples/.work/s.exe\x00.txt",
    "a DEL": "/data/samples/.work/s.exe\x7f",
    "a relative climb": "../.work/s.exe",
    "another sample": OTHER,
}

# The spellings the spelling rules leave keyable with no held copy: plain
# absolute paths of other files, each keyed as itself.
PLAIN_OTHER_FILES = {
    "a symlink of another name",
    "another case",
    "the host's mount",
    "another sample",
}


class _Where(BaseModel):
    where: str = ""


class _Handle(BaseModel):
    handle: str = ""


class _Server:
    """Opens whatever it is given; names what it opened (or a crafted name)."""

    def __init__(self, name_for: dict[str, str] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.name_for = name_for or {}

    def tools(self) -> list[Any]:
        async def open_thing(where: str = "") -> str:
            self.calls.append(("open_thing", {"where": where}))
            return json.dumps({"handle": self.name_for.get(where, f"prog:{where}")})

        async def pick(handle: str = "") -> str:
            self.calls.append(("pick", {"handle": handle}))
            return "{}"

        async def study(handle: str = "") -> str:
            self.calls.append(("study", {"handle": handle}))
            return "{}"

        return [
            StructuredTool.from_function(
                coroutine=fn, name=fn.__name__, description=fn.__name__, args_schema=schema
            )
            for fn, schema in ((open_thing, _Where), (pick, _Handle), (study, _Handle))
        ]

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


def _open_tool(server: _Server, notes: SampleNotes, held: str | None) -> Any:
    tools = server.tools()
    wrapped = wrap_open_tool(
        tools,
        tools,
        server=SERVER,
        spec=SPEC,
        notes=notes,
        held_path=(lambda: held) if held is not None else None,
    )
    return next(t for t in wrapped if t.name == "open_thing")


def _open(tool: Any, path: Any) -> str:
    return str(asyncio.run(tool.ainvoke({"where": path})))


class TestAHostileSpellingIsForwardedAndNeverNoted:
    @pytest.mark.parametrize("why", sorted(HOSTILE))
    def test_with_a_held_copy_it_is_sent_as_written_and_not_noted(self, why: str) -> None:
        server = _Server()
        notes = SampleNotes()
        _open(_open_tool(server, notes, HELD), HOSTILE[why])
        assert server.calls == [("open_thing", {"where": HOSTILE[why]})], why
        assert notes.get(SERVER, HOSTILE[why]) is None
        assert notes.get(SERVER, HELD) is None

    @pytest.mark.parametrize("why", sorted(set(HOSTILE) - PLAIN_OTHER_FILES))
    def test_with_no_held_copy_a_spelling_a_server_reads_its_own_way_is_not_noted(
        self, why: str
    ) -> None:
        server = _Server()
        notes = SampleNotes()
        tool = _open_tool(server, notes, None)
        _open(tool, HOSTILE[why])
        _open(tool, HOSTILE[why])
        # Opened each time as written: there is no note for it to be answered from.
        assert server.names() == ["open_thing", "open_thing"], why

    def test_a_relative_name_with_no_held_copy_is_forwarded_and_not_noted(self) -> None:
        server = _Server()
        notes = SampleNotes()
        _open(_open_tool(server, notes, None), "s.exe")
        assert server.calls == [("open_thing", {"where": "s.exe"})]
        assert notes.get(SERVER, "s.exe") is None

    def test_a_path_that_is_not_text_keys_nothing(self) -> None:
        assert path_refusal(None) is not None
        assert open_key(["/data/samples/.work/s.exe"]) is None


class TestTheHeldCopyIsPlatformData:
    """The job's own copy is compared exactly, whatever characters it holds."""

    @pytest.mark.parametrize(
        "held",
        [
            "/data/samples/.work/0123abcd.e%78e",
            "/data/samples/.work/0123abcd.%TEMP%",
            "/data/samples/.work/0123abcd.e\\xe",
            "/data/samples/.work/0123abcd.ex\x7fe",
        ],
    )
    def test_an_odd_held_path_opens_and_is_noted(self, held: str) -> None:
        server = _Server()
        notes = SampleNotes()
        tool = _open_tool(server, notes, held)
        _open(tool, held)
        _open(tool, held)
        assert server.calls[0] == ("open_thing", {"where": held})
        assert server.names() == ["open_thing", "pick", "study", "pick"]
        assert notes.get(SERVER, held) is not None

    def test_a_relative_name_of_the_held_copy_is_sent_as_the_held_copy(self) -> None:
        server = _Server()
        _open(_open_tool(server, SampleNotes(), HELD), "s.exe")
        assert server.calls[0] == ("open_thing", {"where": HELD})


class TestOneSpellingEverywhere:
    def test_the_job_s_sample_is_sent_as_it_is_keyed(self) -> None:
        server = _Server()
        notes = SampleNotes()
        _open(_open_tool(server, notes, HELD), HELD)
        assert server.calls[0] == ("open_thing", {"where": HELD})
        assert notes.get(SERVER, HELD) is not None

    def test_a_plain_path_with_no_held_copy_is_keyed_as_itself(self) -> None:
        server = _Server()
        notes = SampleNotes()
        tool = _open_tool(server, notes, None)
        _open(tool, OTHER)
        _open(tool, OTHER)
        assert server.names() == ["open_thing", "pick", "study", "pick"]


class TestNoCraftedPathReachesAnotherNote:
    def test_a_crafted_spelling_is_not_answered_from_the_sample_s_note(self) -> None:
        server = _Server()
        notes = SampleNotes()
        tool = _open_tool(server, notes, None)
        _open(tool, HELD)
        server.calls.clear()
        crafted = "/data/samples/link/../.work/s.exe"
        _open(tool, crafted)
        # Sent to the server as written; no select of the sample's program.
        assert server.calls == [("open_thing", {"where": crafted})]

    def test_a_crafted_path_cannot_write_its_program_into_the_sample_s_note(self) -> None:
        server = _Server(name_for={HELD: "the-sample"})
        notes = SampleNotes()
        tool = _open_tool(server, notes, None)
        _open(tool, "/data/samples/.work/x/../s.exe")
        assert notes.get(SERVER, HELD) is None
        _open(tool, HELD)
        assert notes.get(SERVER, HELD).name == "the-sample"

    def test_an_answer_naming_another_program_decides_no_note(self) -> None:
        server = _Server(name_for={HELD: OTHER})
        notes = SampleNotes()
        _open(_open_tool(server, notes, HELD), HELD)
        assert server.calls[1] == ("pick", {"handle": OTHER})
        assert notes.get(SERVER, OTHER) is None
        assert notes.get(SERVER, HELD).name == OTHER

    def test_another_job_s_program_is_never_selected(self) -> None:
        first_job, second_job = SampleNotes(), SampleNotes()
        first_job.note(SERVER, HELD, "first-job-program", "{}")
        server = _Server(name_for={HELD: "second-job-program"})
        _open(_open_tool(server, second_job, HELD), HELD)
        picked = [args["handle"] for name, args in server.calls if name == "pick"]
        assert picked == ["second-job-program"]

    def test_the_sync_opener_reads_the_path_by_the_same_rule(self) -> None:
        calls: list[tuple[str, dict[str, Any]]] = []

        def call(tool: str, arguments: dict[str, Any]) -> str:
            calls.append((tool, arguments))
            return "{}"

        notes = SampleNotes()
        opener = SampleOpener(SERVER, SPEC, notes)
        crafted = "/data/samples/.work/../.work/s.exe"
        opener.open(crafted, call, held=HELD)
        assert calls == [("open_thing", {"where": crafted})]
        assert notes.get(SERVER, HELD) is None


class TestANoteFollowsTheServersNames:
    def test_a_fresh_open_under_a_name_drops_the_older_note_of_that_name(self) -> None:
        """A server that names programs by file name replaces one with the other."""
        a, b = "/a/payload.bin", "/b/payload.bin"
        server = _Server(name_for={a: "payload.bin", b: "payload.bin"})
        notes = SampleNotes()
        tool = _open_tool(server, notes, None)
        _open(tool, a)
        _open(tool, b)
        assert notes.get(SERVER, a) is None
        server.calls.clear()
        _open(tool, a)
        assert server.names() == ["open_thing", "pick", "study"]

    def test_a_forwarded_open_drops_the_note_its_program_name_replaced(self) -> None:
        """A forwarded spelling of another file is opened under the same name and replaces it."""
        a, b = "/samples/a/payload.bin", "/samples/b//payload.bin"
        server = _Server(name_for={a: "payload.bin", b: "payload.bin"})
        notes = SampleNotes()
        tool = _open_tool(server, notes, None)
        _open(tool, a)
        assert notes.get(SERVER, a) is not None
        _open(tool, b)  # forwarded: a doubled separator keys nothing
        assert notes.get(SERVER, a) is None
        server.calls.clear()
        _open(tool, a)
        assert server.names() == ["open_thing", "pick", "study"]

    def test_a_forwarded_open_with_no_readable_name_drops_every_note_of_the_server(
        self,
    ) -> None:
        calls: list[str] = []

        def call(tool: str, arguments: dict[str, Any]) -> str:
            calls.append(tool)
            return "opened" if arguments.get("where") == "x.bin" else json.dumps({"handle": "h"})

        notes = SampleNotes()
        opener = SampleOpener(SERVER, SPEC, notes)
        opener.open(HELD, call)
        opener.open(OTHER, call, {"arch": "arm"})
        notes.note("someone else", HELD, "h", "{}")
        opener.open("x.bin", call)  # relative: forwarded; its answer names nothing
        assert notes.get(SERVER, HELD) is None
        assert notes.get(SERVER, OTHER, {"arch": "arm"}) is None
        assert notes.get("someone else", HELD) is not None

    def test_a_forwarded_open_the_server_refused_drops_nothing(self) -> None:
        def call(tool: str, arguments: dict[str, Any]) -> str:
            if arguments.get("where") == "x.bin":
                return json.dumps({"error": "no such file"})
            return json.dumps({"handle": "h"})

        notes = SampleNotes()
        opener = SampleOpener(SERVER, SPEC, notes)
        opener.open(HELD, call)
        opener.open("x.bin", call)
        assert notes.get(SERVER, HELD) is not None

    def test_an_open_with_other_options_is_another_note(self) -> None:
        calls: list[tuple[str, dict[str, Any]]] = []

        def call(tool: str, arguments: dict[str, Any]) -> str:
            calls.append((tool, arguments))
            # A server that names each loaded image by its options.
            return json.dumps({"handle": f"h-{arguments.get('arch', '')}"})

        opener = SampleOpener(SERVER, SPEC, SampleNotes())
        opener.open(OTHER, call, {"arch": "arm"})
        opener.open(OTHER, call, {"arch": "x86"})
        opener.open(OTHER, call, {"arch": "arm"})
        assert [t for t, _ in calls].count("open_thing") == 2
