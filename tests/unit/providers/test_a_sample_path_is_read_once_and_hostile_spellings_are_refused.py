"""The path a server opens is read once: one spelling keys the note and is the argument sent.

The differential this closes: the note was keyed by a lexical tidy-up of the
path (``..`` segments folded, backslashes turned into separators, doubled
separators collapsed) while the server was sent the path as the model wrote it.
The server resolves its own symlinks, case and mounts, so a crafted spelling
could be answered from another file's note, or open another file and have that
file's program written into the job's own sample's note, so every later open
of the real sample selected the crafted one's program.

Now the opener reads a path once (``sample_open.canonical_path``) and that one
spelling is the note's key, the check against the job's held sample and the
argument every declared tool is sent. Nothing is tidied: a spelling a server
might read another way is refused, a relative path is read against the held
sample (refused where there is none), and where the job holds a sample any
other path is refused. Nothing read from a tool's answer decides which note
answers. The server and its tools are invented.
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
    canonical_path,
    is_refusal,
    path_refusal,
    wrap_open_tool,
)

HELD = "/data/samples/.work/s.exe"
OTHER = "/data/samples/.work/other.exe"
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
    "a relative climb": "../.work/s.exe",
    "another sample": OTHER,
}


class _Where(BaseModel):
    where: str = ""


class _Handle(BaseModel):
    handle: str = ""


class _Server:
    """Opens whatever it is given; answers with the name its open gives (or a crafted one)."""

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


def _open_tool(server: _Server, notes: SampleNotes, held: str | None) -> Any:
    tools = server.tools()
    wrapped = wrap_open_tool(
        tools,
        tools,
        server="invented",
        spec=SPEC,
        notes=notes,
        held_path=(lambda: held) if held is not None else None,
    )
    return next(t for t in wrapped if t.name == "open_thing")


def _open(tool: Any, path: Any) -> str:
    return str(asyncio.run(tool.ainvoke({"where": path})))


class TestEveryHostileSpellingIsRefused:
    @pytest.mark.parametrize("why", sorted(HOSTILE))
    def test_with_a_held_sample_the_spelling_is_refused_and_nothing_is_called(
        self, why: str
    ) -> None:
        server = _Server()
        said = _open(_open_tool(server, SampleNotes(), HELD), HOSTILE[why])
        assert is_refusal(said), why
        assert server.calls == [], why

    @pytest.mark.parametrize(
        "why",
        sorted(
            set(HOSTILE)
            - {"another sample", "a symlink of another name", "another case", "the host's mount"}
        ),
    )
    def test_with_no_held_sample_a_spelling_a_server_reads_its_own_way_is_refused(
        self, why: str
    ) -> None:
        server = _Server()
        said = _open(_open_tool(server, SampleNotes(), None), HOSTILE[why])
        assert is_refusal(said), why
        assert server.calls == [], why

    def test_a_relative_path_with_no_held_sample_is_refused_and_not_noted(self) -> None:
        server = _Server()
        notes = SampleNotes()
        said = _open(_open_tool(server, notes, None), "s.exe")
        assert is_refusal(said) and "relative" in said
        assert server.calls == []
        assert notes.get("invented", "s.exe") is None

    def test_a_path_that_is_not_text_is_refused(self) -> None:
        assert path_refusal(None) is not None
        assert path_refusal(["/data/samples/.work/s.exe"]) is not None


class TestOneSpellingEverywhere:
    def test_the_job_s_sample_is_sent_as_it_is_keyed(self) -> None:
        server = _Server()
        notes = SampleNotes()
        _open(_open_tool(server, notes, HELD), HELD)
        assert server.calls[0] == ("open_thing", {"where": HELD})
        assert notes.get("invented", HELD) is not None

    def test_a_relative_spelling_of_the_held_sample_is_sent_in_the_one_spelling(self) -> None:
        server = _Server()
        notes = SampleNotes()
        _open(_open_tool(server, notes, HELD), "s.exe")
        assert server.calls[0] == ("open_thing", {"where": HELD})
        assert canonical_path("s.exe", HELD) == HELD

    def test_the_note_store_reads_a_path_by_the_same_rule(self) -> None:
        notes = SampleNotes()
        notes.note("invented", HELD, "prog", "{}")
        for spelling in HOSTILE.values():
            assert notes.get("invented", spelling) is None, spelling
        notes.note("invented", "/data/samples//.work/s.exe", "crafted", "{}")
        assert notes.get("invented", HELD).name == "prog"


class TestNoCraftedPathReachesAnotherNote:
    def test_a_crafted_spelling_is_not_answered_from_the_sample_s_note(self) -> None:
        server = _Server()
        notes = SampleNotes()
        tool = _open_tool(server, notes, None)
        _open(tool, HELD)
        server.calls.clear()
        crafted = _open(tool, "/data/samples/link/../.work/s.exe")
        assert is_refusal(crafted)
        assert server.calls == [], "no select of the sample's program for a crafted path"

    def test_a_crafted_path_cannot_write_its_program_into_the_sample_s_note(self) -> None:
        """The crafted path opens nothing, so the sample's note still names the sample's program."""
        server = _Server(name_for={HELD: "the-sample"})
        notes = SampleNotes()
        tool = _open_tool(server, notes, None)
        _open(tool, "/data/samples/.work/x/../s.exe")
        assert notes.get("invented", HELD) is None
        _open(tool, HELD)
        assert notes.get("invented", HELD).name == "the-sample"

    def test_an_answer_naming_another_program_decides_no_note(self) -> None:
        server = _Server(name_for={HELD: OTHER})
        notes = SampleNotes()
        _open(_open_tool(server, notes, HELD), HELD)
        # The answer's name is only what the select and analysis tools are sent.
        assert server.calls[1] == ("pick", {"handle": OTHER})
        assert notes.get("invented", OTHER) is None
        assert notes.get("invented", HELD).name == OTHER

    def test_another_job_s_program_is_never_selected(self) -> None:
        first_job, second_job = SampleNotes(), SampleNotes()
        first_job.note("invented", HELD, "first-job-program", "{}")
        server = _Server(name_for={HELD: "second-job-program"})
        _open(_open_tool(server, second_job, HELD), HELD)
        picked = [args["handle"] for name, args in server.calls if name == "pick"]
        assert picked == ["second-job-program"]

    def test_the_sync_opener_reads_the_path_by_the_same_rule(self) -> None:
        calls: list[str] = []

        def call(tool: str, arguments: dict[str, Any]) -> str:
            calls.append(tool)
            return "{}"

        opener = SampleOpener("invented", SPEC, SampleNotes())
        said = opener.open("/data/samples/.work/../.work/s.exe", call, held=HELD)
        assert is_refusal(said) and calls == []
