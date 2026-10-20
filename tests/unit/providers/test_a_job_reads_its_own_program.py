"""On a server other jobs share, every call is held to the job's own programs and sample.

A server that holds programs keeps one *current* program per server, not per
job. Two workers sharing one server each open their sample, and a call that
names no program then answers about whichever sample was opened last; a call
naming another job's program or path reads or replaces it. Every rule comes
from the server's ``sample_open``: each declared program argument a call
carries must name a program the job opened, one it leaves out is given the
job's program, each declared path argument may only name the job's own copy of
the sample, and a tool taking none of them is withheld with its reason unless
the declaration lists it as job-safe. A server no other job shares (stdio) is
left exactly as it was.

No server runs here: one in-process fake keeps a current program per server,
as Ghidra does, and two jobs speak to it interleaved.
"""

from __future__ import annotations

import asyncio
import json
import posixpath
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
from pydantic import SecretStr

from maljan.core.config import GHIDRA_SAMPLE_OPEN, MCPServerConfig, SampleOpenConfig
from maljan.providers.sample_open import (
    FOREIGN_PROGRAM,
    NO_JOB_PROGRAM,
    SampleNotes,
    pin_program_argument,
)
from maljan.providers.static.ghidra import GhidraStaticProvider
from maljan.providers.static.ghidra.http_client import GhidraHTTPClient

URL = "http://ghidra.invalid"
KEY = "remote http://ghidra.invalid:80"
A = "/data/samples/.work/a.exe"
B = "/data/samples/.work/b.exe"
FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures/tools/reverser_ghidra_tool_definitions.json"
)


def _query(name: str) -> dict[str, Any]:
    return {"name": name, "type": "string", "source": "query"}


SCHEMA = [
    {
        "path": "/load_program",
        "method": "POST",
        "params": [{"name": "file", "type": "string", "required": True, "source": "body"}],
    },
    {"path": "/switch_program", "method": "POST", "params": [_query("program")]},
    {
        "path": "/run_analysis",
        "method": "POST",
        "params": [{"name": "program", "type": "string", "source": "body"}],
    },
    {
        "path": "/decompile_function",
        "method": "GET",
        "params": [{**_query("address"), "required": True}, _query("program")],
    },
    {
        "path": "/get_xrefs_to",
        "method": "GET",
        "params": [{**_query("address"), "required": True}, _query("program")],
    },
    {
        "path": "/diff_functions",
        "method": "GET",
        "params": [
            _query("address_a"),
            _query("address_b"),
            _query("program_a"),
            _query("program_b"),
        ],
    },
    {"path": "/list_project_files", "method": "GET", "params": [_query("folder")]},
    {"path": "/server_status", "method": "GET", "params": []},
    {"path": "/convert_number", "method": "GET", "params": [_query("text")]},
    {
        "path": "/run_script_inline",
        "method": "POST",
        "params": [{"name": "code", "type": "string", "source": "body"}, _query("program")],
    },
    {
        "path": "/create_folder",
        "method": "POST",
        "params": [_query("path"), _query("program")],
    },
]


class _SharedGhidra:
    """One Ghidra for every job: a current program per server, as the real one keeps."""

    def __init__(self) -> None:
        self.current: str | None = None
        self.requests: list[httpx.Request] = []

    def _field(self, request: httpx.Request, name: str) -> str | None:
        query = parse_qs(request.url.query.decode())
        if name in query:
            return query[name][0]
        try:
            body = json.loads(request.content or b"{}")
        except ValueError:
            body = {}
        return body.get(name) if isinstance(body, dict) else None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/load_program":
            name = posixpath.basename(json.loads(request.content)["file"])
            if self.current is None:
                self.current = name
            return httpx.Response(200, text=json.dumps({"success": True, "program": name}))
        if path == "/switch_program":
            self.current = self._field(request, "program")
            return httpx.Response(
                200, text=json.dumps({"success": True, "switched_to": self.current})
            )
        if path == "/diff_functions":
            pair = [self._field(request, k) or self.current for k in ("program_a", "program_b")]
            return httpx.Response(200, text=json.dumps({"programs": pair}))
        read = self._field(request, "program") or self.current
        if path == "/run_analysis":
            return httpx.Response(200, text=json.dumps({"success": True, "program": read}))
        if path == "/get_full_call_graph":
            return httpx.Response(200, text=f"entry_{read} -> CreateProcessA\n")
        if path == "/get_bulk_function_hashes":
            item = {"name": f"f_{read}", "hash": f"h_{read}", "instruction_count": 50}
            return httpx.Response(200, text=json.dumps({"functions": [item]}))
        return httpx.Response(200, text=json.dumps({"program": read}))

    def sent(self, path: str, name: str = "program") -> list[str | None]:
        return [self._field(r, name) for r in self.requests if r.url.path == path]


def _cfg(spec: SampleOpenConfig | None = GHIDRA_SAMPLE_OPEN) -> MCPServerConfig:
    return MCPServerConfig(
        enabled=True,
        transport="http",
        url=URL,
        auth_token=SecretStr(""),
        sample_open=spec if spec is not None else SampleOpenConfig(),
    )


class _Job:
    """One job's Ghidra provider, its own note, on the shared server."""

    def __init__(
        self, ghidra: _SharedGhidra, held: str, spec: SampleOpenConfig | None = GHIDRA_SAMPLE_OPEN
    ) -> None:
        self.provider = GhidraStaticProvider(_cfg(spec), None, None)  # type: ignore[arg-type]
        self.provider.sample_notes = SampleNotes()
        client = GhidraHTTPClient(base_url=URL)
        client._http = httpx.AsyncClient(transport=httpx.MockTransport(ghidra.handler))
        self.provider._toolkit = client
        self.provider.pin_sample(held)
        self.tools = {
            t.name: t
            for t in self.provider._pin_load_program_path(
                [client._create_langchain_tool(entry) for entry in SCHEMA]
            )
        }

    def call(self, tool: str, **arguments: Any) -> str:
        return str(asyncio.run(self.tools[tool].ainvoke(arguments)))


def _error(answer: str) -> dict[str, Any]:
    payload = json.loads(answer)
    assert isinstance(payload, dict) and "error" in payload, answer
    return payload["error"]


def _rest(monkeypatch: Any, ghidra: _SharedGhidra) -> None:
    real = httpx.Client

    def client(**kwargs: Any) -> httpx.Client:
        return real(transport=httpx.MockTransport(ghidra.handler), **kwargs)

    monkeypatch.setattr(httpx, "Client", client)


class TestTwoJobsOnOneServer:
    def test_each_job_s_calls_read_its_own_program_however_they_interleave(self) -> None:
        ghidra = _SharedGhidra()
        job_a, job_b = _Job(ghidra, A), _Job(ghidra, B)
        job_a.call("load_program", file=A)
        job_b.call("load_program", file=B)
        # B opened last: the server's current program is B's.
        assert ghidra.current == "b.exe"
        assert json.loads(job_a.call("decompile_function", address="0x1000")) == {
            "program": "a.exe"
        }
        assert json.loads(job_b.call("get_xrefs_to", address="0x1000")) == {"program": "b.exe"}
        assert json.loads(job_a.call("get_xrefs_to", address="0x2000")) == {"program": "a.exe"}
        assert ghidra.sent("/decompile_function") == ["a.exe"]
        assert ghidra.sent("/get_xrefs_to") == ["b.exe", "a.exe"]

    def test_a_call_that_omits_the_program_is_given_the_job_s(self) -> None:
        ghidra = _SharedGhidra()
        job = _Job(ghidra, A)
        job.call("load_program", file=A)
        job.call("decompile_function", address="0x1000")
        (request,) = [r for r in ghidra.requests if r.url.path == "/decompile_function"]
        assert parse_qs(request.url.query.decode())["program"] == ["a.exe"]

    def test_the_job_s_own_program_named_by_the_model_is_sent_as_named(self) -> None:
        ghidra = _SharedGhidra()
        job = _Job(ghidra, A)
        job.call("load_program", file=A)
        assert json.loads(job.call("decompile_function", address="0x1", program="a.exe")) == {
            "program": "a.exe"
        }

    def test_another_job_s_program_named_by_the_model_is_refused_and_said(self) -> None:
        ghidra = _SharedGhidra()
        job_a, job_b = _Job(ghidra, A), _Job(ghidra, B)
        job_a.call("load_program", file=A)
        job_b.call("load_program", file=B)
        before = len(ghidra.requests)
        error = _error(job_a.call("decompile_function", address="0x1", program="b.exe"))
        assert error["code"] == FOREIGN_PROGRAM
        assert "b.exe" in error["message"] and "a.exe" in error["remediation"]
        # Refused before anything reached the server.
        assert len(ghidra.requests) == before

    def test_a_select_of_another_job_s_program_is_refused(self) -> None:
        ghidra = _SharedGhidra()
        job_a, job_b = _Job(ghidra, A), _Job(ghidra, B)
        job_a.call("load_program", file=A)
        job_b.call("load_program", file=B)
        assert _error(job_a.call("switch_program", program="b.exe"))["code"] == FOREIGN_PROGRAM
        assert ghidra.current == "b.exe"

    def test_before_the_job_opened_anything_a_shared_server_is_not_trusted(self) -> None:
        ghidra = _SharedGhidra()
        job_a, job_b = _Job(ghidra, A), _Job(ghidra, B)
        job_b.call("load_program", file=B)
        error = _error(job_a.call("decompile_function", address="0x1"))
        assert error["code"] == NO_JOB_PROGRAM
        assert "load_program" in error["remediation"]
        assert ghidra.sent("/decompile_function") == []


class TestEveryProgramArgument:
    """The further program arguments the declaration names are held like the first."""

    def test_another_job_s_program_in_a_further_argument_is_refused(self) -> None:
        ghidra = _SharedGhidra()
        job_a, job_b = _Job(ghidra, A), _Job(ghidra, B)
        job_a.call("load_program", file=A)
        job_b.call("load_program", file=B)
        error = _error(job_a.call("diff_functions", program_a="a.exe", program_b="b.exe"))
        assert error["code"] == FOREIGN_PROGRAM and "program_b" in error["message"]
        assert ghidra.sent("/diff_functions") == []

    def test_further_arguments_left_out_are_given_the_job_s_program(self) -> None:
        ghidra = _SharedGhidra()
        job_a, job_b = _Job(ghidra, A), _Job(ghidra, B)
        job_a.call("load_program", file=A)
        job_b.call("load_program", file=B)
        answer = json.loads(job_a.call("diff_functions", address_a="0x1", address_b="0x2"))
        assert answer == {"programs": ["a.exe", "a.exe"]}


class TestToolsThatTakeNoProgram:
    def test_a_tool_taking_no_declared_argument_is_withheld_with_its_reason(self) -> None:
        job = _Job(_SharedGhidra(), A)
        assert "list_project_files" not in job.tools
        reason = job.provider.withheld_tools["list_project_files"]
        assert "withheld" in reason and "job_safe_tools" in reason
        assert reason in job.provider.withheld_reasons()

    def test_a_tool_the_declaration_lists_as_job_safe_is_offered(self) -> None:
        ghidra = _SharedGhidra()
        job = _Job(ghidra, A)
        assert "convert_number" in job.tools
        assert "convert_number" not in job.provider.withheld_tools
        assert json.loads(job.call("convert_number", text="0x10")) == {"program": None}

    def test_the_server_s_status_is_withheld_it_may_name_other_jobs_programs(self) -> None:
        job = _Job(_SharedGhidra(), A)
        assert "server_status" not in job.tools
        assert "server_status" in job.provider.withheld_tools

    def test_a_script_tool_is_withheld_though_it_takes_a_program(self) -> None:
        job = _Job(_SharedGhidra(), A)
        for name in ("run_script_inline", "create_folder"):
            assert name not in job.tools
            assert "shared_withheld_tools" in job.provider.withheld_tools[name]

    def test_on_a_server_no_other_job_shares_the_script_tool_is_kept(self) -> None:
        from langchain_core.tools import StructuredTool
        from pydantic import create_model

        async def run(**_kwargs: Any) -> str:
            return "{}"

        script = StructuredTool.from_function(
            func=None,
            coroutine=run,
            name="run_script_inline",
            description="d",
            args_schema=create_model("ScriptArgs", code=(str, ...), program=(str | None, None)),
        )
        out = pin_program_argument(
            [script], server=KEY, spec=GHIDRA_SAMPLE_OPEN, notes=SampleNotes(), shared=False
        )
        assert out == [script]

    def test_the_shipped_declaration_withholds_only_the_project_wide_tools(self) -> None:
        from langchain_core.tools import StructuredTool
        from pydantic import create_model

        async def answer(**_kwargs: Any) -> str:
            return "{}"

        tools = []
        for entry in json.loads(FIXTURE.read_text(encoding="utf-8")):
            props = entry.get("input_schema", {}).get("properties", {})
            fields: dict[str, Any] = {name: (Any, None) for name in props}
            schema = create_model(f"S_{entry['name']}", **fields)
            tools.append(
                StructuredTool.from_function(
                    func=None,
                    coroutine=answer,
                    name=entry["name"],
                    description="d",
                    args_schema=schema,
                )
            )
        withheld: dict[str, str] = {}
        pin_program_argument(
            tools,
            server=KEY,
            spec=GHIDRA_SAMPLE_OPEN,
            notes=SampleNotes(),
            shared=True,
            held_path=lambda: A,
            withheld=withheld,
        )
        from maljan.core.builtin_reverser_tools import GHIDRA_TOOLS

        # The fixture merges the knowledge and VirusTotal servers' tools in;
        # none of them is Ghidra's to list, and none takes a program.
        others = {entry for entry in withheld if entry not in GHIDRA_TOOLS}
        assert others and all("job_safe_tools" in withheld[n] for n in others)
        assert set(withheld) - others == {
            "create_folder",
            "run_ghidra_script",
            "run_script_inline",
            "server_status",
            "close_program",
            "close_project",
            "create_project",
            "delete_file",
            "get_project_info",
            "import_data_types",
            "list_open_programs",
            "list_project_files",
            "load_program_from_project",
            "open_program",
            "open_project",
            "save_all_programs",
        }


class TestThePlatformsOwnCalls:
    def test_the_call_graph_reads_the_job_s_program(self, monkeypatch: Any) -> None:
        ghidra = _SharedGhidra()
        _rest(monkeypatch, ghidra)
        job_a, job_b = _Job(ghidra, A), _Job(ghidra, B)
        assert job_a.provider.open_sample(A)
        assert job_b.provider.open_sample(B)
        graph = job_a.provider.call_graph(A)
        assert graph is not None
        assert ghidra.sent("/get_full_call_graph") == ["a.exe"]
        assert "entry_a.exe" in json.dumps(graph, default=str)

    def test_a_call_graph_of_a_program_the_job_did_not_open_is_absent(
        self, monkeypatch: Any
    ) -> None:
        ghidra = _SharedGhidra()
        _rest(monkeypatch, ghidra)
        job = _Job(ghidra, A)
        assert job.provider.call_graph(A) is None
        assert ghidra.sent("/get_full_call_graph") == []

    def test_the_function_hashes_are_the_job_s_program(self, monkeypatch: Any) -> None:
        from maljan.core.config import PreprocessingConfig
        from maljan.providers.base import StaticJobContext

        ghidra = _SharedGhidra()
        _rest(monkeypatch, ghidra)
        job_a, job_b = _Job(ghidra, A), _Job(ghidra, B)
        job_a.provider._pre = PreprocessingConfig()
        assert job_a.provider.open_sample(A)
        assert job_b.provider.open_sample(B)
        got = job_a.provider.function_hashes(StaticJobContext(mirror_sample_path=A))
        assert got == [("f_a.exe", "h_a.exe")]
        assert ghidra.sent("/get_bulk_function_hashes") == ["a.exe"]


# A declaration that opens a sample but names no argument a program goes in.
NO_ARGUMENT = SampleOpenConfig(open_tool="load_program", path_argument="file")


class TestNothingFailsOpen:
    """Where the job's program cannot be named on a shared server, nothing is read."""

    def _hashes(self, monkeypatch: Any, ghidra: _SharedGhidra, **over: Any) -> Any:
        from maljan.providers.static.ghidra import function_hashes as hashes

        common: dict[str, Any] = {
            "base_url": URL,
            "auth_token": "",
            "file_path": A,
            "min_instructions": 1,
            "sample_open": GHIDRA_SAMPLE_OPEN,
            "sample_notes": SampleNotes(),
            "note_key": KEY,
            "shared": True,
        }
        return hashes.fetch_bulk_function_hashes(**{**common, **over})

    def test_hashes_of_a_program_the_job_did_not_open_are_absent_on_a_shared_server(
        self, monkeypatch: Any
    ) -> None:
        from maljan.providers.static.ghidra import function_hashes as hashes

        ghidra = _SharedGhidra()
        _rest(monkeypatch, ghidra)
        # The open answers as done, yet the note holds no program for the path.
        monkeypatch.setattr(hashes, "_opened_for_hashes", lambda *a, **k: True)
        assert self._hashes(monkeypatch, ghidra) == []
        assert ghidra.sent("/get_bulk_function_hashes") == []
        # A server no other job shares holds only this job's programs.
        assert self._hashes(monkeypatch, ghidra, shared=False) != []
        assert ghidra.sent("/get_bulk_function_hashes") == [None]

    def test_hashes_with_no_declared_argument_are_absent_on_a_shared_server(
        self, monkeypatch: Any
    ) -> None:
        ghidra = _SharedGhidra()
        _rest(monkeypatch, ghidra)
        assert self._hashes(monkeypatch, ghidra, sample_open=NO_ARGUMENT) == []
        assert self._hashes(monkeypatch, ghidra, sample_open=None) == []
        assert ghidra.sent("/get_bulk_function_hashes") == []

    def test_an_undeclared_ghidra_no_other_job_shares_keeps_today_s_read(
        self, monkeypatch: Any
    ) -> None:
        ghidra = _SharedGhidra()
        _rest(monkeypatch, ghidra)
        got = self._hashes(monkeypatch, ghidra, sample_open=None, shared=False)
        assert got == [("f_a.exe", "h_a.exe")]
        assert ghidra.sent("/get_bulk_function_hashes") == [None]

    def test_a_call_graph_with_no_declared_argument_is_absent_on_a_shared_server(
        self, monkeypatch: Any
    ) -> None:
        ghidra = _SharedGhidra()
        _rest(monkeypatch, ghidra)
        for spec in (NO_ARGUMENT, None):
            job = _Job(ghidra, A, spec)
            job.call("load_program", file=A)
            assert job.provider.call_graph(A) is None
        assert ghidra.sent("/get_full_call_graph") == []

    def _unwrappable(self, monkeypatch: Any) -> None:
        from langchain_core.tools import StructuredTool

        real = StructuredTool.from_function

        def refuse(*args: Any, **kwargs: Any) -> Any:
            # Only the rebuild that holds a tool to the job fails.
            if "pin_program_argument" in getattr(kwargs.get("coroutine"), "__qualname__", ""):
                raise TypeError("cannot rebuild")
            return real(*args, **kwargs)

        monkeypatch.setattr(StructuredTool, "from_function", refuse)

    def test_the_ghidra_provider_withholds_a_tool_it_cannot_wrap_and_says_why(
        self, monkeypatch: Any
    ) -> None:
        self._unwrappable(monkeypatch)
        job = _Job(_SharedGhidra(), A)
        assert "decompile_function" not in job.tools
        assert "withheld" in job.provider.withheld_tools["decompile_function"]


class TestEveryServerAlike:
    """The shared server lifecycle gives any server's tools the same rule, by its declaration."""

    SPEC = SampleOpenConfig(
        open_tool="open",
        path_argument="path",
        name_field="name",
        select_tool="select",
        select_argument="target",
        job_safe_tools=["status"],
    )

    def _handle(
        self, transport: str, notes: SampleNotes, held: str | None = "/s/a.bin"
    ) -> tuple[Any, list[tuple[str, dict[str, Any]]]]:
        from langchain_core.tools import StructuredTool
        from pydantic import BaseModel

        from maljan.providers.servers import ServerHandle

        seen: list[tuple[str, dict[str, Any]]] = []

        class _ReadArgs(BaseModel):
            address: str
            target: str | None = None

        class _OpenArgs(BaseModel):
            path: str

        class _SelectArgs(BaseModel):
            target: str

        class _NoArgs(BaseModel):
            pass

        def answering(name: str) -> Any:
            async def answer(**kwargs: Any) -> str:
                seen.append((name, kwargs))
                if name == "open":
                    return json.dumps({"name": posixpath.basename(kwargs["path"])})
                return json.dumps({name: kwargs.get("target")})

            return answer

        def tool(name: str, schema: Any) -> Any:
            return StructuredTool.from_function(
                func=None, coroutine=answering(name), name=name, description="d", args_schema=schema
            )

        cfg = MCPServerConfig(
            enabled=True,
            transport=transport,  # type: ignore[arg-type]
            url="http://server.invalid/mcp",
            command="server",
            sample_open=self.SPEC,
        )
        handle = ServerHandle("server", cfg)
        handle._all_tools = [
            tool("read", _ReadArgs),
            tool("open", _OpenArgs),
            tool("select", _SelectArgs),
            tool("status", _NoArgs),
            tool("list_everything", _NoArgs),
        ]
        handle.sample_notes = notes
        handle.error_sample_path = lambda: held
        return handle, seen

    def _call(self, handle: Any, tool: str, **arguments: Any) -> str:
        (found,) = [t for t in handle.tools() if t.name == tool]
        return str(asyncio.run(found.ainvoke(arguments)))

    def test_a_remote_server_s_call_is_given_the_job_s_program(self) -> None:
        notes = SampleNotes()
        handle, seen = self._handle("streamable-http", notes)
        notes.note(handle.note_key, "/s/a.bin", "a", "{}")
        assert json.loads(self._call(handle, "read", address="0x1")) == {"read": "a"}
        assert seen[-1] == ("read", {"address": "0x1", "target": "a"})

    def test_a_remote_server_refuses_a_program_the_job_did_not_open(self) -> None:
        notes = SampleNotes()
        handle, seen = self._handle("streamable-http", notes)
        notes.note(handle.note_key, "/s/a.bin", "a", "{}")
        error = _error(self._call(handle, "read", address="0x1", target="z"))
        assert error["code"] == FOREIGN_PROGRAM
        assert seen == []

    def test_an_open_of_another_job_s_path_is_refused_before_it_is_sent(self) -> None:
        notes = SampleNotes()
        handle, seen = self._handle("streamable-http", notes)
        error = _error(self._call(handle, "open", path="/s/other.bin"))
        assert error["code"] == FOREIGN_PROGRAM and "/s/a.bin" in error["remediation"]
        assert seen == []
        assert notes.current(handle.note_key) is None
        assert not notes.owns(handle.note_key, "other.bin")

    def test_the_job_s_own_path_opens_and_becomes_the_job_s_program(self) -> None:
        notes = SampleNotes()
        handle, seen = self._handle("streamable-http", notes)
        self._call(handle, "open", path="/s/a.bin")
        assert [name for name, _ in seen] == ["open", "select"]
        assert notes.current(handle.note_key) == "a.bin"

    def test_with_no_held_copy_no_open_is_sent_on_a_shared_server(self) -> None:
        handle, seen = self._handle("streamable-http", SampleNotes(), held=None)
        assert _error(self._call(handle, "open", path="/s/a.bin"))["code"] == FOREIGN_PROGRAM
        assert seen == []

    def test_an_uncovered_tool_is_withheld_and_a_job_safe_one_offered(self) -> None:
        handle, _seen = self._handle("streamable-http", SampleNotes())
        names = [t.name for t in handle.tools()]
        assert "status" in names and "list_everything" not in names
        reason = handle.withheld_reason("list_everything")
        assert reason is not None and "withheld" in reason

    def test_a_withheld_reason_is_known_before_the_tools_are_read(self) -> None:
        handle, _seen = self._handle("streamable-http", SampleNotes())
        assert any("list_everything" in r for r in handle.withheld_reasons())

    def test_the_registry_s_merge_records_the_reason(self) -> None:
        from maljan.core.config import Settings
        from maljan.providers.servers import ServerRegistry

        handle, _seen = self._handle("streamable-http", SampleNotes())
        registry = ServerRegistry(Settings())
        merged: list[Any] = []
        registry._merge(handle, merged, {})
        assert "list_everything" not in [t.name for t in merged]
        assert any("list_everything" in r for r in registry.degradation_reasons)

    def test_a_tool_whose_schema_cannot_be_read_is_withheld(self) -> None:
        class _Unread:
            name = "opaque"
            description = "d"

            @property
            def args(self) -> Any:
                raise RuntimeError("no schema")

        withheld: dict[str, str] = {}
        out = pin_program_argument(
            [_Unread()],
            server=KEY,
            spec=self.SPEC,
            notes=SampleNotes(),
            shared=True,
            withheld=withheld,
        )
        assert out == [] and "could not be read" in withheld["opaque"]

    def test_a_local_server_is_left_as_it_was(self) -> None:
        notes = SampleNotes()
        handle, seen = self._handle("stdio", notes)
        notes.note(handle.note_key, "/s/a.bin", "a", "{}")
        # After an import the declaration did not make, the server's own
        # current program answers: nothing is filled in or refused.
        assert json.loads(self._call(handle, "read", address="0x1")) == {"read": None}
        assert seen[-1][0] == "read" and seen[-1][1].get("target") is None
        assert json.loads(self._call(handle, "read", address="0x1", target="z")) == {"read": "z"}
        assert "list_everything" in [t.name for t in handle.tools()]
        assert handle.withheld_reasons() == []


class TestEveryArgumentACallCarries:
    """The declared arguments checked are the call's own, whatever its schema names."""

    def _safe_tool(self, seen: list[dict[str, Any]]) -> Any:
        from langchain_core.tools import StructuredTool

        async def convert(**kwargs: Any) -> str:
            seen.append(kwargs)
            return "{}"

        # A schema as a server lists it (JSON), naming no program.
        schema = {"type": "object", "properties": {"text": {"type": "string"}}}
        return StructuredTool.from_function(
            func=None, coroutine=convert, name="convert_number", description="d", args_schema=schema
        )

    def test_an_undeclared_program_on_a_job_safe_tool_is_held_to_the_job(self) -> None:
        notes = SampleNotes()
        notes.note(KEY, A, "a.exe", "{}")
        seen: list[dict[str, Any]] = []
        (tool,) = pin_program_argument(
            [self._safe_tool(seen)],
            server=KEY,
            spec=GHIDRA_SAMPLE_OPEN,
            notes=notes,
            shared=True,
            held_path=lambda: A,
        )
        foreign = asyncio.run(tool.ainvoke({"text": "1", "program": "b.exe"}))
        assert _error(str(foreign))["code"] == FOREIGN_PROGRAM
        path = asyncio.run(tool.ainvoke({"text": "1", "file_path": B}))
        assert _error(str(path))["code"] == FOREIGN_PROGRAM
        asyncio.run(tool.ainvoke({"text": "1"}))
        # No program is filled into a tool whose schema takes none.
        assert seen == [{"text": "1"}]


class TestTheRegistryHoldsTheJobsPath:
    """A registry-bound server on a shared transport opens the job's own sample."""

    def _registry(self) -> Any:
        from maljan.core.config import Settings
        from maljan.providers.servers import ServerRegistry

        registry = ServerRegistry(Settings())
        handle, _seen = TestEveryServerAlike()._handle("streamable-http", SampleNotes(), held=None)
        handle.name = "decompiler"
        registry._handles["decompiler"] = handle
        return registry

    def _stamped(self, handle: Any) -> Any:
        from maljan.agents.tool_pinning import SERVER_METADATA_KEY

        return handle._all_tools[0].model_copy(
            update={"metadata": {SERVER_METADATA_KEY: "decompiler"}}
        )

    def test_with_no_sample_every_open_stays_refused(self) -> None:
        handle = self._registry()._handles["decompiler"]
        (tool,) = [t for t in handle.tools() if t.name == "open"]
        answer = str(asyncio.run(tool.ainvoke({"path": "/s/a.bin"})))
        assert _error(answer)["code"] == FOREIGN_PROGRAM

    def test_the_held_path_reaches_the_handle_and_every_replica(self) -> None:
        from maljan.agents.composition import hold_sample_paths

        registry = self._registry()
        handle = registry._handles["decompiler"]
        loops = [asyncio.new_event_loop() for _ in range(3)]
        try:
            handle._owner_loop = loops[0]
            replica = registry._handle_for(handle, loops[1])
            hold_sample_paths(registry, [self._stamped(handle)], {"decompiler": "/s/a.bin"})
            assert handle.held_sample_path == replica.held_sample_path == "/s/a.bin"
            # A replica made afterwards copies it.
            assert registry._handle_for(handle, loops[2]).held_sample_path == "/s/a.bin"
        finally:
            for loop in loops:
                loop.close()
        handle._owner_loop = None
        (opener,) = [t for t in handle.tools() if t.name == "open"]
        asyncio.run(opener.ainvoke({"path": "/s/a.bin"}))
        foreign = str(asyncio.run(opener.ainvoke({"path": "/s/other.bin"})))
        assert _error(foreign)["code"] == FOREIGN_PROGRAM

    def test_the_agent_s_own_path_is_held_where_no_server_path_is_known(self) -> None:
        from maljan.agents.composition import hold_sample_paths

        registry = self._registry()
        handle = registry._handles["decompiler"]
        hold_sample_paths(registry, [self._stamped(handle)], {}, "/s/a.bin")
        assert handle.held_sample_path == "/s/a.bin"


class TestDecidedOncePerManifest:
    def test_every_reader_reads_one_decision(self, monkeypatch: Any) -> None:
        from maljan.providers import sample_open

        handle, _seen = TestEveryServerAlike()._handle("streamable-http", SampleNotes())
        built: list[int] = []
        real = sample_open.pin_program_argument

        def counting(*args: Any, **kwargs: Any) -> Any:
            built.append(1)
            return real(*args, **kwargs)

        monkeypatch.setattr(sample_open, "pin_program_argument", counting)
        first = handle.tools()
        handle.withheld_reasons()
        handle.withheld_reason("list_everything")
        again = handle.tools()
        assert all(t is u for t, u in zip(first, again, strict=True))
        assert built == [1]
        # A new manifest is decided afresh.
        handle._all_tools = list(handle._all_tools)[:-1]
        handle.tools()
        assert built == [1, 1]


def _tool(name: str, seen: list[tuple[str, dict[str, Any]]], **fields: Any) -> Any:
    from langchain_core.tools import StructuredTool
    from pydantic import create_model

    async def answer(**kwargs: Any) -> str:
        seen.append((name, kwargs))
        return "{}"

    return StructuredTool.from_function(
        func=None,
        coroutine=answer,
        name=name,
        description="d",
        args_schema=create_model(f"Args_{name}", **fields),
    )


class TestADeclarationWithNoProgramArgument:
    """A shared server that declares an open but no program argument is still held."""

    SPEC = SampleOpenConfig(
        open_tool="open",
        path_argument="path",
        open_path_arguments=["file_path"],
        shared_withheld_tools=["run"],
    )

    def _pinned(self, notes: SampleNotes | None, seen: list[Any]) -> tuple[list[Any], dict]:
        withheld: dict[str, str] = {}
        tools = [
            _tool("open", seen, path=(str, ...)),
            _tool("import_it", seen, file_path=(str, ...)),
            _tool("status", seen),
            _tool("run", seen, path=(str, ...)),
        ]
        out = pin_program_argument(
            tools,
            server=KEY,
            spec=self.SPEC,
            notes=notes,
            shared=True,
            held_path=lambda: A,
            withheld=withheld,
        )
        return out, withheld

    def test_a_foreign_path_is_refused_and_the_lists_apply(self) -> None:
        seen: list[Any] = []
        out, withheld = self._pinned(SampleNotes(), seen)
        assert [t.name for t in out] == ["open", "import_it"]
        assert set(withheld) == {"status", "run"}
        (opener, _imp) = out
        answer = str(asyncio.run(opener.ainvoke({"path": B})))
        assert _error(answer)["code"] == FOREIGN_PROGRAM
        assert seen == []

    def test_with_no_note_store_every_tool_is_withheld(self) -> None:
        seen: list[Any] = []
        out, withheld = self._pinned(None, seen)
        assert out == []
        assert set(withheld) == {"open", "import_it", "status", "run"}
        assert all("no note" in reason for reason in withheld.values())

    def test_a_server_with_no_declaration_is_left_as_it_was(self) -> None:
        seen: list[Any] = []
        tools = [_tool("status", seen)]
        out = pin_program_argument(
            tools, server=KEY, spec=SampleOpenConfig(), notes=None, shared=True
        )
        assert out == tools

    def test_a_path_that_passes_is_sent_as_the_held_path(self) -> None:
        seen: list[Any] = []
        out, _withheld = self._pinned(SampleNotes(), seen)
        (_opener, importer) = out
        asyncio.run(importer.ainvoke({"file_path": posixpath.basename(A)}))
        assert seen == [("import_it", {"file_path": A})]


class TestAFallbackNeverReplacesAServersPath:
    def test_only_a_server_s_own_path_replaces_a_held_one(self) -> None:
        from maljan.agents.composition import hold_sample_paths

        registry_test = TestTheRegistryHoldsTheJobsPath()
        registry = registry_test._registry()
        handle = registry._handles["decompiler"]
        tool = registry_test._stamped(handle)
        hold_sample_paths(registry, [tool], {"decompiler": "/staged/a.bin"})
        # Another agent, with only its own path: the staged one stays.
        hold_sample_paths(registry, [tool], {}, "/worker/a.bin")
        assert handle.held_sample_path == "/staged/a.bin"
        hold_sample_paths(registry, [tool], {"decompiler": "/staged/b.bin"})
        assert handle.held_sample_path == "/staged/b.bin"


class TestTheCacheKey:
    def test_the_same_manifest_by_name_is_one_decision_and_a_reattach_another(
        self, monkeypatch: Any
    ) -> None:
        from maljan.providers import sample_open

        handle, _seen = TestEveryServerAlike()._handle("streamable-http", SampleNotes())
        built: list[int] = []
        real = sample_open.pin_program_argument

        def counting(*args: Any, **kwargs: Any) -> Any:
            built.append(1)
            return real(*args, **kwargs)

        monkeypatch.setattr(sample_open, "pin_program_argument", counting)
        handle.tools()
        # The same names in new objects: the same manifest.
        handle._all_tools = [t.model_copy() for t in handle._all_tools]
        handle.tools()
        assert built == [1]
        handle._attach_count += 1
        handle.tools()
        assert built == [1, 1]
        handle.sample_notes = SampleNotes()
        handle.tools()
        assert built == [1, 1, 1]
