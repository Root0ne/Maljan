"""The pack's readings of the sample, run on the server of their tool, answer as in process (X2).

A place stands in for the server here: it sends each ``run_reader`` call as
JSON, runs the server's side of it (``tools.readers.serve_reader``) and
answers as JSON, exactly what crosses the boundary. The pack over the same
sample then records the same entries, the same answers, in the same order.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.agents.tool_pinning import DELIVERY_TOOLS
from maljan.pipeline.triage_pack import (
    PIPELINE,
    CapaSettings,
    FlossSettings,
    PackInputs,
    run_pack,
)
from maljan.schemas.evidence import EvidenceCounter
from maljan.tools import emulated_strings, readers, rules, staging, upx
from maljan.tools.readers import READERS, RUN_READER, Place, SampleReaders

from ..tools import synthetic_upx as su

JOB = "a3d1c0de-0000-4000-8000-000000000002"
EVERY_TOOL = frozenset(spec.stands_for for spec in READERS.values())
SERVICES = Path(__file__).resolve().parents[3] / "services"


@cache
def _offered(name: str) -> frozenset[str]:
    """The tools the real server ``name`` runs readings of (its ``_OFFERED``)."""
    spec = importlib.util.spec_from_file_location(
        f"{name}_mcp_server_readers", SERVICES / f"{name}-mcp" / "server.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return frozenset(module._OFFERED)


@pytest.fixture(autouse=True)
def _no_capa_and_no_floss(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        rules, "capa", lambda path, **_: {"capabilities": [], "function_starts": [], "meta": {}}
    )
    monkeypatch.setattr(emulated_strings, "floss_unavailable", lambda environ=None: "not here")
    # The server's side reads its own environment: the same staging base here.
    monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))


def _sample(tmp_path: Path) -> str:
    target = tmp_path / "samples" / "packed.exe"
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(su.build().data)
    return str(target)


class _Server:
    """The server's side of ``run_reader``, reached as JSON both ways."""

    def __init__(self, seen_as: dict[str, str] | None = None, server: str = "analysis") -> None:
        self.calls: list[dict[str, Any]] = []
        self.waits: dict[str, float | None] = {}
        # The path this server opens, by the path the worker handed it.
        self.seen_as = dict(seen_as or {})
        # The readings the real server of that name runs, and no other.
        self.offered = _offered(server)

    def __call__(self, payload: dict[str, Any], timeout: float | None) -> Any:
        sent = json.loads(json.dumps(payload))
        self.calls.append(sent)
        self.waits[sent["reader"]] = timeout
        answer = readers.serve_reader(
            sent["reader"],
            sent["arguments"],
            sent["job"],
            offered=self.offered,
            confine=lambda path, job: self.seen_as.get(path, path),
        )
        return json.loads(json.dumps(answer))


def _pack(
    path: str,
    tmp_path: Path,
    place_readers: SampleReaders | None,
    file_type: str = "pe",
    budget_s: float = 0.0,
    capa_seconds: int = 1,
) -> Any:
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    environ = {staging.STAGING_DIR_ENV: str(tmp_path / "staging")}
    inputs = PackInputs(
        sample_path=path,
        sha256="a" * 64,
        file_type=file_type,
        strings_head=10,
        capa=CapaSettings(
            rules_dir="data/capa-rules", signatures_dir="", timeout_s=capa_seconds, job_id=JOB
        ),
        floss=FlossSettings(environ=environ, job_id=JOB),
        readers=place_readers,
        budget_s=budget_s,
    )
    return run_pack(recorder, inputs)


def _placed(path: str, server: _Server, sample_path: str | None = None) -> SampleReaders:
    """Every reading on a place of the server whose real counterpart runs it."""
    capture = _Server(server="network")
    places: dict[str, Place] = {}
    for tool in EVERY_TOOL:
        call = server if tool in server.offered else capture
        assert tool in call.offered, tool
        places[tool] = Place(
            server="analysis" if call is server else "network",
            sample_path=path if sample_path is None else sample_path,
            job=JOB,
            call=call,
            hand=lambda local: local,
        )
    return SampleReaders(sample_path=path, places=places)


def _shown(result: Any) -> list[tuple[Any, ...]]:
    return [(e.id, e.tool, e.ok, e.args, e.output, e.error) for e in result.entries]


def test_run_reader_is_a_delivery_primitive_no_model_is_shown() -> None:
    assert RUN_READER in DELIVERY_TOOLS


def test_every_reading_answers_on_its_server_as_it_does_in_process(tmp_path: Path) -> None:
    path = _sample(tmp_path)
    here = _pack(path, tmp_path, None)
    server = _Server()
    there = _pack(path, tmp_path, _placed(path, server))
    assert _shown(there) == _shown(here)
    assert [e.function_ranges for e in there.entries] == [e.function_ranges for e in here.entries]
    asked = {call["reader"] for call in server.calls}
    # Every reading of the sample the pack made went to the server, the
    # unpacker and the directed-text scan of the file it wrote included.
    assert {"identify_file", "pe_info", "strings", "yara_scan", "unpack_upx"} <= asked
    assert {"directed_scan", "function_index", "floss_unavailable"} <= asked
    assert any(e.tool == upx.TOOL and e.ok for e in there.entries)
    assert all(call["job"] == JOB for call in server.calls)


def test_the_server_is_handed_its_own_path_of_the_sample(tmp_path: Path) -> None:
    path = _sample(tmp_path)
    mounted = "/data/samples/.work/packed.exe"
    server = _Server(seen_as={mounted: path})
    result = _pack(path, tmp_path, _placed(path, server, sample_path=mounted))
    identity = next(call for call in server.calls if call["reader"] == "identify_file")
    assert identity["arguments"]["path"] == mounted
    assert next(e for e in result.entries if e.tool == "identify_file").ok


def test_a_server_handed_no_copy_of_the_sample_fails_each_reading_and_says_why(
    tmp_path: Path,
) -> None:
    path = _sample(tmp_path)
    result = _pack(path, tmp_path, _placed(path, _Server(), sample_path=""))
    identity = next(e for e in result.entries if e.tool == "identify_file")
    assert not identity.ok
    assert "SampleNotPlaced" in str(identity.error)
    assert "sample_mount" in str(identity.error)


def test_the_server_runs_only_the_readings_of_its_own_tools() -> None:
    said = readers.serve_reader(
        "capa", {"path": "/x"}, JOB, offered=frozenset({"pcap_summary"}), confine=lambda p, j: p
    )
    assert "error" in said and "value" not in said
    said = readers.serve_reader(
        "no_such_reading", {}, JOB, offered=EVERY_TOOL, confine=lambda p, j: p
    )
    assert "error" in said


def test_an_argument_only_a_call_in_process_passes_is_refused_by_the_server() -> None:
    said = readers.serve_reader(
        "directed_scan",
        {"path": "/x", "source": "file", "into": {}},
        JOB,
        offered=EVERY_TOOL,
        confine=lambda p, j: p,
    )
    assert "error" in said


def test_every_file_argument_is_held_by_the_servers_confinement() -> None:
    held: list[tuple[str, str]] = []

    def confine(path: str, job: str) -> str:
        held.append((path, job))
        raise PermissionError("outside the roots")

    said = readers.serve_reader(
        "pe_info", {"path": "/etc/passwd"}, JOB, offered=EVERY_TOOL, confine=confine
    )
    assert held == [("/etc/passwd", JOB)]
    assert said["raised"]["type"] == "PermissionError"


def test_what_the_reading_raised_there_is_raised_here_under_its_class(tmp_path: Path) -> None:
    missing = str(tmp_path / "gone.exe")
    server = _Server()
    held = _placed(missing, server)
    with pytest.raises(FileNotFoundError):
        held.read("directed_scan", path=missing, source="the file")
    # A class name that is no built-in is made here, holding only the words.
    raised = readers._raised({"type": "PathOutsideRoots", "message": "outside"})
    assert type(raised).__name__ == "PathOutsideRoots" and str(raised) == "outside"
    assert isinstance(readers._raised({"type": "not a name!", "message": "x"}), Exception)


def test_a_reading_with_no_place_runs_in_this_process(tmp_path: Path) -> None:
    path = _sample(tmp_path)
    assert SampleReaders(sample_path=path).read("upx_header", path=path) is True


def test_the_emulators_page_and_its_whole_rows_cross_as_one_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [{"kind": "decoded", "string": f"text {n}", "function": "0x401000"} for n in range(30)]
    monkeypatch.setattr(emulated_strings, "floss_unavailable", lambda environ=None: None)
    monkeypatch.setattr(
        emulated_strings,
        "recovered",
        lambda path, **_: {"rows": rows, "counts": {"decoded": len(rows)}, "meta": {}},
    )
    monkeypatch.setattr(
        emulated_strings,
        "floss",
        lambda path, limit, found, **_: {"strings": list(found["rows"])[:limit], "meta": {}},
    )
    path = _sample(tmp_path)
    here = _pack(path, tmp_path, None)
    server = _Server()
    there = _pack(path, tmp_path, _placed(path, server))
    assert _shown(there) == _shown(here)
    assert any(e.tool == "floss" and e.ok for e in there.entries)
    assert "floss" in {call["reader"] for call in server.calls}


def test_a_reading_runs_on_its_tools_server_only_when_that_server_is_reached_at_an_address() -> (
    None
):
    from types import SimpleNamespace

    from maljan.core.config import Settings
    from maljan.pipeline import nodes

    servers = dict(Settings(_env_file=None).mcp.servers)

    def container(held: dict[str, Any]) -> Any:
        return SimpleNamespace(
            config=SimpleNamespace(mcp=SimpleNamespace(servers=held)),
            server_sample_paths={"analysis": "/data/samples/.work/x.exe"},
            job_key=lambda: JOB,
        )

    # Shipped: every server a child of the worker, every reading in process.
    assert nodes.sample_readers(container(servers), "/w/x.exe").places == {}
    isolated = dict(servers)
    isolated["analysis"] = servers["analysis"].model_copy(
        update={
            "transport": "streamable-http",
            "url": "http://analysis-mcp:8098/mcp",
            "sample_mount": "/data/samples",
        }
    )
    held = nodes.sample_readers(container(isolated), "/w/x.exe")
    for reading in ("identify_file", "pe_info", "capa", "unpack_upx", "directed_scan", "toolchain"):
        place = held.place_of(reading)
        assert place is not None and place.server == "analysis", reading
        assert place.sample_path == "/data/samples/.work/x.exe" and place.job == JOB
    # The capture's reading stays with the network server, a child here.
    assert held.place_of("pcap_summary") is None
    # A server switched off holds no reading.
    isolated["analysis"] = isolated["analysis"].model_copy(update={"enabled": False})
    assert nodes.sample_readers(container(isolated), "/w/x.exe").place_of("pe_info") is None


def test_a_document_reads_on_its_server_as_it_does_in_process(tmp_path: Path) -> None:
    target = tmp_path / "samples" / "note.pdf"
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(
        b"%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n"
        b"2 0 obj << /S /JavaScript /JS (app.alert('http://example.test/x')) >> endobj\n"
        b"trailer << /Root 1 0 R >>\n%%EOF\n"
    )
    path = str(target)
    here = _pack(path, tmp_path, None, file_type="pdf")
    server = _Server()
    there = _pack(path, tmp_path, _placed(path, server), file_type="pdf")
    assert _shown(there) == _shown(here)
    assert "document_info" in {call["reader"] for call in server.calls}
    assert next(e for e in there.entries if e.tool == "document_info").ok


def test_each_reading_on_a_server_waits_its_own_clock_and_a_margin(tmp_path: Path) -> None:
    path = _sample(tmp_path)
    server = _Server()
    _pack(path, tmp_path, _placed(path, server), budget_s=600.0, capa_seconds=420)
    margin = readers.CALL_MARGIN_SECONDS
    # capa its operator's clock, YARA its tool's default; the rest what is
    # left of the pack's budget.
    assert server.waits["capa"] == 420 + margin
    assert server.waits["yara_scan"] == 60 + margin
    assert 600 < (server.waits["pe_info"] or 0) <= 600 + margin
    # With no budget and no clock of its own, a reading waits as long as it takes.
    unbounded = _Server()
    _pack(path, tmp_path, _placed(path, unbounded))
    assert unbounded.waits["pe_info"] is None


def _routing_container(servers: dict[str, Any]) -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(
        config=SimpleNamespace(mcp=SimpleNamespace(servers=servers)),
        server_sample_paths={"analysis": "/data/samples/.work/x.exe"},
        job_key=lambda: JOB,
    )


def test_a_reading_runs_only_on_a_server_that_runs_readings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.core.config import Settings
    from maljan.pipeline import nodes

    servers = dict(Settings(_env_file=None).mcp.servers)
    # The analysis server off, YARA-X switched on at its address: it declares
    # a rule matcher of YARA's kind but runs no reading, so YARA stays here.
    servers["analysis"] = servers["analysis"].model_copy(update={"enabled": False})
    servers["yarax"] = servers["yarax"].model_copy(update={"enabled": True})
    held = nodes.sample_readers(_routing_container(servers), "/w/x.exe")
    assert held.place_of("yara_scan") is None
    assert held.places == {}


def test_where_each_reading_runs_is_resolved_once_per_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.core.config import Settings
    from maljan.pipeline import nodes

    servers = dict(Settings(_env_file=None).mcp.servers)
    servers["analysis"] = servers["analysis"].model_copy(
        update={"transport": "streamable-http", "url": "http://analysis-mcp:8098/mcp"}
    )
    asked: list[str] = []
    real = nodes._declaring_server_key

    def counted(held: Any, tool: str, *, purpose: str) -> str:
        asked.append(tool)
        return real(held, tool, purpose=purpose)

    monkeypatch.setattr(nodes, "_declaring_server_key", counted)
    container = _routing_container(servers)
    first = nodes.sample_readers(container, "/w/x.exe")
    once = len(asked)
    second = nodes.sample_readers(container, "/w/x.exe")
    assert once and len(asked) == once
    assert set(first.places) == set(second.places) and "pe_info" in first.places


@pytest.mark.parametrize("asked", ["../../../../../../../../etc", "/etc"])
def test_capas_rule_directories_are_held_to_the_data_root(
    asked: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(rules, "capa", lambda path, **kwargs: seen.append(kwargs) or {})
    for name in ("rules_dir", "signatures_dir"):
        arguments = {
            "path": "/x",
            "timeout_s": 1,
            "backend": "auto",
            "rules_dir": "data/capa-rules",
            "signatures_dir": "data/capa-signatures",
            name: asked,
        }
        said = readers.serve_reader(
            "capa", arguments, JOB, offered=EVERY_TOOL, confine=lambda p, j: p
        )
        assert said["raised"]["type"] == "PathOutsideRoots", (name, said)
    assert seen == []


def test_capa_reads_a_rule_directory_inside_the_data_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.core.paths import get_project_root

    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(rules, "capa", lambda path, **kwargs: seen.append(kwargs) or {"ok": 1})
    said = readers.serve_reader(
        "capa",
        {
            "path": "/x",
            "timeout_s": 1,
            "backend": "vivisect",
            "rules_dir": "data/yara-x-rules",
            "signatures_dir": "",
        },
        JOB,
        offered=EVERY_TOOL,
        confine=lambda p, j: p,
    )
    assert said == {"value": {"ok": 1}}
    data = (get_project_root() / "data").resolve()
    assert seen[0]["rules_dir"] == str(data / "yara-x-rules")
    assert seen[0]["signatures_dir"] == ""


def test_capas_backend_is_one_the_provider_names(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rules, "capa", lambda path, **kwargs: {"ok": 1})
    said = readers.serve_reader(
        "capa",
        {
            "path": "/x",
            "timeout_s": 1,
            "backend": "something-else",
            "rules_dir": "data/capa-rules",
            "signatures_dir": "",
        },
        JOB,
        offered=EVERY_TOOL,
        confine=lambda p, j: p,
    )
    assert said["raised"]["type"] == "ValueError"


# -- A data directory or a file argument is a string (T-326) ---------------------------


def _capa_arguments(**over: Any) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "path": "/x",
        "timeout_s": 1,
        "backend": "auto",
        "rules_dir": "data/capa-rules",
        "signatures_dir": "data/capa-signatures",
    }
    arguments.update(over)
    return arguments


def test_an_empty_rule_directory_is_refused_and_never_names_the_project_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(rules, "capa", lambda path, **kwargs: seen.append(kwargs) or {})
    said = readers.serve_reader(
        "capa", _capa_arguments(rules_dir=""), JOB, offered=EVERY_TOOL, confine=lambda p, j: p
    )
    assert said["raised"]["type"] == "ValueError"
    assert "rules_dir" in said["raised"]["message"]
    assert seen == []


def test_an_empty_signature_directory_is_the_optional_one_left_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(rules, "capa", lambda path, **kwargs: seen.append(kwargs) or {"ok": 1})
    said = readers.serve_reader(
        "capa", _capa_arguments(signatures_dir=""), JOB, offered=EVERY_TOOL, confine=lambda p, j: p
    )
    assert said == {"value": {"ok": 1}}
    assert seen[0]["signatures_dir"] == ""
    assert READERS["capa"].optional_dirs == ("signatures_dir",)


@pytest.mark.parametrize("value", [None, 0, 7, 1.5, True, ["data/capa-rules"], {"a": 1}])
@pytest.mark.parametrize("name", ["rules_dir", "signatures_dir"])
def test_a_data_directory_that_is_no_string_raises_type_error(
    name: str, value: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(rules, "capa", lambda path, **kwargs: seen.append(kwargs) or {})
    said = readers.serve_reader(
        "capa", _capa_arguments(**{name: value}), JOB, offered=EVERY_TOOL, confine=lambda p, j: p
    )
    assert said["raised"]["type"] == "TypeError", said
    assert seen == []


@pytest.mark.parametrize("value", [None, 0, 3, ["/etc/passwd"], {"path": "/etc/passwd"}])
def test_a_file_argument_that_is_no_string_never_reaches_the_reading(value: Any) -> None:
    # A number is a file descriptor to ``open``: it must not pass unconfined.
    held: list[Any] = []

    def confine(path: str, job: str) -> str:
        held.append(path)
        return path

    said = readers.serve_reader("hashes", {"path": value}, JOB, offered=EVERY_TOOL, confine=confine)
    assert said["raised"]["type"] == "TypeError", said
    assert held == []


def test_an_empty_file_argument_is_held_by_the_confinement_too() -> None:
    held: list[str] = []

    def confine(path: str, job: str) -> str:
        held.append(path)
        raise PermissionError("outside the roots")

    said = readers.serve_reader("hashes", {"path": ""}, JOB, offered=EVERY_TOOL, confine=confine)
    assert held == [""]
    assert said["raised"]["type"] == "PermissionError"


# -- Where each reading ran is recorded with its entry (T-324) --------------------------


def test_an_entry_whose_readings_ran_on_a_server_names_that_server(tmp_path: Path) -> None:
    path = _sample(tmp_path)
    there = _pack(path, tmp_path, _placed(path, _Server()))
    by_tool = {e.tool: e for e in there.entries}
    for tool in ("identify_file", "hashes", "pe_info", "strings", "yara_scan", "capa"):
        assert by_tool[tool].ran_on == ["mcp:analysis"], tool
    assert by_tool[upx.TOOL].ran_on == ["mcp:analysis"]
    # A step that reads nothing of the sample names nowhere.
    assert all(
        not e.ran_on for e in there.entries if e.tool in ("sandbox_status", "api_capability")
    )


def test_an_entry_whose_readings_ran_in_the_worker_dumps_as_it_did(tmp_path: Path) -> None:
    path = _sample(tmp_path)
    here = _pack(path, tmp_path, None)
    assert here.entries
    for entry in here.entries:
        assert entry.ran_on == []
        assert "ran_on" not in entry.model_dump(mode="json")


def test_an_emulator_started_beside_the_pack_names_the_server_it_ran_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.pipeline import triage_pack

    rows = [{"kind": "decoded", "string": "text", "function": "0x401000"}]
    monkeypatch.setattr(emulated_strings, "floss_unavailable", lambda environ=None: None)
    monkeypatch.setattr(
        emulated_strings,
        "recovered",
        lambda path, **_: {"rows": rows, "counts": {"decoded": 1}, "meta": {}},
    )
    monkeypatch.setattr(
        emulated_strings,
        "floss",
        lambda path, limit, found, **_: {"strings": list(found["rows"]), "meta": {}},
    )
    # The host has room for it beside the rest: it starts on a thread of its own.
    monkeypatch.setattr(triage_pack._Pack, "_no_room_beside", lambda self, step: "")
    path = _sample(tmp_path)
    there = _pack(path, tmp_path, _placed(path, _Server()))
    floss = next(e for e in there.entries if e.tool == "floss")
    assert floss.ok and floss.ran_on == ["mcp:analysis"]
    assert "floss" in there.schedules and there.schedules["floss"].startswith("beside")


def test_where_readings_ran_is_noted_per_thread_and_in_every_open_block(tmp_path: Path) -> None:
    import threading

    path = _sample(tmp_path)
    placed = _placed(path, _Server())
    local = SampleReaders(sample_path=path)
    with placed.noting() as outer:
        with placed.noting() as inner:
            placed.read("upx_header", path=path)
        placed.read("hashes", path=path)
        elsewhere: list[Any] = []
        worker = threading.Thread(target=lambda: elsewhere.append(placed.read("hashes", path=path)))
        worker.start()
        worker.join()
    assert inner == ["analysis"]
    assert outer == ["analysis", "analysis"]
    with local.noting() as here:
        local.read("hashes", path=path)
    assert here == [None]


def test_a_mixed_entry_names_the_worker_beside_the_server() -> None:
    from maljan.pipeline.triage_pack import PACK_SOURCE, _ran_on

    assert _ran_on([None, None]) == []
    assert _ran_on([]) == []
    assert _ran_on(["analysis", "analysis"]) == ["mcp:analysis"]
    assert _ran_on(["analysis", None, "network"]) == ["mcp:analysis", PACK_SOURCE, "mcp:network"]


def _isolation_rows(entries: list[Any]) -> dict[str, dict[str, Any]]:
    from maljan.analysis.isolation import isolation_part, sample_readers
    from maljan.core.host_locality import LOCAL

    def route(source: str) -> tuple[str, str, str, str]:
        return ("streamable-http", "analysis-mcp", LOCAL, "")

    counted, unsourced = sample_readers({}, entries, lambda source: None)
    part = isolation_part(
        counted,
        unsourced,
        {},
        worker={"uid": 1000},
        in_process={"pack": "Triage pack"},
        route=route,
        needs_network=lambda source: False,
    )
    return {row["source"]: row for row in part["rows"]}


def test_the_isolation_part_places_a_reading_where_it_ran(tmp_path: Path) -> None:
    from maljan.analysis.isolation import IN_PROCESS, LOCAL_SERVICE

    path = _sample(tmp_path)
    there = _pack(path, tmp_path, _placed(path, _Server()))
    # The emulator's absence was asked of the server too.
    assert next(e for e in there.entries if e.tool == "floss").ran_on == ["mcp:analysis"]
    rows = _isolation_rows(list(there.entries))
    assert rows["mcp:analysis"]["where"] == LOCAL_SERVICE
    assert rows["mcp:analysis"]["calls"] > 0
    # Only a reading the worker ran is the pack's, in process: here, none.
    assert "pack" not in rows
    here = _pack(path, tmp_path, None)
    rows = _isolation_rows(list(here.entries))
    assert rows["pack"]["where"] == IN_PROCESS
    assert "mcp:analysis" not in rows


def test_a_stored_entry_without_the_field_counts_as_it_did() -> None:
    from maljan.analysis.isolation import sample_readers
    from maljan.schemas.evidence import LedgerEntry

    stored = {
        "id": "ev_0001",
        "tool": "pe_info",
        "server": PIPELINE,
        "source": "pack",
        "args": {"path": "/w/x.exe"},
        "seq": 1,
    }
    entry = LedgerEntry.model_validate(stored)
    assert entry.ran_on == []
    assert LedgerEntry.model_validate(stored).model_dump(mode="json") == entry.model_dump(
        mode="json"
    )
    assert "ran_on" not in entry.model_dump(mode="json")
    for given in (stored, entry):
        assert sample_readers({}, [given], lambda source: None, ["/w/x.exe"]) == ({"pack": 1}, 0)
    mixed = {**stored, "ran_on": ["mcp:analysis", "pack"]}
    assert sample_readers({}, [mixed], lambda source: None, ["/w/x.exe"]) == (
        {"mcp:analysis": 1, "pack": 1},
        0,
    )


def test_the_emulators_row_reads_where_it_ran(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.analysis.isolation import IN_PROCESS, LOCAL_SERVICE, isolation_part, sample_readers
    from maljan.analysis.tool_effects import effects_part
    from maljan.core.host_locality import LOCAL

    rows = [{"kind": "decoded", "string": "text", "function": "0x401000"}]
    monkeypatch.setattr(emulated_strings, "floss_unavailable", lambda environ=None: None)
    monkeypatch.setattr(
        emulated_strings,
        "recovered",
        lambda path, **_: {"rows": rows, "counts": {"decoded": 1}, "meta": {}},
    )
    monkeypatch.setattr(
        emulated_strings,
        "floss",
        lambda path, limit, found, **_: {"strings": list(found["rows"]), "meta": {}},
    )
    path = _sample(tmp_path)

    def read_where(result: Any) -> Any:
        entries = list(result.entries)
        counted, unsourced = sample_readers({}, entries, lambda source: None)
        part = isolation_part(
            counted,
            unsourced,
            {},
            worker={"uid": 1000},
            in_process={"pack": "Triage pack"},
            route=lambda source: ("streamable-http", "analysis-mcp", LOCAL, ""),
            needs_network=lambda source: False,
        )
        tools = effects_part(entries, isolation=part)["tools"]
        return next(row for row in tools if row["tool"] == "floss")["read_where"]

    assert read_where(_pack(path, tmp_path, _placed(path, _Server()))) == LOCAL_SERVICE
    assert read_where(_pack(path, tmp_path, None)) == IN_PROCESS
    # Run partly in the worker, it reads as the worker, its least isolated place.
    mixed = _pack(path, tmp_path, _placed(path, _Server()))
    floss = next(e for e in mixed.entries if e.tool == "floss")
    floss.ran_on = ["mcp:analysis", "pack"]
    assert read_where(mixed) == IN_PROCESS
    floss.ran_on = ["pack", "mcp:analysis"]
    assert read_where(mixed) == IN_PROCESS
