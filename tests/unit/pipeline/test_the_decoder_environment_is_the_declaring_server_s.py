"""The pack's decoder reads the environment of the server its step declares.

* As shipped, the decoded-strings step stands in for the analysis server's
  tool, and that server's ``env`` is read, as before.
* Another server that declares the step's tool, first in ``mcp.servers``, is
  the one read: no server is found by its key.
* A step that names its own server reads that server.
* A switched-off step still reads its shipped declaration's server.
* No server declaring the tool leaves this process's environment.
* Among several declaring servers an enabled one is read before a switched-off
  one, and a server declaring only a tool of the step's tool's kind qualifies
  after the ones naming the tool.
* The in-process steps run with the server switched off, so a switched-off
  server that alone declares the tool still lends its ``env``, and that is
  logged.
* Several qualifying servers give the first, and the choice is logged once.
* The UPX carve's environment is the unpack-declaring server's, apart from
  the decoder's: an operator who moves the decoded-strings step to its own
  server leaves the carve staging where that server's file tools read.
* The capa step reads the server declaring ``capa`` the same way, so the job
  directory its runs go in is under the base that server's sweep reaches.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from maljan.core.pack_steps import PackStep, default_steps, effective_steps
from maljan.pipeline import nodes


def _server(
    tools: tuple[str, ...],
    env: dict[str, str] | None = None,
    *,
    enabled: bool = True,
    kinds: dict[str, str] | None = None,
) -> Any:
    facts = {tool: SimpleNamespace(kind=(kinds or {}).get(tool, "")) for tool in tools}
    return SimpleNamespace(tool_facts=facts, env=env or {}, enabled=enabled)


def _container(servers: dict[str, Any]) -> Any:
    return SimpleNamespace(config=SimpleNamespace(mcp=SimpleNamespace(servers=servers)))


def test_as_shipped_the_analysis_servers_env_is_read() -> None:
    from maljan.core.config import Settings

    servers = Settings(_env_file=None).mcp.servers
    assert nodes._decoder_server_key(servers, default_steps()) == "analysis"
    assert nodes._carve_server_key(servers) == "analysis"


def test_the_first_server_declaring_the_steps_tool_is_read_whatever_its_key() -> None:
    servers = {
        "lookups": _server(("get_ip_report",), {"X": "no"}),
        "workbench": _server(("floss", "capa"), {"MALJAN_FLOSS_PATH": "/opt/build"}),
        "other": _server(("floss",), {"MALJAN_FLOSS_PATH": "/elsewhere"}),
    }
    environ = nodes._decoder_server_environ(_container(servers), default_steps())
    assert environ["MALJAN_FLOSS_PATH"] == "/opt/build"
    assert environ.get("X") != "no"


def test_a_step_naming_its_server_reads_that_server() -> None:
    steps = (
        PackStep(
            id="floss", server="remote", tool="decode", renderer="emulated_strings", formats=("pe",)
        ),
    )
    servers = {"analysis": _server(("floss",)), "remote": _server(("decode",))}
    assert nodes._decoder_server_key(servers, steps) == "remote"


def test_a_switched_off_step_reads_its_shipped_declarations_server() -> None:
    steps = effective_steps([{"id": "floss", "enabled": False}])
    assert all(step.id != "floss" for step in steps)
    servers = {"workbench": _server(("floss",), {"MALJAN_STAGING_DIR": "/stage"})}
    assert nodes._decoder_server_environ(_container(servers), steps)["MALJAN_STAGING_DIR"] == (
        "/stage"
    )


def test_no_declaring_server_leaves_this_processs_environment(monkeypatch: Any) -> None:
    monkeypatch.setenv("MALJAN_FLOSS_PATH", "/own")
    servers = {"lookups": _server(("get_ip_report",), {"MALJAN_FLOSS_PATH": "/not-this"})}
    environ = nodes._decoder_server_environ(_container(servers), default_steps())
    assert environ["MALJAN_FLOSS_PATH"] == "/own"


def test_an_enabled_server_is_read_before_a_switched_off_one() -> None:
    servers = {
        "old": _server(("floss", "unpack_upx"), {"MALJAN_STAGING_DIR": "/old"}, enabled=False),
        "analysis": _server(("floss", "unpack_upx"), {"MALJAN_STAGING_DIR": "/shared"}),
    }
    container = _container(servers)
    assert nodes._decoder_server_environ(container, default_steps())["MALJAN_STAGING_DIR"] == (
        "/shared"
    )
    assert nodes._carve_server_environ(container)["MALJAN_STAGING_DIR"] == "/shared"


def test_a_switched_off_server_alone_still_lends_its_env(monkeypatch: Any) -> None:
    from maljan.core.config import Settings

    said: list[str] = []
    monkeypatch.setattr(nodes.logger, "info", lambda msg, *args: said.append(msg % args))
    settings = Settings(_env_file=None)
    analysis = settings.mcp.servers["analysis"]
    analysis.enabled = False
    analysis.env = {"MALJAN_STAGING_DIR": "/shared"}
    container = SimpleNamespace(config=settings)
    steps = effective_steps(())
    assert nodes._decoder_server_environ(container, steps)["MALJAN_STAGING_DIR"] == "/shared"
    assert nodes._carve_server_environ(container)["MALJAN_STAGING_DIR"] == "/shared"
    assert len(said) == 2 and all("switched off" in line for line in said)


def test_a_server_declaring_the_tools_kind_qualifies_after_one_naming_it() -> None:
    kind_only = _server(("unwrap",), {"MALJAN_STAGING_DIR": "/kind"}, kinds={"unwrap": "unpack"})
    assert nodes._carve_server_key({"unpacker": kind_only}) == "unpacker"
    named = _server(("unpack_upx",), {"MALJAN_STAGING_DIR": "/named"})
    assert nodes._carve_server_key({"unpacker": kind_only, "analysis": named}) == "analysis"


def test_several_qualifying_servers_give_the_first_and_say_so_once(monkeypatch: Any) -> None:
    said: list[str] = []
    monkeypatch.setattr(nodes.logger, "info", lambda msg, *args: said.append(msg % args))
    servers = {
        "first": _server(("unpack_upx",), {"MALJAN_STAGING_DIR": "/first"}),
        "second": _server(("unpack_upx",), {"MALJAN_STAGING_DIR": "/second"}),
    }
    assert nodes._carve_server_environ(_container(servers))["MALJAN_STAGING_DIR"] == "/first"
    assert len(said) == 1
    assert "'first'" in said[0] and "'second'" in said[0]


def test_moving_the_decoded_strings_step_leaves_the_carve_where_it_was() -> None:
    steps = (
        PackStep(
            id="floss", server="emu", tool="unwind", renderer="emulated_strings", formats=("pe",)
        ),
    )
    servers = {
        "analysis": _server(("floss", "unpack_upx"), {"MALJAN_STAGING_DIR": "/shared"}),
        "emu": _server(("unwind",), {"MALJAN_STAGING_DIR": "/emu-only"}),
    }
    container = _container(servers)
    assert nodes._decoder_server_environ(container, steps)["MALJAN_STAGING_DIR"] == "/emu-only"
    assert nodes._carve_server_environ(container)["MALJAN_STAGING_DIR"] == "/shared"


def test_the_capa_step_reads_the_server_declaring_capa() -> None:
    from maljan.core.config import Settings

    shipped = Settings(_env_file=None).mcp.servers
    key = nodes._step_server_key(shipped, default_steps(), nodes._CAPA_RENDERER, purpose="capa")
    assert key == "analysis"
    servers = {
        "decoder": _server(("floss",), {"MALJAN_STAGING_DIR": "/decoder"}),
        "rules": _server(("capa",), {"MALJAN_STAGING_DIR": "/rules"}),
    }
    environ = nodes._capa_server_environ(_container(servers), default_steps())
    assert environ["MALJAN_STAGING_DIR"] == "/rules"
