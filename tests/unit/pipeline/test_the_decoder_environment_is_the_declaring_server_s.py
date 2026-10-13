"""The pack's decoder reads the environment of the server its step declares.

* As shipped, the decoded-strings step stands in for the analysis server's
  tool, and that server's ``env`` is read, as before.
* Another server that declares the step's tool, first in ``mcp.servers``, is
  the one read: no server is found by its key.
* A step that names its own server reads that server.
* A switched-off step still reads its shipped declaration's server.
* No server declaring the tool leaves this process's environment.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from maljan.core.pack_steps import PackStep, default_steps, effective_steps
from maljan.pipeline import nodes


def _server(tools: tuple[str, ...], env: dict[str, str] | None = None) -> Any:
    return SimpleNamespace(tool_facts={tool: {} for tool in tools}, env=env or {})


def _container(servers: dict[str, Any]) -> Any:
    return SimpleNamespace(config=SimpleNamespace(mcp=SimpleNamespace(servers=servers)))


def test_as_shipped_the_analysis_servers_env_is_read() -> None:
    from maljan.core.config import Settings

    servers = Settings(_env_file=None).mcp.servers
    assert nodes._decoder_server_key(servers, default_steps()) == "analysis"


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
