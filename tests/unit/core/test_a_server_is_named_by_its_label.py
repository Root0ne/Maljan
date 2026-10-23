"""A tool server is named to people by its label; its key stays the id.

* A reputation lookup whose facts name no service is attributed to its tool
  server's label when the entry is written; with no label, by its key as
  before; a declared service or display name still comes first.
* A rest names the server's label beside its key, in the record, the event
  and the sentence the report and the console print; a server with no label
  (or a label equal to its key) gives the record it gave before.
* The roster names each labelled server's display name by its key, and
  leaves the key out when no server has one of its own.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.core import config as config_module
from maljan.core import declared_reading
from maljan.core.settings_overrides import build_settings
from maljan.schemas.evidence import build_entry

LOOKUP: dict[str, Any] = {
    "lookup_hash": {
        "kind": "reputation",
        "arguments": {"hash": "sha256"},
        "reputation": {
            "malicious": "/data/malicious",
            "total": "/data/total",
            "rank": 50,
        },
    }
}
ANSWER = '{"data": {"malicious": 3, "total": 60}}'


@pytest.fixture
def servers(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Install settings holding ``mcp.servers`` as given, for the entry's write."""

    def install(entries: dict[str, Any]) -> None:
        monkeypatch.setattr(
            config_module, "_settings_instance", build_settings({"mcp.servers": entries})
        )
        declared_reading.forget()

    yield install
    declared_reading.forget()


def _block(**extra: Any) -> dict[str, Any]:
    return {"enabled": True, "command": "x", "tool_facts": LOOKUP, **extra}


def _service(server: str = "repstub") -> str:
    entry = build_entry(
        entry_id="E1",
        seq=1,
        agent="judge",
        tool="lookup_hash",
        args={"sha256": "a" * 64},
        server=server,
        output=ANSWER,
        source=f"mcp:{server}",
    )
    assert entry.reputation is not None
    assert entry.reputation["malicious"] == 3
    return str(entry.reputation["service"])


def test_a_lookup_is_named_by_its_servers_label(servers: Any) -> None:
    servers({"repstub": _block(label="Stub reputation")})
    assert _service() == "Stub reputation"


def test_a_server_with_no_label_is_named_by_its_key_as_before(servers: Any) -> None:
    servers({"repstub": _block()})
    assert _service() == "repstub"
    servers({"repstub": _block(label="   ")})
    assert _service() == "repstub"


def test_a_declared_service_or_display_name_comes_first(servers: Any) -> None:
    named = {"lookup_hash": {**LOOKUP["lookup_hash"], "display_name": "Declared name"}}
    servers({"repstub": _block(label="Stub reputation", tool_facts=named)})
    assert _service() == "Declared name"
    service = {
        "lookup_hash": {
            **LOOKUP["lookup_hash"],
            "reputation": {**LOOKUP["lookup_hash"]["reputation"], "service": "Its service"},
        }
    }
    servers({"repstub": _block(label="Stub reputation", tool_facts=service)})
    assert _service() == "Its service"


def test_only_a_tool_servers_source_reads_a_label() -> None:
    from maljan.core.reputation import server_label

    assert server_label("provider:ghidra", "ghidra") == "ghidra"
    assert server_label(None, "x") == "x"
    assert server_label("sandbox", None) is None


def _rest(label: str) -> dict[str, Any]:
    from maljan.providers.server_guard import ServerGuard

    said: list[dict[str, Any]] = []
    guard = ServerGuard("repstub", failures_to_open=1, on_open=said.append, label=label)
    guard.failed("timed out")
    return said[0]


def test_a_rest_names_the_label_beside_the_key() -> None:
    from maljan.analysis.run_summary import server_rest_sentence

    record = _rest("Stub reputation")
    assert record["server"] == "repstub" and record["label"] == "Stub reputation"
    assert server_rest_sentence(record).startswith(
        "Tool server Stub reputation (repstub) was rested"
    )


@pytest.mark.parametrize("label", ["", "repstub"])
def test_a_rest_of_a_server_with_no_label_of_its_own_is_as_before(label: str) -> None:
    from maljan.analysis.run_summary import server_rest_sentence

    record = _rest(label)
    assert set(record) == {"server", "failures", "cooldown_s", "reason"}
    assert server_rest_sentence(record).startswith("Tool server repstub was rested")


def test_the_rest_event_carries_the_label_only_where_there_is_one() -> None:
    from maljan.pipeline.events import TOOL_SERVER_RESTED, emit_tool_server_rested

    got: list[tuple[str, dict[str, Any]]] = []

    def sink(kind: str, data: dict[str, Any]) -> None:
        got.append((kind, data))

    row = {"server": "repstub", "failures": 3, "cooldown_s": 60.0, "reason": "timed out"}
    emit_tool_server_rested(sink, row)
    emit_tool_server_rested(sink, {**row, "label": "Stub reputation"})
    assert [kind for kind, _ in got] == [TOOL_SERVER_RESTED, TOOL_SERVER_RESTED]
    assert "label" not in got[0][1]
    assert got[1][1]["label"] == "Stub reputation" and got[1][1]["server"] == "repstub"


def test_the_roster_names_labelled_servers_by_their_key() -> None:
    from maljan.pipeline.events import roster_payload

    settings = build_settings(
        {"mcp.servers": {"repstub": _block(label="Stub reputation"), "plain": _block()}}
    )
    roster = roster_payload({}, settings.agents.definitions, servers=settings.mcp.servers)
    labels = roster["servers"]
    assert labels["repstub"] == "Stub reputation"
    assert "plain" not in labels
    # The built-ins ship labels of their own.
    assert labels["analysis"] == "Analysis MCP"


def test_the_roster_has_no_servers_key_when_no_server_has_a_label() -> None:
    from maljan.pipeline.events import roster_payload

    assert roster_payload({}, {}) == {"agents": [], "stages": []}
    assert roster_payload({}, {}, servers={"plain": {"label": ""}, "same": {"label": "same"}}) == {
        "agents": [],
        "stages": [],
    }
