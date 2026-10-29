"""What a server declares of its own tools outlives the process that listed it.

The platform's own sidecars ship no table of their tools: what the platform
reads of them is what each serves (``core.served_declarations``). A reader that
decides before any server attaches (the pack's servers and steps, the
reputation order, the routed formats, the capability binding) reads what each
declared when it was last listed, kept in a store of its own
(``app.services.served_declarations_store``) and loaded into every process.

* The kept form reads back as the listing did, field by field.
* A load never replaces what this process listed and has not saved; a source
  the store no longer keeps is forgotten.
* A block whose launch identity changed forgets what its source declared; no
  launch identity stands for another, the empty one included; a row listed
  through the shipped launch is read under this host's shipped launch.
* A built-in pointed at its sidecar's container, trusting it, is read through
  that block by every reader that reads the platform's own servers.
* Before the first listing a built-in server is read as any undeclared server
  is, and nothing is refused for it; a job's start lists each trusted server
  nothing is kept for (``providers.served_listing``), at most four at a time,
  and one that could not be listed is not reached again for a while.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from maljan.core import config as config_module
from maljan.core import served_declarations as sd
from maljan.core.config import Settings
from maljan.core.declared_reading import (
    builtin_tools,
    facts_record,
    routed_formats_of,
    shipped_by_name,
    ships_tool,
)
from maljan.core.pack_steps import PackStep, default_steps, effective_steps, server_steps
from maljan.core.tool_declarations import (
    ToolDeclarations,
    ToolFacts,
    launch_identity,
    shipped_launch,
)
from maljan.providers import served_listing
from maljan.providers.served_listing import unlisted as _unlisted

ROOT = Path(__file__).resolve().parents[3]
CAPTURED = json.loads((ROOT / "tests" / "fixtures" / "own_server_tool_facts.json").read_text())


def _fields(facts: Any) -> dict[str, Any]:
    return {t: f.model_dump(mode="json", exclude_defaults=True) for t, f in facts.items()}


def _captured(key: str) -> dict[str, ToolFacts]:
    return {t: ToolFacts.model_validate(f) for t, f in CAPTURED[key].items()}


@pytest.fixture(autouse=True)
def _nothing_resting() -> Iterator[None]:
    served_listing._NOT_BEFORE.clear()
    yield
    served_listing._NOT_BEFORE.clear()


# ---------------------------------------------------------------------------
# The kept form
# ---------------------------------------------------------------------------


def test_the_kept_form_reads_back_as_the_listing_did() -> None:
    listed = {
        "scan": ToolFacts.model_validate(
            {"kind": "strings", "rows": "/s/*", "routed_formats": [], "effects": {"network": True}}
        )
    }
    sd.forget_served()
    sd._UNSAVED.clear()
    sd.install_persisted(json.loads(json.dumps([("mcp:mine", "L", sd.stored_form(listed))])))
    held = sd.served("mcp:mine", "L")
    assert set(held) == {"scan"}
    # Every field the server gave, the one at its default included.
    assert sd._set_fields(held["scan"]) == sd._set_fields(listed["scan"])
    assert "routed_formats" in held["scan"].model_fields_set


def test_a_kept_declaration_is_read_as_leniently_as_a_listing() -> None:
    sd.install_persisted(
        [
            ("mcp:mine", "L", {"t": {"kind": "strings", "not_a_field": 1}, "bad": ["x"]}),
            ("not a row",),
        ]
    )
    held = sd.served("mcp:mine")
    assert set(held) == {"t"} and held["t"].kind == "strings"


def test_the_own_servers_kept_declarations_are_the_capture() -> None:
    # The suite's starting point (``tests/conftest.py``): a deployment whose
    # own servers were listed once.
    for key, tools in CAPTURED.items():
        assert _fields(builtin_tools(key)) == tools


# ---------------------------------------------------------------------------
# Loading, saving, forgetting
# ---------------------------------------------------------------------------


def test_a_load_keeps_what_this_process_listed_and_has_not_saved() -> None:
    sd.register_served("mcp:mine", {"t": ToolFacts(kind="strings")}, "L")
    sd.install_persisted([("mcp:other", "M", {"u": {"kind": "identity"}})])
    assert set(sd.served("mcp:mine")) == {"t"}
    assert set(sd.served("mcp:other")) == {"u"}
    # The own servers' rows were not in that load: the store no longer keeps them.
    assert sd.served("mcp:analysis") == {}


def test_what_was_listed_is_saved_once_and_a_later_listing_again() -> None:
    sd.register_served("mcp:mine", {"t": ToolFacts(kind="strings")}, "L")
    rows = sd.unsaved()
    assert rows == [("mcp:mine", "L", {"t": {"kind": "strings"}}, False)]
    sd.mark_saved(rows)
    assert sd.unsaved() == []
    sd.register_served("mcp:mine", {"t": ToolFacts(kind="identity")}, "L")
    stale = [("mcp:mine", "L", {"t": {"kind": "strings"}}, False)]
    sd.mark_saved(stale)
    # Listed again since that row: still to be saved.
    assert sd.unsaved() == [("mcp:mine", "L", {"t": {"kind": "identity"}}, False)]


def test_a_forgotten_source_is_taken_out_of_the_store() -> None:
    sd.forget_served("mcp:analysis")
    assert ("mcp:analysis", "", None, False) in sd.unsaved()
    assert builtin_tools("analysis") == {}


def test_a_block_pointed_elsewhere_forgets_what_its_server_declared() -> None:
    settings = Settings(_env_file=None)
    moved = settings.mcp.servers["knowledge"].model_copy(update={"cwd": "/elsewhere"})
    launches = {
        "mcp:knowledge": launch_identity(moved),
        "mcp:analysis": launch_identity(settings.mcp.servers["analysis"]),
    }
    assert sd.forget_moved(launches) == ["mcp:knowledge"]
    assert sd.served("mcp:knowledge") == {}
    assert ("mcp:knowledge", "", None, False) in sd.unsaved()
    assert set(sd.served("mcp:analysis")) == set(CAPTURED["analysis"])


def test_no_launch_identity_stands_for_another() -> None:
    sd.register_served("mcp:mine", {"t": ToolFacts(kind="strings")}, "")
    assert sd.served("mcp:mine", "L") == {}
    assert set(sd.served("mcp:mine", "")) == {"t"}
    sd.register_served("mcp:mine", {"t": ToolFacts(kind="strings")}, "L")
    assert sd.served("mcp:mine", "") == {}
    # A row kept under none is never loaded, and never kept.
    sd.install_persisted([("mcp:none", "", {"t": {"kind": "strings"}})])
    assert sd.served("mcp:none") == {}
    sd.register_served("mcp:none", {"t": ToolFacts(kind="strings")}, "")
    assert ("mcp:none", "", None, False) in sd.unsaved()


def test_a_row_listed_through_the_shipped_launch_is_read_under_this_host_s() -> None:
    here = shipped_launch("mcp:analysis")
    assert here
    sd.install_persisted(
        [
            ("mcp:analysis", "another host's spelling", CAPTURED["analysis"], True),
            ("mcp:knowledge", "another host's spelling", CAPTURED["knowledge"], False),
        ]
    )
    assert set(sd.served("mcp:analysis", here)) == set(CAPTURED["analysis"])
    assert sd.served("mcp:knowledge", shipped_launch("mcp:knowledge")) == {}
    # Saved from here, the row says whether its launch is the shipped one.
    sd.forget_served("mcp:analysis")
    sd.register_served("mcp:analysis", _captured("analysis"), here)
    sd.register_served("mcp:knowledge", _captured("knowledge"), "elsewhere")
    shipped = {row[0]: row[3] for row in sd.unsaved()}
    assert shipped == {"mcp:analysis": True, "mcp:knowledge": False}


def test_two_names_of_one_program_in_one_place_are_one_launch(tmp_path: Path) -> None:
    program = tmp_path / "python3.13"
    program.write_text("")
    other = tmp_path / "node"
    other.write_text("")
    for name in ("python", "python3"):
        (tmp_path / name).symlink_to(program.name)
    (tmp_path / "runner").symlink_to(other.name)
    elsewhere = tmp_path / "other"
    elsewhere.mkdir()
    (elsewhere / "python").symlink_to(program)

    def launch(command: Path) -> str:
        block = SimpleNamespace(transport="stdio", command=str(command), args=["s.py"], cwd="s")
        return launch_identity(block)

    assert launch(tmp_path / "python") == launch(tmp_path / "python3")
    # Another program in the same place, or the same one elsewhere, is another launch.
    assert launch(tmp_path / "python") != launch(tmp_path / "runner")
    assert launch(tmp_path / "python") != launch(elsewhere / "python")


# ---------------------------------------------------------------------------
# A built-in pointed at its sidecar's own container
# ---------------------------------------------------------------------------


def test_a_moved_trusted_built_in_is_read_through_its_block_by_every_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.agents.prompt_tools import known_tool_names

    settings = Settings(_env_file=None)
    moved = settings.mcp.servers["analysis"].model_copy(
        update={
            "transport": "streamable-http",
            "url": "http://analysis-mcp:8098/mcp",
            "command": "",
            "args": [],
            "cwd": "",
            "trusts_served_declaration": True,
        }
    )
    settings.mcp.servers["analysis"] = moved
    monkeypatch.setattr(config_module, "_settings_instance", settings)
    # Listed at the container, as its attach lists it; nothing kept for the shipped launch.
    sd.forget_served("mcp:analysis")
    sd.register_served("mcp:analysis", _captured("analysis"), launch_identity(moved))
    assert set(builtin_tools("analysis")) == set(CAPTURED["analysis"])
    assert len(CAPTURED["analysis"]) == 31
    assert ships_tool("mcp:analysis", "carve_payloads")
    assert "carve_payloads" in shipped_by_name()
    assert routed_formats_of("mcp:analysis", "macho_info") == frozenset({"mach-o"})
    assert "carve_payloads" in known_tool_names(settings)
    # The same block untrusted reads only the server's cautious claims.
    settings.mcp.servers["analysis"] = moved.model_copy(update={"trusts_served_declaration": False})
    assert "carve_payloads" not in builtin_tools("analysis")


# ---------------------------------------------------------------------------
# A fresh install, before any listing
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_install() -> Any:
    sd.forget_served()
    sd._UNSAVED.clear()
    return Settings(_env_file=None)


def test_before_its_first_listing_a_built_in_reads_as_an_undeclared_server(
    fresh_install: Settings,
) -> None:
    undeclared = Settings.model_validate(
        {"mcp": {"servers": {"mine": {"command": "x", "trusts_served_declaration": True}}}}
    )
    theirs = ToolDeclarations.from_settings(undeclared)
    ours = ToolDeclarations.from_settings(fresh_install)
    for key in CAPTURED:
        held = ours.source(f"mcp:{key}")
        assert held is not None and dict(held.tools) == {}
        for tool in CAPTURED[key]:
            # Each of its entries records what an undeclared tool's records.
            assert facts_record(f"mcp:{key}", tool, declared=ours) == facts_record(
                "mcp:mine", tool, declared=theirs
            )
            assert routed_formats_of(f"mcp:{key}", tool) == frozenset()
    assert not any(name in shipped_by_name() for name in ("die_scan", "check_hash"))


def test_before_its_first_listing_nothing_is_refused(fresh_install: Settings) -> None:
    assert {s.id: fresh_install.pack_step_problem(s) for s in default_steps()} == {
        s.id: "" for s in default_steps()
    }


def _reader_container(settings: Settings) -> Any:
    from maljan.pipeline import nodes

    servers = dict(settings.mcp.servers)
    servers["analysis"] = servers["analysis"].model_copy(
        update={"transport": "streamable-http", "url": "http://analysis-mcp:8098/mcp"}
    )
    container = SimpleNamespace(
        config=SimpleNamespace(mcp=SimpleNamespace(servers=servers)),
        server_sample_paths={"analysis": "/data/samples/.work/x.exe"},
        job_key=lambda: "job-1",
    )
    return nodes.sample_readers(container, "/w/x.exe").places


def _readers() -> dict[str, Callable[[Settings], Any]]:
    """Each rerouted reader family, read over the settings in force."""
    from maljan.agents.composition import servers_of_capability
    from maljan.agents.prompt_tools import known_tool_names
    from maljan.core import pack_servers
    from maljan.core.reputation import pack_lookups
    from maljan.pipeline.validation import shipped_matcher_names
    from maljan.providers.servers import _handle_tools_in_force
    from maljan.providers.static.declared_prepass import block_declaration

    def die_step_kind(s: Settings) -> str:
        return s._step_tool_kind(PackStep(id="die_scan", server="die", tool="die_scan"))

    def server_step_ids(s: Settings) -> list[str]:
        # The steps the tools give, off or not; a server not listed yet is
        # off by its key, giving none.
        found, off = server_steps(effective_steps(), s.mcp.servers)
        return sorted({*(step.id for step in found), *off} - set(s.mcp.servers))

    return {
        "pack servers": lambda s: pack_servers._decoder_server_key(s.mcp.servers, default_steps()),
        "pack kinds": lambda s: pack_servers._declared_kind("die_scan"),
        "readings": lambda s: sorted(_reader_container(s)),
        "pre-pass": lambda s: block_declaration(s.mcp.servers["die"], "die_scan", "mcp:die"),
        "handle": lambda s: sorted(
            _handle_tools_in_force(SimpleNamespace(name="die", config=s.mcp.servers["die"]))
        ),
        "reputation": lambda s: [
            x.server for x in pack_lookups(s.mcp.servers, ToolDeclarations.from_settings(s))
        ],
        "routed formats": lambda s: sorted(routed_formats_of("mcp:analysis", "pe_info")),
        "capability": lambda s: servers_of_capability(s.mcp.servers, "strings"),
        "known names": lambda s: "die_scan" in known_tool_names(s),
        "matchers": lambda s: "yara-x" in shipped_matcher_names(),
        "step kind": die_step_kind,
        "server steps": server_step_ids,
        "ships": lambda s: ships_tool("mcp:die", "die_scan"),
    }


@pytest.mark.parametrize("family", sorted(_readers()))
def test_each_reader_reads_a_fresh_install_as_undeclared_and_the_listing_once_kept(
    fresh_install: Settings, monkeypatch: pytest.MonkeyPatch, family: str
) -> None:
    monkeypatch.setattr(config_module, "_settings_instance", fresh_install)
    read = _readers()[family]
    before = read(fresh_install)
    for key in CAPTURED:
        block = fresh_install.mcp.servers[key]
        sd.register_served(f"mcp:{key}", _captured(key), launch_identity(block))
    if family == "readings":
        # The readings' server is reached at an address, listed there.
        moved = fresh_install.mcp.servers["analysis"].model_copy(
            update={"transport": "streamable-http", "url": "http://analysis-mcp:8098/mcp"}
        )
        sd.register_served("mcp:analysis", _captured("analysis"), launch_identity(moved))
    after = read(fresh_install)
    assert before != after, family
    assert before in ("", None, [], False, {}) or family == "reputation", (family, before)


def test_a_job_lists_each_trusted_server_nothing_is_kept_for(
    fresh_install: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.providers import server_probe

    monkeypatch.setattr(served_listing, "unlisted", _unlisted)
    reached: list[str] = []

    async def _handshake(block: Any, key: str, **kwargs: Any) -> Any:
        reached.append(key)
        if key == "network":
            raise TimeoutError("no MCP handshake")
        sd.register_served(f"mcp:{key}", _captured(key), launch_identity(block))
        return [], None

    monkeypatch.setattr(server_probe, "handshake", _handshake)
    settings = fresh_install
    enabled = {k for k, b in settings.mcp.servers.items() if b.enabled}
    listed = asyncio.run(served_listing.list_unlisted(settings))
    # Only the enabled servers whose block trusts their declaration.
    assert set(reached) == enabled & set(CAPTURED)
    assert "virustotal" not in reached
    # One that could not be reached is left undeclared, never refused.
    assert "network" not in listed and builtin_tools("network") == {}
    for key in listed:
        assert _fields(builtin_tools(key)) == CAPTURED[key]
    # Listed now, nothing is listed again; the one not reached rests a while.
    reached.clear()
    assert asyncio.run(served_listing.list_unlisted(settings)) == []
    assert reached == []
    monkeypatch.setattr(served_listing, "RETRY_SECONDS", 0.0)
    served_listing._NOT_BEFORE.clear()
    asyncio.run(served_listing.list_unlisted(settings))
    assert reached == ["network"]


def test_a_listing_that_declares_nothing_rests_too_and_its_rest_ends(
    fresh_install: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.providers import server_probe

    monkeypatch.setattr(served_listing, "unlisted", _unlisted)
    reached: list[str] = []

    async def _handshake(block: Any, key: str, **kwargs: Any) -> Any:
        reached.append(key)
        return [], None

    monkeypatch.setattr(server_probe, "handshake", _handshake)
    now = [1000.0]
    monkeypatch.setattr(served_listing.time, "monotonic", lambda: now[0])
    asyncio.run(served_listing.list_unlisted(fresh_install))
    first = sorted(reached)
    assert first
    reached.clear()
    asyncio.run(served_listing.list_unlisted(fresh_install))
    assert reached == []
    now[0] += served_listing.RETRY_SECONDS + 1
    asyncio.run(served_listing.list_unlisted(fresh_install))
    assert sorted(reached) == first


def test_at_most_four_servers_are_listed_at_once(
    fresh_install: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.providers import server_probe

    for key in CAPTURED:
        fresh_install.mcp.servers[key].enabled = True
    monkeypatch.setattr(served_listing, "unlisted", _unlisted)
    running = [0]
    most = [0]

    async def _handshake(block: Any, key: str, **kwargs: Any) -> Any:
        running[0] += 1
        most[0] = max(most[0], running[0])
        await asyncio.sleep(0.01)
        running[0] -= 1
        return [], None

    monkeypatch.setattr(server_probe, "handshake", _handshake)
    asyncio.run(served_listing.list_unlisted(fresh_install))
    assert most[0] == served_listing.AT_ONCE == 4


def test_all_the_listings_together_keep_within_one_budget(
    fresh_install: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.providers import server_probe

    monkeypatch.setattr(served_listing, "unlisted", _unlisted)
    monkeypatch.setattr(served_listing, "AT_ONCE", 1)
    now = [0.0]
    monkeypatch.setattr(served_listing.time, "monotonic", lambda: now[0])
    budgets: list[float] = []

    async def _handshake(block: Any, key: str, *, budget: float, **kwargs: Any) -> Any:
        budgets.append(budget)
        now[0] += 20.0  # each one takes twenty seconds and lists nothing
        return [], None

    monkeypatch.setattr(server_probe, "handshake", _handshake)
    wanted = served_listing.unlisted(fresh_install)
    assert len(wanted) >= 3
    asyncio.run(served_listing.list_unlisted(fresh_install, budget=30.0))
    # One deadline for all: the second is given what is left, the rest never start.
    assert budgets == [30.0, 10.0]
    # Those never tried are not rested: the next job tries them.
    assert len(served_listing._NOT_BEFORE) == 2
