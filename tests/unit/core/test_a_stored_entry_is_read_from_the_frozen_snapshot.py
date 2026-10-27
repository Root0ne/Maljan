"""A stored entry with no source and no facts is read from the frozen snapshot alone.

The legacy reading of such an entry (every entry of a run stored before
entries recorded their source) once looked its bare tool name up in the
declarations the platform ships. It now reads one versioned snapshot of what
those gave (``core.legacy_tool_facts``), so the shipped declarations can
change, or go, without changing how a stored run reads.

Held here: the snapshot is the pinned file; it equals the shipped tables tool
by tool and field by field, and each consumer's legacy names; and a shipped
table emptied, given other kinds, or reshaped with each kind kept leaves every
source-less entry reading as before, and a stored run's rule matchers named
as the snapshot names them.

The snapshot is never regenerated. The tests that hold it equal to the shipped
tables (the frozen-equals-live ones below) hold only while the shipped tables
stand as they were cut: the later change that makes a shipped table diverge
deletes those tests, it never updates them or the snapshot.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator, Mapping
from types import SimpleNamespace
from typing import Any

import pytest

from maljan.analysis import evidence_roots
from maljan.core import builtin_declarations as shipped
from maljan.core import declared_reading, legacy_tool_facts
from maljan.core.builtin_declarations import CONSUMER_KINDS
from maljan.core.paths import resolve_data
from maljan.core.tool_declarations import ToolFacts
from maljan.pipeline import validation
from maljan.reporting import legacy_tool_names as legacy
from maljan.reporting import tool_kinds

_FIELDS = tuple(ToolFacts.model_fields)


def _table_legacy_names(consumer: str) -> frozenset[str]:
    """A consumer's ``legacy_names`` as the shipped table gives them (``same_as`` followed)."""
    spec = CONSUMER_KINDS[consumer]
    spec = CONSUMER_KINDS[spec["same_as"]] if "same_as" in spec else spec
    return frozenset(spec.get("legacy_names", ()))


def test_the_snapshot_is_the_pinned_file() -> None:
    raw = resolve_data(legacy_tool_facts.SNAPSHOT_PATH).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == legacy_tool_facts.SNAPSHOT_SHA256


def test_a_snapshot_whose_digest_is_not_the_pinned_one_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_tool_facts._document.cache_clear()
    try:
        monkeypatch.setattr(legacy_tool_facts, "SNAPSHOT_SHA256", "0" * 64)
        with pytest.raises(ValueError, match="not the frozen snapshot"):
            legacy_tool_facts._document()
    finally:
        legacy_tool_facts._document.cache_clear()


def test_the_snapshot_names_every_tool_the_platform_s_own_sources_declare() -> None:
    # The own servers' declarations are kept per tool, in no order of a table.
    assert set(legacy_tool_facts.facts_by_name()) == set(declared_reading.shipped_by_name())


@pytest.mark.parametrize("tool", sorted(declared_reading.shipped_by_name()))
def test_each_tool_s_frozen_facts_are_its_shipped_facts_field_by_field(tool: str) -> None:
    frozen = legacy_tool_facts.facts_by_name()[tool]
    live = declared_reading.shipped_by_name()[tool]
    assert frozen.model_fields_set == live.model_fields_set
    differ = [name for name in _FIELDS if getattr(frozen, name) != getattr(live, name)]
    assert differ == []


@pytest.mark.parametrize("consumer", sorted(CONSUMER_KINDS))
def test_each_consumer_s_frozen_legacy_names_are_its_table_s(consumer: str) -> None:
    assert legacy_tool_facts.legacy_names(consumer) == _table_legacy_names(consumer)


def test_the_snapshot_holds_legacy_names_only_for_a_consumer_the_tables_name() -> None:
    held = legacy_tool_facts._document()["legacy_names"]
    assert set(held) <= set(CONSUMER_KINDS)
    assert all(held[consumer] for consumer in held)


# ---------------------------------------------------------------------------
# A changed shipped table leaves the legacy reading as it was
# ---------------------------------------------------------------------------


def _forget_shipped() -> None:
    declared_reading._BY_NAME[:] = [-1, None]
    declared_reading._BUILTIN_TOOLS.clear()
    declared_reading._shipped_tools_by_source.cache_clear()
    declared_reading._in_process_blocks.cache_clear()


def _reading() -> dict[str, Any]:
    """How every name the snapshot or a consumer table holds reads for a source-less entry."""
    names = set(legacy_tool_facts.facts_by_name())
    for consumer in CONSUMER_KINDS:
        names |= legacy_tool_facts.legacy_names(consumer)
    consumers = sorted(CONSUMER_KINDS)
    out: dict[str, Any] = {}
    for name in sorted(names):
        entry = {"tool": name}
        facts = declared_reading.facts_of(entry)
        out[name] = (
            facts.model_dump(mode="json") if facts is not None else None,
            declared_reading.kind_of(entry),
            declared_reading.kind_free_facts(entry).model_dump(mode="json"),
            tuple(c for c in consumers if declared_reading.reads_as(entry, c)),
            tool_kinds.kind_of(entry),
            tuple(c for c in legacy.TABLES if tool_kinds.is_of(entry, c)),
            tuple(
                c
                for c in consumers
                if c not in legacy.TABLES
                and "kinds" in CONSUMER_KINDS[c]
                and legacy.in_table(c, name)
            ),
            evidence_roots.reading_branch(entry),
        )
    return out


def _emptied(declaration: Callable[[str], dict[str, Any]]) -> Callable[[str], dict[str, Any]]:
    return lambda key: {**declaration(key), "tool_facts": {}}


def _rekinded(declaration: Callable[[str], dict[str, Any]]) -> Callable[[str], dict[str, Any]]:
    def changed(key: str) -> dict[str, Any]:
        held: Mapping[str, Any] = declaration(key).get("tool_facts") or {}
        return {**declaration(key), "tool_facts": {name: {"kind": "reference"} for name in held}}

    return changed


def _reshape(name: str, raw: Any) -> ToolFacts:
    """``raw``'s facts with their kind kept and every shape and naming field changed."""
    facts = raw if isinstance(raw, ToolFacts) else ToolFacts.model_validate(raw)
    return facts.model_copy(
        update={
            "rows": "/reshaped/*",
            "places": {"reshaped": "/reshaped"},
            "display_name": f"Reshaped {name}",
            "source": f"reshaped_{name}",
            "arguments": {"reshaped": "reshaped"},
        }
    )


def _reshaped(declaration: Callable[[str], dict[str, Any]]) -> Callable[[str], dict[str, Any]]:
    def changed(key: str) -> dict[str, Any]:
        held: Mapping[str, Any] = declaration(key).get("tool_facts") or {}
        return {
            **declaration(key),
            "tool_facts": {name: _reshape(name, raw) for name, raw in held.items()},
        }

    return changed


def _serve_changed(change: Callable[..., Any]) -> None:
    """What the platform's own servers serve, changed as ``change`` changes the shipped tables."""
    from maljan.core import served_declarations

    for source, (launch, facts) in dict(served_declarations._SERVED).items():
        if change is _emptied:
            served_declarations.forget_served(source)
        elif change is _reshaped:
            reshaped = {n: _reshape(n, f) for n, f in facts.items()}
            served_declarations.register_served(source, reshaped, launch)
        else:
            rekinded = {n: ToolFacts(kind="reference") for n in facts}
            served_declarations.register_served(source, rekinded, launch)


def _in_process(change: Callable[..., Any]) -> Callable[[], dict[Any, Any]]:
    """The in-process sources as ``change`` leaves them: reshaped in place, else none."""
    if change is not _reshaped:
        return lambda: {}
    real = shipped.in_process_declarations

    def changed() -> dict[Any, Any]:
        return {
            ref: cfg.model_copy(
                update={"tool_facts": {n: _reshape(n, f) for n, f in cfg.tool_facts.items()}}
            )
            for ref, cfg in real().items()
        }

    return changed


@pytest.fixture
def _shipped_restored() -> Iterator[None]:
    _forget_shipped()
    yield
    _forget_shipped()


@pytest.mark.usefixtures("_shipped_restored")
@pytest.mark.parametrize(
    "change", [_emptied, _rekinded, _reshaped], ids=["emptied", "rekinded", "reshaped"]
)
def test_a_changed_shipped_table_leaves_a_source_less_entry_reading_as_before(
    monkeypatch: pytest.MonkeyPatch,
    change: Callable[[Callable[[str], dict[str, Any]]], Callable[[str], dict[str, Any]]],
) -> None:
    before = _reading()
    live_before = dict(declared_reading.shipped_by_name())
    with monkeypatch.context() as patch:
        patch.setattr(shipped, "server_declaration", change(shipped.server_declaration))
        patch.setattr(shipped, "provider_declaration", change(shipped.provider_declaration))
        patch.setattr(shipped, "in_process_declarations", _in_process(change))
        _serve_changed(change)
        for spec in CONSUMER_KINDS.values():
            if "legacy_names" in spec:
                patch.setitem(spec, "legacy_names", [])
        _forget_shipped()
        # The shipped tables did change: the live reading sees it.
        assert dict(declared_reading.shipped_by_name()) != live_before
        assert not any(_table_legacy_names(c) for c in CONSUMER_KINDS)
        assert _reading() == before


# ---------------------------------------------------------------------------
# A stored run's rule matchers are the ones the snapshot names
# ---------------------------------------------------------------------------


def _stored_entry(tool: str) -> SimpleNamespace:
    return SimpleNamespace(tool=tool, source=None, facts=None)


def test_a_stored_run_names_its_rule_matchers_as_the_snapshot_does_whatever_ships_now(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stored = validation._stored_matcher_names()
    assert stored
    # A shipped matcher renamed: the names built from the live tables are another.
    monkeypatch.setattr(validation, "shipped_matcher_names", lambda: ("renamed matcher",))
    named = set(validation.matcher_names([_stored_entry("an_unknown_tool")]))
    assert stored <= named
    for name in stored:
        assert validation._says_only_that_a_rule_matched(
            f"{name} matched Loader_Generic", tuple(sorted(named))
        )


def test_a_run_with_no_stored_entry_names_no_frozen_matcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(validation, "shipped_matcher_names", lambda: ("renamed matcher",))
    declared = SimpleNamespace(tool="an_unknown_tool", source="mcp:somewhere", facts={"v": 1})
    assert validation.matcher_names([declared]) == ("renamed matcher",)


def test_a_consumer_the_platform_does_not_name_is_refused() -> None:
    with pytest.raises(KeyError):
        legacy_tool_facts.legacy_names("no_such_consumer")
    with pytest.raises(KeyError):
        declared_reading.legacy_names("no_such_consumer")


@pytest.mark.usefixtures("_shipped_restored")
def test_a_stored_run_reads_produced_layers_by_the_argument_names_the_snapshot_declares(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.analysis import coverage

    frozen = {
        str(name)
        for facts in legacy_tool_facts.facts_by_name().values()
        if (name := facts.arguments.get(coverage.LAYER_ROLE))
    }
    assert frozen
    with monkeypatch.context() as patch:
        patch.setattr(shipped, "server_declaration", _emptied(shipped.server_declaration))
        patch.setattr(shipped, "provider_declaration", _emptied(shipped.provider_declaration))
        patch.setattr(shipped, "in_process_declarations", lambda: {})
        _serve_changed(_emptied)
        _forget_shipped()
        assert frozen <= coverage._layer_names([_stored_entry("an_unknown_tool")])
        declared = SimpleNamespace(tool="an_unknown_tool", source="mcp:somewhere", facts={"v": 1})
        assert not frozen & coverage._layer_names([declared])


@pytest.mark.usefixtures("_shipped_restored")
def test_a_live_entry_with_stored_facts_keeps_its_reading_branch_when_shipped_places_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [
        SimpleNamespace(
            tool=name,
            source="mcp:somewhere",
            facts=declared_reading.stored_record(facts),
            ok=True,
        )
        for name, facts in legacy_tool_facts.facts_by_name().items()
        if facts.rows and facts.places
    ]
    assert entries
    before = [evidence_roots.reading_branch(entry) for entry in entries]
    with monkeypatch.context() as patch:
        patch.setattr(shipped, "server_declaration", _reshaped(shipped.server_declaration))
        patch.setattr(shipped, "provider_declaration", _reshaped(shipped.provider_declaration))
        patch.setattr(shipped, "in_process_declarations", _in_process(_reshaped))
        _serve_changed(_reshaped)
        _forget_shipped()
        assert all(
            f.places == {"reshaped": "/reshaped"}
            for f in declared_reading.shipped_by_name().values()
        )
        assert [evidence_roots.reading_branch(entry) for entry in entries] == before
