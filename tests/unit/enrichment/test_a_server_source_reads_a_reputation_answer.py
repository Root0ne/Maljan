"""A server source that declares no record reads its tool's answer as a reputation answer.

Through the paths the tool's declaration in force gives, else by the answer's
shape; a source that declares one, and every REST source, reads its record
as it always did.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.core.tool_declarations import ReputationFacts, ToolFacts
from maljan.enrichment.declared import (
    EnrichmentSource,
    read_reputation_record,
    validate_sources,
)

REST = {
    "kinds": ["domain"],
    "requests": {"domain": {"url": "https://rep.acme-labs.net/{value}"}},
    "record": [{"name": "malicious", "path": "/bad", "read": "count"}],
}


def _server(**extra: Any) -> dict[str, Any]:
    return {"kinds": ["domain", "ip"], "server": "acme", **extra}


def test_a_server_source_may_name_no_tool_and_no_record() -> None:
    assert validate_sources({"acme": _server()}) == {}
    assert validate_sources({"acme": _server(tool="lookup")}) == {}
    assert (
        validate_sources({"acme": _server(malicious_when=[{"field": "malicious", "at_least": 1}])})
        == {}
    )


@pytest.mark.parametrize(
    ("entry", "says"),
    [
        (_server(arguments={"ip": "addr"}), "name the tool too"),
        (_server(malicious_when=[{"field": "abuse", "at_least": 1}]), "abuse"),
        (_server(answer_root="/data"), "declare record"),
        ({**REST, "record": []}, "a REST source needs record"),
        ({"kinds": ["ip"], "tool": "lookup"}, "a server source needs server"),
    ],
)
def test_a_declaration_that_cannot_work_is_refused_in_words(
    entry: dict[str, Any], says: str
) -> None:
    errors = validate_sources({"acme": entry})
    assert says in errors.get("acme", "")


SOURCE = EnrichmentSource.model_validate(_server())


def test_an_answer_is_read_through_the_paths_its_declaration_gives() -> None:
    facts = ToolFacts(
        kind="indicator_reputation",
        reputation=ReputationFacts(
            malicious="/r/bad", suspicious="/r/odd", total="/r/all", labels=("/r/names",)
        ),
    )
    answer = {"r": {"bad": 2, "odd": 0, "all": 70, "names": ["one", "two"]}, "stats": {"x": 9}}
    assert read_reputation_record("acme", SOURCE, facts, answer) == {
        "source": "acme",
        "malicious": 2,
        "suspicious": 0,
        "total": 70,
        "labels": ["one", "two"],
    }


def test_an_answer_is_read_by_its_shape_where_its_declaration_gives_no_path() -> None:
    answer = '{"service": "Relayed", "stats": {"malicious": 0, "harmless": 3, "undetected": 1}}'
    assert read_reputation_record("acme", SOURCE, None, answer) == {
        "source": "acme",
        "malicious": 0,
        "total": 4,
        "service": "Relayed",
    }


@pytest.mark.parametrize("answer", [{}, {"note": "nothing known"}, "no record", [1, 2]])
def test_an_answer_that_says_nothing_is_no_record(answer: Any) -> None:
    assert read_reputation_record("acme", SOURCE, None, answer) is None
