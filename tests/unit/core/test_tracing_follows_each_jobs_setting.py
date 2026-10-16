"""Tracing follows each job's setting, and the environment the process started with is kept.

The tracing library reads the process environment, which outlives a job. A
job with ``langchain_tracing_v2`` on sets the variables; the next job with it
off puts them back as they were, and never clears what the operator's own
environment set. An environment that traces with the setting off is warned
about, and read as tracing by the run's disclosure block.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest

from maljan.core import tracing
from maljan.core.tracing import apply_tracing_setting, tracing_in_environment


@pytest.fixture(autouse=True)
def _nothing_saved() -> Iterator[None]:
    tracing.forget_saved_environment()
    yield
    tracing.forget_saved_environment()


def test_a_job_with_the_setting_off_undoes_what_an_earlier_job_set() -> None:
    environ: dict[str, str] = {"PATH": "/bin"}

    first = apply_tracing_setting(True, project="maljan", api_key="k", environ=environ)
    assert first is True
    assert environ["LANGCHAIN_TRACING_V2"] == "true"
    assert environ["LANGCHAIN_PROJECT"] == "maljan"

    second = apply_tracing_setting(False, environ=environ)

    assert second is False
    assert environ == {"PATH": "/bin"}
    assert tracing_in_environment(environ) is False


def test_two_jobs_on_then_one_off_puts_back_what_the_environment_held_first() -> None:
    environ = {"LANGCHAIN_PROJECT": "operators-own"}

    apply_tracing_setting(True, project="first", environ=environ)
    apply_tracing_setting(True, project="second", environ=environ)
    apply_tracing_setting(False, environ=environ)

    assert environ == {"LANGCHAIN_PROJECT": "operators-own"}


def test_the_operators_own_tracing_is_never_cleared_and_is_warned_about(
    caplog: pytest.LogCaptureFixture,
) -> None:
    environ = {"LANGSMITH_TRACING": "true"}

    with caplog.at_level(logging.WARNING):
        traced = apply_tracing_setting(False, environ=environ)

    assert traced is True
    assert environ == {"LANGSMITH_TRACING": "true"}
    assert any("tracing is on through the process environment" in r.message for r in caplog.records)


@pytest.mark.parametrize(
    ("environ", "traced"),
    [
        ({}, False),
        ({"LANGCHAIN_TRACING_V2": "true"}, True),
        ({"LANGSMITH_TRACING_V2": "true"}, True),
        ({"LANGSMITH_TRACING": "true"}, True),
        ({"LANGCHAIN_TRACING": "true"}, True),
        # The first non-empty variable decides, the V2 names before the others.
        ({"LANGSMITH_TRACING_V2": "false", "LANGCHAIN_TRACING_V2": "true"}, False),
        ({"LANGSMITH_TRACING_V2": " ", "LANGCHAIN_TRACING_V2": "true"}, True),
        ({"LANGCHAIN_TRACING_V2": "false", "LANGSMITH_TRACING": "true"}, False),
        ({"LANGCHAIN_TRACING_V2": "True"}, False),
    ],
)
def test_the_environment_is_read_as_the_tracing_library_reads_it(
    environ: dict[str, str], traced: bool
) -> None:
    assert tracing_in_environment(environ) is traced


def test_the_reading_agrees_with_the_library(monkeypatch: pytest.MonkeyPatch) -> None:
    from langsmith import utils

    for name in (*tracing.TRACING_V2_NAMES, *tracing.TRACING_NAMES):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LANGCHAIN_TRACING", "true")
    utils.get_env_var.cache_clear()
    try:
        assert tracing_in_environment() is (utils.tracing_is_enabled() is True)
    finally:
        utils.get_env_var.cache_clear()


def test_the_container_switches_tracing_through_the_one_place(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    from maljan.core.container import ServiceContainer

    calls: list[tuple[bool, dict[str, str]]] = []

    def _applied(enabled: bool, **kwargs: str) -> bool:
        calls.append((enabled, kwargs))
        return enabled

    monkeypatch.setattr(tracing, "apply_tracing_setting", _applied)
    on = SimpleNamespace(
        config=SimpleNamespace(
            langchain_tracing_v2=True, langchain_project="p", langchain_api_key=None
        )
    )
    off = SimpleNamespace(config=SimpleNamespace(langchain_tracing_v2=False))

    ServiceContainer._configure_langsmith(on)  # type: ignore[arg-type]
    ServiceContainer._configure_langsmith(off)  # type: ignore[arg-type]

    assert calls == [(True, {"project": "p", "api_key": ""}), (False, {})]
