"""Fixtures for the agent tests."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def close_the_containers_that_noted_isolation(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """A test's container is closed at its end if its job's servers noted anything.

    A container is closed at the end of its job, and closing it forgets what
    its servers noted of how they were started (``maljan.analysis.isolation``).
    A test that builds a container and reads a tool server through it has no
    job to end, so the notes stayed in the module for the rest of the session
    and a later test asserting that none were held failed in a combined run.
    Only containers whose job holds a note are closed.
    """
    from maljan.analysis import isolation
    from maljan.core.container import ServiceContainer

    built: list[ServiceContainer] = []
    original = ServiceContainer.__init__

    def _init(self: ServiceContainer, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        built.append(self)

    monkeypatch.setattr(ServiceContainer, "__init__", _init)
    yield
    for container in built:
        if isolation.noted(container.job_key()):
            asyncio.run(container.aclose())
