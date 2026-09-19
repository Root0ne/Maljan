"""The ATT&CK index is process-wide, so a test that builds one hands it on.

``maljan.tools.knowledge`` caches the hybrid index, the catalogue and the
memory of a background build having been started in module globals, which is
right for a worker process and wrong for a test session: one validation test
that passes the real knowledge module builds the index for real, and every
later test in the same process then runs against a warm one. The test that
pins the warmer's stickiness asks for the cold state explicitly and got a warm
index instead, which is a pass or a failure depending on which files were
selected.

So the state is owned here rather than left to whoever touched it last: every
test in this package starts from the cold state and leaves it behind.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from maljan.tools import knowledge


@pytest.fixture(autouse=True)
def _cold_attck_index() -> Iterator[None]:
    knowledge.reset_indices()
    yield
    knowledge.reset_indices()
