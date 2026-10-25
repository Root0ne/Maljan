"""Fixtures shared by the reporting tests."""

from __future__ import annotations

import pytest


@pytest.fixture
def no_model_endpoint_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """The renderer reads no configured model endpoint, whatever this machine's .env names.

    A model's recorded endpoint prints kept only where the settings configure
    it, and the settings read the checkout's ``.env``: a stored run pinned
    where none names an endpoint (CI, a worktree) would print it undefanged in
    a checkout whose ``.env`` names the run's own endpoint, and miss its pin.
    """
    import maljan.core.model_assignments as assignments

    monkeypatch.setattr(assignments, "configured_endpoint_labels", lambda settings: set())
