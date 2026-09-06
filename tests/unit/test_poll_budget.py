"""``MaljanApp._poll_budget`` reads the active sandbox provider's own numbers.

Before Task 11's REST provider, ``_submit_to_sandbox`` read
``sandbox.cape2.timeout_seconds``/``poll_interval_seconds`` unconditionally,
regardless of which sandbox was actually configured. These tests pin the
per-provider budget the fixed code must produce: CAPE keeps the constants it
always had, Triage and REST each read their own block, and every other
provider id (mock included) falls back to CAPE's numbers exactly as before.
"""

from __future__ import annotations

from maljan.app import MaljanApp
from maljan.core.config import Settings

# CAPE's pre-Task-11 constants (``SandboxCape2Config`` defaults), pinned here
# so a future change to those defaults is a visible test failure rather than
# a silent drift of what "unchanged" means.
CAPE_TIMEOUT_SECONDS = 300
CAPE_POLL_INTERVAL_SECONDS = 10


class _Provider:
    """A stand-in with only the attribute ``_poll_budget`` reads: ``id``."""

    def __init__(self, id: str) -> None:  # noqa: A002 - mirrors SandboxProvider.id
        self.id = id


def _app(**sandbox_over) -> MaljanApp:
    cfg = Settings(_env_file=None)
    for key, value in sandbox_over.items():
        setattr(cfg.sandbox, key, value)
    return MaljanApp(config=cfg, mock=True)


def test_mock_provider_keeps_capes_numbers():
    app = _app(provider="mock")
    assert app._poll_budget(_Provider("mock")) == (CAPE_TIMEOUT_SECONDS, CAPE_POLL_INTERVAL_SECONDS)


def test_cape2_provider_is_unchanged():
    app = _app(provider="cape2")
    budget = app._poll_budget(_Provider("cape2"))
    assert budget == (CAPE_TIMEOUT_SECONDS, CAPE_POLL_INTERVAL_SECONDS)


def test_cape2_reads_an_override_from_its_own_block_not_a_hardcoded_pair():
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "cape2"
    cfg.sandbox.cape2.timeout_seconds = 111
    cfg.sandbox.cape2.poll_interval_seconds = 7
    app = MaljanApp(config=cfg, mock=True)
    assert app._poll_budget(_Provider("cape2")) == (111, 7)


def test_triage_provider_reads_its_own_block():
    app = _app(provider="triage")
    assert app._poll_budget(_Provider("triage")) == (900, 15)


def test_triage_override_is_honoured_and_not_confused_with_cape_or_rest():
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "triage"
    cfg.sandbox.triage.timeout_seconds = 222
    cfg.sandbox.triage.poll_interval_seconds = 8
    app = MaljanApp(config=cfg, mock=True)
    assert app._poll_budget(_Provider("triage")) == (222, 8)


def test_rest_provider_reads_its_own_block():
    app = _app(provider="rest")
    assert app._poll_budget(_Provider("rest")) == (900, 15)


def test_rest_override_is_honoured_and_not_confused_with_cape_or_triage():
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "rest"
    cfg.sandbox.rest.timeout_seconds = 333
    cfg.sandbox.rest.poll_interval_seconds = 9
    app = MaljanApp(config=cfg, mock=True)
    assert app._poll_budget(_Provider("rest")) == (333, 9)


def test_upload_provider_keeps_capes_numbers():
    app = _app(provider="upload")
    budget = app._poll_budget(_Provider("upload"))
    assert budget == (CAPE_TIMEOUT_SECONDS, CAPE_POLL_INTERVAL_SECONDS)
