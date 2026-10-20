"""AUD-22 fix round 1: closes are all submitted first; a held table failure is read once."""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maljan.core import spend
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer


@pytest.mark.asyncio
async def test_r4_a_cancelled_wait_still_runs_every_close() -> None:
    container = ServiceContainer(config=Settings(), mock=True)
    ran: list[str] = []
    release = threading.Event()

    def slow() -> None:
        release.wait(5)
        ran.append("slow")

    first, second, sandbox = MagicMock(), MagicMock(), MagicMock()
    first.close.side_effect = slow
    second.close.side_effect = lambda: ran.append("second")
    sandbox.close.side_effect = lambda: ran.append("sandbox")
    container._static_provider_cache = {"a": first, "b": second}
    container._sandbox_provider_cache = sandbox

    task = asyncio.create_task(container.aclose())
    await asyncio.sleep(0.1)  # every close is submitted, the first still blocked
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    for _ in range(100):
        if len(ran) == 3:
            break
        await asyncio.sleep(0.02)
    assert sorted(ran) == ["sandbox", "second", "slow"]


def test_r6_a_persisting_failure_is_read_and_warned_once_until_the_file_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    missing = tmp_path / "table.json"
    reads: list[int] = []
    real = Path.read_text

    def counting(self: Path, *args: object, **kwargs: object) -> str:
        if self == missing:
            reads.append(1)
        return real(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", counting)
    monkeypatch.setattr(spend, "_table", None)
    monkeypatch.setattr(spend, "_failed_stat", None)
    monkeypatch.setattr(spend, "table_failure", None)
    monkeypatch.setattr("maljan.core.paths.resolve_data", lambda _p: missing)
    meter = spend.SpendMeter(10.0)
    with caplog.at_level("WARNING"):
        assert meter.price_of("m") is None
        assert meter.price_of("m") is None
    # The missing file is read once (it fails there) and not again while its stat is unchanged.
    assert len(reads) == 1
    assert caplog.text.count("price table could not be read") == 1
    good = {"m": {"input_usd_per_mtok": 1, "output_usd_per_mtok": 2, "source": "t"}}
    missing.write_text(json.dumps({"prices": good}), encoding="utf-8")
    assert meter.price_of("m") is not None
    assert len(reads) == 2
    monkeypatch.setattr(spend, "_table", None)
