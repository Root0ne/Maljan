"""A failed Ghidra program switch must not hash whichever binary is current.

``fetch_bulk_function_hashes`` loads the sample, then must make it the
*current* program before asking for its function hashes (see
``maljan.analysis.ghidra_program`` for why the load response alone is not
enough). If the switch (or the follow-up ``run_analysis``) fails, the
previous behaviour was to swallow the error and hash on regardless —
silently attributing this sample to whatever binary Ghidra was still
looking at. The fix (L14, security hardening) is to skip attribution
entirely and warn loudly instead.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from maljan.analysis import function_hash_attribution as fha
from maljan.analysis.ghidra_program import SWITCH_PATH

LOAD_OK = json.dumps({"success": True, "program": "sample.exe"})


class _Resp:
    def __init__(self, text: str) -> None:
        self.text = text

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return json.loads(self.text)


class _Client:
    """Stands in for httpx.Client: a successful load, then a refused switch."""

    def __init__(self, load_body: str) -> None:
        self.load_body = load_body
        self.paths: list[str] = []

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(self, url: str, params: Any = None, json: Any = None) -> _Resp:  # noqa: A002
        self.paths.append(url)
        if url.endswith("/load_program"):
            return _Resp(self.load_body)
        raise ConnectionError("switch refused")

    def get(self, url: str, params: Any = None) -> _Resp:
        self.paths.append(url)
        return _Resp("{}")


class TestAFailedSwitchSkipsAttribution:
    def test_a_failed_program_switch_skips_attribution_with_a_warning(
        self, monkeypatch: Any, caplog: Any
    ) -> None:
        client = _Client(LOAD_OK)
        monkeypatch.setattr("httpx.Client", lambda **kw: client)

        with caplog.at_level(logging.WARNING):
            result = fha.fetch_bulk_function_hashes(
                base_url="http://ghidra",
                auth_token="",
                file_path="/data/samples/.work/s.exe",
                min_instructions=3,
            )

        assert result == []
        assert any("ConnectionError" in r.getMessage() for r in caplog.records)
        assert client.paths == ["http://ghidra/load_program", f"http://ghidra{SWITCH_PATH}"]
        assert not any(p.endswith("/get_bulk_function_hashes") for p in client.paths)
