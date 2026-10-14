"""What a download of the ATT&CK index or a bundle is held to.

A redirect is followed only to HTTPS on the same host; the body is bounded by
a multiple of the largest cached bundle (or, with none cached, by its own
declared length); and the transfer as a whole ends at its deadline, not only
each read. No network: the opener is a stand-in.
"""

from __future__ import annotations

import io
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from maljan.memory import attck_loader


class FakeResponse:
    def __init__(self, body: bytes, *, length: str | None = None, pause: float = 0.0) -> None:
        self._body = io.BytesIO(body)
        self.headers = {"Content-Length": length} if length else {}
        self._pause = pause

    def read(self, size: int = -1) -> bytes:
        if self._pause:
            time.sleep(self._pause)
        return self._body.read(min(size, 16) if size > 0 else -1)

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: Any) -> None:
        return None


def _serve(monkeypatch: pytest.MonkeyPatch, response: FakeResponse) -> None:
    class Opener:
        def open(self, url: str, timeout: float) -> FakeResponse:
            return response

    monkeypatch.setattr(attck_loader, "_guarded_opener", lambda: Opener())


@pytest.fixture
def cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(
        attck_loader,
        "ATTCK_CACHE_FILES",
        {d: tmp_path / f"{d}-attack.json" for d in attck_loader.DOMAINS},
    )
    return tmp_path


def test_the_bound_is_a_multiple_of_the_largest_cached_bundle(cache: Path) -> None:
    assert attck_loader._size_bound() is None
    (cache / "enterprise-attack.json").write_bytes(b"x" * 100)
    (cache / "ics-attack.json").write_bytes(b"x" * 10)
    assert attck_loader._size_bound() == attck_loader.DOWNLOAD_SIZE_FACTOR * 100


def test_a_body_past_the_bound_is_stopped_and_said(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _serve(monkeypatch, FakeResponse(b"y" * 100))
    out = io.BytesIO()
    with caplog.at_level("WARNING"), pytest.raises(RuntimeError, match="size bound of 40"):
        attck_loader._stream("https://x/b.json", out, timeout=5, deadline=None, max_bytes=40)
    assert "passed its size bound of 40 bytes" in caplog.text
    assert len(out.getvalue()) <= 40


def test_with_nothing_cached_the_declared_length_bounds_it(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(monkeypatch, FakeResponse(b"z" * 100, length="50"))
    with pytest.raises(RuntimeError, match="size bound of 50"):
        attck_loader._stream(
            "https://x/b.json", io.BytesIO(), timeout=5, deadline=None, max_bytes=None
        )


def test_a_trickle_ends_at_the_total_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(monkeypatch, FakeResponse(b"t" * 1000, pause=0.02))
    with pytest.raises(RuntimeError, match="did not finish in the time"):
        attck_loader._stream(
            "https://x/b.json",
            io.BytesIO(),
            timeout=5,
            deadline=time.monotonic() + 0.1,
            max_bytes=None,
        )


def test_a_whole_body_within_both_is_written(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(monkeypatch, FakeResponse(b'{"objects": []}'))
    out = io.BytesIO()
    attck_loader._stream("https://x/b.json", out, timeout=5, deadline=None, max_bytes=1000)
    assert out.getvalue() == b'{"objects": []}'


class TestRedirects:
    @staticmethod
    def _handler() -> Any:
        opener = attck_loader._guarded_opener()
        return next(h for h in opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler))

    def test_one_to_https_on_the_same_host_is_followed(self) -> None:
        request = urllib.request.Request("https://raw.githubusercontent.com/a.json")
        followed = self._handler().redirect_request(
            request, None, 302, "Found", {}, "https://raw.githubusercontent.com/b.json"
        )
        assert followed is not None and followed.full_url.endswith("/b.json")

    @pytest.mark.parametrize(
        "target",
        ["https://elsewhere.example/b.json", "http://raw.githubusercontent.com/b.json"],
    )
    def test_one_off_the_host_or_to_plain_http_is_refused(self, target: str) -> None:
        request = urllib.request.Request("https://raw.githubusercontent.com/a.json")
        with pytest.raises(urllib.error.HTTPError, match="refused"):
            self._handler().redirect_request(request, None, 302, "Found", {}, target)
