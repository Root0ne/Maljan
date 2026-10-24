"""A cancelled job ends the artefact fetch it has in flight at once (T-353).

The cancel stopped the waits between tries and any further try, but a request
already sent ran until its HTTP timeout: up to 120 s on CAPE, with a worker
thread held the whole time. The job's cancellation now shuts the connections
of the fetching client down, so a blocked read returns at once, the failure is
said as ``cancelled`` and never as the transport error the shutdown caused, and
no further try is made.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from maljan.core.cancellation import Cancellation
from maljan.core.config import Settings
from maljan.loaders.cape2_client import CAPEv2Client
from maljan.providers.errors import ArtefactFetchFailed
from maljan.providers.sandbox.rest import RestSandboxProvider
from maljan.providers.sandbox.triage import (
    ArtefactAttemptFailed,
    FetchBudget,
    TriageSandboxProvider,
    abort_requests,
    fetch_artefact,
    fetch_budget,
    with_fetch_retries,
)

# Far below every client's own timeout (60 s, 120 s on CAPE): a fetch that
# ends inside it was ended by the cancel, not by a timeout.
ENDED_WITHIN = 5.0
_OVERVIEW = json.dumps({"tasks": [{"name": "behavioral1", "kind": "behavioral"}]}).encode()


class _StallingSandbox:
    """A keep-alive HTTP server that answers an overview and stalls on a capture.

    ``stall`` is ``"headers"`` (the capture's answer never starts),
    ``"body"`` (its headers and a first chunk arrive, then nothing),
    ``"close"`` (as ``"body"``, with a body that ends only at the connection's
    close) or ``"handshake"`` (the connection is accepted and nothing is ever
    read or answered, so a TLS handshake stalls). Each capture request is
    counted in ``captures``.
    """

    def __init__(self, stall: str) -> None:
        self.stall = stall
        self.captures = 0
        self._release = threading.Event()
        self._server = socket.socket()
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(8)
        self.url = f"http://127.0.0.1:{self._server.getsockname()[1]}"
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        with conn:
            if self.stall == "handshake":
                self.captures += 1
                self._release.wait(60)
                return
            pending = b""
            while True:
                while b"\r\n\r\n" not in pending:
                    chunk = conn.recv(65536)
                    if not chunk:
                        return
                    pending += chunk
                head, pending = pending.split(b"\r\n\r\n", 1)
                path = head.split(b" ")[1].decode()
                if path.endswith("overview.json"):
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        + f"Content-Length: {len(_OVERVIEW)}\r\n\r\n".encode()
                        + _OVERVIEW
                    )
                    continue
                self.captures += 1
                if self.stall == "body":
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.tcpdump.pcap\r\n"
                        b"Content-Length: 1000000\r\n\r\n" + b"\xd4\xc3\xb2\xa1" + b"\x00" * 60
                    )
                elif self.stall == "close":
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nConnection: close\r\n"
                        b"Content-Type: application/vnd.tcpdump.pcap\r\n\r\n"
                        + b"\xd4\xc3\xb2\xa1"
                        + b"\x00" * 5000
                    )
                self._release.wait(60)
                return

    def close(self) -> None:
        self._release.set()
        self._server.close()


@pytest.fixture(params=["headers", "body"])
def sandbox(request):
    server = _StallingSandbox(request.param)
    yield server
    server.close()


def _triage(url: str) -> TriageSandboxProvider:
    cfg = Settings(_env_file=None)
    cfg.sandbox.triage.api_token = __import__("pydantic").SecretStr("not-a-real-token")
    cfg.sandbox.triage.base_url = url
    return TriageSandboxProvider.from_settings(cfg)


def _rest(url: str) -> RestSandboxProvider:
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "rest"
    cfg.sandbox.rest.base_url = url
    cfg.sandbox.rest.report.pcap_path = "/tasks/{task_id}/pcap"
    return RestSandboxProvider.from_settings(cfg)


def _cape(url: str) -> CAPEv2Client:
    return CAPEv2Client(base_url=url, api_token="not-a-real-token")


def _fetch_cancelled(fetch, dest: Path) -> tuple[ArtefactFetchFailed, float]:
    """Run ``fetch(dest)`` under a job's budget and cancel the job mid-request."""
    cancellation = Cancellation()
    budget = FetchBudget(
        deadline=time.monotonic() + 600,
        sleep=cancellation.wait,
        cancelled=lambda: cancellation.is_cancelled,
        track=cancellation.track,
    )
    timer = threading.Timer(0.5, cancellation.cancel, args=("the operator cancelled the job",))
    started = time.monotonic()
    timer.start()
    try:
        with fetch_budget(budget), pytest.raises(ArtefactFetchFailed) as exc:
            fetch(dest)
    finally:
        timer.cancel()
    return exc.value, time.monotonic() - started


@pytest.mark.parametrize("build", [_triage, _rest, _cape], ids=["triage", "rest", "cape"])
def test_a_cancel_ends_the_request_in_flight_and_says_cancelled(sandbox, build, tmp_path):
    provider = build(sandbox.url)
    try:
        failure, took = _fetch_cancelled(lambda dest: provider.fetch_pcap("s1", dest), tmp_path)
    finally:
        provider.close()
    assert took < ENDED_WITHIN
    assert failure.cause == "cancelled"
    assert failure.reason == "packet capture not fetched (cancelled)"
    assert failure.record()["statement"] == "the packet capture could not be fetched (cancelled)"
    # The retry policy makes no further try after a cancel.
    assert sandbox.captures == 1
    assert not [p for p in tmp_path.rglob("*") if p.is_file()]


def test_a_failure_after_the_cancel_is_said_as_cancelled_not_as_itself():
    """A non-transient error the shutdown caused is not the failure the run reports."""
    cancelled = {"now": False}
    tries: list[int] = []

    def attempt():
        tries.append(1)
        cancelled["now"] = True
        raise httpx.StreamClosed()

    budget = FetchBudget(deadline=1e9, cancelled=lambda: cancelled["now"])
    with fetch_budget(budget), pytest.raises(ArtefactFetchFailed) as exc:
        with_fetch_retries(
            attempt, artefact="packet capture", what="t", sleep=lambda _s: None, interval=1
        )
    assert exc.value.cause == "cancelled"
    assert tries == [1]


def test_a_refusal_answered_after_the_cancel_is_said_as_cancelled():
    tries: list[int] = []

    def attempt():
        tries.append(1)
        raise ArtefactAttemptFailed("HTTP 403", transient=False)

    budget = FetchBudget(deadline=1e9, cancelled=lambda: len(tries) >= 1)
    with fetch_budget(budget), pytest.raises(ArtefactFetchFailed) as exc:
        with_fetch_retries(
            attempt, artefact="packet capture", what="t", sleep=lambda _s: None, interval=1
        )
    assert exc.value.cause == "cancelled"
    assert tries == [1]


def test_a_finished_try_leaves_nothing_for_the_cancel_to_stop():
    """Each try is tracked only while it runs: a later cancel stops nothing of it."""
    cancellation = Cancellation()
    budget = FetchBudget(deadline=1e9, cancelled=lambda: False, track=cancellation.track)
    with fetch_budget(budget), httpx.Client() as client:
        answer = with_fetch_retries(
            lambda: "ok",
            artefact="packet capture",
            what="t",
            sleep=lambda _s: None,
            interval=1,
            client=client,
        )
    assert answer == "ok"
    assert cancellation._in_flight == {}


def test_the_jobs_capture_fetch_is_bound_to_its_cancellation(tmp_path):
    """``MaljanApp._fetch_capture`` hands the provider's fetch the job's cancellation."""
    from types import SimpleNamespace

    from maljan.app import MaljanApp
    from maljan.providers.sandbox import triage

    cancellation = Cancellation()
    seen: list[FetchBudget | None] = []

    class Provider:
        def fetch_pcap(self, task_id, dest_dir):
            seen.append(triage._FETCH_BUDGET.get())

    app = MaljanApp.__new__(MaljanApp)
    app.container = SimpleNamespace(cancellation=cancellation)
    app._fetch_capture(Provider(), "s1", str(tmp_path), time.monotonic() + 60)
    (budget,) = seen
    assert budget is not None
    assert budget.track == cancellation.track
    assert budget.sleep == cancellation.wait


@pytest.mark.parametrize("build", [_triage, _rest, _cape], ids=["triage", "rest", "cape"])
def test_a_cancel_ends_a_request_sent_through_a_proxy(sandbox, build, tmp_path, monkeypatch):
    """A request through an operator's proxy goes by a proxy mount, which is ended too."""
    for name in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "http_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HTTP_PROXY", sandbox.url)
    provider = build("http://sandbox.invalid")
    try:
        failure, took = _fetch_cancelled(lambda dest: provider.fetch_pcap("s1", dest), tmp_path)
    finally:
        provider.close()
    assert took < ENDED_WITHIN
    assert failure.cause == "cancelled"
    assert sandbox.captures == 1


def _write_body(out: Path):
    def keep(response: httpx.Response) -> bool:
        with out.open("wb") as handle:
            for chunk in response.iter_bytes():
                handle.write(chunk)
        return True

    return keep


def _fetch_from(client: httpx.Client, out: Path, **over):
    return fetch_artefact(
        lambda: client.stream("GET", "/p"),
        _write_body(out),
        out,
        artefact="packet capture",
        what="t",
        sleep=lambda _s: None,
        interval=1,
        client=client,
        **over,
    )


def test_a_cancel_ends_a_stalled_tls_handshake(tmp_path):
    """A connection still in its handshake has no pooled stream yet; it is ended too."""
    server = _StallingSandbox("handshake")
    out = tmp_path / "c.pcap"
    client = httpx.Client(base_url=server.url.replace("http:", "https:"), timeout=60)
    try:
        failure, took = _fetch_cancelled(lambda _dest: _fetch_from(client, out), tmp_path)
    finally:
        client.close()
        server.close()
    assert took < ENDED_WITHIN
    assert failure.cause == "cancelled"
    assert server.captures == 1


def test_a_body_ended_by_the_cancels_shutdown_is_not_kept_as_a_capture(tmp_path):
    """A close-delimited body reads to an ordinary end once its socket is shut down."""
    server = _StallingSandbox("close")
    out = tmp_path / "c.pcap"
    client = httpx.Client(base_url=server.url, timeout=60)
    try:
        failure, took = _fetch_cancelled(
            lambda _dest: _fetch_from(client, out, min_bytes=100), tmp_path
        )
    finally:
        client.close()
        server.close()
    assert took < ENDED_WITHIN
    assert failure.cause == "cancelled"
    assert not out.exists()


def test_a_cancel_between_the_check_and_the_try_asks_nothing():
    """Cancelled after the stop check and before the try is tracked: no request is made."""
    checks: list[int] = []
    tries: list[int] = []

    def cancelled() -> bool:
        checks.append(1)
        return len(checks) > 1

    budget = FetchBudget(deadline=1e9, cancelled=cancelled)
    with fetch_budget(budget), httpx.Client() as client:
        with pytest.raises(ArtefactFetchFailed) as exc:
            with_fetch_retries(
                lambda: tries.append(1),
                artefact="packet capture",
                what="t",
                sleep=lambda _s: None,
                interval=1,
                client=client,
            )
    assert exc.value.cause == "cancelled"
    assert tries == []


def test_abort_requests_without_a_pool_does_nothing_and_never_raises():
    """A transport without httpx's pool leaves the try to its timeout, as before."""
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as mocked:
        abort_requests(mocked)
    abort_requests(SimpleNamespace())
    abort_requests(None)
    opening = SimpleNamespace(_connection=None)
    pool = SimpleNamespace(connections=[opening])
    abort_requests(SimpleNamespace(_transport=SimpleNamespace(_pool=pool), _mounts={}))
    odd_stream = SimpleNamespace(get_extra_info=lambda _info: 1)
    odd = SimpleNamespace(_connection=SimpleNamespace(_network_stream=odd_stream))
    pool = SimpleNamespace(connections=[odd])
    abort_requests(SimpleNamespace(_transport=SimpleNamespace(_pool=pool), _mounts={"x": None}))


def test_a_held_socket_is_never_closed_while_a_stop_shuts_it_down():
    """A close racing a stop waits for its shutdowns: no descriptor is freed mid-stop."""
    from maljan.providers.sandbox.triage import _TryInFlight

    events: list[str] = []
    in_flight = _TryInFlight(None)
    closing = threading.Event()

    def close() -> None:
        closing.set()
        in_flight.close()

    closer = threading.Thread(target=close)

    class Dup:
        def shutdown(self, _how):
            # The try ends while the cancel is shutting this socket down.
            closer.start()
            assert closing.wait(5)
            # The closer is about to call close(), or waits in it; it never
            # finishes while this shutdown holds the lock, however slow it is.
            closer.join(0.05)
            events.append("closer blocked" if closer.is_alive() else "closer ran")
            events.append("shutdown")

        def close(self):
            events.append("close")

    in_flight.hold(SimpleNamespace(dup=Dup))
    in_flight.stop()
    closer.join(5)
    assert events == ["closer blocked", "shutdown", "close"]
