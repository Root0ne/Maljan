"""Hatching Triage cloud sandbox behind the provider contract.

Triage detonates on Hatching's own cloud VMs and hands back two report
shapes per run: one overview (``overview.json``) for the whole sample, and
one behavioural report (``report_triage.json``) per task. Submission is a
multipart POST, completion is polled rather than pushed, and the sandbox
publishes no per-API-call log — ``UNAVAILABLE`` on this provider says exactly
that, so a rendered report never reads like a clean sample by omission.

Endpoints verified against https://tria.ge/docs/cloud-api/ on 2026-09-04.
The docs root itself returns HTTP 403 to an automated fetch; every path below
and the terminal-status set were instead confirmed against the indexed
content of the "Samples", "Overview Report", "Resources" and "Conventions"
sub-pages, which were reachable. What was actually confirmed:

- ``POST /samples`` — sample submission (the "Samples" page); multipart
  field names ``file``, ``_json``, ``kind`` (``"file"``/``"url"``/``"fetch"``/
  ``"import"``), ``target``, ``interactive``, ``password``, ``profiles``
  (an array of ``{"profile": ..., "pick": ...}`` mappings), ``user_tags``,
  ``defaults.timeout``, ``defaults.network``.
- ``GET /samples/{sampleID}`` — status; quoted exactly by the "Samples" page,
  whose Sample Object definition enumerates the status progression pending,
  static_analysis, scheduled, running, processing, then the two terminal
  states reported and failed.
- ``GET /samples/{sampleID}/overview.json`` — quoted exactly by the
  "Overview Report" page.
- ``GET /samples/{sampleID}/{taskID}/report_triage.json`` — quoted exactly by
  the "Samples" page; returns ``404 REPORT_NOT_AVAILABLE`` before the task
  reaches "reported".
- ``GET /samples/{sampleID}/{taskID}/dump.pcap`` — quoted in full, including
  the ``https://tria.ge/api/v0`` base, alongside its documented ``.pcapng``
  sibling — this is also what confirms the base URL already configured on
  ``SandboxTriageConfig.base_url``.
- ``GET /resources`` — "List all resources available" (the "Resources"
  page); the cheapest authenticated read this API documents, used below for
  the connection test the same way CAPE2 uses ``tasks/view/1/``.
- Auth: ``Authorization: Bearer <apikey>``, quoted exactly by the
  "Conventions" page.

None of the five path constants or the terminal-status set needed correcting
against the brief. No rate-limit, 429 or Retry-After section was reachable in
any of the pages above; the backoff and Retry-After handling in
``wait_for_completion`` is therefore defensive engineering, not a documented
contract, and is called out as such here rather than implied to be spec'd.

A first pass at ``report_triage.json``'s ``network`` shape (flat
``requests``/``flows`` arrays with CAPE-like fields) turned out to be wrong —
found during review, not confirmed against anything. The "Dynamic Report"
docs page, reached the same way as the pages above, gives the real shape:
``network.flows[]`` carries the endpoint as one combined ``"host:port"``
string (no separate port field) plus per-flow ``proto``/``country``/
``as_num``/``as_org``; ``network.requests[]`` is a discriminated union —
``domain_req``/``domain_resp`` for a DNS lookup, ``web_req``/``web_resp`` for
an HTTP request — never a flat DNS/HTTP row. ``triage_overview_to_sandbox_report``
(``schemas/sandbox_report.py``) maps both into the shapes
``network_extractor``/``network_parser`` actually read, not Triage's own
field names.
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import httpx

from maljan.core.logger import logger
from maljan.providers.base import ProviderProbe, SandboxCapabilities, SandboxProvider
from maljan.providers.errors import PACKET_CAPTURE, ArtefactFetchFailed, ProviderError
from maljan.providers.registry import register_sandbox_provider
from maljan.providers.sandbox.limits import read_capped, stream_to_file_capped
from maljan.providers.sandbox.readers import required_reader

# The registered report reader (``providers.sandbox.readers``) this provider's
# reports are read by.
_READER = "triage"

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from maljan.core.config import SandboxTriageConfig, Settings
    from maljan.schemas.sandbox_report import SandboxRun

# The five calls this provider makes, as named constants so a documentation
# change is a one-line edit. Verified against https://tria.ge/docs/cloud-api/
# on 2026-09-04 (see the module docstring for exactly what was reachable and
# how each constant was confirmed).
SUBMIT_PATH = "/samples"  # POST, multipart: file + _json
OWNED_SAMPLES_PATH = "/samples"  # GET ?subset=owned, the caller's own submissions
STATUS_PATH = "/samples/{sample_id}"  # GET, status "reported" is terminal
OVERVIEW_PATH = "/samples/{sample_id}/overview.json"  # GET
TASK_REPORT_PATH = "/samples/{sample_id}/{task}/report_triage.json"  # GET
PCAP_PATH = "/samples/{sample_id}/{task}/dump.pcap"  # GET, streamed
TERMINAL_STATUSES = frozenset({"reported", "failed"})

# The read used by both connection tests (this provider's own ``probe`` and
# the settings UI's ``probe_triage``): "List all resources available", the
# cheapest authenticated GET this API documents — the same role CAPE2's
# ``/apiv2/tasks/view/1/`` plays for that provider.
RESOURCES_PATH = "/resources"

_BACKOFF_FACTOR = 1.5
_MAX_INTERVAL_SECONDS = 60.0

# A submission whose response never arrived is reconciled against the
# caller's own recent samples before anything is posted a second time.
_RECONCILE_LIMIT = 20
_RECONCILE_WINDOW_SECONDS = 600.0
_SUBMIT_RETRY_DELAY_SECONDS = 2.0

_SAFE_PATH_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_path_component(value: str) -> str:
    """Keep only characters safe in a filename and a URL path segment.

    M12 (final review): ``task_id`` comes from Triage's own submit response
    and the task name from its overview — both are interpolated into a
    destination path and a URL path. The trust boundary is the operator's
    own configured Triage instance, so the exposure is small, but a
    ``Path(...).name``-style guard costs nothing. A value that sanitises to
    nothing (empty, or e.g. all ``..``/``/``) falls back to a fresh uuid
    rather than producing an empty or traversal-prone path segment.
    """
    cleaned = _SAFE_PATH_COMPONENT_RE.sub("_", value).strip("._")
    return cleaned or uuid.uuid4().hex


def _parse_retry_after(value: str, now: float) -> float | None:
    """RFC 9110 permits delta-seconds or an HTTP-date; a server may send either.

    Returns seconds to wait, or ``None`` when the header is present but
    unparseable in both forms (the caller falls back to its own backoff
    rather than raising, and than crashing the poll loop on a header from a
    third party this provider does not control).
    """
    try:
        return float(value)
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        # RFC 9110 HTTP-dates are always GMT; treat a naive value as such
        # rather than comparing it against a UTC "now" as if it were local.
        when = when.replace(tzinfo=UTC)
    return (when - datetime.now(UTC)).total_seconds()


# A status poll that failed in transit (a timeout, a dropped connection, a body
# that would not decode) says nothing about the task: it is the sandbox busy or
# briefly unreachable, waited out like a 429 until the poll's own deadline. A
# running detonation is never thrown away over one of them.
POLL_TRANSPORT_ERRORS: tuple[type[Exception], ...] = (httpx.TransportError, httpx.DecodingError)


def poll_failure(response: httpx.Response) -> str | None:
    """Why a status answer is the sandbox's trouble rather than a verdict, or ``None``.

    A 5xx is the server failing to answer, not an answer about the task; a 4xx
    stays a verdict (a refused token or an unknown task will be the same in
    twenty minutes), and so do 501 and 505, which say the request can never be
    served (``loaders.sandbox_client.PERMANENT_SERVER_STATUSES``). 429 and 503
    are not read here: they have their own ``Retry-After`` branch.
    """
    from maljan.loaders.sandbox_client import PERMANENT_SERVER_STATUSES

    status = response.status_code
    if status >= 500 and status not in PERMANENT_SERVER_STATUSES:
        return f"HTTP {response.status_code}"
    return None


def wait_after_poll_failure(
    sleep: Any, now: Any, interval: float, deadline: float, what: str, error: str
) -> float:
    """Wait the current backoff, clamped to the deadline; the next interval.

    ``error`` is logged, and the caller keeps it for the deadline's message.
    """
    logger.warning("%s: status poll failed transiently (%s); retrying.", what, error)
    clamped = min(interval, _MAX_INTERVAL_SECONDS, deadline - now())
    if clamped > 0:
        sleep(clamped)
    return min(interval * _BACKOFF_FACTOR, _MAX_INTERVAL_SECONDS)


def poll_deadline_error(what: str, budget: float, last_error: str) -> ProviderError:
    """The deadline's failure, naming the last transient poll error when there was one."""
    suffix = f" Last poll error: {last_error}" if last_error else ""
    return ProviderError(f"{what} did not complete within {budget:.0f}s.{suffix}")


# How many times an artefact fetch is tried in all: the count the platform's
# transient-retry policy gives a model call (``llm.transient.DEFAULT_ATTEMPTS``).
# The waits between tries are the status poll's: its interval, backed off 1.5x
# to 60 s, or a ``Retry-After`` the sandbox sent, clamped the same way.
ARTEFACT_FETCH_ATTEMPTS = 3

# The size below which a fetched capture holds nothing: the libpcap/pcapng
# global header alone is 24 bytes.
CAPTURE_MIN_BYTES = 24


@dataclass(frozen=True)
class FetchBudget:
    """What bounds a job's artefact fetch beyond its attempt count.

    ``deadline`` is on ``now``'s clock (the job's sandbox deadline); ``sleep``
    waits between tries and returns early once ``cancelled()`` holds.
    ``track(stop)`` registers a try in flight, whose ``stop`` the job's cancel
    calls, and returns its unregister (``core.cancellation.Cancellation.track``).
    """

    deadline: float
    now: Callable[[], float] = time.monotonic
    sleep: Callable[[float], Any] = time.sleep
    cancelled: Callable[[], bool] = lambda: False
    track: Callable[[Callable[[], None]], Callable[[], None]] = lambda _stop: lambda: None

    def stop_cause(self, *, retry: bool) -> str:
        """Why no further try is made, or ``""``: the job was cancelled, or a retry is late."""
        if self.cancelled():
            return "cancelled"
        if retry and self.now() >= self.deadline:
            return "deadline"
        return ""


# The budget of the fetch running in this context; ``None`` outside a job.
_FETCH_BUDGET: ContextVar[FetchBudget | None] = ContextVar("maljan_fetch_budget", default=None)


@contextmanager
def fetch_budget(budget: FetchBudget) -> Iterator[None]:
    """Bound every artefact fetch made inside the block by ``budget``."""
    token = _FETCH_BUDGET.set(budget)
    try:
        yield
    finally:
        _FETCH_BUDGET.reset(token)


def stop_if_cancelled(artefact: str) -> None:
    """Raise ``ArtefactFetchFailed(artefact, "cancelled")`` once the job is cancelled.

    Called before a provider makes the directory an artefact goes in: a cancel
    that arrived during an earlier request must not recreate the job's capture
    directory after its staging was torn down.
    """
    budget = _FETCH_BUDGET.get()
    if budget is not None and budget.cancelled():
        logger.warning("%s not fetched (cancelled).", artefact)
        raise ArtefactFetchFailed(artefact, "cancelled")


def _transports(client: Any) -> list[Any]:
    """The client's own transport and every proxy mount's, the ones a request may go through."""
    mounts = getattr(client, "_mounts", None)
    held = [getattr(client, "_transport", None)]
    if isinstance(mounts, dict):
        held += list(mounts.values())
    return [transport for transport in held if transport is not None]


def _shut_down(sock: Any) -> None:
    """Shut ``sock`` down both ways, which wakes a thread blocked on it; never raises."""
    with suppress(Exception):
        sock.shutdown(socket.SHUT_RDWR)


def abort_requests(client: Any) -> None:
    """End every request ``client`` has in flight on a pooled connection; never raises.

    Closing the client is not enough: its pool closes a socket without shutting
    it down, and a thread blocked reading that socket waits out its timeout
    (up to 120 s on CAPE). The socket of each connection pooled by the client's
    transport and by every proxy mount is shut down instead, which wakes the
    read, before headers or in the body alike. A connection still opening has
    no socket here yet; :class:`_TryInFlight` holds those. A transport without
    such a pool (a test's mock) has nothing to end.
    """
    try:
        for transport in _transports(client):
            pool = getattr(transport, "_pool", None)
            for connection in list(getattr(pool, "connections", None) or ()):
                # A proxied connection wraps the one that holds the stream.
                held, stream = connection, None
                for _ in range(4):
                    stream = getattr(held, "_network_stream", None)
                    held = getattr(held, "_connection", None)
                    if stream is not None or held is None:
                        break
                if stream is not None:
                    _shut_down(stream.get_extra_info("socket"))
    except Exception as exc:  # noqa: BLE001 — the cancel goes on; the try ends at its timeout
        logger.debug("an artefact request in flight could not be ended (%s).", type(exc).__name__)


class _TryInFlight:
    """One artefact try's sockets, so the job's cancel reaches a connection still opening.

    A connection opened during the try registers its socket here as soon as it
    is connected (:class:`_TrackedBackend`), before any TLS handshake, proxy
    tunnel or request on it; a duplicate of the descriptor is held, which
    outlives the TLS wrap and shuts down the same socket. ``stop`` (the job's
    cancel) shuts down every one held, every one registered after it, and the
    client's pooled connections (:func:`abort_requests`).
    """

    def __init__(self, client: Any) -> None:
        self._client = client
        self._lock = threading.Lock()
        self._held: list[socket.socket] = []
        self._stopped = False

    def hold(self, sock: Any) -> None:
        try:
            dup = sock.dup()
        except Exception:  # noqa: BLE001 — not a socket (a test's stream): nothing to hold
            return
        with self._lock:
            stopped = self._stopped
            if not stopped:
                self._held.append(dup)
        if stopped:
            _shut_down(dup)
            dup.close()

    # The shutdowns and the closes are made under the lock (a shutdown does not
    # block): a dup closed while a stop shut it down could free its descriptor
    # for an unrelated socket the stop would then reach.
    def stop(self) -> None:
        with self._lock:
            self._stopped = True
            for sock in self._held:
                _shut_down(sock)
        abort_requests(self._client)

    def close(self) -> None:
        with self._lock:
            held, self._held = self._held, []
            for sock in held:
                with suppress(OSError):
                    sock.close()


# The artefact try running in this context; ``None`` outside one.
_TRY_IN_FLIGHT: ContextVar[_TryInFlight | None] = ContextVar("maljan_try_in_flight", default=None)


class _TrackedBackend:
    """A pool's network backend that registers each new socket with the try in flight.

    The three calls httpx's connection pool makes of its backend, each passed
    to the one it wraps.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def _held(self, stream: Any) -> Any:
        running = _TRY_IN_FLIGHT.get()
        if running is not None:
            with suppress(Exception):
                running.hold(stream.get_extra_info("socket"))
        return stream

    def connect_tcp(self, *args: Any, **kwargs: Any) -> Any:
        return self._held(self._inner.connect_tcp(*args, **kwargs))

    def connect_unix_socket(self, *args: Any, **kwargs: Any) -> Any:
        return self._held(self._inner.connect_unix_socket(*args, **kwargs))

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


def _track_connections(client: Any) -> None:
    """Have every pool of ``client`` open its connections through :class:`_TrackedBackend`.

    Its own transport's and each proxy mount's. Idempotent; a transport
    without such a pool is left as it is.
    """
    with suppress(Exception):
        for transport in _transports(client):
            pool = getattr(transport, "_pool", None)
            backend = getattr(pool, "_network_backend", None)
            if hasattr(backend, "connect_tcp") and not isinstance(backend, _TrackedBackend):
                pool._network_backend = _TrackedBackend(backend)  # type: ignore[union-attr]


class ArtefactAttemptFailed(Exception):
    """One try at an artefact that failed, in words the provider composed.

    ``transient`` says whether asking again can change the answer (a 5xx other
    than 501/505, a 429, a dropped transport); ``retry_after`` is the wait the
    sandbox asked for, in seconds, where it asked for one.
    """

    def __init__(self, cause: str, *, transient: bool, retry_after: float | None = None) -> None:
        super().__init__(cause)
        self.cause = cause
        self.transient = transient
        self.retry_after = retry_after


def status_failure(response: httpx.Response, step: str = "") -> ArtefactAttemptFailed:
    """An HTTP error answer to an artefact request, as one failed try."""
    status = response.status_code
    transient = status == 429 or poll_failure(response) is not None
    header = response.headers.get("Retry-After") if transient else None
    retry_after = _parse_retry_after(header, time.time()) if header else None
    cause = f"{step} HTTP {status}" if step else f"HTTP {status}"
    return ArtefactAttemptFailed(cause, transient=transient, retry_after=retry_after)


def with_fetch_retries(
    attempt: Callable[[], Any],
    *,
    artefact: str,
    what: str,
    sleep: Callable[[float], Any],
    interval: float,
    step: str = "",
    client: httpx.Client | None = None,
) -> Any:
    """``attempt()``'s answer, asked again after a transient failure; never silent.

    A try that raises :class:`ArtefactAttemptFailed` or a transport error and
    is transient is tried again, up to :data:`ARTEFACT_FETCH_ATTEMPTS` in all;
    any other exception is final at once. Each failure is logged with its
    status or the exception's type (never a URL or the exception's text, which
    may carry one), and the last raises :class:`ArtefactFetchFailed`, which
    names the artefact lost and why.

    Under a :class:`FetchBudget` (:func:`fetch_budget`, set by the job) its
    sleep replaces ``sleep``, each wait is clamped to what remains of its
    deadline, a retry past the deadline stops with the cause ``deadline``, and
    a cancelled job neither sleeps nor tries again (``cancelled``): a thread
    the job abandoned must not write a capture after its staging is gone.
    While a try runs, the job's cancel ends the requests ``client`` has in
    flight (:func:`abort_requests`), and a try that fails once the job is
    cancelled is said as ``cancelled``, never as the error the cancel caused.
    """
    budget = _FETCH_BUDGET.get()
    if budget is not None:
        sleep = budget.sleep
    wait = float(interval)
    for tried in range(1, ARTEFACT_FETCH_ATTEMPTS + 1):
        stop = budget.stop_cause(retry=tried > 1) if budget is not None else ""
        if stop:
            logger.warning("%s: %s not fetched (%s).", what, artefact, stop)
            raise ArtefactFetchFailed(artefact, stop)
        in_flight = untrack = token = None
        if budget is not None and client is not None:
            _track_connections(client)
            in_flight = _TryInFlight(client)
            token = _TRY_IN_FLIGHT.set(in_flight)
            untrack = budget.track(in_flight.stop)
        try:
            if budget is not None and budget.cancelled():
                # Cancelled since the check above, before anything was asked.
                failure = ArtefactAttemptFailed("before the try", transient=False)
            else:
                return attempt()
        except ArtefactAttemptFailed as exc:
            failure = exc
        except Exception as exc:  # noqa: BLE001 — named by its type, never re-raised raw
            label = f"{step} {type(exc).__name__}" if step else type(exc).__name__
            failure = ArtefactAttemptFailed(label, transient=isinstance(exc, POLL_TRANSPORT_ERRORS))
        finally:
            if untrack is not None:
                untrack()
            if token is not None:
                _TRY_IN_FLIGHT.reset(token)
            if in_flight is not None:
                in_flight.close()
        if budget is not None and budget.cancelled():
            logger.warning(
                "%s: %s not fetched (cancelled; the try in flight ended %s).",
                what,
                artefact,
                failure.cause,
            )
            raise ArtefactFetchFailed(artefact, "cancelled")
        if not failure.transient or tried == ARTEFACT_FETCH_ATTEMPTS:
            logger.warning(
                "%s: %s not fetched (%s) after %d attempt%s.",
                what,
                artefact,
                failure.cause,
                tried,
                "" if tried == 1 else "s",
            )
            raise ArtefactFetchFailed(artefact, failure.cause) from None
        stop = budget.stop_cause(retry=True) if budget is not None else ""
        if stop:
            logger.warning("%s: %s not fetched (%s, then %s).", what, artefact, failure.cause, stop)
            raise ArtefactFetchFailed(artefact, stop)
        logger.warning(
            "%s: %s fetch attempt %d failed transiently (%s); retrying.",
            what,
            artefact,
            tried,
            failure.cause,
        )
        asked = failure.retry_after
        delay = min(asked if asked is not None and asked > 0 else wait, _MAX_INTERVAL_SECONDS)
        if budget is not None:
            delay = min(delay, budget.deadline - budget.now())
        if delay > 0:
            sleep(delay)
        wait = min(wait * _BACKOFF_FACTOR, _MAX_INTERVAL_SECONDS)
    raise AssertionError("unreachable")  # pragma: no cover


def fetch_artefact(
    request: Callable[[], AbstractContextManager[httpx.Response]],
    keep: Callable[[httpx.Response], bool],
    out: Path,
    *,
    artefact: str,
    what: str,
    sleep: Callable[[float], Any],
    interval: float,
    min_bytes: int = CAPTURE_MIN_BYTES,
    client: httpx.Client | None = None,
) -> str | None:
    """Stream one artefact to ``out``; its path, or ``None`` where none is offered.

    ``request()`` opens the streamed answer and ``keep(response)`` writes it to
    ``out``, returning ``False`` where the answer says there is no artefact
    after all. A 404 is the sandbox offering none, as is ``keep``'s ``False``;
    every other failure is retried by :func:`with_fetch_retries` and, when it
    persists, raises :class:`ArtefactFetchFailed`. A file under ``min_bytes``
    raises it too, with its size as the cause. Whatever is left of a failed or
    empty fetch is removed: half a capture is a file of somebody's traffic
    nobody will read. ``client`` is the one ``request()`` asks with, whose
    request in flight the job's cancel ends.
    """

    def once() -> bool:
        try:
            with request() as response:
                if response.status_code == 404:
                    return False
                if response.status_code >= 400:
                    raise status_failure(response)
                return keep(response)
        except BaseException:
            out.unlink(missing_ok=True)
            raise

    fetched = with_fetch_retries(
        once, artefact=artefact, what=what, sleep=sleep, interval=interval, client=client
    )
    budget = _FETCH_BUDGET.get()
    if fetched and budget is not None and budget.cancelled():
        # A body that ends at the connection's close reads to its end once the
        # cancel shuts the socket down: what was written is half a capture.
        out.unlink(missing_ok=True)
        logger.warning("%s: %s not fetched (cancelled while it was read).", what, artefact)
        raise ArtefactFetchFailed(artefact, "cancelled")
    if not fetched:
        logger.info("%s: the sandbox offers no %s.", what, artefact)
        out.unlink(missing_ok=True)
        return None
    size = out.stat().st_size if out.exists() else 0
    if size < min_bytes:
        out.unlink(missing_ok=True)
        logger.warning("%s: %s fetched empty (%d bytes).", what, artefact, size)
        raise ArtefactFetchFailed(artefact, f"{size} bytes", empty=True)
    return str(out)


@register_sandbox_provider("triage")
class TriageSandboxProvider(SandboxProvider):
    """Hatching Triage cloud sandbox: submit, poll, fetch, all over REST.

    Triage never publishes a per-API-call log, so there is no ``apistats``,
    ``calls``, registry timeline or generic-event stream to map, and a file
    sample gets no screenshot either (the "Dynamic Report" docs page lists
    Triage's own top-level report fields — Version/Sample/Task/Errors/
    Analysis/Processes/Signatures/Network/Debug/Dumped/Extracted — and none
    of them is a screenshot). ``UNAVAILABLE`` names all five, by the
    platform's own section ids (``schemas.sandbox_report.SECTION_IDS``), rather
    than leaving them silently empty, which would read exactly like a clean
    sample.
    """

    # What the console calls this provider and says about it, and its test's label.
    choice_label = "Hatching Triage"
    guide_leaves = (
        "api_token",
        "base_url",
        "profile",
        "fetch_pcap",
        "poll_interval_seconds",
        "timeout_seconds",
    )
    choice_order = 3
    title = "Hatching Triage"
    description = "Triage runs the sample in its cloud and returns the report it produced."
    probe_label = "Test Triage connection"
    settings_intro = "The API token is stored on the server and never shown again."
    # The behavioural task reports are fetched beside the overview (``fetch``).
    FETCHES_TASK_REPORTS = True

    UNAVAILABLE: ClassVar[tuple[str, ...]] = (
        "apistats",
        "api_calls",
        "registry",
        "events",
        "screenshots",
    )

    def __init__(self, cfg: SandboxTriageConfig) -> None:
        self._cfg = cfg
        self._http: httpx.Client | None = None
        # Instance attributes, not module functions, so a test can drive the
        # clock and the sleeps without patching the stdlib.
        self._sleep = time.sleep
        self._now = time.monotonic
        self._now_utc = lambda: datetime.now(UTC)

    @classmethod
    def from_settings(cls, cfg: Settings) -> TriageSandboxProvider:
        return cls(cfg.sandbox.triage)

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            can_submit=True,
            can_poll=True,
            can_fetch_report=True,
            can_fetch_pcap=bool(self._cfg.fetch_pcap),
            provides_tools=False,
            report_format=_READER,
            degrade_on_failure=True,
        )

    def _require_token(self) -> str:
        token = self._cfg.api_token.get_secret_value()
        if not token:
            raise ProviderError(
                "Hatching Triage requires an API token; set sandbox.triage.api_token."
            )
        return token

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._require_token()}"}

    def _get_http(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(
                base_url=self._cfg.base_url,
                headers=self._auth_headers(),
                timeout=60.0,
            )
        return self._http

    @staticmethod
    def _raise_for_status(response: httpx.Response, operation: str, sent: str = "") -> None:
        """A refusal as Triage worded it: its ``error`` and ``message`` fields, else its body.

        ``sent`` names what this platform chose to send, where an operator's
        setting shaped the request, so a refusal of it points at the setting.
        """
        if response.status_code < 400:
            return
        said = response.text[:200]
        try:
            body = response.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            words = [str(body[key]) for key in ("error", "message") if body.get(key)]
            if words:
                said = ": ".join(words)[:400]
        raise ProviderError(
            f"Triage {operation} failed (HTTP {response.status_code}): {said}"
            + (f" (sent {sent})" if sent else "")
        )

    def _submit_settings_said(self) -> str:
        """The operator's settings the submission carries, for a refusal to name."""
        seconds = self._cfg.analysis_seconds
        if seconds is None:
            return ""
        return f"defaults.timeout={seconds} from sandbox.triage.analysis_seconds"

    def _profile_for(self, path: Path) -> str:
        """The VM profile this sample's format asks for, else the plain default.

        ``profile_by_format`` is keyed by detected file type with ``"*"`` as
        its fallback, and ``profile`` is the fallback behind that — so an
        operator who never touches the map keeps the profile they configured.
        """
        from maljan.providers.sandbox.formats import detect_sample_format, option_for_format

        file_type, _platform = detect_sample_format(path)
        return option_for_format(self._cfg.profile_by_format, file_type, self._cfg.profile)

    def submission_address(self) -> str | None:
        """The host the submission reaches: ``SUBMIT_PATH`` on the base URL."""
        from maljan.providers.base import requested_host

        return requested_host(self._cfg.base_url, SUBMIT_PATH)

    def _post_sample(self, path: Path, headers: dict[str, str]) -> httpx.Response:
        payload: dict[str, Any] = {"kind": "file", "interactive": False}
        profile = self._profile_for(path)
        if profile:
            payload["profiles"] = [{"profile": profile, "pick": "default"}]
        # How long the VM runs the sample: the operator's, or nothing sent and
        # Triage's own default.
        if self._cfg.analysis_seconds is not None:
            payload["defaults"] = {"timeout": int(self._cfg.analysis_seconds)}
        with open(path, "rb") as fh:
            return self._get_http().post(
                SUBMIT_PATH,
                files={
                    "file": (path.name, fh, "application/octet-stream"),
                    "_json": (None, json.dumps(payload), "application/json"),
                },
                headers=headers,
            )

    @staticmethod
    def _sha256_of(path: Path) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _submitted_at(entry: dict[str, Any]) -> datetime | None:
        """Parse a sample's own timestamp, whichever of the two fields carries it."""
        raw = str(entry.get("submitted") or entry.get("created") or "")
        if not raw:
            return None
        try:
            when = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        return when if when.tzinfo else when.replace(tzinfo=UTC)

    def _find_recent_owned_sample(self, sha256: str, headers: dict[str, str]) -> str | None:
        """The id of this operator's own newest sample with ``sha256``, if it is fresh.

        Answers ``None`` for anything uncertain — an unreachable listing, an
        error status, a body in another shape, a match older than the
        reconcile window — because a wrong id here would attach a run to
        somebody else's detonation of the same file.
        """
        try:
            response = self._get_http().get(
                OWNED_SAMPLES_PATH,
                params={"subset": "owned", "limit": _RECONCILE_LIMIT},
                headers=headers,
            )
        except httpx.HTTPError as exc:
            logger.warning("Triage: could not list owned samples to reconcile: %s", exc)
            return None
        if response.status_code >= 400:
            return None
        try:
            body = response.json()
        except ValueError:
            return None
        rows = body.get("data") if isinstance(body, dict) else None
        if not isinstance(rows, list):
            return None
        now = self._now_utc()
        candidates: list[tuple[datetime, str]] = []
        for row in rows:
            if not isinstance(row, dict) or not row.get("id"):
                continue
            if str(row.get("sha256") or "").lower() != sha256.lower():
                continue
            when = self._submitted_at(row)
            if when is None or (now - when).total_seconds() > _RECONCILE_WINDOW_SECONDS:
                continue
            candidates.append((when, str(row["id"])))
        if not candidates:
            return None
        return max(candidates)[1]

    def submit(self, sample_path: str | Path) -> str:
        # Checked before the file is opened or any request is built: a
        # missing token is a configuration error, not something worth
        # burning a filesystem check or a connection on first.
        headers = self._auth_headers()
        path = Path(sample_path)
        try:
            response = self._post_sample(path, headers)
        except httpx.TransportError as exc:
            # The upload can have been accepted in full and only the response
            # dropped — live run S6: the sample was on Triage, reported,
            # while the run treated the submission as failed and lost its
            # sandbox data. Look for it before posting the same file again,
            # so a reconciled submission leaves no orphan behind. An HTTP
            # status is a different matter and is never retried: a 401 or a
            # 400 means the request itself was refused.
            logger.warning("Triage: submit response was dropped (%s); reconciling.", exc)
            existing = self._find_recent_owned_sample(self._sha256_of(path), headers)
            if existing:
                logger.info("Triage: the dropped submission is sample %s; reusing it.", existing)
                return existing
            self._sleep(_SUBMIT_RETRY_DELAY_SECONDS)
            try:
                response = self._post_sample(path, headers)
            except httpx.TransportError:
                raise ProviderError(f"Triage submit failed: {exc}") from exc
            # Anything else the retry raises is left exactly as it is: only a
            # dropped transport is this path's business, and rewriting an
            # unrelated failure into "Triage submit failed" would hide it.
        self._raise_for_status(response, "submit", self._submit_settings_said())
        data = response.json()
        sample_id = data.get("id")
        if not sample_id:
            raise ProviderError("Unexpected Triage submit response: no sample id returned.")
        return str(sample_id)

    def wait_for_completion(
        self,
        task_id: str,
        timeout_seconds: int | None = None,
        poll_interval_seconds: int | None = None,
    ) -> str:
        headers = self._auth_headers()
        interval = float(poll_interval_seconds or self._cfg.poll_interval_seconds)
        budget = float(
            timeout_seconds if timeout_seconds is not None else self._cfg.timeout_seconds
        )
        deadline = self._now() + budget
        http = self._get_http()
        url = STATUS_PATH.format(sample_id=task_id)
        what = f"Triage task {task_id}"
        last_error = ""
        while True:
            # Checked at the top of every iteration, including the rate-limit
            # branch below: a server that keeps answering 429/503 past the
            # deadline must still raise rather than loop forever.
            if self._now() >= deadline:
                raise poll_deadline_error(what, budget, last_error)
            try:
                response = http.get(url, headers=headers)
            except POLL_TRANSPORT_ERRORS as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                interval = wait_after_poll_failure(
                    self._sleep, self._now, interval, deadline, what, last_error
                )
                continue
            if response.status_code in (429, 503):
                # "Come back later" — no documented rate limit was reachable
                # (see the module docstring), so a Retry-After header is
                # honoured when present and the ordinary backoff otherwise.
                # The header may be delta-seconds or an HTTP-date (RFC 9110);
                # either way the wait is clamped to what remains of this
                # call's own deadline, since the top-of-loop check above
                # cannot interrupt a sleep already in progress — a server
                # answering e.g. "Retry-After: 86400" must not park this
                # call for a day.
                retry_after = response.headers.get("Retry-After")
                parsed = _parse_retry_after(retry_after, self._now()) if retry_after else None
                # A sustained ``Retry-After: 0`` (or a negative/expired
                # HTTP-date) must not spin the loop: floor the wait at the
                # current backoff interval whenever the header does not ask
                # for a positive wait, the same as when it is absent.
                honoured = parsed is not None and parsed > 0
                wait_seconds: float = parsed if parsed is not None and honoured else interval
                remaining = deadline - self._now()
                clamped = min(wait_seconds, _MAX_INTERVAL_SECONDS, remaining)
                if clamped > 0:
                    self._sleep(clamped)
                if not honoured:
                    interval = min(interval * _BACKOFF_FACTOR, _MAX_INTERVAL_SECONDS)
                continue
            failure = poll_failure(response)
            if failure is None:
                self._raise_for_status(response, "status check")
                try:
                    payload = response.json()
                except ValueError as exc:
                    failure = f"an unparsable status body ({exc})"
                else:
                    if not isinstance(payload, dict):
                        failure = f"a status body that is a {type(payload).__name__}"
            if failure is not None:
                last_error = failure
                interval = wait_after_poll_failure(
                    self._sleep, self._now, interval, deadline, what, last_error
                )
                continue
            status = str(payload.get("status") or "")
            if status in TERMINAL_STATUSES:
                return status
            self._sleep(interval)
            interval = min(interval * _BACKOFF_FACTOR, _MAX_INTERVAL_SECONDS)

    @staticmethod
    def _behavioral_task_names(overview: dict[str, Any]) -> list[str]:
        """Names of every behavioural task in an overview, in listed order.

        The one place this is worked out, shared by ``fetch`` (which needs
        every behavioural task's report) and ``fetch_pcap`` (which needs the
        first one's capture) — so a sample whose first task isn't literally
        named ``"behavioral1"``, or that ran several, is handled the same way
        in both places instead of one of them guessing.

        The live API returns ``tasks`` as a dict keyed by task id while the
        documented shape is a list; both are read here, keeping the order the
        overview listed them in.
        """
        tasks = overview.get("tasks")
        if isinstance(tasks, dict):
            listed: list[Any] = list(tasks.values())
        elif isinstance(tasks, list):
            listed = list(tasks)
        else:
            listed = []
        names: list[str] = []
        for one_task in listed:
            if not isinstance(one_task, dict) or one_task.get("kind") != "behavioral":
                continue
            name = str(one_task.get("name") or "")
            if name:
                names.append(name)
        return names

    def _json_capped(
        self,
        http: httpx.Client,
        url: str,
        headers: dict[str, str],
        operation: str,
        *,
        skip_errors: bool = False,
    ) -> Any:
        """One JSON body, streamed and refused past the cap.

        ``skip_errors`` is for the bodies a run can do without: a behavioural
        task that never reached "reported" answers 4xx, and the overview alone
        still yields a usable, if thinner, report.
        """
        with http.stream("GET", url, headers=headers) as response:
            if response.status_code >= 400:
                if skip_errors:
                    return None
                response.read()
                self._raise_for_status(response, operation)
            body = read_capped(response, what=f"The Triage {operation.split()[0]} body")
        from maljan.core.safe_json import loads

        try:
            # Read at any nesting depth (``core.safe_json``).
            return loads(body)
        except ValueError as exc:
            raise ProviderError(f"Triage {operation} did not return valid JSON.") from exc

    def fetch(self, task_id: str) -> SandboxRun:
        from maljan.schemas.sandbox_report import SandboxRun

        headers = self._auth_headers()
        http = self._get_http()
        # Streamed and capped rather than fetched whole: an overview
        # and its behavioural reports are the bodies Triage legitimately sends
        # by the hundreds of megabytes, and their size is the remote end's
        # choice alone.
        overview = self._json_capped(
            http, OVERVIEW_PATH.format(sample_id=task_id), headers, "overview fetch"
        )

        task_reports: dict[str, dict[str, Any]] = {}
        for name in self._behavioral_task_names(overview):
            report = self._json_capped(
                http,
                TASK_REPORT_PATH.format(sample_id=task_id, task=name),
                headers,
                "task report fetch",
                # A task that never reached "reported" has no report yet; the
                # overview alone still yields a usable, if thinner, report.
                skip_errors=True,
            )
            if report is None:
                continue
            task_reports[name] = report

        report = required_reader(_READER).read(
            overview, provider=self.id, task_id=str(task_id), task_reports=task_reports
        )
        return SandboxRun(
            task_id=str(task_id),
            sample_sha256=report.target.sha256,
            sample_name=report.target.name,
            status="reported",
            report=report,
            raw=overview,
        )

    def fetch_pcap(self, task_id: str, dest_dir: str | Path) -> str | None:
        if not self._cfg.fetch_pcap:
            return None
        headers = self._auth_headers()
        http = self._get_http()
        what = f"Triage sample {task_id}"
        interval = float(self._cfg.poll_interval_seconds)

        # The overview names the task whose capture this is. Read again here
        # rather than kept from ``fetch``; a failure to read it loses the
        # capture as surely as a failed download does, and is said the same way.
        def overview() -> Any:
            response = http.get(OVERVIEW_PATH.format(sample_id=task_id), headers=headers)
            if response.status_code >= 400:
                raise status_failure(response, "overview")
            try:
                return response.json()
            except ValueError:
                # A body cut short in transit reads the same as one that is not
                # JSON; asking again is what tells them apart.
                raise ArtefactAttemptFailed("overview JSONDecodeError", transient=True) from None

        names = self._behavioral_task_names(
            with_fetch_retries(
                overview,
                artefact=PACKET_CAPTURE,
                what=what,
                sleep=self._sleep,
                interval=interval,
                step="overview",
                client=http,
            )
        )
        if not names:
            logger.info("Triage: sample %s has no behavioural task; no PCAP to fetch.", task_id)
            return None

        # A cancel that arrived during the overview request leaves no
        # directory behind it.
        stop_if_cancelled(PACKET_CAPTURE)
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        safe_task_id = _safe_path_component(str(task_id))
        safe_task_name = _safe_path_component(names[0])
        out = dest / f"triage_{safe_task_id}.pcap"
        url = PCAP_PATH.format(sample_id=safe_task_id, task=safe_task_name)

        def keep(response: httpx.Response) -> bool:
            # A capture past the cap fails this fetch rather than filling the disk.
            stream_to_file_capped(response, out, what="The Triage capture")
            return True

        # Never a hard failure of the run: the network analyst falls back to
        # the structured ``network`` block alone, and the run says what it lost
        # (``ArtefactFetchFailed``). What is left of a capture nobody will read
        # goes with the answer (``fetch_artefact``).
        return fetch_artefact(
            lambda: http.stream("GET", url, headers=headers),
            keep,
            out,
            artefact=PACKET_CAPTURE,
            what=what,
            sleep=self._sleep,
            interval=interval,
            client=http,
        )

    async def probe(self) -> ProviderProbe:
        """List resources: the cheapest documented call that exercises URL and token."""
        t0 = time.perf_counter()
        try:
            token = self._require_token()
        except ProviderError as exc:
            return ProviderProbe(ok=False, detail=str(exc))
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self._cfg.base_url.rstrip('/')}{RESOURCES_PATH}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            from maljan.core.settings_overrides import redact_url

            return ProviderProbe(
                ok=False,
                detail=redact_url(f"{type(exc).__name__}: {exc}"),
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )
        return ProviderProbe(
            ok=response.status_code < 400,
            detail=f"HTTP {response.status_code}",
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )

    def close(self) -> None:
        """Release the REST connection pool, if one was ever built. Never raises."""
        client, self._http = self._http, None
        if client is not None:
            with suppress(Exception):
                client.close()
