from collections.abc import Iterator
from functools import cache
from unittest.mock import MagicMock

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.compiler import compiles

from app import observability
from app.auth import throttle
from maljan.app import MaljanApp
from maljan.core.ctype_locale import pin_character_classification
from tests.golden_fixtures import report_absent_fixture_skips


@compiles(postgresql.UUID, "sqlite")
def _uuid_as_text_on_sqlite(element, compiler, **kw):  # noqa: ANN001, ANN202
    # SQLite types a column by its declared name: "UUID" gets NUMERIC affinity,
    # which stores a 32-digit hex id holding one "e" as a REAL. CHAR keeps text.
    return "CHAR(32)"


def pytest_configure(config: pytest.Config) -> None:
    """The test process pins its character classes at its start, as the platform's do.

    Before any test module loads the YARA engine, whose ``nocase`` table is
    built by the LC_CTYPE in force when it loads: every test then runs under
    the locale the worker, the CLI and the sidecars run under. A test that
    changes the locale itself does so in a subprocess.
    """
    pin_character_classification()


@pytest.fixture(autouse=True)
def no_configured_secret_outlives_its_test() -> Iterator[None]:
    """The values the scrub masks by value are registered per test and forgotten after it.

    The registry is module state, filled by whatever built a worker, an app or
    a job's settings; left behind, one test's defaults masked words in every
    later test's text.
    """
    from maljan.pipeline import events

    events.forget_secret_values()
    yield
    events.forget_secret_values()


@pytest.fixture(autouse=True)
def reset_observability_state() -> None:
    """Resets observability counters and throttle state before each test.

    The counters and throttle are module-level singletons shared across
    tests. Without resetting them, a test that fails to increment/decrement
    a counter or that leaves a Redis pool set would interfere with every
    test that runs after it.
    """
    observability.counters.audit_write_failures = 0
    observability.throttle.available = True
    observability.throttle.degraded_since = None
    observability.throttle.last_error = None
    throttle._pool = None
    throttle._last_failure_at = None


@cache
def _own_servers_kept() -> tuple[tuple[str, str, dict], ...]:
    """What each of the platform's own servers declares of its tools, as the store keeps it.

    The frozen capture the parity gate holds every server's own listing to
    (``tests/unit/servers/test_each_own_server_declares_its_tools.py``), under
    the launch identity of the block it ships with.
    """
    import json
    from pathlib import Path

    from maljan.core.config import _builtin_servers
    from maljan.core.tool_declarations import launch_identity

    captured = json.loads(
        (Path(__file__).parent / "fixtures" / "own_server_tool_facts.json").read_text()
    )
    blocks = _builtin_servers()
    return tuple(
        (f"mcp:{key}", launch_identity(blocks[key]), tools) for key, tools in captured.items()
    )


@pytest.fixture(autouse=True)
def the_own_servers_have_declared_their_tools() -> Iterator[None]:
    """Each test starts where a deployment is once its own servers were first listed.

    The platform's own sidecars ship no table of their tools: what the
    platform reads of them is what each declared when it was last listed,
    kept past the process (``core.served_declarations``). Every test starts
    with that kept declaration, and with nothing this process listed or
    forgot since; a test of a fresh install, before any listing, forgets it
    (``forget_served``).
    """
    from maljan.core import served_declarations

    served_declarations._UNSAVED.clear()
    served_declarations.install_persisted(_own_servers_kept())
    yield
    # And between tests, where a module's or a session's fixture is built.
    served_declarations._UNSAVED.clear()
    served_declarations.install_persisted(_own_servers_kept())


@pytest.fixture(autouse=True, scope="session")
def the_own_servers_declared_their_tools_before_the_first_test() -> None:
    """As above, before any fixture of a wider scope than a test is built."""
    from maljan.core import served_declarations

    served_declarations.install_persisted(_own_servers_kept())


@pytest.fixture(autouse=True)
def no_server_is_listed_or_reread_unless_a_test_asks(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test lists a server before its run, nor rereads the kept declarations per request.

    A job's start lists each trusted server nothing is kept for
    (``providers.served_listing``), and the API rereads what is kept every few
    seconds (``served_declarations_store.refresh``): left on, a test's worker
    would start the real sidecars and a test's request would read an empty
    test database over the kept declarations, depending on the clock. A test
    of either asks for it itself.
    """
    from app.services import served_declarations_store
    from maljan.providers import served_listing

    monkeypatch.setattr(served_listing, "unlisted", lambda settings: [])
    # Read last at the end of time: never due again.
    monkeypatch.setattr(served_declarations_store, "_READ_AT", [float("inf")])


@pytest.fixture(autouse=True)
def no_floss_unless_a_test_names_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """The triage pack runs FLOSS on every PE, and a test's pack runs none.

    The build lives outside the environment, so whether a test found one was a
    fact about the machine: on a box with it installed every pack over a
    synthetic PE spent seconds emulating it and recorded an entry a runner
    without it never had. ``MALJAN_FLOSS_PATH`` naming no file is the one
    answer both give. A test about FLOSS sets or clears the variable itself,
    and a sidecar a test starts never sees it — ``child_env`` passes no such
    variable.
    """
    monkeypatch.setenv("MALJAN_FLOSS_PATH", "/nonexistent/maljan-tests/floss")


@pytest.fixture(autouse=True)
def close_the_sidecars_a_test_opened() -> Iterator[None]:
    """A test's tool servers go with the test, the way a job's go with the job.

    ``_ATTACHED_HANDLES`` holds an open handle strongly for as long as it is
    attached, which is right — dropping the last reference to an open stdio
    toolkit spins the agent loop — but it means a test that opens one and does
    not close it leaves it there for the whole session. An instrumented run
    found eighty-three of them at the end, twenty-odd still holding live child
    pids, so the two files that retire the shared agent loop on purpose met a
    registry holding every earlier test's handles and reaped them all on the
    watchdog thread.

    Only what this test left is closed: the set is read before it runs and the
    difference afterwards is what it opened.
    """
    from maljan.providers import servers

    before = set(servers._ATTACHED_HANDLES)
    yield
    for handle in set(servers._ATTACHED_HANDLES) - before:
        try:
            handle.close()
        except Exception:  # noqa: BLE001 — a test's leftovers never fail a test
            pass
        # ``close`` declines a handle ``aopen`` attached, whose exit stack
        # belongs to a loop this thread is not on and which is usually already
        # closed by the time a test ends. Its child is this process's either
        # way, and nothing else will come back for it.
        if handle in servers._ATTACHED_HANDLES:
            handle._toolkit = None
            handle._all_tools = []
            handle._opened_async = False
            try:
                handle._reap_children()
            except Exception:  # noqa: BLE001
                pass
            handle._forget_attachment()


@pytest.fixture(autouse=True)
def remove_the_staging_a_test_left() -> Iterator[None]:
    """A test's staging directory goes with the test, as a job's goes with the job.

    A test that drives a sandbox fetch or a sidecar without a job id of its own
    composes one from this process, and there is no worker ``finally`` behind
    it to take the directory away — so a suite run left `job-cli-<pid>`
    directories, one of them holding a capture, in the real staging base. Only
    what this test composed is removed: the record is read before it runs and
    the difference afterwards is what it made.
    """
    from maljan.tools import staging

    before = {job: set(paths) for job, paths in staging._COMPOSED.items()}
    yield
    for job in [key for key in staging._COMPOSED if key not in before]:
        staging.remove_job_staging(job)
    for job, paths in before.items():
        for path in set(staging._COMPOSED.get(job, ())) - paths:
            staging.remove_tree(path)


@pytest.fixture
def mock_maljan_app() -> MaljanApp:
    """MaljanApp in mock mode for fast facade-level tests."""
    return MaljanApp(mock=True)


@pytest.fixture
def mock_llm() -> MagicMock:
    """Mock LLM instance for testing agents without hitting real APIs."""
    mock = MagicMock()
    mock.invoke.return_value = MagicMock(content="Mocked LLM Response")
    return mock


@pytest.fixture
def sample_static_data() -> list[dict]:
    """Sample static analysis data matching Ghidra JSON format."""
    return [
        {
            "file": "test_sample.exe",
            "decompiled_summary": "CryptAcquireContext, CreateRemoteThread.",
            "strings": [
                "http://malware-c2.example/beacon",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ],
            "pe_header": {
                "entry_point": "0x401000",
                "sections": [".text", ".rdata", ".data"],
            },
        }
    ]


@pytest.fixture
def sample_dynamic_data() -> dict:
    """Sample sandbox behavior report matching CAPEv2 format."""
    return {
        "behavior": {
            "apistats": {
                "2572": {
                    "CreateProcessInternalW": 2,
                    "RegSetValueExW": 1,
                    "HttpSendRequestW": 4,
                }
            },
            "generic": [
                {
                    "category": "persistence",
                    "description": "Sets a Run key for future execution.",
                },
                {
                    "category": "evasion",
                    "description": "Injects code into explorer.exe via CreateRemoteThread.",
                },
            ],
        }
    }


@pytest.fixture
def sample_network_data() -> list[dict]:
    """Sample Zeek connection log data."""
    return [
        {
            "service": "dns",
            "id.resp_h": "9.9.9.9",
            "id.resp_p": 53,
            "query": "malware-c2.example",
        },
        {
            "service": "ssl",
            "id.resp_h": "185.199.110.153",
            "id.resp_p": 443,
            "resp_bytes": 512,
        },
    ]


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    """The session ends with how many golden cases compared nothing for want of a source."""
    report_absent_fixture_skips(terminalreporter)
