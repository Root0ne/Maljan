from collections.abc import Iterator
from unittest.mock import MagicMock

import pytest

from app import observability
from app.auth import throttle
from maljan.app import MaljanApp


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
