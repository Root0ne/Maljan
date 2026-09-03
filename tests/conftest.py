import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maljan.app import MaljanApp

# Import observability to reset counters/throttle
_API_PATH = Path(__file__).resolve().parent.parent / "apps" / "api"
if str(_API_PATH) not in sys.path:
    sys.path.insert(0, str(_API_PATH))

from app import observability  # noqa: E402


@pytest.fixture(autouse=True)
def reset_observability_state() -> None:
    """Reset observability counters and throttle before each test.

    The counters and throttle are module-level singletons shared across tests.
    Without resetting them, tests that fail to increment/decrement counters will
    interfere with subsequent tests. This fixture ensures each test starts with
    a clean state.
    """
    observability.counters.audit_write_failures = 0
    observability.throttle.available = True
    observability.throttle.degraded_since = None
    observability.throttle.last_error = None


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
