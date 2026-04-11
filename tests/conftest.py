from unittest.mock import MagicMock

import pytest


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
