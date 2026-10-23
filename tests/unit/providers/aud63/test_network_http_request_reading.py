"""PS-L11: any HTTP method, and a Host header however it was written, are read."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def _server():
    spec = importlib.util.spec_from_file_location(
        "network_mcp_aud63", ROOT / "services" / "network-mcp" / "server.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_other_methods_and_host_spellings_are_read():
    read = _server().http_request_of
    assert read(b"PATCH /a HTTP/1.1\r\nHost: x.example\r\n\r\n") == (
        b"PATCH /a HTTP/1.1",
        b"Host: x.example",
    )
    assert read(b"OPTIONS * HTTP/1.1\r\nHOST:y.example\r\n\r\n")[1] == b"HOST:y.example"
    assert read(b"GET / HTTP/1.1\r\n\r\nHost: in-the-body\r\n") == (b"GET / HTTP/1.1", b"")
    assert read(b"\x16\x03\x01 not http") is None
