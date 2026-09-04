"""``_read_payload`` alone: gzip detection, BOM tolerance and shape checks.

The upload route decides whether to inflate by looking at the first two bytes,
never at the filename — a ``.json.gz`` upload that is not actually gzipped
must come through as plain JSON rather than fail. A UTF-8 byte-order mark
(still written by some Windows tooling) must not break the parse. Anything
that parses to something other than a JSON object is refused before the
format sniffer or storage ever see it.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

import pytest  # noqa: E402
from app.api.v1 import sandbox_reports as module  # noqa: E402
from fastapi import HTTPException, UploadFile  # noqa: E402


def _upload(data: bytes, filename: str) -> UploadFile:
    return UploadFile(io.BytesIO(data), filename=filename)


def test_a_dot_gz_filename_with_non_gzip_bytes_is_read_as_plain_json():
    payload = {"info": {"version": "CAPEv2"}, "target": {"sha256": "a" * 64}}
    raw = json.dumps(payload).encode()
    body, parsed = module._read_payload(_upload(raw, "report.json.gz"), "report.json.gz")
    assert parsed == payload
    assert body == raw


def test_a_utf8_bom_is_tolerated():
    payload = {"info": {"version": "CAPEv2"}, "target": {"sha256": "b" * 64}}
    raw = b"\xef\xbb\xbf" + json.dumps(payload).encode()
    _, parsed = module._read_payload(_upload(raw, "report.json"), "report.json")
    assert parsed == payload


def test_a_top_level_json_list_is_refused_with_400():
    with pytest.raises(HTTPException) as exc_info:
        module._read_payload(_upload(b"[1, 2, 3]", "report.json"), "report.json")
    assert exc_info.value.status_code == 400
