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
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException, UploadFile

from app.api.v1 import sandbox_reports as module


def _upload(data: bytes, filename: str) -> UploadFile:
    return UploadFile(io.BytesIO(data), filename=filename)


def _db() -> MagicMock:
    """A ``db`` whose settings read (``effective_core_settings``) resolves to
    the model defaults: no stored rows, so ``sandbox.upload.max_report_bytes``
    is whatever ``build_settings({})`` gives it -- comfortably above every
    payload these tests write."""
    from app.services.settings_service import core_settings_cache

    core_settings_cache.invalidate()
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock(scalars=lambda: MagicMock(all=lambda: [])))
    return db


@pytest.mark.asyncio
async def test_a_dot_gz_filename_with_non_gzip_bytes_is_read_as_plain_json():
    payload = {"info": {"version": "CAPEv2"}, "target": {"sha256": "a" * 64}}
    raw = json.dumps(payload).encode()
    body, parsed = await module._read_payload(_upload(raw, "report.json.gz"), _db())
    assert parsed == payload
    assert body == raw


@pytest.mark.asyncio
async def test_a_utf8_bom_is_tolerated():
    payload = {"info": {"version": "CAPEv2"}, "target": {"sha256": "b" * 64}}
    raw = b"\xef\xbb\xbf" + json.dumps(payload).encode()
    _, parsed = await module._read_payload(_upload(raw, "report.json"), _db())
    assert parsed == payload


@pytest.mark.asyncio
async def test_a_top_level_json_list_is_refused_with_400():
    with pytest.raises(HTTPException) as exc_info:
        await module._read_payload(_upload(b"[1, 2, 3]", "report.json"), _db())
    assert exc_info.value.status_code == 400
