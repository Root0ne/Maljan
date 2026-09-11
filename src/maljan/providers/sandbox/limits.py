"""How much of a sandbox's answer Maljan is willing to read.

The REST and Triage providers read a report
with ``response.json()`` and streamed a pcap to disk with no ceiling on
either. A sandbox is a remote service under someone else's control, often a
public one, and a report is the one body that is legitimately large -- so a
misbehaving or hostile endpoint could hand a worker a body until it ran out of
memory or filled the disk, with nothing in between to stop it.

The cap and its shape are the sandbox-report upload endpoint's, which has read
its input this way since it was written: accumulate in chunks, stop the moment
the total passes the limit, and say which body it was rather than dying on an
allocation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from maljan.providers.errors import ProviderError

# Read at call time, never bound at import: the tests lower it, and a future
# setting can point at it without every caller having to be found again.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
CHUNK_BYTES = 64 * 1024


def _too_large(what: str, cap: int) -> ProviderError:
    return ProviderError(
        f"{what} is larger than the {cap // (1024 * 1024)} MiB the sandbox providers "
        "will read; refusing it rather than reading the rest."
    )


def read_capped(response: Any, *, what: str, cap: int | None = None) -> bytes:
    """The body of a streamed response, refused the moment it passes the cap.

    ``response`` is an httpx response opened with ``client.stream(...)``, so
    what is read here is what has actually crossed the wire: an over-cap body
    costs the cap plus one chunk, not the whole of whatever the server meant
    to send.
    """
    limit = MAX_RESPONSE_BYTES if cap is None else cap
    body = bytearray()
    for chunk in response.iter_bytes(CHUNK_BYTES):
        body.extend(chunk)
        if len(body) > limit:
            raise _too_large(what, limit)
    return bytes(body)


def stream_to_file_capped(response: Any, out: Path, *, what: str, cap: int | None = None) -> None:
    """Write a streamed response to ``out``, stopping if it passes the cap.

    The partial file is removed on the way out: half a capture is not a
    capture, and leaving it behind would let the next reader mistake it for
    one.
    """
    limit = MAX_RESPONSE_BYTES if cap is None else cap
    written = 0
    with open(out, "wb") as handle:
        for chunk in response.iter_bytes(CHUNK_BYTES):
            written += len(chunk)
            if written > limit:
                handle.close()
                out.unlink(missing_ok=True)
                raise _too_large(what, limit)
            handle.write(chunk)
