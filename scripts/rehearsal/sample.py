"""The rehearsal's sample: a small benign PE built in memory, never a real program.

It is the repository's synthetic image (``tests/unit/tools/synthetic_pe``) with
four imports and one URL string, so every pack step, every analyst and every
report section has something to read. It does nothing when run, and nothing
here runs it. It is written as ``sample_1.exe`` because that is the name the
mock sandbox's recorded fixture answers to (``data/samples/dynamic/sample_1.json``),
which gives the dynamic and network analysts sandbox data without a sandbox.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# The name the mock sandbox's recorded fixture is filed under.
SAMPLE_NAME = "sample_1.exe"
# The one network value the sample holds, so the report has an indicator to carry.
SAMPLE_URL = "http://rehearsal.example.net/beacon"
# The values that give the report's list sections something to hold: a host
# identifier, an operator command and a command-line flag.
SAMPLE_MUTEX = "Global\\RehearsalMutex"
SAMPLE_COMMAND = "cmd.exe /c whoami"
SAMPLE_FLAG = "--install"


def sample_bytes() -> bytes:
    """The image's bytes: the same on every call."""
    from tests.unit.tools.synthetic_pe import SyntheticPE

    image = SyntheticPE()
    image.imports_at(
        0x0,
        {
            "KERNEL32.dll": ["CreateFileW", "WriteFile", "Sleep"],
            "WININET.dll": ["InternetOpenW"],
        },
    )
    image.put("data", 0x10, SAMPLE_URL.encode("ascii") + b"\x00")
    offset = 0x60
    for value in (SAMPLE_MUTEX, SAMPLE_COMMAND, SAMPLE_FLAG):
        image.put("data", offset, value.encode("ascii") + b"\x00")
        offset += 0x40
    # The first two words of SHA-256's initial hash, as the published constant
    # scan finds them, so the encryption section has a fact to read.
    sha256_iv = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A)
    image.put("rdata", 0x300, b"".join(v.to_bytes(4, "little") for v in sha256_iv))
    return image.build()


def write_sample(directory: Path) -> tuple[Path, str]:
    """Write the sample into ``directory``; answer its path and sha256."""
    data = sample_bytes()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / SAMPLE_NAME
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()
