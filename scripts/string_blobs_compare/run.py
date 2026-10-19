"""Compare ``decode_string_blobs`` with another revision of it on synthetic PEs.

    uv run python -m scripts.string_blobs_compare.run --ref origin/dev

The other revision's ``src/maljan/tools/string_blobs.py`` is read from git
(``--ref``) or from a file (``--module``) and loaded beside this tree's. Both
decode the same images, built by ``tests/unit/tools/synthetic_pe.py`` from
invented strings: one key byte and a rising key, each string ending in its NUL
encoded, a raw zero after it, a newline or a space before either, or the
section's edge (an adversarial set adds inverted case, punctuation, tabs, CRLF and
headers); and random, compressed and zero-split sections. Nothing is
executed but the two decoders.

Per category (tail and scheme) it prints the wrong rows of each (any row that
is not the string under its scheme) and the strings decoded right, and lists
every string the other revision decoded right that this tree does not. It
exits 1 when this tree has more wrong rows than the other in any category or
loses any string, else 0.
"""

from __future__ import annotations

import argparse
import collections
import importlib.util
import random
import struct
import subprocess
import sys
import tempfile
import zlib
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

from tests.unit.tools.synthetic_pe import TEXT_RVA, SyntheticPE

from maljan.tools import string_blobs as this_tree

MODULE = "src/maljan/tools/string_blobs.py"
FUNCTION = TEXT_RVA + 0x100
STRING_AT = 0x40

# Invented strings of the kinds a sample keeps encoded.
TEXTS = (
    b"Hello world",
    b"Connecting to server",
    b"Injection done",
    b"advapi32.dll",
    b"CreateMutexA",
    b"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"User-Agent: Mozilla/5.0",
    b"cmd.exe /c del %s",
    b"GetProcAddress",
    b"Failed to open file",
    b"http://example.invalid/gate.php",
    b"svchost.exe",
    b"Starting service",
    b"password",
    b"VirtualAllocEx",
    b"Error code %d",
)
SWEEP_TEXTS = (
    b"kernel32.dll",
    b"Software\\Microsoft\\Windows",
    b"password",
    b"GetProcAddress",
    b"http://a.invalid/x",
    b"svchost.exe",
    b"User-Agent",
    b"advapi32",
    b"open the settings file",
    b"remote folder name",
    b"CreateMutexA",
    b"config.ini",
    b"Mozilla/5.0",
    b"WinHttpOpen",
)
# The bytes after the text inside the encoding, and the raw bytes after it.
TAILS = {
    "NULenc": (b"\0", b""),
    "rawzero": (b"", b"\0"),
    "NL+NULenc": (b"\n\0", b""),
    "NL+rawzero": (b"\n", b"\0"),
    "SP+rawzero": (b" ", b"\0"),
    "edge": (b"", b""),
    "edge+NL": (b"\n", b""),
}
# Adversarial strings: inverted case, punctuation, white space before the end.
ADV_TEXTS = (
    b"pASSWORD",
    b"cREATEmUTEXa",
    b"C:\\Temp\\a.exe",
    b"user@host:~",
    b"key=value;name=x",
    b"%s:%d",
    b"[%s] <%s>",
    b"\\\\.\\PIPE\\x",
    b"GETPROCADDRESS",
    b"Global\\{8F6F0AC4}",
    b"HKLM\\SYSTEM\\Run",
    b"a1b2c3d4e5f6",
    b"==>> ready",
    b"ID:%08X;OS:%s",
    b"/c ping 127.0.0.1",
    b"Content-Type: text/html",
    b"READY",
    b"xor key is OK",
)
ADV_TAILS = {
    "NL+raw": (b"\n", b"\0"),
    "SP+raw": (b" ", b"\0"),
    "TAB+raw": (b"\t", b"\0"),
    "CRLF+raw": (b"\r\n", b"\0"),
    "NL+NUL": (b"\n\0", b""),
    "NUL": (b"\0", b""),
    "SP+NUL": (b" \0", b""),
    "edge": (b"\n", b""),
}
ADV_HEADERS = 60
NOISE_SEEDS = 6
NOISE_SIZE = 0x8000


def xor8(text: bytes, key: int) -> bytes:
    return bytes(byte ^ key for byte in text)


def rising(text: bytes, first: int) -> bytes:
    return bytes(byte ^ ((first + index) & 0xFF) for index, byte in enumerate(text))


ENCODERS: dict[str, Callable[[bytes, int], bytes]] = {"xor8": xor8, "xor8_rolling": rising}


def load_other(ref: str | None, module: str | None) -> ModuleType:
    if module:
        path = Path(module)
    else:
        source = subprocess.run(
            ["git", "show", f"{ref}:{MODULE}"], check=True, capture_output=True
        ).stdout
        path = Path(tempfile.mkdtemp()) / "string_blobs_other.py"
        path.write_bytes(source)
    spec = importlib.util.spec_from_file_location("maljan.tools.string_blobs_other", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    other = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = other
    spec.loader.exec_module(other)
    return other


class Compare:
    def __init__(self, other: ModuleType) -> None:
        self.modules = {"other": other, "this": this_tree}
        self.target = Path(tempfile.mkdtemp()) / "s.exe"
        self.correct: collections.Counter[tuple[str, str]] = collections.Counter()
        self.wrong: collections.Counter[tuple[str, str]] = collections.Counter()
        self.lost: list[tuple[str, bytes, list[tuple[str, str]]]] = []

    def rows(self, name: str, blob: bytes, at: int) -> list[tuple[str, str]]:
        image = SyntheticPE(functions=[(TEXT_RVA, FUNCTION), (FUNCTION, TEXT_RVA + 0x300)])
        image.lea_to(0x120, image.put("data", at, blob))
        self.target.write_bytes(image.build())
        answer = self.modules[name].decode_string_blobs(str(self.target), include_unreferenced=True)
        return [
            (row["scheme"], row["text"])
            for row in answer["results"] + answer["unreferenced_results"]
        ]

    def string(self, category: str, scheme: str, want: str, blob: bytes) -> None:
        found = {}
        for name in self.modules:
            rows = found[name] = self.rows(name, blob, STRING_AT)
            self.correct[(category, name)] += (scheme, want) in rows
            self.wrong[(category, name)] += sum(1 for row in rows if row != (scheme, want))
        if (scheme, want) in found["other"] and (scheme, want) not in found["this"]:
            self.lost.append((category, want.encode(), found["this"]))

    def noise(self, category: str, blob: bytes) -> None:
        for name in self.modules:
            self.wrong[(category, name)] += len(self.rows(name, blob, 0))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ref", default="origin/dev", help="git ref of the other revision")
    parser.add_argument("--module", help="a file holding the other revision instead")
    arguments = parser.parse_args(argv)
    compare = Compare(load_other(arguments.ref, arguments.module))

    picker = random.Random(5)
    keys = [picker.randrange(0x80, 0x100) for _ in range(5)]
    for tail, (inside, after) in TAILS.items():
        for scheme, encode in ENCODERS.items():
            for text in TEXTS:
                want = (text + inside.rstrip(b"\0")).decode()
                for key in keys:
                    compare.string(
                        f"{tail}/{scheme}", scheme, want, encode(text + inside, key) + after
                    )
    for scheme, encode in ENCODERS.items():
        for text in SWEEP_TEXTS:
            for key in range(0x80, 0x100, 7):
                compare.string(
                    f"sweep-NULenc/{scheme}", scheme, text.decode(), encode(text + b"\0", key)
                )
    picker = random.Random(9)
    keys = [picker.randrange(0x80, 0x100) for _ in range(4)]
    for tail, (inside, after) in ADV_TAILS.items():
        for scheme, encode in ENCODERS.items():
            for text in ADV_TEXTS:
                want = (text + inside.rstrip(b"\0")).decode()
                for key in keys:
                    compare.string(
                        f"adv-{tail}/{scheme}", scheme, want, encode(text + inside, key) + after
                    )
    for _ in range(ADV_HEADERS):
        seed = picker.getrandbits(32)
        text = picker.choice(ADV_TEXTS) + b"\0"
        stored = len(text) ^ (seed & 0xFFFF)
        blob = struct.pack("<IH", seed, stored) + rising(text, seed & 0xFF)
        compare.string("adv-seed-header", "xor8_rolling_header", text[:-1].decode(), blob)
        key = bytes(picker.randrange(1, 256) for _ in range(picker.choice((1, 2, 4))))
        body = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(text))
        blob = bytes([len(key)]) + key + body
        compare.string("adv-stored-key", "xor_keyed_header", text[:-1].decode(), blob)
    for seed in range(NOISE_SEEDS):
        rng = random.Random(seed)
        split = bytearray()
        while len(split) < NOISE_SIZE:
            split += bytes(rng.randrange(1, 256) for _ in range(rng.randrange(8, 40)))
            split += b"\0" * rng.randrange(1, 4)
        letters = bytes(rng.choice(b"abcdefghij klmnop\n") for _ in range(2 * NOISE_SIZE))
        compare.noise("random", bytes(rng.randrange(256) for _ in range(NOISE_SIZE)))
        compare.noise("compressed", zlib.compress(letters)[:NOISE_SIZE])
        compare.noise("zero-split", bytes(split))

    failed = bool(compare.lost)
    heads = ("wrong other", "wrong this", "right other", "right this")
    print(f"{'category':26} " + " ".join(f"{head:>11}" for head in heads))
    for category in sorted({category for category, _ in compare.wrong}):
        other, this = compare.wrong[(category, "other")], compare.wrong[(category, "this")]
        failed |= this > other
        print(
            f"{category:26} {other:11} {this:10} {compare.correct[(category, 'other')]:11} "
            f"{compare.correct[(category, 'this')]:10}{'  MORE WRONG' if this > other else ''}"
        )
    for category, text, rows in compare.lost:
        print("LOST", category, text, rows)
    print("FAIL" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
