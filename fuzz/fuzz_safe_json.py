"""Fuzz the reader every sandbox report and stored ledger body goes through.

A sandbox report is the remote end's choice, bytes and nesting included.
``safe_json.loads`` either answers a value or raises ``ValueError`` (the
decoder's complaint, or bytes that are not text), at any depth, and what it
answers is written back out by ``safe_json.dumps`` without raising.
"""

import logging
import sys

import atheris

with atheris.instrument_imports():
    from malspark.core import safe_json

# The guard's "marked N containers" warning would print on every deep input.
logging.disable(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:  # noqa: N802 - the name libFuzzer looks for
    if not data:
        return
    body: str | bytes = data[1:] if data[0] & 1 else data[1:].decode("utf-8", "replace")
    try:
        value = safe_json.loads(body)
    except ValueError:
        return
    safe_json.dumps(value)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
