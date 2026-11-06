"""Fuzz the reader that takes JSON out of a model's answer.

A model's answer is text the model chose, and a sample's own strings reach it.
The reader finds the payload among fences and prose, repairs what it can and
answers ``None`` where nothing parses; none of its entry points raises.
"""

import sys

import atheris

with atheris.instrument_imports():
    from maljan.utils import json_cleaner


def TestOneInput(data: bytes) -> None:  # noqa: N802 - the name libFuzzer looks for
    text = atheris.FuzzedDataProvider(data).ConsumeUnicodeNoSurrogates(len(data))
    json_cleaner.extract_json(text)
    json_cleaner.repair_json(text)
    json_cleaner.safe_parse_json(text)
    json_cleaner.json_decode_error(text)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
